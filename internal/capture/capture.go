// Package capture records packet headers into a rolling set of short pcap
// files on disk. Memory use stays at one small write buffer no matter how much
// traffic flows. When an event fires, the retained files are moved into the
// event's folder instead of being deleted, then merged into one pcap.
package capture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
)

type Options struct {
	Device   string
	SnapLen  int
	Filter   string
	Segment  time.Duration
	Keep     int // closed segments retained while no event is open
	BufferKB int
	Dir      string // ring directory; emptied on start
}

type Stats struct {
	Running  bool   `json:"running"`
	Packets  uint64 `json:"packets"`
	Dropped  uint64 `json:"dropped"`
	Segments int    `json:"segments"`
	Filter   string `json:"filter"`
	Error    string `json:"error,omitempty"`
}

type op int

const (
	opFreeze op = iota
	opCollect
)

type request struct {
	op    op
	dst   string
	reply chan result
}

type result struct {
	files []string
	err   error
}

type Capturer struct {
	opts    Options
	handle  *pcap.Handle
	link    layers.LinkType
	reqs    chan request
	done    chan struct{}
	cancel  context.CancelFunc
	packets atomic.Uint64

	mu       sync.Mutex
	err      string
	closed   []string // finished segments, oldest first
	holding  bool     // an event is open: don't delete segments
	segments int

	// owned by the capture goroutine
	file     *os.File
	buf      *bufio.Writer
	w        *pcapgo.Writer
	segPath  string
	segStart time.Time
}

// Start opens the adapter and begins capturing in a background goroutine.
func Start(ctx context.Context, o Options) (*Capturer, error) {
	if err := loadDriver(); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(o.Dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(o.Dir, 0o755); err != nil {
		return nil, err
	}
	in, err := pcap.NewInactiveHandle(o.Device)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", o.Device, err)
	}
	defer in.CleanUp()
	in.SetSnapLen(o.SnapLen)
	in.SetPromisc(false)
	// A short read timeout keeps the loop responsive to rotation and event
	// requests even when the line is quiet.
	in.SetTimeout(250 * time.Millisecond)
	if o.BufferKB > 0 {
		in.SetBufferSize(o.BufferKB * 1024)
	}
	h, err := in.Activate()
	if err != nil {
		return nil, fmt.Errorf("activate %s: %w", o.Device, err)
	}
	if o.Filter != "" {
		if err := h.SetBPFFilter(o.Filter); err != nil {
			h.Close()
			return nil, fmt.Errorf("capture filter %q: %w", o.Filter, err)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &Capturer{
		opts:   o,
		handle: h,
		link:   h.LinkType(),
		reqs:   make(chan request),
		done:   make(chan struct{}),
		cancel: cancel,
	}
	if err := c.openSegment(time.Now()); err != nil {
		h.Close()
		cancel()
		return nil, err
	}
	go c.loop(ctx)
	return c, nil
}

func (c *Capturer) Stop() {
	c.cancel()
	<-c.done
}

func (c *Capturer) Stats() Stats {
	c.mu.Lock()
	s := Stats{Running: true, Segments: len(c.closed), Error: c.err, Filter: c.opts.Filter}
	c.mu.Unlock()
	s.Packets = c.packets.Load()
	select {
	case <-c.done:
		s.Running = false
	default:
		if st, err := c.handle.Stats(); err == nil {
			s.Dropped = uint64(st.PacketsDropped)
		}
	}
	return s
}

// Freeze closes the current segment and moves every retained segment into
// dst. Until Collect is called, new segments are kept rather than rotated away.
func (c *Capturer) Freeze(dst string) ([]string, error) { return c.do(opFreeze, dst) }

// Collect closes the current segment and moves every segment written since
// Freeze into dst, then resumes normal rotation.
func (c *Capturer) Collect(dst string) ([]string, error) { return c.do(opCollect, dst) }

func (c *Capturer) do(o op, dst string) ([]string, error) {
	r := request{op: o, dst: dst, reply: make(chan result, 1)}
	select {
	case c.reqs <- r:
	case <-c.done:
		return nil, errors.New("capture stopped")
	}
	res := <-r.reply
	return res.files, res.err
}

func (c *Capturer) loop(ctx context.Context) {
	defer close(c.done)
	defer c.handle.Close()
	defer c.closeSegment()
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-c.reqs:
			r.reply <- c.handle_(r)
			continue
		default:
		}
		data, ci, err := c.handle.ReadPacketData()
		now := time.Now()
		switch {
		case err == nil:
			c.packets.Add(1)
			if werr := c.w.WritePacket(ci, data); werr != nil {
				c.setErr(werr)
			}
		case errors.Is(err, pcap.NextErrorTimeoutExpired):
		case errors.Is(err, io.EOF):
			c.setErr(errors.New("adapter closed"))
			return
		default:
			c.setErr(err)
			// Avoid spinning if the adapter disappeared (unplugged USB NIC, driver reset).
			time.Sleep(500 * time.Millisecond)
		}
		if now.Sub(c.segStart) >= c.opts.Segment {
			c.rotate(now)
		}
	}
}

func (c *Capturer) handle_(r request) result {
	c.rotate(time.Now())
	c.mu.Lock()
	files := c.closed
	c.closed = nil
	c.holding = r.op == opFreeze
	c.mu.Unlock()
	if err := os.MkdirAll(r.dst, 0o755); err != nil {
		return result{err: err}
	}
	var moved []string
	for _, f := range files {
		to := filepath.Join(r.dst, filepath.Base(f))
		if err := moveFile(f, to); err != nil {
			return result{files: moved, err: err}
		}
		moved = append(moved, to)
	}
	return result{files: moved}
}

func (c *Capturer) openSegment(now time.Time) error {
	c.segPath = filepath.Join(c.opts.Dir, fmt.Sprintf("seg-%d.pcap", now.UnixMilli()))
	f, err := os.Create(c.segPath)
	if err != nil {
		return err
	}
	c.file = f
	c.buf = bufio.NewWriterSize(f, 64*1024)
	c.w = pcapgo.NewWriter(c.buf)
	c.segStart = now
	return c.w.WriteFileHeader(uint32(c.opts.SnapLen), c.link)
}

func (c *Capturer) closeSegment() {
	if c.file == nil {
		return
	}
	c.buf.Flush()
	c.file.Close()
	c.file = nil
}

func (c *Capturer) rotate(now time.Time) {
	c.closeSegment()
	c.mu.Lock()
	c.closed = append(c.closed, c.segPath)
	var drop []string
	if !c.holding && len(c.closed) > c.opts.Keep {
		drop = c.closed[:len(c.closed)-c.opts.Keep]
		c.closed = append([]string(nil), c.closed[len(c.closed)-c.opts.Keep:]...)
	}
	c.mu.Unlock()
	for _, f := range drop {
		os.Remove(f)
	}
	if err := c.openSegment(now); err != nil {
		c.setErr(err)
	}
}

func (c *Capturer) setErr(err error) {
	c.mu.Lock()
	c.err = err.Error()
	c.mu.Unlock()
}

func moveFile(from, to string) error {
	if err := os.Rename(from, to); err == nil {
		return nil
	}
	// Different volumes: copy, then remove.
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	in.Close()
	return os.Remove(from)
}

// Merge writes the packets from segment files whose timestamps fall within
// [from, to] into a single pcap at out, then deletes the segments.
// It returns how many packets were written.
func Merge(segments []string, out string, from, to time.Time) (int, error) {
	sort.Slice(segments, func(i, j int) bool { return segName(segments[i]) < segName(segments[j]) })
	f, err := os.Create(out)
	if err != nil {
		return 0, err
	}
	bw := bufio.NewWriterSize(f, 64*1024)
	var w *pcapgo.Writer
	count := 0
	for _, seg := range segments {
		n, err := appendSegment(seg, bw, &w, from, to)
		count += n
		if err != nil {
			bw.Flush()
			f.Close()
			return count, fmt.Errorf("%s: %w", filepath.Base(seg), err)
		}
	}
	if w == nil {
		// No readable segments: still produce a valid, empty capture.
		w = pcapgo.NewWriter(bw)
		w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		return count, err
	}
	if err := f.Close(); err != nil {
		return count, err
	}
	for _, seg := range segments {
		os.Remove(seg)
	}
	return count, nil
}

func appendSegment(seg string, bw *bufio.Writer, w **pcapgo.Writer, from, to time.Time) (int, error) {
	sf, err := os.Open(seg)
	if err != nil {
		return 0, err
	}
	defer sf.Close()
	r, err := pcapgo.NewReader(bufio.NewReader(sf))
	if err != nil {
		// A segment can be empty if it was rotated before its header flushed.
		return 0, nil
	}
	if *w == nil {
		*w = pcapgo.NewWriter(bw)
		if err := (*w).WriteFileHeader(r.Snaplen(), r.LinkType()); err != nil {
			return 0, err
		}
	}
	n := 0
	for {
		data, ci, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		if ci.Timestamp.Before(from) || ci.Timestamp.After(to) {
			continue
		}
		if err := (*w).WritePacket(gopacket.CaptureInfo{
			Timestamp: ci.Timestamp, CaptureLength: ci.CaptureLength, Length: ci.Length,
		}, data); err != nil {
			return n, err
		}
		n++
	}
}

func segName(p string) string {
	// seg-<millis>.pcap: same digit count for centuries, so string order is time order.
	return strings.TrimSuffix(filepath.Base(p), ".pcap")
}

// Devices lists capture devices, for the `interfaces` command.
func Devices() ([]pcap.Interface, error) {
	if err := loadDriver(); err != nil {
		return nil, err
	}
	return pcap.FindAllDevs()
}
