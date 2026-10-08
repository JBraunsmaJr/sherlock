// Package monitor runs Sherlock's collectors, detects problems, and records
// event snapshots.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"sherlock/internal/capture"
	"sherlock/internal/config"
	"sherlock/internal/platform"
	"sherlock/internal/store"
)

type Monitor struct {
	cfg   config.Config
	store *store.Store
	log   *log.Logger

	detector *Detector
	recorder *Recorder
	tput     *Throughput

	ctx context.Context

	mu          sync.Mutex
	started     time.Time
	ifName      string
	ifStats     platform.IfStats
	ifErr       string
	gateway     net.IP
	probes      map[int]*probeState
	traffic     [10]float64 // recent rx+tx Mbps, newest at trafficPos-1
	trafficPos  int
	trafficN    int
	capturer    *capture.Capturer
	captureOn   bool
	captureErr  string
	captureFile string
}

type probeState struct {
	addr    string
	lastRTT float64 // NaN if the last probe failed
	lastTS  int64
	ring    [60]bool // true = lost
	pos, n  int
}

func New(cfg config.Config, st *store.Store, logger *log.Logger) *Monitor {
	m := &Monitor{
		cfg:     cfg,
		store:   st,
		log:     logger,
		started: time.Now(),
		probes: map[int]*probeState{
			store.TargetGateway:  {lastRTT: math.NaN()},
			store.TargetInternet: {addr: cfg.Targets.Internet, lastRTT: math.NaN()},
			store.TargetDNS:      {addr: cfg.Targets.DNSHost, lastRTT: math.NaN()},
		},
	}
	m.captureOn = cfg.Capture.Enabled
	if v, ok := st.Setting("capture_enabled"); ok {
		m.captureOn = v == "true"
	}
	m.recorder = newRecorder(m)
	m.detector = newDetector(cfg.Events, m.recorder)
	m.tput = newThroughput(m)
	return m
}

func (m *Monitor) Store() *store.Store     { return m.store }
func (m *Monitor) Throughput() *Throughput { return m.tput }
func (m *Monitor) EventsDir() string       { return filepath.Join(m.cfg.DataDir, "events") }
func (m *Monitor) Config() config.Config   { return m.cfg }
func (m *Monitor) ActiveEventID() string   { return m.recorder.activeID() }
func (m *Monitor) logf(f string, a ...any) { m.log.Printf(f, a...) }

// Run starts every collector and blocks until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) error {
	m.ctx = ctx
	reader, err := m.waitForInterface(ctx)
	if err != nil {
		return err
	}
	if m.captureOn {
		if err := m.startCapture(); err != nil {
			m.logf("capture: %v", err)
		}
	}

	var wg sync.WaitGroup
	run := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	run(func(ctx context.Context) { m.linkLoop(ctx, reader) })
	run(m.gatewayLoop)
	if m.cfg.Targets.Internet != "" {
		run(m.internetLoop)
	}
	if m.cfg.Targets.DNSHost != "" {
		run(m.dnsLoop)
	}
	run(m.flushLoop)
	run(m.pruneLoop)
	run(func(context.Context) { m.recorder.repairCaptures() })
	run(m.tput.run)

	<-ctx.Done()
	wg.Wait()
	m.recorder.wait()
	m.mu.Lock()
	c := m.capturer
	m.capturer = nil
	m.mu.Unlock()
	if c != nil {
		c.Stop()
	}
	return m.store.Flush()
}

// waitForInterface picks the adapter to watch, retrying until it exists so
// Sherlock can be started before a USB adapter is plugged in.
func (m *Monitor) waitForInterface(ctx context.Context) (*platform.IfReader, error) {
	for {
		name := m.cfg.Interface
		var err error
		if name == "" {
			_, name, err = platform.DefaultGateway("")
			if err == nil && name == "" {
				err = errors.New("default route has no adapter name")
			}
			if err != nil {
				err = fmt.Errorf("auto-detecting the adapter: %w (set \"interface\" in the config)", err)
			}
		}
		if err == nil {
			var r *platform.IfReader
			if r, err = platform.NewIfReader(name); err == nil {
				m.mu.Lock()
				m.ifName, m.ifErr = name, ""
				m.mu.Unlock()
				m.logf("watching adapter %q", name)
				return r, nil
			}
		}
		m.mu.Lock()
		m.ifErr = err.Error()
		m.mu.Unlock()
		m.logf("%v; retrying in 5s", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (m *Monitor) linkLoop(ctx context.Context, r *platform.IfReader) {
	t := time.NewTicker(m.cfg.Sampling.LinkInterval.D())
	defer t.Stop()
	prev, err := r.Read()
	havePrev := err == nil
	prevT := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			cur, err := r.Read()
			row := store.LinkRow{TS: now.UnixMilli()}
			if err != nil {
				// A vanished adapter is, for our purposes, a down link.
				m.mu.Lock()
				m.ifErr = err.Error()
				m.ifStats.Up, m.ifStats.SpeedMbps = false, 0
				m.mu.Unlock()
				m.store.AddLink(row)
				m.detector.OnLink(row, nil)
				havePrev = false
				continue
			}
			if havePrev {
				dt := now.Sub(prevT).Seconds()
				row.Up, row.SpeedMbps = cur.Up, cur.SpeedMbps
				row.RxBps = float64(delta(cur.RxBytes, prev.RxBytes)) * 8 / dt
				row.TxBps = float64(delta(cur.TxBytes, prev.TxBytes)) * 8 / dt
				row.RxErrors = delta(cur.RxErrors, prev.RxErrors)
				row.TxErrors = delta(cur.TxErrors, prev.TxErrors)
				row.RxDiscards = delta(cur.RxDiscards, prev.RxDiscards)
				row.TxDiscards = delta(cur.TxDiscards, prev.TxDiscards)
				m.store.AddLink(row)
				m.detector.OnLink(row, &cur)
			}
			m.mu.Lock()
			m.ifStats, m.ifErr = cur, ""
			if havePrev {
				m.traffic[m.trafficPos] = (row.RxBps + row.TxBps) / 1e6
				m.trafficPos = (m.trafficPos + 1) % len(m.traffic)
				if m.trafficN < len(m.traffic) {
					m.trafficN++
				}
			}
			m.mu.Unlock()
			prev, prevT, havePrev = cur, now, true
		}
	}
}

// delta handles counters that reset (driver restart, adapter replug) by treating the reset as zero.
func delta(cur, prev uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

func (m *Monitor) gatewayLoop(ctx context.Context) {
	var (
		pinger     platform.Pinger
		pinged     net.IP
		lastLookup time.Time
	)
	defer func() {
		if pinger != nil {
			pinger.Close()
		}
	}()
	m.pingLoop(ctx, store.TargetGateway, func() (platform.Pinger, error) {
		// Re-check the gateway every 30s in case DHCP changed it.
		if pinger == nil || time.Since(lastLookup) > 30*time.Second {
			lastLookup = time.Now()
			ip := net.ParseIP(m.cfg.Targets.Gateway)
			if ip == nil {
				m.mu.Lock()
				ifName := m.ifName
				m.mu.Unlock()
				var err error
				if ip, _, err = platform.DefaultGateway(ifName); err != nil {
					return nil, err
				}
			}
			if pinger == nil || !ip.Equal(pinged) {
				if pinger != nil {
					pinger.Close()
				}
				p, err := platform.NewPinger(ip)
				if err != nil {
					pinger = nil
					return nil, err
				}
				pinger, pinged = p, ip
				m.mu.Lock()
				m.gateway = ip
				m.probes[store.TargetGateway].addr = ip.String()
				m.mu.Unlock()
				m.logf("gateway is %s", ip)
			}
		}
		return pinger, nil
	})
}

func (m *Monitor) internetLoop(ctx context.Context) {
	ip := net.ParseIP(m.cfg.Targets.Internet)
	if ip == nil {
		m.logf("targets.internet %q is not an IP address; internet checks disabled", m.cfg.Targets.Internet)
		return
	}
	var pinger platform.Pinger
	defer func() {
		if pinger != nil {
			pinger.Close()
		}
	}()
	m.pingLoop(ctx, store.TargetInternet, func() (platform.Pinger, error) {
		if pinger == nil {
			p, err := platform.NewPinger(ip)
			if err != nil {
				return nil, err
			}
			pinger = p
		}
		return pinger, nil
	})
}

func (m *Monitor) pingLoop(ctx context.Context, target int, get func() (platform.Pinger, error)) {
	t := time.NewTicker(m.cfg.Sampling.PingInterval.D())
	defer t.Stop()
	var lastErr string
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			rtt := math.NaN()
			p, err := get()
			if err == nil {
				var d time.Duration
				if d, err = p.Ping(m.cfg.Sampling.PingTimeout.D()); err == nil {
					rtt = float64(d.Microseconds()) / 1000
				}
			}
			if err != nil && !errors.Is(err, platform.ErrTimeout) && err.Error() != lastErr {
				m.logf("%s probe: %v", targetName(target), err)
			}
			errText := ""
			if err != nil {
				errText = err.Error()
			}
			lastErr = errText
			m.recordProbe(now, target, rtt, errText)
		}
	}
}

func (m *Monitor) dnsLoop(ctx context.Context) {
	t := time.NewTicker(m.cfg.Sampling.DNSInterval.D())
	defer t.Stop()
	// The pure-Go resolver talks to the configured DNS server directly instead of
	// going through the OS cache, so this measures the network rather than the cache.
	res := &net.Resolver{PreferGo: true}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			start := time.Now()
			_, err := res.LookupHost(lctx, m.cfg.Targets.DNSHost)
			cancel()
			rtt, errText := math.NaN(), ""
			if err == nil {
				rtt = float64(time.Since(start).Microseconds()) / 1000
			} else {
				errText = err.Error()
			}
			m.recordProbe(now, store.TargetDNS, rtt, errText)
		}
	}
}

func (m *Monitor) recordProbe(now time.Time, target int, rtt float64, errText string) {
	m.store.AddProbe(store.ProbeRow{TS: now.UnixMilli(), Target: target, RTTms: rtt})
	m.mu.Lock()
	ps := m.probes[target]
	ps.lastRTT, ps.lastTS = rtt, now.UnixMilli()
	ps.ring[ps.pos] = math.IsNaN(rtt)
	ps.pos = (ps.pos + 1) % len(ps.ring)
	if ps.n < len(ps.ring) {
		ps.n++
	}
	addr := ps.addr
	m.mu.Unlock()
	m.detector.OnProbe(target, addr, rtt, errText)
}

func targetName(t int) string {
	switch t {
	case store.TargetGateway:
		return "gateway"
	case store.TargetInternet:
		return "internet"
	case store.TargetDNS:
		return "dns"
	}
	return "unknown"
}

func (m *Monitor) flushLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.store.Flush(); err != nil {
				m.logf("store: %v", err)
			}
		}
	}
}

func (m *Monitor) pruneLoop(ctx context.Context) {
	if m.cfg.RetentionDays <= 0 {
		return
	}
	prune := func() {
		cutoff := time.Now().AddDate(0, 0, -m.cfg.RetentionDays).UnixMilli()
		if err := m.store.Prune(cutoff); err != nil {
			m.logf("prune: %v", err)
		}
	}
	prune()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			prune()
		}
	}
}

// recentTrafficMbps is the average rx+tx rate over the last ~10 link samples.
func (m *Monitor) recentTrafficMbps() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.trafficN == 0 {
		return 0
	}
	sum := 0.0
	for i := 0; i < m.trafficN; i++ {
		sum += m.traffic[i]
	}
	return sum / float64(m.trafficN)
}

// ---- capture ----

func (m *Monitor) captureFilter() string {
	f := m.cfg.Capture.Filter
	if m.cfg.Throughput.Server != "" && m.cfg.Throughput.Port > 0 {
		// Speed tests would flood the capture with bulk data; leave them out.
		ex := fmt.Sprintf("not (tcp port %d)", m.cfg.Throughput.Port)
		if f == "" {
			f = ex
		} else {
			f = "(" + f + ") and " + ex
		}
	}
	return f
}

func (m *Monitor) startCapture() error {
	m.mu.Lock()
	dev := m.ifStats.CaptureDevice
	m.mu.Unlock()
	if dev == "" {
		// The link loop may not have read the adapter yet.
		r, err := platform.NewIfReader(m.ifName)
		if err != nil {
			return err
		}
		st, err := r.Read()
		if err != nil {
			return err
		}
		dev = st.CaptureDevice
	}
	seg := m.cfg.Capture.Segment.D()
	keep := int(math.Ceil(float64(m.cfg.Events.PreWindow.D())/float64(seg))) + 1
	c, err := capture.Start(m.ctx, capture.Options{
		Device:   dev,
		SnapLen:  m.cfg.Capture.SnapLen,
		Filter:   m.captureFilter(),
		Segment:  seg,
		Keep:     keep,
		BufferKB: m.cfg.Capture.BufferKB,
		Dir:      filepath.Join(m.cfg.DataDir, "capture-ring"),
	})
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.captureErr = err.Error()
		return err
	}
	m.capturer, m.captureErr = c, ""
	m.logf("capturing on %s (snaplen %d, filter %q)", dev, m.cfg.Capture.SnapLen, m.captureFilter())
	return nil
}

// SetCapture turns packet capture on or off and remembers the choice.
func (m *Monitor) SetCapture(on bool) error {
	m.mu.Lock()
	c := m.capturer
	m.captureOn = on
	if !on {
		m.capturer = nil
		m.captureErr = ""
	}
	m.mu.Unlock()
	val := "false"
	if on {
		val = "true"
	}
	if err := m.store.SetSetting("capture_enabled", val); err != nil {
		return err
	}
	if !on {
		if c != nil {
			c.Stop()
			m.logf("capture stopped")
		}
		return nil
	}
	if c != nil {
		return nil
	}
	return m.startCapture()
}

func (m *Monitor) currentCapturer() *capture.Capturer {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.capturer
}

// ---- status ----

type ProbeStatus struct {
	Addr    string   `json:"addr"`
	LastRTT *float64 `json:"last_rtt_ms"`
	LastTS  int64    `json:"last_ts"`
	LossPct float64  `json:"loss_pct"` // over the last 60 probes
	Samples int      `json:"samples"`
}

type CaptureStatus struct {
	Enabled bool `json:"enabled"`
	capture.Stats
}

type Status struct {
	Now         int64                  `json:"now"`
	Started     int64                  `json:"started"`
	OS          string                 `json:"os"`
	Interface   platform.IfStats       `json:"interface"`
	IfError     string                 `json:"interface_error,omitempty"`
	Probes      map[string]ProbeStatus `json:"probes"`
	TrafficMbps float64                `json:"traffic_mbps"`
	Capture     CaptureStatus          `json:"capture"`
	Throughput  ThroughputStatus       `json:"throughput"`
	ActiveEvent string                 `json:"active_event,omitempty"`
}

func (m *Monitor) Status() Status {
	traffic := m.recentTrafficMbps()
	m.mu.Lock()
	s := Status{
		Now:         time.Now().UnixMilli(),
		Started:     m.started.UnixMilli(),
		OS:          runtime.GOOS,
		Interface:   m.ifStats,
		IfError:     m.ifErr,
		Probes:      map[string]ProbeStatus{},
		TrafficMbps: traffic,
		Capture:     CaptureStatus{Enabled: m.captureOn},
	}
	if s.Interface.Name == "" {
		s.Interface.Name = m.ifName
	}
	for t, ps := range m.probes {
		p := ProbeStatus{Addr: ps.addr, LastTS: ps.lastTS, Samples: ps.n}
		if !math.IsNaN(ps.lastRTT) {
			v := ps.lastRTT
			p.LastRTT = &v
		}
		lost := 0
		for i := 0; i < ps.n; i++ {
			if ps.ring[i] {
				lost++
			}
		}
		if ps.n > 0 {
			p.LossPct = float64(lost) / float64(ps.n) * 100
		}
		s.Probes[targetName(t)] = p
	}
	c := m.capturer
	captureErr := m.captureErr
	m.mu.Unlock()
	if c != nil {
		s.Capture.Stats = c.Stats()
	} else {
		s.Capture.Error = captureErr
	}
	s.Throughput = m.tput.Status()
	s.ActiveEvent = m.recorder.activeID()
	return s
}

// AddNote records an annotation like "raised the desk".
func (m *Monitor) AddNote(text string) (store.Note, error) {
	n, err := m.store.AddNote(time.Now().UnixMilli(), text)
	if err == nil {
		m.logf("note: %s", text)
	}
	return n, err
}
