package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gopacket/gopacket/layers"
)

// segmentSnapLen is the snaplen written into segment and event file headers.
//
// It is deliberately larger than the snaplen we ask the driver for. Npcap
// re-inserts an 802.1Q tag when the adapter has "Packet Priority & VLAN"
// enabled, after truncation, so a 128-byte capture arrives as 132 bytes.
// Strict pcap readers (including gopacket's) reject packets longer than the
// header's snaplen, which made whole events unreadable. 65535 is the
// conventional "no limit" value and every tool accepts it.
const segmentSnapLen = 65535

const (
	magicMicros = 0xa1b2c3d4
	magicNanos  = 0xa1b23c4d
	// Sanity bound on a single record so a corrupt length can't make us
	// allocate gigabytes. Far above any real frame, jumbo or not.
	maxRecordLen = 256 * 1024
)

type segmentPacket struct {
	ts     time.Time
	length uint32 // original length on the wire
	data   []byte
}

// segmentReader reads classic pcap files without enforcing the header's
// snaplen, so files written by older Sherlock versions (snaplen 128) can
// still be recovered.
type segmentReader struct {
	r        *bufio.Reader
	order    binary.ByteOrder
	nanos    bool
	linkType layers.LinkType
	hdr      [16]byte
}

func newSegmentReader(r io.Reader) (*segmentReader, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	var h [24]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		return nil, err
	}
	s := &segmentReader{r: br}
	switch {
	case binary.LittleEndian.Uint32(h[:4]) == magicMicros:
		s.order = binary.LittleEndian
	case binary.LittleEndian.Uint32(h[:4]) == magicNanos:
		s.order, s.nanos = binary.LittleEndian, true
	case binary.BigEndian.Uint32(h[:4]) == magicMicros:
		s.order = binary.BigEndian
	case binary.BigEndian.Uint32(h[:4]) == magicNanos:
		s.order, s.nanos = binary.BigEndian, true
	default:
		return nil, fmt.Errorf("not a pcap file (magic %x)", h[:4])
	}
	s.linkType = layers.LinkType(s.order.Uint32(h[20:24]) & 0x0fffffff)
	return s, nil
}

// next returns the next packet, or io.EOF at the end. A record cut off by a
// crash or a mid-write rotation is treated as the end of the file.
func (s *segmentReader) next() (segmentPacket, error) {
	if _, err := io.ReadFull(s.r, s.hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = io.EOF
		}
		return segmentPacket{}, err
	}
	sec := s.order.Uint32(s.hdr[0:4])
	frac := s.order.Uint32(s.hdr[4:8])
	capLen := s.order.Uint32(s.hdr[8:12])
	origLen := s.order.Uint32(s.hdr[12:16])
	if capLen > maxRecordLen {
		return segmentPacket{}, fmt.Errorf("corrupt record: capture length %d", capLen)
	}
	data := make([]byte, capLen)
	if _, err := io.ReadFull(s.r, data); err != nil {
		return segmentPacket{}, io.EOF
	}
	if !s.nanos {
		frac *= 1000
	}
	// A re-inserted VLAN tag can also make the capture longer than the
	// reported wire length; pcap writers require origLen >= capLen.
	if origLen < capLen {
		origLen = capLen
	}
	return segmentPacket{ts: time.Unix(int64(sec), int64(frac)), length: origLen, data: data}, nil
}
