//go:build windows

package platform

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

// icmpEchoReply mirrors ICMP_ECHO_REPLY on 64-bit Windows.
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Ttl           uint8
	Tos           uint8
	Flags         uint8
	OptionsSize   uint8
	OptionsData   uintptr
}

const (
	ipSuccess       = 0
	ipReqTimedOut   = 11010
	pingPayloadSize = 32
)

// icmpPinger uses the Windows ICMP helper API. Unlike raw sockets it doesn't
// need administrator rights. IcmpSendEcho only reports whole milliseconds, so
// the round trip is timed around the call instead, which gives sub-millisecond
// resolution for LAN targets at the cost of a few microseconds of call overhead.
type icmpPinger struct {
	handle  uintptr
	dst     uint32
	payload [pingPayloadSize]byte
	reply   []byte
}

func NewPinger(ip net.IP) (Pinger, error) {
	v4, err := toIPv4(ip)
	if err != nil {
		return nil, err
	}
	h, _, callErr := procIcmpCreateFile.Call()
	if h == uintptr(windows.InvalidHandle) || h == 0 {
		return nil, fmt.Errorf("IcmpCreateFile: %v", callErr)
	}
	p := &icmpPinger{
		handle: h,
		dst:    binary.LittleEndian.Uint32(v4),
		reply:  make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+pingPayloadSize+64),
	}
	copy(p.payload[:], "sherlock-sherlock-sherlock-sherl")
	return p, nil
}

func (p *icmpPinger) Ping(timeout time.Duration) (time.Duration, error) {
	ms := uint32(timeout / time.Millisecond)
	if ms == 0 {
		ms = 1
	}
	start := time.Now()
	n, _, callErr := procIcmpSendEcho.Call(
		p.handle,
		uintptr(p.dst),
		uintptr(unsafe.Pointer(&p.payload[0])),
		uintptr(len(p.payload)),
		0,
		uintptr(unsafe.Pointer(&p.reply[0])),
		uintptr(len(p.reply)),
		uintptr(ms),
	)
	rtt := time.Since(start)
	if n == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == ipReqTimedOut {
			return 0, ErrTimeout
		}
		return 0, fmt.Errorf("IcmpSendEcho: %v", callErr)
	}
	r := (*icmpEchoReply)(unsafe.Pointer(&p.reply[0]))
	switch r.Status {
	case ipSuccess:
		return rtt, nil
	case ipReqTimedOut:
		return 0, ErrTimeout
	default:
		return 0, fmt.Errorf("ICMP status %d", r.Status)
	}
}

func (p *icmpPinger) Close() error {
	procIcmpCloseHandle.Call(p.handle)
	return nil
}
