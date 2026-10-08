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
	kernel32                      = windows.NewLazySystemDLL("kernel32.dll")
	procQueryPerformanceCounter   = kernel32.NewProc("QueryPerformanceCounter")
	procQueryPerformanceFrequency = kernel32.NewProc("QueryPerformanceFrequency")

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
// the round trip is timed around the call with QueryPerformanceCounter.
//
// Go's own clock (time.Now / time.Since) isn't usable for this on Windows: its
// monotonic reading only advances on the system timer tick, typically every
// 0.5 to 15.6 ms, so a 0.3 ms LAN ping measured as either 0 or one whole tick.
// QPC resolves to well under a microsecond. The figure includes a few
// microseconds of call overhead, which is negligible next to a real RTT.
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
	start := qpc()
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
	rtt := qpcSince(start)
	if n == 0 {
		errno, _ := callErr.(syscall.Errno)
		if errno == ipReqTimedOut {
			return 0, ErrTimeout
		}
		return 0, fmt.Errorf("IcmpSendEcho returned no reply: %s (Windows code %d)", ipStatusText(uint32(errno), callErr), uint32(errno))
	}
	r := (*icmpEchoReply)(unsafe.Pointer(&p.reply[0]))
	switch {
	case r.Status == ipReqTimedOut:
		return 0, ErrTimeout
	case r.Status != ipSuccess:
		return 0, fmt.Errorf("%s (ICMP status %d) from %s", ipStatusText(r.Status, nil), r.Status, addrString(r.Address))
	case r.Address != p.dst:
		// An echo reply always comes from the host that was pinged. Anything
		// else means the reply belongs to a different request, so don't count it.
		return 0, fmt.Errorf("reply came from %s, not %s", addrString(r.Address), addrString(p.dst))
	}
	return rtt, nil
}

func addrString(a uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], a)
	return net.IP(b[:]).String()
}

// ipStatusText names the IP_STATUS codes from ipexport.h that a ping can return.
func ipStatusText(code uint32, fallback error) string {
	switch code {
	case 11001:
		return "reply buffer too small"
	case 11002:
		return "destination network unreachable"
	case 11003:
		return "destination host unreachable"
	case 11004:
		return "destination protocol unreachable"
	case 11005:
		return "destination port unreachable"
	case 11006:
		return "no resources"
	case 11007:
		return "bad option"
	case 11008:
		return "hardware error"
	case 11009:
		return "packet too big"
	case 11011:
		return "bad request"
	case 11012:
		return "bad route"
	case 11013:
		return "TTL expired in transit"
	case 11014:
		return "TTL expired during reassembly"
	case 11015:
		return "parameter problem"
	case 11016:
		return "source quench"
	case 11018:
		return "bad destination"
	case 11050:
		return "general failure"
	}
	if fallback != nil {
		return fallback.Error()
	}
	return "unknown status"
}

func (p *icmpPinger) Close() error {
	procIcmpCloseHandle.Call(p.handle)
	return nil
}

var qpcFreq = func() int64 {
	var f int64
	procQueryPerformanceFrequency.Call(uintptr(unsafe.Pointer(&f)))
	return f
}()

func qpc() int64 {
	var c int64
	procQueryPerformanceCounter.Call(uintptr(unsafe.Pointer(&c)))
	return c
}

func qpcSince(start int64) time.Duration { return ticksToDuration(qpc()-start, qpcFreq) }
