//go:build linux

package platform

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var pingerSeq atomic.Uint32

type icmpPinger struct {
	conn *icmp.PacketConn
	dst  net.Addr
	id   int
	seq  int
	raw  bool
	buf  []byte
}

// NewPinger tries an unprivileged ICMP socket first (allowed by
// net.ipv4.ping_group_range on most distros) and falls back to a raw socket,
// which needs root or CAP_NET_RAW.
func NewPinger(ip net.IP) (Pinger, error) {
	v4, err := toIPv4(ip)
	if err != nil {
		return nil, err
	}
	p := &icmpPinger{buf: make([]byte, 1500)}
	if c, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
		p.conn, p.dst = c, &net.UDPAddr{IP: v4}
	} else if c, err2 := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err2 == nil {
		p.conn, p.dst, p.raw = c, &net.IPAddr{IP: v4}, true
	} else {
		return nil, fmt.Errorf("cannot open ICMP socket (unprivileged: %v; raw: %v)", err, err2)
	}
	// Raw sockets see every ICMP reply on the host, so each pinger needs its own id.
	p.id = (os.Getpid() + int(pingerSeq.Add(1))) & 0xffff
	return p, nil
}

func (p *icmpPinger) Ping(timeout time.Duration) (time.Duration, error) {
	p.seq = (p.seq + 1) & 0xffff
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: p.id, Seq: p.seq, Data: []byte("sherlock-sherlock-sherlock-sherl")},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}
	deadline := time.Now().Add(timeout)
	if err := p.conn.SetReadDeadline(deadline); err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err := p.conn.WriteTo(b, p.dst); err != nil {
		return 0, err
	}
	for {
		n, _, err := p.conn.ReadFrom(p.buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return 0, ErrTimeout
			}
			return 0, err
		}
		rtt := time.Since(start)
		m, err := icmp.ParseMessage(1, p.buf[:n])
		if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := m.Body.(*icmp.Echo)
		// Unprivileged sockets rewrite the id to the socket's port, so only check it for raw sockets.
		if !ok || echo.Seq != p.seq || (p.raw && echo.ID != p.id) {
			continue
		}
		return rtt, nil
	}
}

func (p *icmpPinger) Close() error { return p.conn.Close() }
