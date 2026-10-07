package monitor

import (
	"math"
	"testing"
	"time"

	"sherlock/internal/config"
	"sherlock/internal/platform"
	"sherlock/internal/store"
)

type fakeSink struct{ triggers, infos []string }

func (f *fakeSink) Trigger(kind, _ string) { f.triggers = append(f.triggers, kind) }
func (f *fakeSink) Info(kind, _ string)    { f.infos = append(f.infos, kind) }

func newTestDetector() (*Detector, *fakeSink) {
	s := &fakeSink{}
	return newDetector(config.Default().Events, s), s
}

func link(up bool, speed float64) (store.LinkRow, *platform.IfStats) {
	return store.LinkRow{Up: up, SpeedMbps: speed}, &platform.IfStats{Up: up, SpeedMbps: speed}
}

func TestLinkTransitions(t *testing.T) {
	d, s := newTestDetector()
	d.OnLink(link(true, 1000))
	d.OnLink(link(true, 1000))
	d.OnLink(link(true, 100)) // renegotiated down: the classic bad-cable symptom
	d.OnLink(link(false, 0))
	d.OnLink(link(false, 0))
	d.OnLink(link(true, 1000))
	want := []string{KindSpeedChange, KindLinkDown}
	if len(s.triggers) != 2 || s.triggers[0] != want[0] || s.triggers[1] != want[1] {
		t.Fatalf("triggers = %v, want %v", s.triggers, want)
	}
	if len(s.infos) != 1 || s.infos[0] != KindLinkUp {
		t.Fatalf("infos = %v, want [link_up]", s.infos)
	}
}

func TestReconnectAtSameSpeedIsNotASpeedChange(t *testing.T) {
	d, s := newTestDetector()
	d.OnLink(link(true, 1000))
	d.OnLink(link(false, 0))
	d.OnLink(link(true, 1000))
	if len(s.triggers) != 1 {
		t.Fatalf("triggers = %v, want only link_down", s.triggers)
	}
}

func TestGatewayLossFiresOncePerOutage(t *testing.T) {
	d, s := newTestDetector()
	for i := 0; i < 10; i++ {
		d.OnProbe(store.TargetGateway, "gw", math.NaN(), "")
	}
	d.OnProbe(store.TargetGateway, "gw", 0.4, "")
	for i := 0; i < 3; i++ {
		d.OnProbe(store.TargetGateway, "gw", math.NaN(), "")
	}
	if n := count(s.triggers, KindGatewayLoss); n != 2 {
		t.Fatalf("gateway_loss fired %d times, want 2 (one per outage)", n)
	}
	if count(s.infos, KindRecovered) != 1 {
		t.Fatalf("expected one recovery note, got %v", s.infos)
	}
}

func TestLatencySuppressedDuringSpeedTest(t *testing.T) {
	d, s := newTestDetector()
	d.SuppressLatency(time.Now().Add(time.Minute))
	for i := 0; i < 5; i++ {
		d.OnProbe(store.TargetGateway, "gw", 200, "")
	}
	if len(s.triggers) != 0 {
		t.Fatalf("latency should be ignored during a speed test, got %v", s.triggers)
	}
}

func TestInterfaceErrors(t *testing.T) {
	d, s := newTestDetector()
	row, st := link(true, 1000)
	d.OnLink(row, st)
	row.RxErrors = 3
	d.OnLink(row, st)
	if count(s.triggers, KindIfErrors) != 1 {
		t.Fatalf("triggers = %v, want interface_errors", s.triggers)
	}
}

func count(xs []string, x string) int {
	n := 0
	for _, v := range xs {
		if v == x {
			n++
		}
	}
	return n
}
