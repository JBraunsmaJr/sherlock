package monitor

import (
	"fmt"
	"math"
	"sync"
	"time"

	"sherlock/internal/config"
	"sherlock/internal/platform"
	"sherlock/internal/store"
)

// Trigger kinds.
const (
	KindLinkDown       = "link_down"
	KindSpeedChange    = "speed_change"
	KindIfErrors       = "interface_errors"
	KindGatewayLoss    = "gateway_loss"
	KindGatewayLatency = "gateway_latency"
	KindInternetLoss   = "internet_loss"
	KindDNSFailure     = "dns_failure"
	KindThroughputLow  = "throughput_low"
	// Informational: recorded on an open event but never opens one.
	KindLinkUp    = "link_up"
	KindRecovered = "recovered"
)

const dnsFailConsecutive = 2

type sink interface {
	Trigger(kind, detail string)
	Info(kind, detail string)
}

// Detector applies the thresholds from the config. Every rule is edge-triggered:
// it fires once when the condition starts and re-arms when it clears.
type Detector struct {
	cfg  config.Events
	sink sink

	mu             sync.Mutex
	haveLink       bool
	wasUp          bool
	lastSpeed      float64
	gwFail, gwSlow int
	inetFail       int
	dnsFail        int
	suppressUntil  time.Time
}

func newDetector(cfg config.Events, s sink) *Detector {
	return &Detector{cfg: cfg, sink: s}
}

// SuppressLatency ignores latency spikes until t. Used during speed tests,
// which saturate the link and would otherwise trip the latency rule on any network.
func (d *Detector) SuppressLatency(until time.Time) {
	d.mu.Lock()
	if until.After(d.suppressUntil) {
		d.suppressUntil = until
	}
	d.mu.Unlock()
}

func (d *Detector) OnLink(row store.LinkRow, st *platform.IfStats) {
	d.mu.Lock()
	defer d.mu.Unlock()
	up := st != nil && row.Up
	if d.haveLink {
		switch {
		case d.wasUp && !up:
			detail := "Link went down"
			if st == nil {
				detail = "Adapter disappeared"
			}
			d.sink.Trigger(KindLinkDown, detail)
		case !d.wasUp && up:
			d.sink.Info(KindLinkUp, fmt.Sprintf("Link came back at %s", mbps(row.SpeedMbps)))
		case up && d.lastSpeed > 0 && row.SpeedMbps != d.lastSpeed:
			d.sink.Trigger(KindSpeedChange, fmt.Sprintf("Link speed changed from %s to %s", mbps(d.lastSpeed), mbps(row.SpeedMbps)))
		}
	}
	d.haveLink, d.wasUp = true, up
	if up {
		d.lastSpeed = row.SpeedMbps
	}
	if d.cfg.InterfaceErrorDelta > 0 {
		total := row.RxErrors + row.TxErrors + row.RxDiscards + row.TxDiscards
		if total >= d.cfg.InterfaceErrorDelta {
			d.sink.Trigger(KindIfErrors, fmt.Sprintf(
				"Adapter counted %d bad frames in one sample (rx errors %d, tx errors %d, rx discards %d, tx discards %d)",
				total, row.RxErrors, row.TxErrors, row.RxDiscards, row.TxDiscards))
		}
	}
}

func (d *Detector) OnProbe(target int, addr string, rtt float64, errText string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	lost := math.IsNaN(rtt)
	switch target {
	case store.TargetGateway:
		if lost {
			d.gwFail++
			if d.gwFail == d.cfg.GatewayLossConsecutive {
				d.sink.Trigger(KindGatewayLoss, fmt.Sprintf("Gateway %s: %d pings lost in a row", addr, d.gwFail))
			}
		} else {
			if d.gwFail >= d.cfg.GatewayLossConsecutive {
				d.sink.Info(KindRecovered, fmt.Sprintf("Gateway answering again after %d lost pings (%.1f ms)", d.gwFail, rtt))
			}
			d.gwFail = 0
		}
		if d.cfg.GatewayLatencyMs > 0 && !lost && time.Now().After(d.suppressUntil) && rtt > d.cfg.GatewayLatencyMs {
			d.gwSlow++
			if d.gwSlow == d.cfg.GatewayLatencyConsecutive {
				d.sink.Trigger(KindGatewayLatency, fmt.Sprintf("Gateway %s above %.0f ms for %d pings in a row (last %.1f ms)",
					addr, d.cfg.GatewayLatencyMs, d.gwSlow, rtt))
			}
		} else if !lost {
			d.gwSlow = 0
		}
	case store.TargetInternet:
		if lost {
			d.inetFail++
			if d.cfg.InternetLossConsecutive > 0 && d.inetFail == d.cfg.InternetLossConsecutive {
				d.sink.Trigger(KindInternetLoss, fmt.Sprintf("Internet target %s: %d pings lost in a row", addr, d.inetFail))
			}
		} else {
			d.inetFail = 0
		}
	case store.TargetDNS:
		if lost {
			d.dnsFail++
			if d.cfg.DNSFailure && d.dnsFail == dnsFailConsecutive {
				d.sink.Trigger(KindDNSFailure, fmt.Sprintf("DNS lookup of %s failed %d times in a row: %s", addr, d.dnsFail, errText))
			}
		} else {
			d.dnsFail = 0
		}
	}
}

func (d *Detector) OnThroughput(r store.ThroughputRow) {
	if d.cfg.ThroughputMinMbps <= 0 || r.Error != "" {
		return
	}
	low := func(v float64) bool { return !math.IsNaN(v) && v < d.cfg.ThroughputMinMbps }
	if low(r.DownMbps) || low(r.UpMbps) {
		d.sink.Trigger(KindThroughputLow, fmt.Sprintf("Speed test: %.0f Mbps down, %.0f Mbps up (minimum %.0f)",
			r.DownMbps, r.UpMbps, d.cfg.ThroughputMinMbps))
	}
}

func mbps(v float64) string {
	switch {
	case v <= 0:
		return "no link"
	case v >= 1000 && math.Mod(v, 1000) == 0:
		return fmt.Sprintf("%.0f Gbps", v/1000)
	case v >= 1000:
		return fmt.Sprintf("%.1f Gbps", v/1000)
	default:
		return fmt.Sprintf("%.0f Mbps", v)
	}
}
