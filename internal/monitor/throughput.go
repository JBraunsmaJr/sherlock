package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"sherlock/internal/config"
	"sherlock/internal/platform"
	"sherlock/internal/store"
)

const (
	ModeOff       = "off"
	ModeManual    = "manual"
	ModeScheduled = "scheduled"

	skipRetry = 5 * time.Minute
)

// Throughput runs iperf3 speed tests. They saturate the link on purpose, so
// they never run unless asked: "off" disables them, "manual" runs only from the
// dashboard button, and "scheduled" runs every interval unless a listed game is
// running or the connection is already busy.
type Throughput struct {
	m   *Monitor
	cfg config.Throughput
	now chan struct{}

	mu      sync.Mutex
	mode    string
	running bool
	last    *store.ThroughputRow
	skip    string
	skipTS  int64
	nextRun time.Time
}

type ThroughputStatus struct {
	Mode       string               `json:"mode"`
	Configured bool                 `json:"configured"`
	Server     string               `json:"server"`
	Running    bool                 `json:"running"`
	Last       *store.ThroughputRow `json:"last,omitempty"`
	Skip       string               `json:"skip,omitempty"`
	SkipTS     int64                `json:"skip_ts,omitempty"`
	NextRun    int64                `json:"next_run,omitempty"`
}

func newThroughput(m *Monitor) *Throughput {
	t := &Throughput{m: m, cfg: m.cfg.Throughput, now: make(chan struct{}, 1), mode: m.cfg.Throughput.Mode}
	if v, ok := m.store.Setting("throughput_mode"); ok {
		t.mode = v
	}
	t.nextRun = time.Now().Add(2 * time.Minute)
	return t
}

func (t *Throughput) Status() ThroughputStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := ThroughputStatus{
		Mode: t.mode, Configured: t.cfg.Server != "", Server: t.server(),
		Running: t.running, Last: t.last, Skip: t.skip, SkipTS: t.skipTS,
	}
	if t.mode == ModeScheduled {
		s.NextRun = t.nextRun.UnixMilli()
	}
	return s
}

func (t *Throughput) server() string {
	if t.cfg.Server == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", t.cfg.Server, t.cfg.Port)
}

func (t *Throughput) SetMode(mode string) error {
	switch mode {
	case ModeOff, ModeManual, ModeScheduled:
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	if err := t.m.store.SetSetting("throughput_mode", mode); err != nil {
		return err
	}
	t.mu.Lock()
	t.mode = mode
	if mode == ModeScheduled {
		t.nextRun = time.Now().Add(time.Minute)
	}
	t.mu.Unlock()
	t.m.logf("speed tests: %s", mode)
	return nil
}

// RunNow starts a test immediately, in manual or scheduled mode.
func (t *Throughput) RunNow() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case t.cfg.Server == "":
		return errors.New("no speed-test server configured (throughput.server)")
	case t.mode == ModeOff:
		return errors.New("speed tests are off")
	case t.running:
		return errors.New("a test is already running")
	}
	select {
	case t.now <- struct{}{}:
	default:
	}
	return nil
}

func (t *Throughput) run(ctx context.Context) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.now:
			t.test(ctx)
		case now := <-tick.C:
			t.mu.Lock()
			due := t.mode == ModeScheduled && t.cfg.Server != "" && !now.Before(t.nextRun)
			t.mu.Unlock()
			if !due {
				continue
			}
			if reason := t.shouldSkip(now); reason != "" {
				t.mu.Lock()
				t.skip, t.skipTS, t.nextRun = reason, now.UnixMilli(), now.Add(skipRetry)
				t.mu.Unlock()
				continue
			}
			t.test(ctx)
			t.mu.Lock()
			t.nextRun = time.Now().Add(t.cfg.Interval.D())
			t.mu.Unlock()
		}
	}
}

func (t *Throughput) shouldSkip(now time.Time) string {
	if !config.InWindows(t.cfg.Windows, now) {
		return "Outside the scheduled hours"
	}
	if len(t.cfg.SkipProcesses) > 0 {
		if running, err := platform.ProcessNames(); err == nil {
			for _, p := range t.cfg.SkipProcesses {
				if running[strings.ToLower(p)] {
					return "Paused while " + p + " is running"
				}
			}
		}
	}
	if t.cfg.SkipAboveMbps > 0 {
		if mbps := t.m.recentTrafficMbps(); mbps > t.cfg.SkipAboveMbps {
			return fmt.Sprintf("Paused: connection already busy (%.0f Mbps)", mbps)
		}
	}
	return ""
}

func (t *Throughput) test(ctx context.Context) {
	t.mu.Lock()
	if t.running || t.cfg.Server == "" {
		t.mu.Unlock()
		return
	}
	t.running, t.skip = true, ""
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		t.running = false
		t.mu.Unlock()
	}()

	d := t.cfg.Duration.D()
	// Speed tests saturate the link and would trip the latency rule on any network.
	t.m.detector.SuppressLatency(time.Now().Add(2*d + 15*time.Second))
	t.m.logf("speed test against %s", t.server())

	row := store.ThroughputRow{TS: time.Now().UnixMilli(), Server: t.server(), DownMbps: math.NaN(), UpMbps: math.NaN()}
	var errs []string
	if up, retr, err := t.iperf(ctx, false); err != nil {
		errs = append(errs, "upload: "+err.Error())
	} else {
		row.UpMbps, row.Retransmits = up, retr
	}
	if down, retr, err := t.iperf(ctx, true); err != nil {
		errs = append(errs, "download: "+err.Error())
	} else {
		row.DownMbps = down
		row.Retransmits += retr
	}
	row.Error = strings.Join(errs, "; ")
	if err := t.m.store.AddThroughput(row); err != nil {
		t.m.logf("speed test: %v", err)
	}
	if row.Error != "" {
		t.m.logf("speed test failed: %s", row.Error)
	} else {
		t.m.logf("speed test: %.0f Mbps down, %.0f Mbps up, %d retransmits", row.DownMbps, row.UpMbps, row.Retransmits)
	}
	t.mu.Lock()
	t.last = &row
	t.mu.Unlock()
	t.m.detector.OnThroughput(row)
}

type iperfResult struct {
	Error string `json:"error"`
	End   struct {
		SumSent struct {
			BitsPerSecond float64 `json:"bits_per_second"`
			Retransmits   int64   `json:"retransmits"`
		} `json:"sum_sent"`
		SumReceived struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum_received"`
	} `json:"end"`
}

// iperf runs one direction. reverse=false measures upload (this machine sends),
// reverse=true measures download (the server sends).
func (t *Throughput) iperf(ctx context.Context, reverse bool) (mbps float64, retransmits int64, err error) {
	secs := int(math.Max(1, math.Round(t.cfg.Duration.D().Seconds())))
	args := []string{"-c", t.cfg.Server, "-p", strconv.Itoa(t.cfg.Port), "-t", strconv.Itoa(secs), "-J"}
	if reverse {
		args = append(args, "-R")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(secs)*time.Second+20*time.Second)
	defer cancel()
	out, runErr := platform.Command(ctx, t.cfg.Iperf3Path, args...).Output()
	var res iperfResult
	if jerr := json.Unmarshal(out, &res); jerr != nil {
		if runErr != nil {
			return 0, 0, fmt.Errorf("%v (is iperf3 installed? throughput.iperf3_path is %q)", runErr, t.cfg.Iperf3Path)
		}
		return 0, 0, fmt.Errorf("unreadable iperf3 output: %v", jerr)
	}
	if res.Error != "" {
		return 0, 0, errors.New(res.Error)
	}
	// sum_received is what actually arrived, which is the honest number either way.
	// Retransmits come from whichever side was sending, if it's Linux.
	return res.End.SumReceived.BitsPerSecond / 1e6, res.End.SumSent.Retransmits, nil
}
