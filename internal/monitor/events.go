package monitor

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"sherlock/internal/capture"
	"sherlock/internal/platform"
	"sherlock/internal/store"
)

type TriggerRec struct {
	TS     int64  `json:"ts"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	// Info entries describe what happened during the event (link back up, pings
	// answering again) but don't open events themselves.
	Info bool `json:"info,omitempty"`
}

// EventFile is written to event.json in each event folder.
type EventFile struct {
	ID          string           `json:"id"`
	Start       int64            `json:"start"`
	End         int64            `json:"end"`
	WindowStart int64            `json:"window_start"`
	Triggers    []TriggerRec     `json:"triggers"`
	Interface   platform.IfStats `json:"interface_at_trigger"`
	Gateway     string           `json:"gateway"`
	Capture     *EventCapture    `json:"capture,omitempty"`
	Notes       []store.Note     `json:"notes"`
	Files       []string         `json:"files"`
	Complete    bool             `json:"complete"`
}

type EventCapture struct {
	File    string `json:"file,omitempty"`
	Packets int    `json:"packets"`
	Error   string `json:"error,omitempty"`
}

type activeEvent struct {
	id       string
	dir      string
	start    time.Time
	triggers []TriggerRec
}

type Recorder struct {
	m *Monitor

	mu            sync.Mutex
	active        *activeEvent
	cooldownUntil time.Time
	quiet         *store.Event // most recent cooldown-only event, extended while triggers keep coming
	wg            sync.WaitGroup
}

func newRecorder(m *Monitor) *Recorder { return &Recorder{m: m} }

func (r *Recorder) activeID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil {
		return ""
	}
	return r.active.id
}

func (r *Recorder) wait() { r.wg.Wait() }

// Info adds context to an open event; with no open event it is dropped.
func (r *Recorder) Info(kind, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != nil {
		r.active.triggers = append(r.active.triggers, TriggerRec{TS: time.Now().UnixMilli(), Kind: kind, Detail: detail, Info: true})
	}
}

// Trigger opens a new event, adds to the open one, or (during cooldown) logs a
// lightweight event without a snapshot.
func (r *Recorder) Trigger(kind, detail string) {
	now := time.Now()
	tr := TriggerRec{TS: now.UnixMilli(), Kind: kind, Detail: detail}
	r.m.logf("trigger %s: %s", kind, detail)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != nil {
		r.active.triggers = append(r.active.triggers, tr)
		return
	}
	if now.Before(r.cooldownUntil) {
		r.recordQuiet(tr)
		return
	}
	r.quiet = nil
	a := &activeEvent{
		id:       now.Format("2006-01-02_15-04-05") + "_" + kind,
		start:    now,
		triggers: []TriggerRec{tr},
	}
	a.dir = filepath.Join(r.m.EventsDir(), a.id)
	r.active = a
	r.wg.Add(1)
	go r.capture(a)
}

// recordQuiet logs a trigger that arrived during the cooldown. Bursts within 30s
// are folded into one row so a flapping link shows as one band, not hundreds.
func (r *Recorder) recordQuiet(tr TriggerRec) {
	q := r.quiet
	if q != nil && tr.TS-q.EndTS < 30_000 {
		q.EndTS = tr.TS
		if !contains(q.Kinds, tr.Kind) {
			q.Kinds = append(q.Kinds, tr.Kind)
		}
	} else {
		q = &store.Event{
			ID:          fmt.Sprintf("q_%d", tr.TS),
			StartTS:     tr.TS,
			EndTS:       tr.TS,
			WindowStart: tr.TS,
			Kinds:       []string{tr.Kind},
			Summary:     tr.Detail + " (during cooldown, no snapshot)",
		}
		r.quiet = q
	}
	if err := r.m.store.PutEvent(*q); err != nil {
		r.m.logf("event: %v", err)
	}
}

func (r *Recorder) capture(a *activeEvent) {
	defer r.wg.Done()
	m := r.m
	cfg := m.cfg.Events
	ctx := m.ctx
	windowStart := a.start.Add(-cfg.PreWindow.D())
	segDir := filepath.Join(a.dir, "segments")
	if err := os.MkdirAll(a.dir, 0o755); err != nil {
		m.logf("event %s: %v", a.id, err)
	}

	// Freeze the capture first, before anything else touches the disk, so the
	// pre-trigger packets can't rotate away.
	var capErr string
	capt := m.currentCapturer()
	if capt != nil {
		if _, err := capt.Freeze(segDir); err != nil {
			capErr = err.Error()
		}
	}

	m.mu.Lock()
	ifAtTrigger := m.ifStats
	gw := ""
	if m.gateway != nil {
		gw = m.gateway.String()
	}
	ifName := m.ifName
	m.mu.Unlock()

	r.mu.Lock()
	first := a.triggers[0]
	r.mu.Unlock()
	m.store.PutEvent(store.Event{
		ID: a.id, StartTS: a.start.UnixMilli(), EndTS: a.start.UnixMilli(), WindowStart: windowStart.UnixMilli(),
		Kinds: []string{first.Kind}, Summary: first.Detail + " (recording…)", Full: true,
	})
	m.logf("event %s opened", a.id)

	diags := platform.DiagCommands(ifName)
	for _, c := range diags {
		if !c.AtFinalize {
			platform.RunDiag(context.Background(), a.dir, c)
		}
	}

	// Keep recording through the post-window to catch the recovery.
	if wait := time.Until(a.start.Add(cfg.PostWindow.D())); wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
		}
	}

	r.mu.Lock()
	end := time.Now()
	triggers := append([]TriggerRec(nil), a.triggers...)
	r.active = nil
	r.cooldownUntil = end.Add(cfg.Cooldown.D())
	r.mu.Unlock()

	ev := EventFile{
		ID: a.id, Start: a.start.UnixMilli(), End: end.UnixMilli(), WindowStart: windowStart.UnixMilli(),
		Triggers: triggers, Interface: ifAtTrigger, Gateway: gw,
	}

	if capt != nil || capErr != "" {
		ev.Capture = &EventCapture{Error: capErr}
		if capt != nil {
			if _, err := capt.Collect(segDir); err != nil && ev.Capture.Error == "" {
				ev.Capture.Error = err.Error()
			}
		}
		segs, _ := filepath.Glob(filepath.Join(segDir, "*.pcap"))
		if len(segs) > 0 {
			out := filepath.Join(a.dir, "capture.pcap")
			n, err := capture.Merge(segs, out, windowStart, end)
			ev.Capture.Packets = n
			ev.Capture.File = "capture.pcap"
			if err != nil {
				ev.Capture.Error = err.Error()
			}
		}
		os.Remove(segDir)
	}

	for _, c := range diags {
		if c.AtFinalize {
			platform.RunDiag(context.Background(), a.dir, c)
		}
	}

	if err := m.store.Flush(); err != nil {
		m.logf("event %s: flush: %v", a.id, err)
	}
	if err := r.writeSamples(a.dir, windowStart.UnixMilli(), end.UnixMilli()); err != nil {
		m.logf("event %s: samples: %v", a.id, err)
	}
	ev.Notes, _ = m.store.Notes(windowStart.UnixMilli(), end.UnixMilli())
	ev.Complete = true
	ev.Files = listFiles(a.dir)
	ev.Files = append(ev.Files, "event.json")
	sort.Strings(ev.Files)
	if b, err := json.MarshalIndent(ev, "", "  "); err == nil {
		os.WriteFile(filepath.Join(a.dir, "event.json"), b, 0o644)
	}

	kinds := []string{}
	for _, t := range triggers {
		if !t.Info && !contains(kinds, t.Kind) {
			kinds = append(kinds, t.Kind)
		}
	}
	summary := triggers[0].Detail
	if extra := countTriggers(triggers) - 1; extra > 0 {
		summary += fmt.Sprintf(" (+%d more)", extra)
	}
	if err := m.store.PutEvent(store.Event{
		ID: a.id, StartTS: ev.Start, EndTS: ev.End, WindowStart: ev.WindowStart,
		Kinds: kinds, Summary: summary, Full: true,
	}); err != nil {
		m.logf("event %s: %v", a.id, err)
	}
	m.logf("event %s closed: %d triggers, files in %s", a.id, len(triggers), a.dir)
}

func (r *Recorder) writeSamples(dir string, from, to int64) error {
	links, err := r.m.store.RawLinks(from, to)
	if err != nil {
		return err
	}
	if err := writeCSV(filepath.Join(dir, "samples-link.csv"),
		[]string{"time", "ts_ms", "up", "speed_mbps", "rx_mbps", "tx_mbps", "rx_errors", "tx_errors", "rx_discards", "tx_discards"},
		len(links), func(i int) []string {
			l := links[i]
			up := "0"
			if l.Up {
				up = "1"
			}
			return []string{iso(l.TS), strconv.FormatInt(l.TS, 10), up, f(l.SpeedMbps), f(l.RxBps / 1e6), f(l.TxBps / 1e6),
				u(l.RxErrors), u(l.TxErrors), u(l.RxDiscards), u(l.TxDiscards)}
		}); err != nil {
		return err
	}
	probes, err := r.m.store.RawProbes(from, to)
	if err != nil {
		return err
	}
	return writeCSV(filepath.Join(dir, "samples-probes.csv"),
		[]string{"time", "ts_ms", "target", "rtt_ms"},
		len(probes), func(i int) []string {
			p := probes[i]
			rtt := ""
			if !math.IsNaN(p.RTTms) {
				rtt = f(p.RTTms)
			}
			return []string{iso(p.TS), strconv.FormatInt(p.TS, 10), targetName(p.Target), rtt}
		})
}

func writeCSV(path string, header []string, n int, row func(int) []string) error {
	fh, err := os.Create(path)
	if err != nil {
		return err
	}
	w := csv.NewWriter(fh)
	w.Write(header)
	for i := 0; i < n; i++ {
		w.Write(row(i))
	}
	w.Flush()
	if err := w.Error(); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}

func listFiles(dir string) []string {
	entries, _ := os.ReadDir(dir)
	out := []string{}
	for _, e := range entries {
		if !e.IsDir() && e.Name() != "event.json" {
			out = append(out, e.Name())
		}
	}
	return out
}

func countTriggers(ts []TriggerRec) int {
	n := 0
	for _, t := range ts {
		if !t.Info {
			n++
		}
	}
	return n
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func iso(ms int64) string { return time.UnixMilli(ms).Format("2006-01-02T15:04:05.000Z07:00") }
func f(v float64) string  { return strconv.FormatFloat(v, 'f', 3, 64) }
func u(v uint64) string   { return strconv.FormatUint(v, 10) }
