// Package config loads and validates Sherlock's JSON configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Duration is a time.Duration that reads and writes as a string like "15s" or "2m".
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"15s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

type Config struct {
	// Interface is the adapter to watch: the Windows adapter name shown in
	// `sherlock interfaces` (for example "Ethernet"), or a Linux name like "eth0".
	// Empty means "whichever adapter holds the default route".
	Interface string `json:"interface"`

	// Listen is where the dashboard is served. Keep it on 127.0.0.1.
	Listen      string `json:"listen"`
	DataDir     string `json:"data_dir"`
	OpenBrowser bool   `json:"open_browser"`

	// MemoryLimitMB is a soft ceiling for the Go runtime (GOMEMLIMIT).
	MemoryLimitMB int  `json:"memory_limit_mb"`
	LowPriority   bool `json:"low_priority"`
	RetentionDays int  `json:"retention_days"`

	Sampling   Sampling   `json:"sampling"`
	Targets    Targets    `json:"targets"`
	Events     Events     `json:"events"`
	Capture    Capture    `json:"capture"`
	Throughput Throughput `json:"throughput"`
}

type Sampling struct {
	LinkInterval Duration `json:"link_interval"`
	PingInterval Duration `json:"ping_interval"`
	PingTimeout  Duration `json:"ping_timeout"`
	DNSInterval  Duration `json:"dns_interval"`
}

type Targets struct {
	// Gateway is pinged to test the segment that includes the extender.
	// Empty means auto-detect from the default route.
	Gateway string `json:"gateway"`
	// Internet is the control target that tells local faults from ISP faults.
	Internet string `json:"internet"`
	// DNSHost is resolved periodically. Empty disables the DNS check.
	DNSHost string `json:"dns_host"`
}

type Events struct {
	// PreWindow is how much history an event keeps from before its first trigger.
	PreWindow Duration `json:"pre_window"`
	// PostWindow keeps recording after the trigger to catch the recovery. "0s" disables it.
	PostWindow Duration `json:"post_window"`
	// Cooldown after an event during which new triggers are logged but don't
	// produce a full snapshot, so a flapping link doesn't create hundreds of folders.
	Cooldown Duration `json:"cooldown"`

	GatewayLossConsecutive    int     `json:"gateway_loss_consecutive"`
	GatewayLatencyMs          float64 `json:"gateway_latency_ms"`
	GatewayLatencyConsecutive int     `json:"gateway_latency_consecutive"`
	InternetLossConsecutive   int     `json:"internet_loss_consecutive"`
	// InterfaceErrorDelta fires when errors+discards rise by at least this much in one sample. 0 disables.
	InterfaceErrorDelta uint64 `json:"interface_error_delta"`
	DNSFailure          bool   `json:"dns_failure"`
	// ThroughputMinMbps fires when a speed test result falls below it. 0 disables.
	ThroughputMinMbps float64 `json:"throughput_min_mbps"`
}

type Capture struct {
	Enabled bool `json:"enabled"`
	// SnapLen bytes are kept from each packet; 128 covers Ethernet/IP/TCP headers.
	SnapLen int `json:"snaplen"`
	// Filter is a BPF expression applied in the capture driver. Speed-test
	// traffic is excluded automatically.
	Filter   string   `json:"filter"`
	Segment  Duration `json:"segment"`
	BufferKB int      `json:"buffer_kb"`
}

type Throughput struct {
	// Mode is "off", "manual" or "scheduled". The dashboard can change it at runtime.
	Mode       string   `json:"mode"`
	Iperf3Path string   `json:"iperf3_path"`
	Server     string   `json:"server"`
	Port       int      `json:"port"`
	Duration   Duration `json:"duration"`
	Interval   Duration `json:"interval"`
	// Windows limits scheduled runs to local time ranges like "01:00-07:00". Empty means any time.
	Windows []string `json:"windows"`
	// SkipProcesses pauses scheduled runs while any of these executables is running.
	SkipProcesses []string `json:"skip_processes"`
	// SkipAboveMbps pauses scheduled runs while existing traffic is above this. 0 disables.
	SkipAboveMbps float64 `json:"skip_above_mbps"`
}

func Default() Config {
	return Config{
		Listen:        "127.0.0.1:7878",
		DataDir:       "sherlock-data",
		OpenBrowser:   true,
		MemoryLimitMB: 128,
		LowPriority:   true,
		RetentionDays: 14,
		Sampling: Sampling{
			LinkInterval: Duration(time.Second),
			PingInterval: Duration(time.Second),
			PingTimeout:  Duration(900 * time.Millisecond),
			DNSInterval:  Duration(10 * time.Second),
		},
		Targets: Targets{Internet: "1.1.1.1", DNSHost: "example.com"},
		Events: Events{
			PreWindow:                 Duration(2 * time.Minute),
			PostWindow:                Duration(20 * time.Second),
			Cooldown:                  Duration(60 * time.Second),
			GatewayLossConsecutive:    3,
			GatewayLatencyMs:          50,
			GatewayLatencyConsecutive: 3,
			InternetLossConsecutive:   5,
			InterfaceErrorDelta:       1,
			DNSFailure:                true,
		},
		Capture: Capture{
			Enabled:  true,
			SnapLen:  128,
			Segment:  Duration(15 * time.Second),
			BufferKB: 2048,
		},
		Throughput: Throughput{
			Mode:       "off",
			Iperf3Path: "iperf3",
			Port:       5201,
			Duration:   Duration(5 * time.Second),
			Interval:   Duration(30 * time.Minute),
			SkipProcesses: []string{
				"cs2.exe", "dota2.exe", "VALORANT-Win64-Shipping.exe",
				"FortniteClient-Win64-Shipping.exe", "r5apex.exe",
				"League of Legends.exe", "RocketLeague.exe", "Overwatch.exe",
			},
			SkipAboveMbps: 20,
		},
	}
}

// Load reads path, filling anything missing with defaults. If the file does
// not exist, the defaults are written there so there is something to edit.
func Load(path string) (Config, bool, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := Write(path, cfg); err != nil {
			return cfg, false, err
		}
		cfg.resolveDataDir(path)
		return cfg, true, cfg.validate()
	}
	if err != nil {
		return cfg, false, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, false, fmt.Errorf("%s: %w", path, err)
	}
	cfg.resolveDataDir(path)
	return cfg, false, cfg.validate()
}

// resolveDataDir makes a relative data dir relative to the config file rather than
// the working directory, so double-clicking the exe and running it from a
// terminal use the same folder.
func (c *Config) resolveDataDir(configPath string) {
	if !filepath.IsAbs(c.DataDir) {
		c.DataDir = filepath.Join(filepath.Dir(configPath), c.DataDir)
	}
}

func Write(path string, cfg Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func (c *Config) validate() error {
	var errs []string
	if c.Sampling.LinkInterval.D() < 200*time.Millisecond {
		errs = append(errs, "sampling.link_interval must be at least 200ms")
	}
	if c.Sampling.PingInterval.D() < 200*time.Millisecond {
		errs = append(errs, "sampling.ping_interval must be at least 200ms")
	}
	if c.Sampling.PingTimeout.D() <= 0 || c.Sampling.PingTimeout.D() > c.Sampling.PingInterval.D() {
		errs = append(errs, "sampling.ping_timeout must be positive and no longer than ping_interval")
	}
	if c.Events.PreWindow.D() < 10*time.Second {
		errs = append(errs, "events.pre_window must be at least 10s")
	}
	if c.Events.PostWindow.D() < 0 {
		errs = append(errs, "events.post_window cannot be negative")
	}
	if c.Capture.SnapLen < 64 || c.Capture.SnapLen > 65535 {
		errs = append(errs, "capture.snaplen must be between 64 and 65535")
	}
	if c.Capture.Segment.D() < 5*time.Second {
		errs = append(errs, "capture.segment must be at least 5s")
	}
	switch c.Throughput.Mode {
	case "off", "manual", "scheduled":
	default:
		errs = append(errs, `throughput.mode must be "off", "manual" or "scheduled"`)
	}
	if c.Throughput.Interval.D() < time.Minute {
		errs = append(errs, "throughput.interval must be at least 1m")
	}
	for _, w := range c.Throughput.Windows {
		if _, _, err := ParseWindow(w); err != nil {
			errs = append(errs, fmt.Sprintf("throughput.windows %q: %v", w, err))
		}
	}
	if len(errs) > 0 {
		return errors.New("invalid config:\n  " + strings.Join(errs, "\n  "))
	}
	return nil
}

// ParseWindow parses "HH:MM-HH:MM" into minutes after midnight. Ranges may wrap past midnight.
func ParseWindow(s string) (start, end int, err error) {
	a, b, ok := strings.Cut(strings.TrimSpace(s), "-")
	if !ok {
		return 0, 0, errors.New(`expected "HH:MM-HH:MM"`)
	}
	pa, err := time.Parse("15:04", strings.TrimSpace(a))
	if err != nil {
		return 0, 0, err
	}
	pb, err := time.Parse("15:04", strings.TrimSpace(b))
	if err != nil {
		return 0, 0, err
	}
	return pa.Hour()*60 + pa.Minute(), pb.Hour()*60 + pb.Minute(), nil
}

// InWindows reports whether t falls inside any of the windows (or there are none).
func InWindows(windows []string, t time.Time) bool {
	if len(windows) == 0 {
		return true
	}
	m := t.Hour()*60 + t.Minute()
	for _, w := range windows {
		s, e, err := ParseWindow(w)
		if err != nil {
			continue
		}
		if s <= e && m >= s && m < e {
			return true
		}
		if s > e && (m >= s || m < e) {
			return true
		}
	}
	return false
}
