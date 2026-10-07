// Package platform hides the OS-specific parts of Sherlock: interface
// counters, ping, the default gateway, process lists and diagnostic commands.
// Windows is the primary target; the Linux implementation exists for
// development and for watching Linux machines.
package platform

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// IfStats is one reading of a network adapter.
type IfStats struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	MAC         string `json:"mac"`
	Up          bool   `json:"up"`
	// SpeedMbps is the negotiated link speed. 0 when the link is down.
	SpeedMbps float64 `json:"speed_mbps"`
	// Physical is true for real hardware adapters (not VPNs, loopback or virtual switches).
	Physical bool `json:"physical"`
	// CaptureDevice is the name the packet-capture driver uses for this adapter.
	CaptureDevice string `json:"capture_device"`

	RxBytes    uint64 `json:"rx_bytes"`
	TxBytes    uint64 `json:"tx_bytes"`
	RxErrors   uint64 `json:"rx_errors"`
	TxErrors   uint64 `json:"tx_errors"`
	RxDiscards uint64 `json:"rx_discards"`
	TxDiscards uint64 `json:"tx_discards"`

	// Only some platforms report these.
	CRCErrors         uint64 `json:"crc_errors,omitempty"`
	HasCRC            bool   `json:"has_crc"`
	CarrierChanges    uint64 `json:"carrier_changes,omitempty"`
	HasCarrierChanges bool   `json:"has_carrier_changes"`
}

var ErrNotFound = errors.New("interface not found")

// Pinger sends one ICMP echo at a time to a single IPv4 target.
type Pinger interface {
	Ping(timeout time.Duration) (time.Duration, error)
	Close() error
}

// ErrTimeout is returned by Ping when no reply arrived in time.
var ErrTimeout = errors.New("timed out")

// DiagCommand is a diagnostic command whose output is saved with an event.
type DiagCommand struct {
	File string // output file name inside the event folder
	Name string
	Args []string
	// AtFinalize commands run when the event closes rather than when it opens,
	// for things like system logs that need the recovery to have happened.
	AtFinalize bool
}

// RunDiag runs a diagnostic command with a timeout and writes its combined output to dir/File.
func RunDiag(ctx context.Context, dir string, c DiagCommand) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		out = append(out, []byte("\n[sherlock] command error: "+err.Error()+"\n")...)
	}
	return os.WriteFile(filepath.Join(dir, c.File), out, 0o644)
}

// Command prepares a command that won't flash a console window on Windows.
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	return cmd
}

func toIPv4(ip net.IP) (net.IP, error) {
	v4 := ip.To4()
	if v4 == nil {
		return nil, errors.New("only IPv4 targets are supported")
	}
	return v4, nil
}
