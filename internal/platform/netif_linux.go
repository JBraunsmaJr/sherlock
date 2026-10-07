//go:build linux

package platform

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const sysNet = "/sys/class/net"

func readSysUint(iface, file string) (uint64, bool) {
	b, err := os.ReadFile(filepath.Join(sysNet, iface, file))
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v, err == nil
}

func readSysString(iface, file string) string {
	b, _ := os.ReadFile(filepath.Join(sysNet, iface, file))
	return strings.TrimSpace(string(b))
}

func readLinux(name string) (IfStats, error) {
	if _, err := os.Stat(filepath.Join(sysNet, name)); err != nil {
		return IfStats{Name: name}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	s := IfStats{Name: name, CaptureDevice: name, MAC: readSysString(name, "address")}
	_, err := os.Stat(filepath.Join(sysNet, name, "device"))
	s.Physical = err == nil
	carrier, _ := readSysUint(name, "carrier")
	s.Up = readSysString(name, "operstate") == "up" && carrier == 1
	if speed, ok := readSysUint(name, "speed"); ok && s.Up && speed < 1<<31 {
		s.SpeedMbps = float64(speed)
	}
	st := "statistics/"
	s.RxBytes, _ = readSysUint(name, st+"rx_bytes")
	s.TxBytes, _ = readSysUint(name, st+"tx_bytes")
	s.RxErrors, _ = readSysUint(name, st+"rx_errors")
	s.TxErrors, _ = readSysUint(name, st+"tx_errors")
	s.RxDiscards, _ = readSysUint(name, st+"rx_dropped")
	s.TxDiscards, _ = readSysUint(name, st+"tx_dropped")
	s.CRCErrors, s.HasCRC = readSysUint(name, st+"rx_crc_errors")
	s.CarrierChanges, s.HasCarrierChanges = readSysUint(name, "carrier_changes")
	return s, nil
}

func ListInterfaces() ([]IfStats, error) {
	entries, err := os.ReadDir(sysNet)
	if err != nil {
		return nil, err
	}
	var out []IfStats
	for _, e := range entries {
		if s, err := readLinux(e.Name()); err == nil {
			out = append(out, s)
		}
	}
	return out, nil
}

type IfReader struct{ name string }

func NewIfReader(name string) (*IfReader, error) {
	if _, err := readLinux(name); err != nil {
		return nil, err
	}
	return &IfReader{name: name}, nil
}

func (r *IfReader) Name() string           { return r.name }
func (r *IfReader) Read() (IfStats, error) { return readLinux(r.name) }

// DefaultGateway parses /proc/net/route for the lowest-metric IPv4 default route.
func DefaultGateway(preferIf string) (net.IP, string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	var (
		bestIP        net.IP
		bestIf        string
		bestMetric    = -1
		bestPreferred bool
	)
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		metric, _ := strconv.Atoi(fields[6])
		preferred := preferIf != "" && fields[0] == preferIf
		if bestMetric < 0 || (preferred && !bestPreferred) || (preferred == bestPreferred && metric < bestMetric) {
			v := binary.LittleEndian.Uint32(raw)
			bestIP = net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
			bestIf, bestMetric, bestPreferred = fields[0], metric, preferred
		}
	}
	if bestIP == nil {
		return nil, "", fmt.Errorf("no IPv4 default route")
	}
	return bestIP, bestIf, nil
}
