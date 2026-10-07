//go:build windows

package platform

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIfTable2       = iphlpapi.NewProc("GetIfTable2")
	procGetIfEntry2       = iphlpapi.NewProc("GetIfEntry2")
	procFreeMibTable      = iphlpapi.NewProc("FreeMibTable")
	procGetIpForwardTable = iphlpapi.NewProc("GetIpForwardTable")
)

// mibIfRow2 mirrors MIB_IF_ROW2 from netioapi.h. Its layout must match the C
// struct exactly; the size check below fails the build if it doesn't.
type mibIfRow2 struct {
	InterfaceLuid               uint64
	InterfaceIndex              uint32
	InterfaceGuid               windows.GUID
	Alias                       [257]uint16
	Description                 [257]uint16
	PhysicalAddressLength       uint32
	PhysicalAddress             [32]byte
	PermanentPhysicalAddress    [32]byte
	Mtu                         uint32
	Type                        uint32
	TunnelType                  uint32
	MediaType                   uint32
	PhysicalMediumType          uint32
	AccessType                  uint32
	DirectionType               uint32
	InterfaceAndOperStatusFlags uint8
	OperStatus                  uint32
	AdminStatus                 uint32
	MediaConnectState           uint32
	NetworkGuid                 windows.GUID
	ConnectionType              uint32
	TransmitLinkSpeed           uint64
	ReceiveLinkSpeed            uint64
	InOctets                    uint64
	InUcastPkts                 uint64
	InNUcastPkts                uint64
	InDiscards                  uint64
	InErrors                    uint64
	InUnknownProtos             uint64
	InUcastOctets               uint64
	InMulticastOctets           uint64
	InBroadcastOctets           uint64
	OutOctets                   uint64
	OutUcastPkts                uint64
	OutNUcastPkts               uint64
	OutDiscards                 uint64
	OutErrors                   uint64
	OutUcastOctets              uint64
	OutMulticastOctets          uint64
	OutBroadcastOctets          uint64
	OutQLen                     uint64
}

// sizeof(MIB_IF_ROW2) is 1352 bytes on 64-bit Windows. These two lines refuse
// to compile if the Go layout drifts (and on 32-bit builds, which aren't supported).
var _ [unsafe.Sizeof(mibIfRow2{}) - 1352]byte
var _ [1352 - unsafe.Sizeof(mibIfRow2{})]byte

const (
	ifOperStatusUp         = 1
	mediaConnectConnected  = 1
	flagHardwareInterface  = 1 << 0
	flagFilterInterface    = 1 << 1
	ifTypeSoftwareLoopback = 24
)

func (r *mibIfRow2) toStats() IfStats {
	s := IfStats{
		Name:          windows.UTF16ToString(r.Alias[:]),
		Description:   windows.UTF16ToString(r.Description[:]),
		Up:            r.OperStatus == ifOperStatusUp && r.MediaConnectState == mediaConnectConnected,
		Physical:      r.InterfaceAndOperStatusFlags&flagHardwareInterface != 0 && r.Type != ifTypeSoftwareLoopback,
		CaptureDevice: `\Device\NPF_` + r.InterfaceGuid.String(),
		RxBytes:       r.InOctets,
		TxBytes:       r.OutOctets,
		RxErrors:      r.InErrors,
		TxErrors:      r.OutErrors,
		RxDiscards:    r.InDiscards,
		TxDiscards:    r.OutDiscards,
	}
	if n := int(r.PhysicalAddressLength); n > 0 && n <= len(r.PhysicalAddress) {
		s.MAC = net.HardwareAddr(r.PhysicalAddress[:n]).String()
	}
	// Disconnected adapters can report 0 or all-ones; only trust the speed while up.
	if s.Up && r.ReceiveLinkSpeed != ^uint64(0) {
		s.SpeedMbps = float64(r.ReceiveLinkSpeed) / 1e6
	}
	return s
}

func getIfTable() ([]mibIfRow2, error) {
	var table *uint32 // points at MIB_IF_TABLE2, allocated by Windows
	if rc, _, _ := procGetIfTable2.Call(uintptr(unsafe.Pointer(&table))); rc != 0 {
		return nil, fmt.Errorf("GetIfTable2: %w", syscall.Errno(rc))
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))
	n := *table
	// MIB_IF_TABLE2 is { ULONG NumEntries; MIB_IF_ROW2 Table[]; } and the rows
	// are 8-byte aligned, so the first row starts at offset 8.
	rows := unsafe.Slice((*mibIfRow2)(unsafe.Add(unsafe.Pointer(table), 8)), n)
	out := make([]mibIfRow2, n)
	copy(out, rows)
	return out, nil
}

// ListInterfaces returns all adapters except Windows' internal filter layers.
func ListInterfaces() ([]IfStats, error) {
	rows, err := getIfTable()
	if err != nil {
		return nil, err
	}
	var out []IfStats
	for i := range rows {
		if rows[i].InterfaceAndOperStatusFlags&flagFilterInterface != 0 {
			continue
		}
		out = append(out, rows[i].toStats())
	}
	return out, nil
}

// IfReader reads one adapter repeatedly. It remembers the adapter's LUID so each
// read is a single cheap GetIfEntry2 call instead of a full table walk.
type IfReader struct {
	name string
	mu   sync.Mutex
	luid uint64
	row  mibIfRow2
}

func NewIfReader(name string) (*IfReader, error) {
	r := &IfReader{name: name}
	if err := r.resolve(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *IfReader) Name() string { return r.name }

func (r *IfReader) resolve() error {
	rows, err := getIfTable()
	if err != nil {
		return err
	}
	for i := range rows {
		if rows[i].InterfaceAndOperStatusFlags&flagFilterInterface != 0 {
			continue
		}
		if strings.EqualFold(windows.UTF16ToString(rows[i].Alias[:]), r.name) {
			r.luid = rows[i].InterfaceLuid
			return nil
		}
	}
	return fmt.Errorf("%w: %q (run `sherlock interfaces` to see names)", ErrNotFound, r.name)
}

func (r *IfReader) Read() (IfStats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		r.row = mibIfRow2{InterfaceLuid: r.luid}
		rc, _, _ := procGetIfEntry2.Call(uintptr(unsafe.Pointer(&r.row)))
		if rc == 0 {
			return r.row.toStats(), nil
		}
		// A USB adapter that was unplugged and replugged can get a new LUID.
		if err := r.resolve(); err != nil {
			return IfStats{Name: r.name}, err
		}
	}
	return IfStats{Name: r.name}, fmt.Errorf("GetIfEntry2 failed for %q", r.name)
}

// mibIPForwardRow mirrors MIB_IPFORWARDROW: fourteen DWORDs.
type mibIPForwardRow struct {
	Dest, Mask, Policy, NextHop, IfIndex, Type, Proto, Age, NextHopAS uint32
	Metric1, Metric2, Metric3, Metric4, Metric5                       uint32
}

// DefaultGateway returns the IPv4 default gateway with the lowest metric and the
// name of the adapter it's reached through. If preferIf is set, routes through
// that adapter win.
func DefaultGateway(preferIf string) (net.IP, string, error) {
	var size uint32
	procGetIpForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 1)
	if size == 0 {
		return nil, "", fmt.Errorf("GetIpForwardTable returned no size")
	}
	buf := make([]byte, size)
	rc, _, _ := procGetIpForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1)
	if rc != 0 {
		return nil, "", fmt.Errorf("GetIpForwardTable: %w", syscall.Errno(rc))
	}
	n := binary.LittleEndian.Uint32(buf[:4])
	rows := unsafe.Slice((*mibIPForwardRow)(unsafe.Pointer(&buf[4])), n)

	ifRows, err := getIfTable()
	if err != nil {
		return nil, "", err
	}
	nameByIndex := map[uint32]string{}
	for i := range ifRows {
		nameByIndex[ifRows[i].InterfaceIndex] = windows.UTF16ToString(ifRows[i].Alias[:])
	}

	var best *mibIPForwardRow
	bestPreferred := false
	for i := range rows {
		rt := &rows[i]
		if rt.Dest != 0 || rt.Mask != 0 || rt.NextHop == 0 {
			continue
		}
		preferred := preferIf != "" && strings.EqualFold(nameByIndex[rt.IfIndex], preferIf)
		switch {
		case best == nil,
			preferred && !bestPreferred,
			preferred == bestPreferred && rt.Metric1 < best.Metric1:
			best, bestPreferred = rt, preferred
		}
	}
	if best == nil {
		return nil, "", fmt.Errorf("no IPv4 default route")
	}
	var ip [4]byte
	// Addresses are stored in network byte order, so the in-memory bytes are already in order.
	binary.LittleEndian.PutUint32(ip[:], best.NextHop)
	return net.IPv4(ip[0], ip[1], ip[2], ip[3]), nameByIndex[best.IfIndex], nil
}
