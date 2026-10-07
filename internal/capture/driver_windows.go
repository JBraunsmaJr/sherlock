//go:build windows

package capture

import (
	"fmt"

	"github.com/gopacket/gopacket/pcap"
)

// loadDriver loads Npcap's wpcap.dll. gopacket loads it lazily and ignores
// failures, so check explicitly to give a useful message instead of a crash.
func loadDriver() error {
	if err := pcap.LoadWinPCAP(); err != nil {
		return fmt.Errorf("Npcap not found (%v). Install it from https://npcap.com, or set capture.enabled to false", err)
	}
	return nil
}
