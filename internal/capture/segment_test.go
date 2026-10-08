package capture

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
)

// writeOldSegment writes a pcap the way Sherlock did before the fix: a header
// snaplen of 128, with packets the driver padded to 132 bytes (a re-inserted
// VLAN tag). Strict readers reject these.
func writeOldSegment(t *testing.T, path string, start time.Time, sizes []int) {
	t.Helper()
	var b bytes.Buffer
	le := binary.LittleEndian
	hdr := make([]byte, 24)
	le.PutUint32(hdr[0:], magicMicros)
	le.PutUint16(hdr[4:], 2)
	le.PutUint16(hdr[6:], 4)
	le.PutUint32(hdr[16:], 128) // snaplen
	le.PutUint32(hdr[20:], 1)   // Ethernet
	b.Write(hdr)
	for i, n := range sizes {
		ts := start.Add(time.Duration(i) * time.Second)
		rec := make([]byte, 16)
		le.PutUint32(rec[0:], uint32(ts.Unix()))
		le.PutUint32(rec[4:], uint32(ts.Nanosecond()/1000))
		le.PutUint32(rec[8:], uint32(n))
		le.PutUint32(rec[12:], uint32(n)) // original length equal to capture: VLAN tag pushed it past the wire length
		b.Write(rec)
		b.Write(bytes.Repeat([]byte{byte(i)}, n))
	}
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMergeAcceptsPacketsLongerThanSnaplen(t *testing.T) {
	dir := t.TempDir()
	start := time.Unix(1_791_416_000, 0)
	seg1 := filepath.Join(dir, "seg-1791416000000.pcap")
	seg2 := filepath.Join(dir, "seg-1791416015000.pcap")
	empty := filepath.Join(dir, "seg-1791416030000.pcap")
	writeOldSegment(t, seg1, start, []int{60, 128, 132, 132})
	writeOldSegment(t, seg2, start.Add(15*time.Second), []int{132, 90})
	os.WriteFile(empty, nil, 0o644) // rotated before its header flushed

	out := filepath.Join(dir, "capture.pcap")
	n, err := Merge([]string{seg2, empty, seg1}, out, start, start.Add(time.Minute))
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if n != 6 {
		t.Fatalf("merged %d packets, want 6", n)
	}

	// The result must open in a strict reader (Wireshark, tcpdump, gopacket).
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var prev time.Time
	read := 0
	for {
		_, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		if ci.Timestamp.Before(prev) {
			t.Fatalf("packets out of order: %s before %s", ci.Timestamp, prev)
		}
		prev = ci.Timestamp
		read++
	}
	if read != 6 {
		t.Fatalf("strict reader read %d packets, want 6", read)
	}
	for _, s := range []string{seg1, seg2, empty} {
		if _, err := os.Stat(s); !os.IsNotExist(err) {
			t.Errorf("%s should be deleted after a clean merge", filepath.Base(s))
		}
	}
}

func TestMergeFiltersToWindow(t *testing.T) {
	dir := t.TempDir()
	start := time.Unix(1_791_416_000, 0)
	seg := filepath.Join(dir, "seg-1.pcap")
	writeOldSegment(t, seg, start, []int{60, 60, 60, 60, 60}) // one packet per second
	n, err := Merge([]string{seg}, filepath.Join(dir, "out.pcap"),
		start.Add(1*time.Second), start.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("merged %d packets, want 3 (seconds 1..3 inclusive)", n)
	}
}

func TestMergeKeepsUnreadableSegments(t *testing.T) {
	dir := t.TempDir()
	start := time.Unix(1_791_416_000, 0)
	good := filepath.Join(dir, "seg-1.pcap")
	bad := filepath.Join(dir, "seg-2.pcap")
	writeOldSegment(t, good, start, []int{60, 60})
	os.WriteFile(bad, bytes.Repeat([]byte{0xff}, 64), 0o644)

	n, err := Merge([]string{good, bad}, filepath.Join(dir, "out.pcap"), start, start.Add(time.Minute))
	if err == nil {
		t.Fatal("expected an error naming the unreadable segment")
	}
	if n != 2 {
		t.Fatalf("merged %d packets from the good segment, want 2", n)
	}
	if _, err := os.Stat(bad); err != nil {
		t.Fatal("unreadable segment should be kept for inspection")
	}
	if _, err := os.Stat(good); !os.IsNotExist(err) {
		t.Fatal("merged segment should be deleted")
	}
}
