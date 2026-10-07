module sherlock

// Run `go mod tidy` once to fetch dependencies:
//   github.com/gopacket/gopacket   packet capture (pure Go on Windows via Npcap)
//   golang.org/x/sys, x/net        Windows APIs, ICMP on Linux
//   modernc.org/sqlite             pure-Go SQLite, no C compiler needed
go 1.26.0

require (
	github.com/gopacket/gopacket v1.7.4
	golang.org/x/net v0.59.0
	golang.org/x/sys v0.48.0
	modernc.org/sqlite v1.60.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
