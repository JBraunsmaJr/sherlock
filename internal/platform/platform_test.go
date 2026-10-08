package platform

import (
	"testing"
	"time"
)

func TestTicksToDuration(t *testing.T) {
	cases := []struct {
		ticks, freq int64
		want        time.Duration
	}{
		{3_000, 10_000_000, 300 * time.Microsecond}, // typical 10 MHz QPC, a 0.3 ms LAN ping
		{1, 10_000_000, 100 * time.Nanosecond},
		{25_000_000, 10_000_000, 2500 * time.Millisecond},
		{1 << 50, 10_000_000, time.Duration(1<<50/10_000_000)*time.Second + time.Duration((1<<50)%10_000_000)*100}, // no overflow
		{-5, 10_000_000, 0},
		{5, 0, 0},
	}
	for _, c := range cases {
		if got := ticksToDuration(c.ticks, c.freq); got != c.want {
			t.Errorf("ticksToDuration(%d, %d) = %v, want %v", c.ticks, c.freq, got, c.want)
		}
	}
}
