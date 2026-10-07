package config

import (
	"testing"
	"time"
)

func TestInWindows(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 1, 1, h, m, 0, 0, time.Local) }
	cases := []struct {
		windows []string
		t       time.Time
		want    bool
	}{
		{nil, at(12, 0), true},
		{[]string{"01:00-07:00"}, at(3, 0), true},
		{[]string{"01:00-07:00"}, at(7, 0), false},
		{[]string{"01:00-07:00"}, at(0, 59), false},
		{[]string{"22:00-06:00"}, at(23, 30), true}, // wraps past midnight
		{[]string{"22:00-06:00"}, at(5, 59), true},
		{[]string{"22:00-06:00"}, at(12, 0), false},
		{[]string{"09:00-10:00", "13:00-14:00"}, at(13, 15), true},
	}
	for _, c := range cases {
		if got := InWindows(c.windows, c.t); got != c.want {
			t.Errorf("InWindows(%v, %s) = %v, want %v", c.windows, c.t.Format("15:04"), got, c.want)
		}
	}
}

func TestDefaultsValidate(t *testing.T) {
	c := Default()
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	c.Throughput.Mode = "always"
	if err := c.validate(); err == nil {
		t.Fatal("expected an invalid mode to be rejected")
	}
}
