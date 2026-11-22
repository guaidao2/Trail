package threatintel

import (
	"testing"
	"time"
)

func TestParseThreatTimeFormats(t *testing.T) {
	cases := []struct {
		in   string
		want time.Time
		zero bool
	}{
		{"2026-11-22T04:07:20Z", time.Date(2026, 11, 22, 4, 7, 20, 0, time.UTC), false},
		{"2026-11-22 04:07:20", time.Date(2026, 11, 22, 4, 7, 20, 0, time.UTC), false},
		{"2026-11-22T04:07:20", time.Date(2026, 11, 22, 4, 7, 20, 0, time.UTC), false},
		{"", time.Time{}, true},
		{"not-a-time", time.Time{}, true},
	}
	for _, c := range cases {
		got := parseThreatTime(c.in)
		if c.zero {
			if !got.IsZero() {
				t.Errorf("parseThreatTime(%q) 应为零值，实际 %v", c.in, got)
			}
			continue
		}
		if !got.Equal(c.want) {
			t.Errorf("parseThreatTime(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
