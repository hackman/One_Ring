package config

import (
	"testing"
	"time"
)

func TestParseDailyAt(t *testing.T) {
	cases := []struct {
		in    string
		hh    int
		mm    int
		wantE bool
	}{
		{"02:00", 2, 0, false},
		{"23:59", 23, 59, false},
		{" 09:30 UTC", 9, 30, false},
		{"24:00", 0, 0, true},
		{"02", 0, 0, true},
		{"02:60", 0, 0, true},
		{"abc", 0, 0, true},
	}
	for _, c := range cases {
		got, err := ParseDailyAt(c.in)
		if (err != nil) != c.wantE {
			t.Errorf("ParseDailyAt(%q) err=%v wantErr=%v", c.in, err, c.wantE)
			continue
		}
		if !c.wantE && (got.Hour != c.hh || got.Minute != c.mm) {
			t.Errorf("ParseDailyAt(%q)=%+v want %d:%d", c.in, got, c.hh, c.mm)
		}
	}
}

func TestDailyAt_Next(t *testing.T) {
	d := DailyAt{Hour: 2, Minute: 0}

	// from a moment before today's 02:00 → today's 02:00
	from := time.Date(2026, 6, 27, 1, 30, 0, 0, time.UTC)
	got := d.Next(from)
	want := time.Date(2026, 6, 27, 2, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Next pre-anchor got %v want %v", got, want)
	}

	// from exactly 02:00 → tomorrow's 02:00 (must be strictly after)
	from = time.Date(2026, 6, 27, 2, 0, 0, 0, time.UTC)
	got = d.Next(from)
	want = time.Date(2026, 6, 28, 2, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Next at-anchor got %v want %v", got, want)
	}

	// from a moment after today's 02:00 → tomorrow's 02:00
	from = time.Date(2026, 6, 27, 2, 30, 0, 0, time.UTC)
	got = d.Next(from)
	want = time.Date(2026, 6, 28, 2, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("Next post-anchor got %v want %v", got, want)
	}
}
