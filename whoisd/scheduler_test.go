package main

import (
	"errors"
	"testing"
	"time"

	"github.com/hackman/One_Ring/internal/config"
)

func TestNextRefresh(t *testing.T) {
	cfg := &config.Config{}
	cfg.Dbase.PollInterval = 1 * time.Hour
	cfg.Dbase.DailyAt = "02:00"
	cfg.Dbase.RetryOnFailure = 5 * time.Minute

	// 1) Daily anchor wins when it's nearer than the poll interval.
	now := time.Date(2026, 6, 27, 1, 30, 0, 0, time.UTC)
	got := nextRefresh(now, cfg, nil)
	want := time.Date(2026, 6, 27, 2, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("daily anchor wins: got %v want %v", got, want)
	}

	// 2) Poll interval wins when it's nearer than the next anchor.
	now = time.Date(2026, 6, 27, 3, 0, 0, 0, time.UTC)
	got = nextRefresh(now, cfg, nil)
	want = now.Add(time.Hour)
	if !got.Equal(want) {
		t.Errorf("poll interval wins: got %v want %v", got, want)
	}

	// 3) Failure backoff overrides scheduling.
	now = time.Date(2026, 6, 27, 1, 30, 0, 0, time.UTC)
	got = nextRefresh(now, cfg, errors.New("boom"))
	want = now.Add(5 * time.Minute)
	if !got.Equal(want) {
		t.Errorf("retry backoff: got %v want %v", got, want)
	}

	// 4) Empty DailyAt -> pure poll interval.
	cfg.Dbase.DailyAt = ""
	now = time.Date(2026, 6, 27, 1, 30, 0, 0, time.UTC)
	got = nextRefresh(now, cfg, nil)
	want = now.Add(time.Hour)
	if !got.Equal(want) {
		t.Errorf("no anchor: got %v want %v", got, want)
	}
}
