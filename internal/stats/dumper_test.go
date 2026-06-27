package stats

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDumper_WritesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	reg := NewRegistry()
	c := reg.Open("198.51.100.7")
	c.SetQuery("AS65001")
	c.AddBytesOut(123)

	d := &Dumper{
		Path:     path,
		Interval: 50 * time.Millisecond,
		Snap:     func() *Snapshot { return reg.Snapshot(nil) },
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	// Give it time for 3 dumps. With sub-second cadence this is fine.
	time.Sleep(200 * time.Millisecond)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, data)
	}
	if len(snap.Live) != 1 || snap.Live[0].Query != "AS65001" {
		t.Errorf("snapshot live wrong: %+v", snap.Live)
	}
	if snap.Counters.CurrentLive != 1 {
		t.Errorf("current_live = %d", snap.Counters.CurrentLive)
	}

	// Last() should be a parsable snapshot too.
	last := d.Last()
	if last == nil {
		t.Fatal("Last() is nil")
	}
	var snap2 Snapshot
	if err := json.Unmarshal(last, &snap2); err != nil {
		t.Fatalf("Last() not valid JSON: %v", err)
	}
}
