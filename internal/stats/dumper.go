package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SnapshotFn returns the JSON-ready snapshot to be written. Wrapping the
// registry call lets callers inject extra fields (e.g. RIPE refresh time).
type SnapshotFn func() *Snapshot

// Dumper writes a Snapshot to a JSON file on disk at a configurable cadence.
// Writes are atomic (write-to-temp + rename) so a concurrent reader never
// observes a partial file. The cadence may be sub-second.
type Dumper struct {
	Path     string
	Interval time.Duration
	Snap     SnapshotFn
	Log      *slog.Logger

	mu   sync.RWMutex
	last []byte // last serialized payload, kept for the HTTP handler
}

// Last returns the most recently dumped JSON payload, or nil if none yet.
func (d *Dumper) Last() []byte {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.last == nil {
		return nil
	}
	out := make([]byte, len(d.last))
	copy(out, d.last)
	return out
}

// Run blocks until ctx is cancelled. It dumps once immediately so consumers
// have data right away, then on every interval tick.
func (d *Dumper) Run(ctx context.Context) error {
	if d.Interval <= 0 {
		return fmt.Errorf("dump interval must be > 0")
	}
	if err := d.dumpOnce(); err != nil {
		d.Log.Warn("stats dump failed", "err", err)
	}
	t := time.NewTicker(d.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := d.dumpOnce(); err != nil {
				d.Log.Warn("stats dump failed", "err", err)
			}
		}
	}
}

func (d *Dumper) dumpOnce() error {
	snap := d.Snap()
	buf, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	d.mu.Lock()
	d.last = buf
	d.mu.Unlock()

	if d.Path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(d.Path), 0o755); err != nil {
		return err
	}
	// Atomic write: tmp + rename so readers never see a torn file.
	tmp, err := os.CreateTemp(filepath.Dir(d.Path), filepath.Base(d.Path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, d.Path)
}
