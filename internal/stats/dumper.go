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
//
// The cadence can be changed at runtime via SetInterval — Run reads the
// new value and resets its internal ticker promptly.
type Dumper struct {
	Path     string
	Interval time.Duration // initial cadence; read once at start of Run
	Snap     SnapshotFn
	Log      *slog.Logger

	mu       sync.RWMutex
	last     []byte        // last serialized payload, kept for the HTTP handler
	curIntvl time.Duration // currently-active cadence; protected by mu
	nudge    chan struct{} // SetInterval wakes Run; lazily created on first use
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

// SetInterval changes the dump cadence at runtime. Sub-second values are
// allowed. The new value takes effect immediately on the next tick of the
// Run loop. Safe to call from any goroutine.
func (d *Dumper) SetInterval(newI time.Duration) {
	if newI <= 0 {
		return
	}
	d.mu.Lock()
	d.curIntvl = newI
	if d.nudge == nil {
		d.nudge = make(chan struct{}, 1)
	}
	ch := d.nudge
	d.mu.Unlock()
	select {
	case ch <- struct{}{}:
	default:
		// already pending; Run will pick up the latest curIntvl
	}
}

// Run blocks until ctx is cancelled. It dumps once immediately so consumers
// have data right away, then on every interval tick. The cadence is checked
// on every iteration so SetInterval changes are picked up promptly.
func (d *Dumper) Run(ctx context.Context) error {
	if d.Interval <= 0 {
		return fmt.Errorf("dump interval must be > 0")
	}
	d.mu.Lock()
	d.curIntvl = d.Interval
	if d.nudge == nil {
		d.nudge = make(chan struct{}, 1)
	}
	nudge := d.nudge
	cur := d.curIntvl
	d.mu.Unlock()

	if err := d.dumpOnce(); err != nil {
		d.Log.Warn("stats dump failed", "err", err)
	}
	t := time.NewTicker(cur)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-nudge:
			d.mu.RLock()
			newI := d.curIntvl
			d.mu.RUnlock()
			if newI != cur && newI > 0 {
				cur = newI
				t.Reset(cur)
				d.Log.Info("stats dump interval changed", "interval", cur)
			}
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
