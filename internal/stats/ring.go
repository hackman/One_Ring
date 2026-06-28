package stats

import (
	"sync"
	"time"
)

// ringCounter buckets event timestamps by Unix-second so we can read the
// count for the most-recent completed second cheaply. Only the current
// in-progress second and the one just before it are needed by callers, but
// we keep a tiny ring (8 buckets) so a brief gap in advance() calls — for
// example, if no tick happens for several seconds and then LastSecond is
// read — still yields zero for those silent seconds.
//
// Total footprint: 8 × 4 = 32 bytes. There is no per-second history kept
// here; the dashboard maintains its own polled-value buffer client-side.
type ringCounter struct {
	mu      sync.Mutex
	buckets [8]uint32
	headSec int64
}

func (r *ringCounter) tick(now time.Time) {
	sec := now.Unix()
	r.mu.Lock()
	r.advance(sec)
	r.buckets[r.idx(sec)]++
	r.mu.Unlock()
}

// LastSecond returns the count of events that occurred during the most
// recent COMPLETED Unix second (i.e. sec - 1 relative to now). The current,
// in-progress second is deliberately excluded — its bucket is still being
// updated and reading it would yield partial counts.
func (r *ringCounter) LastSecond(now time.Time) uint32 {
	sec := now.Unix()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.advance(sec)
	return r.buckets[r.idx(sec-1)]
}

func (r *ringCounter) idx(sec int64) int {
	n := int64(len(r.buckets))
	return int(((sec % n) + n) % n)
}

// advance zeros every bucket between the previously-seen second and now,
// so silent seconds correctly read as 0 instead of stale data left over
// from one full ring revolution ago.
func (r *ringCounter) advance(sec int64) {
	if r.headSec == 0 {
		r.headSec = sec
		return
	}
	delta := sec - r.headSec
	if delta <= 0 {
		return
	}
	n := int64(len(r.buckets))
	if delta >= n {
		for i := range r.buckets {
			r.buckets[i] = 0
		}
	} else {
		for i := int64(1); i <= delta; i++ {
			r.buckets[r.idx(r.headSec+i)] = 0
		}
	}
	r.headSec = sec
}
