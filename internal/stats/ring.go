package stats

import (
	"sync"
	"time"
)

// ringCounter is a 1-second-bucket sliding window of event counts. It is used
// to compute a recent QPS without retaining individual timestamps.
//
// The implementation is intentionally simple: events are bucketed by Unix
// second; tick() advances the head and zeros expired buckets lazily.
type ringCounter struct {
	mu      sync.Mutex
	buckets []uint32
	headSec int64
}

func (r *ringCounter) init(sizeSeconds int) {
	r.buckets = make([]uint32, sizeSeconds)
	r.headSec = 0
}

func (r *ringCounter) tick(now time.Time) {
	sec := now.Unix()
	r.mu.Lock()
	r.advance(sec)
	r.buckets[int(sec%int64(len(r.buckets)))]++
	r.mu.Unlock()
}

// rate returns events per second averaged over the window (excluding the
// current, possibly-partial second to keep the number stable).
func (r *ringCounter) rate(now time.Time) float64 {
	sec := now.Unix()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.advance(sec)
	var total uint64
	n := len(r.buckets)
	// Sum the past (n-1) buckets, skipping the current second.
	for i := 1; i < n; i++ {
		idx := int((sec - int64(i)) % int64(n))
		if idx < 0 {
			idx += n
		}
		total += uint64(r.buckets[idx])
	}
	return float64(total) / float64(n-1)
}

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
			idx := int((r.headSec + i) % n)
			if idx < 0 {
				idx += int(n)
			}
			r.buckets[idx] = 0
		}
	}
	r.headSec = sec
}
