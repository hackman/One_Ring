// Package ratelimit provides a per-source token-bucket limiter that aggregates
// IPv4 addresses by /24 (configurable) and IPv6 by /48 (configurable) so a
// single misbehaving subnet cannot hide behind address space.
package ratelimit

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type Config struct {
	RPS      float64
	Burst    int
	V4Prefix int
	V6Prefix int
	IdleTTL  time.Duration
}

type Limiter struct {
	cfg Config

	mu      sync.Mutex
	buckets map[string]*entry
}

type entry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

func New(cfg Config) *Limiter {
	l := &Limiter{cfg: cfg, buckets: make(map[string]*entry)}
	go l.gcLoop()
	return l
}

// Allow returns true if the source is within its budget.
func (l *Limiter) Allow(src netip.Addr) bool {
	key := l.bucketKey(src)
	l.mu.Lock()
	e, ok := l.buckets[key]
	if !ok {
		e = &entry{lim: rate.NewLimiter(rate.Limit(l.cfg.RPS), l.cfg.Burst)}
		l.buckets[key] = e
	}
	e.lastSeen = time.Now()
	lim := e.lim
	l.mu.Unlock()
	return lim.Allow()
}

// bucketKey aggregates the address into the configured prefix length so the
// limiter dimensions stay bounded under address-space scanning.
func (l *Limiter) bucketKey(src netip.Addr) string {
	if !src.IsValid() {
		return "invalid"
	}
	bits := l.cfg.V6Prefix
	if src.Is4() || src.Is4In6() {
		bits = l.cfg.V4Prefix
		src = src.Unmap()
	}
	p := netip.PrefixFrom(src, bits).Masked()
	return p.String()
}

func (l *Limiter) gcLoop() {
	t := time.NewTicker(l.cfg.IdleTTL / 2)
	defer t.Stop()
	for now := range t.C {
		l.mu.Lock()
		for k, e := range l.buckets {
			if now.Sub(e.lastSeen) > l.cfg.IdleTTL {
				delete(l.buckets, k)
			}
		}
		l.mu.Unlock()
	}
}
