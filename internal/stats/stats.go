// Package stats tracks per-connection liveness and server-wide counters so
// they can be (a) periodically dumped to a JSON file on disk for an external
// dashboard to consume, and (b) optionally served over HTTP by the embedded
// dashboard server.
//
// Concurrency model:
//   - Each in-flight connection is registered as a *Conn. Conn fields are
//     mutated only by the goroutine handling that connection, except for
//     BytesIn / BytesOut which are atomic so the snapshotter can read them
//     without locking.
//   - The connection set itself is guarded by a single RWMutex which is held
//     only briefly on register/unregister and on snapshot construction.
//   - Server-wide counters live in a separate `counters` struct backed by
//     atomic integers.
//
// State machine for a Conn:
//
//	new -> reading -> looking_up -> writing -> done
//	                              \-> error  -> done
//	                              \-> denied -> done    (acl/rate-limit)
package stats

import (
	"sync"
	"sync/atomic"
	"time"
)

// State labels the current phase of an in-flight connection.
type State string

const (
	StateNew       State = "new"
	StateReading   State = "reading"
	StateLookingUp State = "looking_up"
	StateWriting   State = "writing"
	StateDenied    State = "denied"
	StateError     State = "error"
	StateDone      State = "done"
)

// Conn is the live record for one TCP connection. Methods are safe to call
// from the handler goroutine; the snapshotter reads via Snap().
type Conn struct {
	ID      uint64
	Src     string
	started time.Time

	mu       sync.Mutex
	query    string
	state    State
	resultN  int    // number of objects in the WHOIS response
	closed   bool
	closedAt time.Time
	errMsg   string

	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// snapConn is the JSON-serializable projection of a Conn.
type snapConn struct {
	ID         uint64  `json:"id"`
	Src        string  `json:"src"`
	StartedAt  string  `json:"started_at"`
	DurationMS int64   `json:"duration_ms"`
	State      State   `json:"state"`
	Query      string  `json:"query,omitempty"`
	BytesIn    int64   `json:"bytes_in"`
	BytesOut   int64   `json:"bytes_out"`
	Result     int     `json:"result_objects"`
	Error      string  `json:"error,omitempty"`
	RateKBps   float64 `json:"rate_kbps"`
}

// Snap returns a JSON-safe snapshot of this connection at instant `now`.
func (c *Conn) Snap(now time.Time) snapConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	dur := now.Sub(c.started)
	out := snapConn{
		ID:         c.ID,
		Src:        c.Src,
		StartedAt:  c.started.UTC().Format(time.RFC3339Nano),
		DurationMS: dur.Milliseconds(),
		State:      c.state,
		Query:      c.query,
		BytesIn:    c.bytesIn.Load(),
		BytesOut:   c.bytesOut.Load(),
		Result:     c.resultN,
		Error:      c.errMsg,
	}
	if secs := dur.Seconds(); secs > 0 {
		out.RateKBps = float64(out.BytesOut) / 1024.0 / secs
	}
	return out
}

func (c *Conn) SetState(s State)            { c.mu.Lock(); c.state = s; c.mu.Unlock() }
func (c *Conn) SetQuery(q string)           { c.mu.Lock(); c.query = q; c.mu.Unlock() }
func (c *Conn) SetResult(n int)             { c.mu.Lock(); c.resultN = n; c.mu.Unlock() }
func (c *Conn) SetError(msg string)         { c.mu.Lock(); c.errMsg = msg; c.state = StateError; c.mu.Unlock() }
func (c *Conn) AddBytesIn(n int)            { c.bytesIn.Add(int64(n)) }
func (c *Conn) AddBytesOut(n int)           { c.bytesOut.Add(int64(n)) }
func (c *Conn) Started() time.Time          { return c.started }

// Registry holds the live set of connections and aggregate counters.
type Registry struct {
	startedAt time.Time
	nextID    atomic.Uint64

	mu    sync.RWMutex
	conns map[uint64]*Conn

	totals counters
}

// counters are atomic so we can read/write them without coordinating with
// the registry mutex.
type counters struct {
	queriesTotal    atomic.Uint64
	queriesHit      atomic.Uint64 // returned at least one object
	queriesMiss     atomic.Uint64
	queriesEmpty    atomic.Uint64 // blank query
	deniesACL       atomic.Uint64
	deniesRateLimit atomic.Uint64
	deniesBusy      atomic.Uint64
	errorsRead      atomic.Uint64
	errorsWrite     atomic.Uint64
	bytesIn         atomic.Int64
	bytesOut        atomic.Int64

	// rolling QPS sample, last N seconds. Updated on each query.
	qpsRing ringCounter
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	r := &Registry{
		startedAt: time.Now(),
		conns:     make(map[uint64]*Conn),
	}
	// The ringCounter inside r.totals.qpsRing is fixed-size (8 buckets);
	// no init required.
	return r
}

// Open registers a new connection.
func (r *Registry) Open(src string) *Conn {
	c := &Conn{
		ID:      r.nextID.Add(1),
		Src:     src,
		started: time.Now(),
		state:   StateNew,
	}
	r.mu.Lock()
	r.conns[c.ID] = c
	r.mu.Unlock()
	return c
}

// Close removes the connection from the live set and updates aggregate
// counters. Pass a result classification: "hit", "miss", "denied_acl",
// "denied_rate", "denied_busy", "error_read", "error_write", "empty", or "".
func (r *Registry) Close(c *Conn, classification string) {
	c.mu.Lock()
	c.closed = true
	c.closedAt = time.Now()
	if c.state != StateError && c.state != StateDenied {
		c.state = StateDone
	}
	bIn := c.bytesIn.Load()
	bOut := c.bytesOut.Load()
	c.mu.Unlock()

	r.mu.Lock()
	delete(r.conns, c.ID)
	r.mu.Unlock()

	r.totals.bytesIn.Add(bIn)
	r.totals.bytesOut.Add(bOut)

	switch classification {
	case "hit":
		r.totals.queriesTotal.Add(1)
		r.totals.queriesHit.Add(1)
		r.totals.qpsRing.tick(time.Now())
	case "miss":
		r.totals.queriesTotal.Add(1)
		r.totals.queriesMiss.Add(1)
		r.totals.qpsRing.tick(time.Now())
	case "empty":
		r.totals.queriesEmpty.Add(1)
	case "denied_acl":
		r.totals.deniesACL.Add(1)
	case "denied_rate":
		r.totals.deniesRateLimit.Add(1)
	case "denied_busy":
		r.totals.deniesBusy.Add(1)
	case "error_read":
		r.totals.errorsRead.Add(1)
	case "error_write":
		r.totals.errorsWrite.Add(1)
	}
}

// Snapshot is the JSON payload emitted to disk.
//
// RecentQPS is the raw count of queries that completed in the most recent
// fully-elapsed Unix second — NOT a trailing average and NOT a per-second
// history. Consumers that want a graph maintain their own buffer of polled
// values client-side; the server intentionally keeps no history.
type Snapshot struct {
	Generated    string         `json:"generated_at"`
	StartedAt    string         `json:"started_at"`
	UptimeSec    float64        `json:"uptime_s"`
	Live         []snapConn     `json:"live"`
	Counters     sCounters      `json:"counters"`
	RecentQPS    uint32         `json:"recent_qps"`
	RIPELoaded   string         `json:"dbase_last_loaded,omitempty"`
	RIPEClasses  map[string]int `json:"class_counts,omitempty"`
	SourceCounts map[string]int `json:"source_counts,omitempty"`
}

type sCounters struct {
	QueriesTotal    uint64 `json:"queries_total"`
	QueriesHit      uint64 `json:"queries_hit"`
	QueriesMiss     uint64 `json:"queries_miss"`
	QueriesEmpty    uint64 `json:"queries_empty"`
	DeniesACL       uint64 `json:"denies_acl"`
	DeniesRateLimit uint64 `json:"denies_rate_limit"`
	DeniesBusy      uint64 `json:"denies_busy"`
	ErrorsRead      uint64 `json:"errors_read"`
	ErrorsWrite     uint64 `json:"errors_write"`
	BytesIn         int64  `json:"bytes_in"`
	BytesOut        int64  `json:"bytes_out"`
	CurrentLive     int    `json:"current_live"`
}

// Snapshot builds a JSON-ready view.
func (r *Registry) Snapshot(extra func(*Snapshot)) *Snapshot {
	now := time.Now()
	r.mu.RLock()
	live := make([]snapConn, 0, len(r.conns))
	for _, c := range r.conns {
		live = append(live, c.Snap(now))
	}
	currentLive := len(r.conns)
	r.mu.RUnlock()

	s := &Snapshot{
		Generated: now.UTC().Format(time.RFC3339Nano),
		StartedAt: r.startedAt.UTC().Format(time.RFC3339Nano),
		UptimeSec: now.Sub(r.startedAt).Seconds(),
		Live:      live,
		Counters: sCounters{
			QueriesTotal:    r.totals.queriesTotal.Load(),
			QueriesHit:      r.totals.queriesHit.Load(),
			QueriesMiss:     r.totals.queriesMiss.Load(),
			QueriesEmpty:    r.totals.queriesEmpty.Load(),
			DeniesACL:       r.totals.deniesACL.Load(),
			DeniesRateLimit: r.totals.deniesRateLimit.Load(),
			DeniesBusy:      r.totals.deniesBusy.Load(),
			ErrorsRead:      r.totals.errorsRead.Load(),
			ErrorsWrite:     r.totals.errorsWrite.Load(),
			BytesIn:         r.totals.bytesIn.Load(),
			BytesOut:        r.totals.bytesOut.Load(),
			CurrentLive:     currentLive,
		},
		RecentQPS: r.totals.qpsRing.LastSecond(now),
	}
	if extra != nil {
		extra(s)
	}
	return s
}
