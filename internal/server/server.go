// Package server implements the WHOIS protocol (RFC 3912) as a TCP listener.
//
// A client connects, sends a single line of UTF-8 terminated by CRLF, and the
// server replies with one or more RPSL objects followed by EOF. Each
// connection runs in its own goroutine; concurrency is bounded by a semaphore
// configured via Config.MaxConcurrent.
package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hackman/One_Ring/internal/acl"
	"github.com/hackman/One_Ring/internal/logx"
	"github.com/hackman/One_Ring/internal/ratelimit"
	"github.com/hackman/One_Ring/internal/ripe"
	"github.com/hackman/One_Ring/internal/stats"
)

type Config struct {
	Bind          string
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	MaxConcurrent int
	MaxQueryBytes int
}

type Server struct {
	cfg   Config
	store *ripe.Manager
	stats *stats.Registry // may be nil
	log   *slog.Logger

	// Mutable, hot-swappable at runtime via SetACL / SetLimiter. Stored as
	// atomic pointers so handle() can read without locking.
	aclTree atomic.Pointer[acl.BERT]
	limiter atomic.Pointer[ratelimit.Limiter] // nil pointer means disabled

	sem chan struct{} // bounded concurrency

	// Listener state. Guarded by listenMu so Rebind can rotate the listener
	// underneath the accept loop. The shutdown context fires `closed = true`
	// which causes Run to exit even if a rebind is mid-flight.
	listenMu sync.Mutex
	ln       net.Listener
	bindAddr string
	closed   bool
}

func New(cfg Config, store *ripe.Manager, a *acl.BERT, lim *ratelimit.Limiter, reg *stats.Registry, log *slog.Logger) *Server {
	s := &Server{
		cfg:      cfg,
		store:    store,
		stats:    reg,
		log:      log,
		sem:      make(chan struct{}, cfg.MaxConcurrent),
		bindAddr: cfg.Bind,
	}
	s.aclTree.Store(a)
	s.limiter.Store(lim)
	return s
}

// SetACL atomically replaces the active ACL. Safe to call from any goroutine.
func (s *Server) SetACL(a *acl.BERT) { s.aclTree.Store(a) }

// SetLimiter atomically replaces the active rate limiter. Pass nil to disable
// rate limiting.
func (s *Server) SetLimiter(lim *ratelimit.Limiter) { s.limiter.Store(lim) }

// BindAddr returns the address the accept loop is currently listening on.
func (s *Server) BindAddr() string {
	s.listenMu.Lock()
	defer s.listenMu.Unlock()
	return s.bindAddr
}

// Rebind moves the WHOIS listener to addr. If addr is unchanged this is a
// no-op. On any error (e.g. addr in use) the old listener stays active and
// the error is returned.
func (s *Server) Rebind(addr string) error {
	s.listenMu.Lock()
	defer s.listenMu.Unlock()
	if s.closed {
		return errors.New("server is shutting down")
	}
	if addr == s.bindAddr && s.ln != nil {
		return nil
	}
	lc := &net.ListenConfig{KeepAlive: 30 * time.Second}
	newLn, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	oldLn := s.ln
	s.ln = newLn
	s.bindAddr = addr
	// Closing the old listener unblocks Accept; the accept loop then reads
	// s.ln again and picks up the new one. New connections only ever land on
	// the new listener.
	if oldLn != nil {
		_ = oldLn.Close()
	}
	logx.Notice(s.log, "whois listening", "bind", addr)
	return nil
}

// Run blocks until ctx is cancelled. The active listener may be rotated at
// any time via Rebind.
func (s *Server) Run(ctx context.Context) error {
	lc := &net.ListenConfig{KeepAlive: 30 * time.Second}
	initial, err := lc.Listen(ctx, "tcp", s.cfg.Bind)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Bind, err)
	}
	s.listenMu.Lock()
	s.ln = initial
	s.bindAddr = s.cfg.Bind
	s.listenMu.Unlock()
	logx.Notice(s.log, "whois listening", "bind", s.cfg.Bind)

	// Shutdown watcher: on ctx cancel, mark closed and close the current
	// listener so Accept unblocks.
	go func() {
		<-ctx.Done()
		s.listenMu.Lock()
		s.closed = true
		ln := s.ln
		s.ln = nil
		s.listenMu.Unlock()
		if ln != nil {
			_ = ln.Close()
		}
	}()

	var wg sync.WaitGroup
	for {
		s.listenMu.Lock()
		ln := s.ln
		closed := s.closed
		s.listenMu.Unlock()
		if closed || ln == nil {
			wg.Wait()
			return nil
		}
		c, err := ln.Accept()
		if err != nil {
			s.listenMu.Lock()
			isClosed := s.closed
			rotated := s.ln != ln // a Rebind happened during the Accept
			s.listenMu.Unlock()
			if isClosed || ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			if rotated {
				continue // pick up the new listener on the next iteration
			}
			if errors.Is(err, net.ErrClosed) {
				wg.Wait()
				return nil
			}
			s.log.Warn("accept failed", "err", err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, c)
		}()
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()

	src := remoteAddr(c)
	conn := s.openConn(src.String())
	classification := "" // set by each return path

	// Defer log + stats close so every code path is accounted for.
	defer func() {
		if conn != nil {
			s.stats.Close(conn, classification)
		}
		s.log.Info("query",
			"src", src.String(),
			"query", connQuery(conn),
			"state", connState(conn),
			"result", classification,
			"duration_ms", time.Since(connStarted(conn, c)).Milliseconds(),
			"bytes_in", connBytesIn(conn),
			"bytes_out", connBytesOut(conn),
		)
	}()

	// Bound total concurrency. Refuse promptly if saturated.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		classification = "error_read"
		return
	default:
		classification = "denied_busy"
		s.replyAndCount(c, conn, "%% server busy, try again\n", stats.StateDenied)
		return
	}

	aclTree := s.aclTree.Load()
	action, explicit := aclTree.MatchExplicit(src)
	if action == acl.ActionDeny {
		classification = "denied_acl"
		s.log.Info("acl deny", "src", src)
		s.replyAndCount(c, conn, "%% access denied by policy\n", stats.StateDenied)
		return
	}

	// Explicitly allow-listed sources (a CIDR appears in acl.allow that
	// covers src) bypass the rate limiter entirely. Sources that pass
	// only because of the default "allow" policy are still rate-limited.
	bypassRate := explicit && action == acl.ActionAllow
	if lim := s.limiter.Load(); lim != nil && !bypassRate && !lim.Allow(src) {
		classification = "denied_rate"
		s.replyAndCount(c, conn, "%% rate limit exceeded\n", stats.StateDenied)
		return
	}

	if conn != nil {
		conn.SetState(stats.StateReading)
	}
	_ = c.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))
	br := bufio.NewReaderSize(io.LimitReader(c, int64(s.cfg.MaxQueryBytes)), s.cfg.MaxQueryBytes)
	line, err := br.ReadString('\n')
	if conn != nil {
		conn.AddBytesIn(len(line))
	}
	if err != nil && line == "" {
		classification = "error_read"
		return
	}
	query, flags := parseQuery(line)
	if conn != nil {
		conn.SetQuery(query)
	}
	if query == "" {
		classification = "empty"
		s.replyAndCount(c, conn, "%% empty query\n", stats.StateDone)
		return
	}

	if conn != nil {
		conn.SetState(stats.StateLookingUp)
	}
	resp, nObjects := s.answer(query, flags)
	if conn != nil {
		conn.SetResult(nObjects)
		conn.SetState(stats.StateWriting)
	}

	n, werr := writeReply(c, s.cfg.WriteTimeout, resp)
	if conn != nil {
		conn.AddBytesOut(n)
	}
	if werr != nil {
		classification = "error_write"
		if conn != nil {
			conn.SetError(werr.Error())
		}
		return
	}
	if nObjects == 0 {
		classification = "miss"
	} else {
		classification = "hit"
	}
}

// openConn registers a fresh stats.Conn, or returns nil if stats is disabled.
func (s *Server) openConn(src string) *stats.Conn {
	if s.stats == nil {
		return nil
	}
	return s.stats.Open(src)
}

func (s *Server) replyAndCount(c net.Conn, conn *stats.Conn, msg string, st stats.State) {
	if conn != nil {
		conn.SetState(st)
	}
	n, _ := writeReply(c, s.cfg.WriteTimeout, msg)
	if conn != nil {
		conn.AddBytesOut(n)
	}
}

// queryFlags captures the small subset of RIPE-style flags we honor.
type queryFlags struct {
	abuseContact bool // -b
	primaryOnly  bool // -r (no related contacts)
	exactMatch   bool // -x
	moreSpecific bool // -m / -M
	lessSpecific bool // -l / -L
}

func parseQuery(line string) (string, queryFlags) {
	line = strings.TrimRight(line, "\r\n")
	line = strings.TrimSpace(line)
	if line == "" {
		return "", queryFlags{}
	}
	var f queryFlags
	tokens := strings.Fields(line)
	var rest []string
	for _, t := range tokens {
		if !strings.HasPrefix(t, "-") {
			rest = append(rest, t)
			continue
		}
		for _, r := range t[1:] {
			switch r {
			case 'b':
				f.abuseContact = true
			case 'r':
				f.primaryOnly = true
			case 'x':
				f.exactMatch = true
			case 'm', 'M':
				f.moreSpecific = true
			case 'l', 'L':
				f.lessSpecific = true
			}
		}
	}
	return strings.Join(rest, " "), f
}

// answer returns (response text, number of objects returned).
func (s *Server) answer(query string, flags queryFlags) (string, int) {
	objs := s.store.Lookup(query)
	if len(objs) == 0 {
		return fmt.Sprintf("%% No entries found for the selected source(s).\n%% Query: %s\n", query), 0
	}

	picked := pick(query, objs, flags)

	var b strings.Builder
	b.WriteString("% This output is provided by whoisd, sourced from RIPE NCC.\n")
	b.WriteString("% Use of this data is subject to the RIPE Database Terms and Conditions.\n\n")
	for i, o := range picked {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(o.Raw)
		if !strings.HasSuffix(o.Raw, "\n") {
			b.WriteByte('\n')
		}
	}
	n := len(picked)
	if !flags.primaryOnly {
		n += writeRelated(&b, s.store, picked)
	}
	return b.String(), n
}

func pick(query string, objs []*ripe.Object, flags queryFlags) []*ripe.Object {
	if len(objs) == 0 {
		return nil
	}
	switch {
	case flags.moreSpecific:
		return objs
	case flags.lessSpecific:
		return objs[:1]
	}
	if _, err := netip.ParsePrefix(query); err == nil {
		// nothing
	} else if _, err := netip.ParseAddr(query); err != nil {
		return objs
	}
	return objs[len(objs)-1:]
}

// writeRelated appends person/role objects referenced by admin-c/tech-c/
// abuse-c/zone-c attributes. Returns the number of related objects
// appended.
//
// The four contact-handle attributes are pre-extracted into Object.Handles
// during parsing, so this hot path reads them as direct field access
// instead of scanning Raw on every query.
func writeRelated(b *strings.Builder, mgr *ripe.Manager, objs []*ripe.Object) int {
	seen := make(map[string]bool)
	added := 0
	for _, o := range objs {
		for slot := 0; slot < 4; slot++ {
			for _, h := range o.Handles[slot] {
				h = strings.ToUpper(strings.TrimSpace(h))
				if h == "" || seen[h] {
					continue
				}
				seen[h] = true
				related := mgr.Lookup(h)
				for _, r := range related {
					b.WriteByte('\n')
					b.WriteString(r.Raw)
					if !strings.HasSuffix(r.Raw, "\n") {
						b.WriteByte('\n')
					}
					added++
				}
			}
		}
	}
	return added
}

func writeReply(c net.Conn, d time.Duration, msg string) (int, error) {
	if d > 0 {
		_ = c.SetWriteDeadline(time.Now().Add(d))
	}
	return io.WriteString(c, msg)
}

func remoteAddr(c net.Conn) netip.Addr {
	if tcp, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		if a, ok := netip.AddrFromSlice(tcp.IP); ok {
			return a.Unmap()
		}
	}
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	a, _ := netip.ParseAddr(host)
	return a
}

// small accessors used by the structured-logging defer above. They guard
// against the case where stats is disabled (conn == nil).
func connQuery(c *stats.Conn) string {
	if c == nil {
		return ""
	}
	snap := c.Snap(time.Now())
	return snap.Query
}
func connState(c *stats.Conn) string {
	if c == nil {
		return ""
	}
	return string(c.Snap(time.Now()).State)
}
func connStarted(c *stats.Conn, fallback net.Conn) time.Time {
	if c == nil {
		return time.Now()
	}
	return c.Started()
}
func connBytesIn(c *stats.Conn) int64 {
	if c == nil {
		return 0
	}
	return c.Snap(time.Now()).BytesIn
}
func connBytesOut(c *stats.Conn) int64 {
	if c == nil {
		return 0
	}
	return c.Snap(time.Now()).BytesOut
}
