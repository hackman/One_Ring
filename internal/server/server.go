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
	"time"

	"github.com/hackman/One_Ring/internal/acl"
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
	cfg     Config
	store   *ripe.Manager
	acl     *acl.BERT
	limiter *ratelimit.Limiter // may be nil
	stats   *stats.Registry    // may be nil
	log     *slog.Logger

	sem chan struct{} // bounded concurrency
}

func New(cfg Config, store *ripe.Manager, a *acl.BERT, lim *ratelimit.Limiter, reg *stats.Registry, log *slog.Logger) *Server {
	return &Server{
		cfg:     cfg,
		store:   store,
		acl:     a,
		limiter: lim,
		stats:   reg,
		log:     log,
		sem:     make(chan struct{}, cfg.MaxConcurrent),
	}
}

// Run blocks until ctx is cancelled or Accept fails.
func (s *Server) Run(ctx context.Context) error {
	lc := &net.ListenConfig{KeepAlive: 30 * time.Second}
	ln, err := lc.Listen(ctx, "tcp", s.cfg.Bind)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Bind, err)
	}
	s.log.Info("whois listening", "bind", s.cfg.Bind)

	// Close the listener on shutdown so Accept returns.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
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

	if action := s.acl.Match(src); action == acl.ActionDeny {
		classification = "denied_acl"
		s.log.Info("acl deny", "src", src)
		s.replyAndCount(c, conn, "%% access denied by policy\n", stats.StateDenied)
		return
	}

	if s.limiter != nil && !s.limiter.Allow(src) {
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
	store := s.store.Current()
	objs := store.Lookup(query)
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
		n += writeRelated(&b, store, picked)
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

// writeRelated appends person/role objects referenced by admin-c/tech-c.
// Returns the number of related objects appended.
func writeRelated(b *strings.Builder, store *ripe.Store, objs []*ripe.Object) int {
	seen := make(map[string]bool)
	added := 0
	for _, o := range objs {
		for _, attr := range []string{"admin-c", "tech-c", "abuse-c", "zone-c"} {
			for _, h := range o.LookupAll(attr) {
				h = strings.ToUpper(strings.TrimSpace(h))
				if h == "" || seen[h] {
					continue
				}
				seen[h] = true
				related := store.Lookup(h)
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
