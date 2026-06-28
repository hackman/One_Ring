package ripe

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// Store is the in-memory query index for parsed RPSL objects from one or
// more upstream databases (RIPE, ARIN, APNIC, LACNIC, AFRINIC).
//
// Lookup semantics:
//   - byKey indexes every object by (class, primary-key). The same key can
//     legitimately exist in multiple sources, so values are slices.
//   - byHandle indexes person/role objects by their nic-hdl, the form most
//     other objects reference (admin-c, tech-c, ...).
//   - byDomain indexes domain objects by name (lowercased).
//   - inet / inet6 / route / route6 are prefix tries: looking up an IP
//     returns every covering object, least-specific first.
//
// The Store is constructed once during a (re)load cycle and swapped in
// atomically. Readers never block writers and vice versa.
// classPKKey is a composite map key. Using a struct rather than a
// concatenated string saves one string allocation per Insert (~5-8 M during
// a full RIR load) and shrinks the per-entry footprint slightly because
// Class is interned to one of ~20 canonical strings.
type classPKKey struct {
	Class string
	PK    string
}

type Store struct {
	byKey    map[classPKKey][]*Object
	byHandle map[string][]*Object // upper-cased nic-hdl
	byDomain map[string][]*Object // lowercased domain name

	inet4 *netTrie
	inet6 *netTrie

	// counts is (class -> total count across all sources).
	counts map[string]int
	// countsBySource is (source -> total objects loaded).
	countsBySource map[string]int
}

// NewStore returns an empty Store ready for inserts.
//
// Initial map capacities are sized for a full 5-RIR load: byKey ~8 M
// entries, byHandle ~4 M, byDomain ~1 M. Right-sizing these avoids 7-8
// hash-table doublings during load, each of which doubles transient
// memory.
func NewStore() *Store {
	return &Store{
		byKey:          make(map[classPKKey][]*Object, 1<<23),
		byHandle:       make(map[string][]*Object, 1<<22),
		byDomain:       make(map[string][]*Object, 1<<20),
		inet4:          newNetTrie(),
		inet6:          newNetTrie(),
		counts:         make(map[string]int),
		countsBySource: make(map[string]int),
	}
}

// Counts returns objects-per-class summed across all sources.
func (s *Store) Counts() map[string]int {
	out := make(map[string]int, len(s.counts))
	for k, v := range s.counts {
		out[k] = v
	}
	return out
}

// CountsBySource returns objects-per-source.
func (s *Store) CountsBySource() map[string]int {
	out := make(map[string]int, len(s.countsBySource))
	for k, v := range s.countsBySource {
		out[k] = v
	}
	return out
}

func keyOf(class, pk string) classPKKey { return classPKKey{Class: class, PK: pk} }

// Insert files an object into the appropriate indexes. `source` is the name
// of the upstream DB the object came from; it is recorded so the dashboard
// can show per-source counts.
func (s *Store) Insert(obj *Object, source string) {
	s.counts[obj.Class]++
	s.countsBySource[source]++
	k := classPKKey{Class: obj.Class, PK: normalizeKey(obj.Class, obj.PrimaryKey)}
	s.byKey[k] = append(s.byKey[k], obj)

	switch obj.Class {
	case "person", "role":
		// NicHdl was extracted by the parser; avoids an O(n) Lookup scan
		// over Raw on millions of person/role objects during load.
		if obj.NicHdl != "" {
			h := strings.ToUpper(obj.NicHdl)
			s.byHandle[h] = append(s.byHandle[h], obj)
		}
	case "domain":
		dn := strings.ToLower(strings.TrimSuffix(obj.PrimaryKey, "."))
		s.byDomain[dn] = append(s.byDomain[dn], obj)
	case "inetnum":
		s.insertRange(s.inet4, obj.PrimaryKey, obj)
	case "inet6num":
		s.insertPrefix(s.inet6, obj.PrimaryKey, obj)
	case "route":
		s.insertPrefix(s.inet4, obj.PrimaryKey, obj)
	case "route6":
		s.insertPrefix(s.inet6, obj.PrimaryKey, obj)
	}
}

func normalizeKey(class, pk string) string {
	switch class {
	case "aut-num", "as-block", "as-set",
		"mntner", "organisation", "irt", "key-cert",
		"filter-set", "inet-rtr", "peering-set", "route-set", "rtr-set":
		return strings.ToUpper(strings.TrimSpace(pk))
	case "domain":
		return strings.ToLower(strings.TrimSpace(pk))
	}
	return strings.TrimSpace(pk)
}

func (s *Store) insertPrefix(t *netTrie, pk string, obj *Object) {
	p, err := netip.ParsePrefix(strings.TrimSpace(pk))
	if err != nil {
		return
	}
	t.insert(p, obj)
}

func (s *Store) insertRange(t *netTrie, pk string, obj *Object) {
	startStr, endStr, ok := splitRange(pk)
	if !ok {
		return
	}
	start, err1 := netip.ParseAddr(startStr)
	end, err2 := netip.ParseAddr(endStr)
	if err1 != nil || err2 != nil || start.Is6() != end.Is6() {
		return
	}
	for _, p := range rangeToCIDRs(start, end) {
		t.insert(p, obj)
	}
}

func splitRange(s string) (string, string, bool) {
	i := strings.Index(s, "-")
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
}

// Lookup dispatches a WHOIS query string to whichever index can answer it.
// Returns nil if nothing matched.
func (s *Store) Lookup(q string) []*Object {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil
	}

	// IP / prefix?
	if p, err := netip.ParsePrefix(q); err == nil {
		return s.lookupAddr(p.Addr())
	}
	if a, err := netip.ParseAddr(q); err == nil {
		return s.lookupAddr(a)
	}

	upper := strings.ToUpper(q)
	lower := strings.ToLower(q)

	// AS number?
	if strings.HasPrefix(upper, "AS") {
		if objs := s.byKey[keyOf("aut-num", upper)]; len(objs) > 0 {
			return objs
		}
		if objs := s.byKey[keyOf("as-block", upper)]; len(objs) > 0 {
			return objs
		}
	}

	// nic-hdl?
	if isNicHandle(q) {
		if objs := s.byHandle[upper]; len(objs) > 0 {
			return objs
		}
	}

	// domain?
	if strings.Contains(q, ".") {
		if objs := s.byDomain[lower]; len(objs) > 0 {
			return objs
		}
	}

	// Try every class' byKey table for an exact match. Returns the first hit.
	for _, class := range []string{
		"organisation", "mntner", "as-set", "route-set", "filter-set",
		"peering-set", "rtr-set", "inet-rtr", "key-cert", "irt", "person", "role",
	} {
		k := normalizeKey(class, q)
		if objs := s.byKey[keyOf(class, k)]; len(objs) > 0 {
			return objs
		}
	}
	return nil
}

func (s *Store) lookupAddr(a netip.Addr) []*Object {
	if a.Is4() {
		return s.inet4.lookup(a)
	}
	return s.inet6.lookup(a)
}

func isNicHandle(s string) bool {
	// crude: at least one letter and one '-' or digit, all ASCII
	hasAlpha, hasOther := false, false
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
			hasAlpha = true
		case r >= '0' && r <= '9', r == '-':
			hasOther = true
		default:
			return false
		}
	}
	return hasAlpha && hasOther
}

// -----------------------------------------------------------------------------
// netTrie: binary radix tree of network prefixes -> []*Object
// -----------------------------------------------------------------------------

type netTrie struct {
	root *netNode
}

type netNode struct {
	children [2]*netNode
	objs     []*Object
}

func newNetTrie() *netTrie { return &netTrie{root: &netNode{}} }

func (t *netTrie) insert(p netip.Prefix, obj *Object) {
	p = p.Masked()
	a := p.Addr()
	if a.Is4() {
		a = netip.AddrFrom16(a.As16())
	}
	bits := a.As16()
	depth := p.Bits()
	if p.Addr().Is4() {
		depth += 96
	}
	n := t.root
	for i := 0; i < depth; i++ {
		bit := (bits[i>>3] >> (7 - uint(i&7))) & 1
		if n.children[bit] == nil {
			n.children[bit] = &netNode{}
		}
		n = n.children[bit]
	}
	n.objs = append(n.objs, obj)
}

// lookup returns all objects whose prefix covers a, ordered from least to most
// specific.
func (t *netTrie) lookup(a netip.Addr) []*Object {
	if a.Is4() {
		a = netip.AddrFrom16(a.As16())
	}
	bits := a.As16()
	n := t.root
	var out []*Object
	if len(n.objs) > 0 {
		out = append(out, n.objs...)
	}
	for i := 0; i < 128; i++ {
		bit := (bits[i>>3] >> (7 - uint(i&7))) & 1
		c := n.children[bit]
		if c == nil {
			break
		}
		n = c
		if len(n.objs) > 0 {
			out = append(out, n.objs...)
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// IP range -> CIDR decomposition (RFC 4632 §3.1 style)
// -----------------------------------------------------------------------------

// rangeToCIDRs returns the minimum set of CIDRs that exactly cover [start,end].
func rangeToCIDRs(start, end netip.Addr) []netip.Prefix {
	if start.Is6() != end.Is6() {
		return nil
	}
	bitLen := 32
	if start.Is6() {
		bitLen = 128
	}
	var out []netip.Prefix
	cur := start
	for cmpAddr(cur, end) <= 0 {
		// Largest prefix starting at cur that doesn't extend past end.
		size := trailingZeros(cur, bitLen)
		if size > bitLen {
			size = bitLen
		}
		for size > 0 {
			last := addrPlusMask(cur, size)
			if cmpAddr(last, end) <= 0 {
				break
			}
			size--
		}
		out = append(out, netip.PrefixFrom(cur, bitLen-size))
		last := addrPlusMask(cur, size)
		if cmpAddr(last, end) >= 0 {
			break
		}
		cur = addrAddOne(last)
		if !cur.IsValid() {
			break
		}
	}
	return out
}

func cmpAddr(a, b netip.Addr) int {
	return a.Compare(b)
}

// trailingZeros returns the largest k such that the low k bits of a are zero
// (clamped to bitLen).
func trailingZeros(a netip.Addr, bitLen int) int {
	bs := a.As16()
	// Walk from the lowest bit upward.
	start := 16 - bitLen/8
	k := 0
	for i := 15; i >= start; i-- {
		b := bs[i]
		if b == 0 {
			k += 8
			continue
		}
		for j := 0; j < 8; j++ {
			if b&(1<<j) != 0 {
				return k + j
			}
		}
	}
	return k
}

// addrPlusMask returns a | ((1<<size)-1), i.e. a with the low `size` bits set.
func addrPlusMask(a netip.Addr, size int) netip.Addr {
	bs := a.As16()
	for i := 15; size > 0 && i >= 0; i-- {
		bits := size
		if bits > 8 {
			bits = 8
		}
		bs[i] |= byte((1 << bits) - 1)
		size -= bits
	}
	out, _ := netip.AddrFromSlice(bs[:])
	if a.Is4() {
		return out.Unmap()
	}
	return out
}

func addrAddOne(a netip.Addr) netip.Addr {
	bs := a.As16()
	for i := 15; i >= 0; i-- {
		bs[i]++
		if bs[i] != 0 {
			out, _ := netip.AddrFromSlice(bs[:])
			if a.Is4() {
				return out.Unmap()
			}
			return out
		}
	}
	// overflow
	return netip.Addr{}
}

// -----------------------------------------------------------------------------
// Manager: per-source Stores + reload with atomic per-source swap
// -----------------------------------------------------------------------------

// Manager owns one Store per upstream source. Per-source isolation lets
// reload rebuild only the sources whose files actually changed — the rest
// keep their existing sub-store live without touching the heap. This caps
// the rebuild peak at "steady-state + size of the largest changed source"
// instead of the previous "2 × steady-state".
//
// All Lookup-style methods iterate every source and concatenate results.
// Since RIRs partition the IP address space, the per-source longest-prefix
// match across tries still yields a correct global answer for IP queries;
// for primary-key, NIC handle and domain lookups the same object id can
// legitimately exist in two sources and we return both.
type Manager struct {
	mu         sync.RWMutex
	sources    map[string]*Store // keyed by source name (e.g. "ripe")
	lastReload time.Time
	log        *slog.Logger
}

func NewManager(log *slog.Logger) *Manager {
	return &Manager{sources: make(map[string]*Store), log: log}
}

// LastReload reports when the most recent (re)load finished.
func (m *Manager) LastReload() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastReload
}

// IsEmpty reports whether no sources have been loaded yet.
func (m *Manager) IsEmpty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.sources {
		if len(s.byKey) > 0 {
			return false
		}
	}
	return true
}

// snapshot returns a stable slice of (source, *Store) pairs for iteration
// without holding the mutex. Sub-Stores are immutable once installed.
func (m *Manager) snapshot() []*Store {
	m.mu.RLock()
	out := make([]*Store, 0, len(m.sources))
	for _, s := range m.sources {
		out = append(out, s)
	}
	m.mu.RUnlock()
	return out
}

// Lookup dispatches q to every per-source store and concatenates the
// results. Returns nil if no source matched.
func (m *Manager) Lookup(q string) []*Object {
	var out []*Object
	for _, s := range m.snapshot() {
		if got := s.Lookup(q); len(got) > 0 {
			out = append(out, got...)
		}
	}
	return out
}

// Counts returns the aggregate per-class count across all sources.
func (m *Manager) Counts() map[string]int {
	out := make(map[string]int)
	for _, s := range m.snapshot() {
		for k, v := range s.counts {
			out[k] += v
		}
	}
	return out
}

// CountsBySource returns (source -> object count) across all loaded sources.
func (m *Manager) CountsBySource() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]int, len(m.sources))
	for name, s := range m.sources {
		total := 0
		for _, v := range s.countsBySource {
			total += v
		}
		out[name] = total
	}
	return out
}

// LoadFromFiles is a test convenience: build a single source from the
// supplied paths and install it.
func (m *Manager) LoadFromFiles(ctx context.Context, source string, paths []string) error {
	wrapped := make([]SourceFile, 0, len(paths))
	for _, p := range paths {
		wrapped = append(wrapped, SourceFile{Source: source, Path: p, Changed: true})
	}
	_, err := m.Reload(ctx, wrapped, true)
	return err
}

// Reload rebuilds the per-source stores from `fetched`.
//
// Per-source isolation: files are grouped by `SourceFile.Source` and each
// source is processed independently. A source whose files all returned 304
// (Changed=false) and that already has a live sub-store is skipped — its
// existing sub-store remains in place. Only sources with at least one
// changed file (or that are not yet loaded) are rebuilt.
//
// Each rebuilt source is atomically swapped in as soon as it's done, and a
// GC + FreeOSMemory cycle is run between sources so the OS reclaims pages
// from the just-replaced old sub-store before the next rebuild starts.
//
// Returns true if at least one source was rebuilt.
func (m *Manager) Reload(ctx context.Context, fetched []SourceFile, forceRebuild bool) (bool, error) {
	bySource := map[string][]SourceFile{}
	sourceChanged := map[string]bool{}
	for _, f := range fetched {
		bySource[f.Source] = append(bySource[f.Source], f)
		if f.Changed {
			sourceChanged[f.Source] = true
		}
	}

	// Fast no-op path: if nothing changed AND every fetched source already
	// has a sub-store, there's no work to do.
	if !forceRebuild {
		needWork := false
		m.mu.RLock()
		for src := range bySource {
			if sourceChanged[src] {
				needWork = true
				break
			}
			if _, ok := m.sources[src]; !ok {
				needWork = true
				break
			}
		}
		m.mu.RUnlock()
		if !needWork {
			m.log.Debug("dbase reload skipped (no changes)")
			return false, nil
		}
	}

	rebuilt := false
	var firstErr error
	for source, files := range bySource {
		// Skip unchanged sources whose sub-store is already loaded.
		if !forceRebuild && !sourceChanged[source] {
			m.mu.RLock()
			_, alreadyLoaded := m.sources[source]
			m.mu.RUnlock()
			if alreadyLoaded {
				continue
			}
		}

		newSub := NewStore()
		count := 0
		var perr error
		for _, f := range files {
			err := Parse(ctx, f.Path, func(o *Object) error {
				newSub.Insert(o, source)
				count++
				return nil
			})
			if err != nil {
				perr = fmt.Errorf("%s/%s: %w", source, f.Class, err)
				break
			}
			m.log.Info("dbase file loaded",
				"source", source, "class", f.Class, "file_objects", count)
		}
		if perr != nil {
			if firstErr == nil {
				firstErr = perr
			}
			// Don't swap a partial sub-store; keep the old one in place.
			m.log.Warn("dbase source rebuild failed; old sub-store kept",
				"source", source, "err", perr)
			continue
		}

		// Atomic per-source swap.
		m.mu.Lock()
		m.sources[source] = newSub
		m.mu.Unlock()
		m.log.Info("dbase source swapped", "source", source, "objects", count)
		rebuilt = true

		// Give the runtime a chance to release the old sub-store back to
		// the OS before we start building the next one. Without this,
		// each new sub-store accumulates on top of the prior dead one and
		// peak RSS climbs across sources unnecessarily.
		runtime.GC()
		debug.FreeOSMemory()
	}

	if rebuilt {
		m.mu.Lock()
		m.lastReload = time.Now()
		m.mu.Unlock()
		// One final GC pass once everything is in place, so RSS settles
		// promptly rather than waiting for the next allocation cycle.
		runtime.GC()
		debug.FreeOSMemory()
	}
	if firstErr != nil && !rebuilt {
		return false, firstErr
	}
	return rebuilt, nil
}
