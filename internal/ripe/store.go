package ripe

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
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
// Manager: load + atomic swap
// -----------------------------------------------------------------------------

// Manager owns the current Store and supports atomic reloads.
type Manager struct {
	mu         sync.RWMutex
	cur        *Store
	lastReload time.Time
	log        *slog.Logger
}

func NewManager(log *slog.Logger) *Manager {
	return &Manager{cur: NewStore(), log: log}
}

// Current returns the active Store. Callers may hold the returned pointer for
// the duration of one query.
func (m *Manager) Current() *Store {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cur
}

// LastReload reports when the active Store was constructed.
func (m *Manager) LastReload() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastReload
}

// IsEmpty reports whether the active Store has not been populated.
func (m *Manager) IsEmpty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cur.byKey) == 0
}

// LoadFromFiles is a convenience for tests: it builds a SourceFile list with
// Changed=true and force-rebuilds the store.
func (m *Manager) LoadFromFiles(ctx context.Context, source string, paths []string) error {
	wrapped := make([]SourceFile, 0, len(paths))
	for _, p := range paths {
		wrapped = append(wrapped, SourceFile{Source: source, Path: p, Changed: true})
	}
	_, err := m.Reload(ctx, wrapped, true)
	return err
}

// Reload (re)builds the Store from fetched files spanning one or more
// upstream sources.
//
// If forceRebuild is false and none of the files has Changed=true AND the
// manager already has a populated Store, this is a no-op and the returned
// bool is false. That lets the polling loop run cheaply when every upstream
// returns 304.
func (m *Manager) Reload(ctx context.Context, fetched []SourceFile, forceRebuild bool) (bool, error) {
	anyChanged := false
	for _, r := range fetched {
		if r.Changed {
			anyChanged = true
			break
		}
	}
	if !forceRebuild && !anyChanged && !m.IsEmpty() {
		m.log.Debug("dbase reload skipped (no changes)")
		return false, nil
	}

	s := NewStore()
	var (
		mu   sync.Mutex
		errs []error
		wg   sync.WaitGroup
		sem  = make(chan struct{}, 4)
	)
	for _, r := range fetched {
		r := r
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Stream parsed objects straight into the store. The earlier
			// version buffered a []*Object per file (~hundreds of thousands
			// of pointers, plus the unattached Object graph) before any
			// Insert ran — wasted 1-2 GiB of peak memory during reload on a
			// 5-DB load. Now each object is indexed and immediately
			// available for GC of any transient parse state.
			count := 0
			err := Parse(ctx, r.Path, func(o *Object) error {
				mu.Lock()
				s.Insert(o, r.Source)
				mu.Unlock()
				count++
				return nil
			})
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s/%s: %w", r.Source, r.Class, err))
				mu.Unlock()
				return
			}
			m.log.Info("dbase file loaded",
				"source", r.Source,
				"class", r.Class,
				"objects", count)
		}()
	}
	wg.Wait()
	if len(errs) > 0 {
		return false, errs[0]
	}
	m.mu.Lock()
	m.cur = s
	m.lastReload = time.Now()
	m.mu.Unlock()
	return true, nil
}
