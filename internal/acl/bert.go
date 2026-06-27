// Package acl implements IP-prefix matching using a Binary Encoded Radix Tree
// (BERT). Conceptually it is a Patricia trie keyed on the canonical 128-bit
// representation of an IP address: IPv4 addresses are stored under the
// IPv4-mapped-IPv6 prefix (::ffff:0:0/96) so a single tree handles both
// families.
//
// Lookups are O(prefix-length-in-bits) and lock-free for readers when the tree
// is constructed once at startup. The "longest matching prefix" wins, which is
// what you want for ACLs that mix broad ranges with surgical exceptions.
package acl

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Action is the value stored on a matching prefix.
type Action uint8

const (
	ActionNone Action = iota
	ActionAllow
	ActionDeny
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionDeny:
		return "deny"
	default:
		return "none"
	}
}

// BERT is a binary radix tree keyed on the 128-bit canonical address form.
// Both IPv4 and IPv6 entries coexist; IPv4 is stored as IPv4-mapped IPv6.
type BERT struct {
	root *node
	// defaultAction is returned when no prefix matches.
	defaultAction Action
}

type node struct {
	// children[0] = the "0" bit branch, children[1] = the "1" bit branch.
	children [2]*node
	// action is ActionNone unless a prefix terminates at this node.
	action Action
	// depth (in bits, 0..128) of the prefix terminating here. Only meaningful
	// when action != ActionNone.
	depth uint8
}

// New constructs an empty tree.
func New(defaultAction Action) *BERT {
	return &BERT{root: &node{}, defaultAction: defaultAction}
}

// Insert adds a prefix with the given action. Later inserts at the same prefix
// overwrite earlier ones.
func (b *BERT) Insert(prefix netip.Prefix, action Action) error {
	if !prefix.IsValid() {
		return fmt.Errorf("invalid prefix: %v", prefix)
	}
	bits, depth := canonicalBits(prefix)
	n := b.root
	for i := uint8(0); i < depth; i++ {
		bit := bitAt(bits, i)
		if n.children[bit] == nil {
			n.children[bit] = &node{}
		}
		n = n.children[bit]
	}
	n.action = action
	n.depth = depth
	return nil
}

// Match returns the action associated with the longest prefix that contains
// addr, or the tree's default action when no prefix matches.
func (b *BERT) Match(addr netip.Addr) Action {
	if !addr.IsValid() {
		return b.defaultAction
	}
	bits := canonicalAddrBits(addr)
	n := b.root
	best := ActionNone
	if n.action != ActionNone {
		best = n.action
	}
	for i := uint8(0); i < 128; i++ {
		bit := bitAt(bits, i)
		c := n.children[bit]
		if c == nil {
			break
		}
		n = c
		if n.action != ActionNone {
			best = n.action
		}
	}
	if best == ActionNone {
		return b.defaultAction
	}
	return best
}

// MatchString is a convenience wrapper for Match that parses addr first.
func (b *BERT) MatchString(addr string) Action {
	// strip [::1] style brackets, drop port suffixes
	addr = strings.TrimPrefix(addr, "[")
	if i := strings.LastIndex(addr, "]"); i >= 0 {
		addr = addr[:i]
	}
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return b.Match(ap.Addr())
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return b.defaultAction
	}
	return b.Match(a)
}

// LoadCIDRs is a helper to bulk-insert prefixes with the same action.
func (b *BERT) LoadCIDRs(cidrs []string, action Action) error {
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			// Allow bare IPs to mean /32 or /128.
			a, err2 := netip.ParseAddr(c)
			if err2 != nil {
				return fmt.Errorf("parse %q: %w", c, err)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if err := b.Insert(p, action); err != nil {
			return err
		}
	}
	return nil
}

// canonicalBits returns the 128-bit big-endian byte representation of the
// prefix's masked address along with the prefix length in bits (already
// adjusted for IPv4 -> IPv4-mapped-IPv6).
func canonicalBits(p netip.Prefix) ([16]byte, uint8) {
	a := p.Masked().Addr()
	if a.Is4() {
		// Convert "1.2.3.0/24" -> "::ffff:1.2.3.0/120"
		a = netip.AddrFrom16(a.As16())
		return a.As16(), uint8(p.Bits()) + 96
	}
	return a.As16(), uint8(p.Bits())
}

func canonicalAddrBits(a netip.Addr) [16]byte {
	if a.Is4() {
		return netip.AddrFrom16(a.As16()).As16()
	}
	return a.As16()
}

func bitAt(b [16]byte, i uint8) uint8 {
	return (b[i>>3] >> (7 - (i & 7))) & 1
}

// CIDRFromIPNet is a convenience for callers that still hold net.IPNet values.
func CIDRFromIPNet(n *net.IPNet) (netip.Prefix, error) {
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("bad IP %v", n.IP)
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(a.Unmap(), ones), nil
}
