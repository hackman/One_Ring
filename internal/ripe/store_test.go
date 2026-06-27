package ripe

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func TestRangeToCIDRs_ExactCIDR(t *testing.T) {
	out := rangeToCIDRs(mustAddr(t, "192.0.2.0"), mustAddr(t, "192.0.2.255"))
	if len(out) != 1 || out[0].String() != "192.0.2.0/24" {
		t.Errorf("got %v", out)
	}
}

func TestRangeToCIDRs_NonAligned(t *testing.T) {
	out := rangeToCIDRs(mustAddr(t, "192.0.2.5"), mustAddr(t, "192.0.2.10"))
	// 192.0.2.5..10 = .5/32, .6/31, .8/31, .10/32
	want := []string{"192.0.2.5/32", "192.0.2.6/31", "192.0.2.8/31", "192.0.2.10/32"}
	if len(out) != len(want) {
		t.Fatalf("got %v want %v", out, want)
	}
	for i := range want {
		if out[i].String() != want[i] {
			t.Errorf("idx %d: got %s want %s", i, out[i], want[i])
		}
	}
}

func TestRangeToCIDRs_FullV4(t *testing.T) {
	out := rangeToCIDRs(mustAddr(t, "0.0.0.0"), mustAddr(t, "255.255.255.255"))
	if len(out) != 1 || out[0].String() != "0.0.0.0/0" {
		t.Errorf("got %v", out)
	}
}

const fixtureRIPE = `inetnum:        10.0.0.0 - 10.255.255.255
netname:        BIG
source:         RIPE

inetnum:        10.1.0.0 - 10.1.255.255
netname:        SMALL
source:         RIPE

aut-num:        AS65000
as-name:        TEST-AS
source:         RIPE

person:         Jane Doe
nic-hdl:        JD1-RIPE
source:         RIPE
`

func TestStoreLookup(t *testing.T) {
	s := NewStore()
	err := parseStream(context.Background(), strings.NewReader(fixtureRIPE), func(o *Object) error {
		s.Insert(o, "ripe")
		return nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// IP lookup returns both, most-specific last
	objs := s.Lookup("10.1.2.3")
	if len(objs) != 2 {
		t.Fatalf("want 2 objects, got %d", len(objs))
	}
	if objs[len(objs)-1].Lookup("netname") != "SMALL" {
		t.Errorf("most-specific should be SMALL, got %q", objs[len(objs)-1].Lookup("netname"))
	}

	// outside both ranges
	if got := s.Lookup("11.0.0.1"); got != nil {
		t.Errorf("expected no match, got %v", got)
	}

	// AS number
	got := s.Lookup("AS65000")
	if len(got) != 1 || got[0].PrimaryKey != "AS65000" {
		t.Errorf("AS lookup: %v", got)
	}

	// nic-hdl
	got = s.Lookup("JD1-RIPE")
	if len(got) != 1 || got[0].Class != "person" {
		t.Errorf("nic-hdl lookup: %v", got)
	}
}
