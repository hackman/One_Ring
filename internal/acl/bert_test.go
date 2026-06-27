package acl

import (
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return p
}

func TestBERT_LongestMatchWins(t *testing.T) {
	b := New(ActionDeny)
	if err := b.Insert(mustPrefix(t, "10.0.0.0/8"), ActionAllow); err != nil {
		t.Fatal(err)
	}
	if err := b.Insert(mustPrefix(t, "10.1.2.0/24"), ActionDeny); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		addr string
		want Action
	}{
		{"10.5.5.5", ActionAllow},
		{"10.1.2.42", ActionDeny},
		{"11.0.0.1", ActionDeny}, // falls through to tree default
	}
	for _, c := range cases {
		got := b.MatchString(c.addr)
		if got != c.want {
			t.Errorf("Match(%s)=%v want %v", c.addr, got, c.want)
		}
	}
}

func TestBERT_V4AndV6Coexist(t *testing.T) {
	b := New(ActionDeny)
	_ = b.Insert(mustPrefix(t, "127.0.0.0/8"), ActionAllow)
	_ = b.Insert(mustPrefix(t, "::1/128"), ActionAllow)
	_ = b.Insert(mustPrefix(t, "2001:db8::/32"), ActionAllow)

	if got := b.MatchString("127.0.0.1"); got != ActionAllow {
		t.Errorf("v4 loopback got %v", got)
	}
	if got := b.MatchString("::1"); got != ActionAllow {
		t.Errorf("v6 loopback got %v", got)
	}
	if got := b.MatchString("2001:db8:1234::1"); got != ActionAllow {
		t.Errorf("v6 doc range got %v", got)
	}
	if got := b.MatchString("8.8.8.8"); got != ActionDeny {
		t.Errorf("public v4 got %v", got)
	}
}

func TestBERT_DefaultAction(t *testing.T) {
	b := New(ActionAllow)
	if got := b.MatchString("1.1.1.1"); got != ActionAllow {
		t.Errorf("empty tree default got %v", got)
	}
}

func TestBERT_BareIP(t *testing.T) {
	b := New(ActionDeny)
	if err := b.LoadCIDRs([]string{"203.0.113.5", "203.0.113.0/24"}, ActionAllow); err != nil {
		t.Fatal(err)
	}
	if got := b.MatchString("203.0.113.5"); got != ActionAllow {
		t.Errorf("/32 got %v", got)
	}
	if got := b.MatchString("203.0.113.99"); got != ActionAllow {
		t.Errorf("/24 got %v", got)
	}
}
