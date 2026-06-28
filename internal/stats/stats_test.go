package stats

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRegistry_OpenSnapshotClose(t *testing.T) {
	r := NewRegistry()
	c1 := r.Open("203.0.113.5")
	c1.SetQuery("AS3333")
	c1.SetState(StateWriting)
	c1.AddBytesOut(2048)

	snap := r.Snapshot(nil)
	if len(snap.Live) != 1 {
		t.Fatalf("want 1 live, got %d", len(snap.Live))
	}
	if snap.Live[0].Query != "AS3333" {
		t.Errorf("query = %q", snap.Live[0].Query)
	}
	if snap.Live[0].BytesOut != 2048 {
		t.Errorf("bytes_out = %d", snap.Live[0].BytesOut)
	}

	r.Close(c1, "hit")
	snap = r.Snapshot(nil)
	if len(snap.Live) != 0 {
		t.Errorf("want 0 live after close, got %d", len(snap.Live))
	}
	if snap.Counters.QueriesHit != 1 {
		t.Errorf("hit counter = %d", snap.Counters.QueriesHit)
	}
	if snap.Counters.BytesOut != 2048 {
		t.Errorf("bytes_out total = %d", snap.Counters.BytesOut)
	}
}

func TestSnapshot_JSONShape(t *testing.T) {
	r := NewRegistry()
	c := r.Open("127.0.0.1")
	c.SetQuery("test")
	snap := r.Snapshot(nil)
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	// just smoke-test that all the fields land
	for _, want := range []string{
		`"generated_at"`, `"started_at"`, `"uptime_s"`,
		`"live"`, `"counters"`, `"recent_qps"`,
		`"queries_total"`, `"bytes_in"`, `"bytes_out"`,
		`"current_live"`,
	} {
		if !contains(string(b), want) {
			t.Errorf("snapshot json missing %s\n--\n%s", want, string(b))
		}
	}
}

func TestRing_LastSecond(t *testing.T) {
	r := &ringCounter{}
	now := time.Unix(2000, 0)
	// 4 events at sec-1
	for i := 0; i < 4; i++ {
		r.tick(now.Add(-time.Second))
	}
	// 1 event in the CURRENT second — must NOT be counted by LastSecond.
	r.tick(now)
	if got := r.LastSecond(now); got != 4 {
		t.Errorf("LastSecond=%d want 4", got)
	}
}

func TestRing_DropsToZeroAfterTrafficStops(t *testing.T) {
	r := &ringCounter{}
	t0 := time.Unix(3000, 0)
	for i := 0; i < 10; i++ {
		r.tick(t0)
	}
	// Several seconds later — the previous-second bucket must read zero;
	// no decay, no leftover smear.
	now := t0.Add(6 * time.Second)
	if got := r.LastSecond(now); got != 0 {
		t.Errorf("LastSecond after silence=%d want 0", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
