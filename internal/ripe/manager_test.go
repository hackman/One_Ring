package ripe

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

const fixtureA = `inetnum:        192.0.2.0 - 192.0.2.255
netname:        FIRST
source:         RIPE
`

const fixtureB = `inetnum:        192.0.2.0 - 192.0.2.255
netname:        SECOND
source:         RIPE
`

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestManager_ReloadSkipsWhenNothingChanged(t *testing.T) {
	mgr := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))

	pathA := writeTemp(t, "a", fixtureA)
	rebuilt, err := mgr.Reload(context.Background(),
		[]SourceFile{{Source: "ripe", Class: "inetnum", Path: pathA, Changed: true}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !rebuilt {
		t.Fatal("first load: expected rebuild")
	}
	got := mgr.Lookup("192.0.2.1")
	if len(got) == 0 || got[len(got)-1].Lookup("netname") != "FIRST" {
		t.Fatalf("first store contents: %v", got)
	}

	// Snapshot the per-source store pointer so we can detect (no) swap.
	mgr.mu.RLock()
	firstSub := mgr.sources["ripe"]
	mgr.mu.RUnlock()

	pathB := writeTemp(t, "b", fixtureB)
	rebuilt, err = mgr.Reload(context.Background(),
		[]SourceFile{{Source: "ripe", Class: "inetnum", Path: pathB, Changed: false}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt {
		t.Fatal("unchanged poll: expected no rebuild")
	}
	mgr.mu.RLock()
	stillFirst := mgr.sources["ripe"] == firstSub
	mgr.mu.RUnlock()
	if !stillFirst {
		t.Fatal("ripe sub-store should be the same pointer (no swap)")
	}

	rebuilt, err = mgr.Reload(context.Background(),
		[]SourceFile{{Source: "ripe", Class: "inetnum", Path: pathB, Changed: true}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !rebuilt {
		t.Fatal("changed poll: expected rebuild")
	}
	got = mgr.Lookup("192.0.2.1")
	if len(got) == 0 || got[len(got)-1].Lookup("netname") != "SECOND" {
		t.Fatalf("post-change store: %v", got)
	}
}

// TestManager_PerSourceIsolation verifies a changed source rebuilds without
// disturbing other sources' sub-stores.
func TestManager_PerSourceIsolation(t *testing.T) {
	mgr := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))

	const fixtureRipe = `inetnum:        192.0.2.0 - 192.0.2.255
netname:        RIPE-NET
source:         RIPE
`
	const fixtureApnic = `inetnum:        203.0.113.0 - 203.0.113.255
netname:        APNIC-NET
source:         APNIC
`
	const fixtureApnicV2 = `inetnum:        203.0.113.0 - 203.0.113.255
netname:        APNIC-NET-V2
source:         APNIC
`

	ripePath := writeTemp(t, "ripe", fixtureRipe)
	apnicPath := writeTemp(t, "apnic", fixtureApnic)

	// Initial load: both sources.
	_, err := mgr.Reload(context.Background(), []SourceFile{
		{Source: "ripe", Class: "inetnum", Path: ripePath, Changed: true},
		{Source: "apnic", Class: "inetnum", Path: apnicPath, Changed: true},
	}, true)
	if err != nil {
		t.Fatal(err)
	}

	mgr.mu.RLock()
	ripeBefore := mgr.sources["ripe"]
	apnicBefore := mgr.sources["apnic"]
	mgr.mu.RUnlock()

	// Second reload: only APNIC changed.
	apnicV2 := writeTemp(t, "apnic2", fixtureApnicV2)
	rebuilt, err := mgr.Reload(context.Background(), []SourceFile{
		{Source: "ripe", Class: "inetnum", Path: ripePath, Changed: false},
		{Source: "apnic", Class: "inetnum", Path: apnicV2, Changed: true},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !rebuilt {
		t.Fatal("expected APNIC to rebuild")
	}

	mgr.mu.RLock()
	ripeAfter := mgr.sources["ripe"]
	apnicAfter := mgr.sources["apnic"]
	mgr.mu.RUnlock()

	if ripeAfter != ripeBefore {
		t.Error("RIPE sub-store should NOT have been replaced (no change)")
	}
	if apnicAfter == apnicBefore {
		t.Error("APNIC sub-store should have been replaced (changed)")
	}

	// Verify the new content is live.
	objs := mgr.Lookup("203.0.113.5")
	if len(objs) == 0 || objs[0].Lookup("netname") != "APNIC-NET-V2" {
		t.Fatalf("expected APNIC-NET-V2, got %v", objs)
	}
	// RIPE space still answers.
	objs = mgr.Lookup("192.0.2.5")
	if len(objs) == 0 || objs[0].Lookup("netname") != "RIPE-NET" {
		t.Fatalf("expected RIPE-NET still live, got %v", objs)
	}
}
