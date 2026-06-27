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
	first := mgr.Current()
	got := first.Lookup("192.0.2.1")
	if len(got) == 0 || got[len(got)-1].Lookup("netname") != "FIRST" {
		t.Fatalf("first store contents: %v", got)
	}

	pathB := writeTemp(t, "b", fixtureB)
	rebuilt, err = mgr.Reload(context.Background(),
		[]SourceFile{{Source: "ripe", Class: "inetnum", Path: pathB, Changed: false}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt {
		t.Fatal("unchanged poll: expected no rebuild")
	}
	if mgr.Current() != first {
		t.Fatal("store should be the same pointer (no swap)")
	}

	rebuilt, err = mgr.Reload(context.Background(),
		[]SourceFile{{Source: "ripe", Class: "inetnum", Path: pathB, Changed: true}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !rebuilt {
		t.Fatal("changed poll: expected rebuild")
	}
	got = mgr.Current().Lookup("192.0.2.1")
	if len(got) == 0 || got[len(got)-1].Lookup("netname") != "SECOND" {
		t.Fatalf("post-change store: %v", got)
	}
}
