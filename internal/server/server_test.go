package server

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hackman/One_Ring/internal/acl"
	"github.com/hackman/One_Ring/internal/ripe"
)

const seedRPSL = `inetnum:        192.0.2.0 - 192.0.2.255
netname:        TESTNET
admin-c:        TST1-RIPE
source:         RIPE

person:         Test Person
nic-hdl:        TST1-RIPE
source:         RIPE
`

func newTestManager(t *testing.T) *ripe.Manager {
	t.Helper()
	mgr := ripe.NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
	path := filepath.Join(t.TempDir(), "seed")
	if err := os.WriteFile(path, []byte(seedRPSL), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.LoadFromFiles(context.Background(), "ripe", []string{path}); err != nil {
		t.Fatal(err)
	}
	return mgr
}

func TestServerEndToEnd(t *testing.T) {
	mgr := newTestManager(t)
	tree := acl.New(acl.ActionAllow)

	// Pick a free port up front so the server binds before we connect.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := Config{
		Bind:          addr,
		ReadTimeout:   2 * time.Second,
		WriteTimeout:  2 * time.Second,
		MaxConcurrent: 4,
		MaxQueryBytes: 256,
	}
	s := New(cfg, mgr, tree, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Run(ctx)
	}()

	// Poll until the listener is up.
	var c net.Conn
	for i := 0; i < 50; i++ {
		c, err = net.Dial("tcp", addr)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if _, err := c.Write([]byte("192.0.2.42\r\n")); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(bufio.NewReader(c))
	resp := string(out)
	if !strings.Contains(resp, "TESTNET") {
		t.Fatalf("response missing TESTNET: %q", resp)
	}
	if !strings.Contains(resp, "Test Person") {
		t.Fatalf("response missing related person object: %q", resp)
	}
}
