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

func TestServer_Rebind(t *testing.T) {
	mgr := newTestManager(t)
	tree := acl.New(acl.ActionAllow)

	// Pick two free ports up front.
	pick := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		return addr
	}
	addr1 := pick()
	addr2 := pick()

	cfg := Config{
		Bind:          addr1,
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

	// Wait for the first listener to come up.
	for i := 0; i < 50; i++ {
		c, err := net.Dial("tcp", addr1)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := s.BindAddr(); got != addr1 {
		t.Fatalf("BindAddr=%q want %q", got, addr1)
	}

	// Rebind.
	if err := s.Rebind(addr2); err != nil {
		t.Fatalf("Rebind: %v", err)
	}
	if got := s.BindAddr(); got != addr2 {
		t.Fatalf("after rebind BindAddr=%q want %q", got, addr2)
	}

	// Query through the new listener — must work end-to-end.
	var c net.Conn
	var err error
	for i := 0; i < 50; i++ {
		c, err = net.Dial("tcp", addr2)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial after rebind: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("192.0.2.42\r\n")); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(bufio.NewReader(c))
	if !strings.Contains(string(out), "TESTNET") {
		t.Fatalf("response missing TESTNET after rebind: %q", out)
	}

	// Old address should no longer accept (connection refused or reset).
	if c, err := net.DialTimeout("tcp", addr1, 200*time.Millisecond); err == nil {
		c.Close()
		t.Errorf("old listener at %s still accepts connections", addr1)
	}
}
