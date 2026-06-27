package stats

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"
)

//go:embed assets/dashboard.html
var assetsFS embed.FS

// HTTPServer serves the dashboard HTML and the current stats JSON.
//
// Routes:
//
//	GET /              -> dashboard.html
//	GET /stats.json    -> the most recent snapshot (from Dumper.Last())
//
// The handler always serves the in-memory snapshot rather than reading
// stats.json from disk, so clients see consistent freshness even if the disk
// dump cadence is slow.
type HTTPServer struct {
	Bind   string
	Dumper *Dumper
	Log    *slog.Logger
}

func (s *HTTPServer) Run(ctx context.Context) error {
	indexBytes, err := fs.ReadFile(assetsFS, "assets/dashboard.html")
	if err != nil {
		return fmt.Errorf("load dashboard: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(indexBytes)
	})
	mux.HandleFunc("/stats.json", func(w http.ResponseWriter, r *http.Request) {
		buf := s.Dumper.Last()
		if buf == nil {
			// Generate one on demand if the dumper hasn't ticked yet.
			snap := s.Dumper.Snap()
			b, err := json.Marshal(snap)
			if err != nil {
				http.Error(w, "snapshot error", 500)
				return
			}
			buf = b
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write(buf)
	})

	srv := &http.Server{
		Addr:              s.Bind,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.Bind)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.Bind, err)
	}
	s.Log.Info("stats http listening", "bind", s.Bind)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

