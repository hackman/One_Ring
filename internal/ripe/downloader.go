package ripe

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SourceFile is the per-file outcome of downloading from one Source.
type SourceFile struct {
	Source  string // Source.Name this file belongs to
	Class   string // RPSL class — empty when Source.Format is FormatSingle
	Path    string // local path to the .gz file
	Changed bool   // true if the server returned a fresh body, false on 304
}

// Downloader fetches RPSL DB files in parallel and caches them to disk per
// source. It uses If-Modified-Since to avoid re-downloading unchanged files.
type Downloader struct {
	CacheDir string
	Client   *http.Client
	Log      *slog.Logger
}

func NewDownloader(cacheDir string, log *slog.Logger) *Downloader {
	return &Downloader{
		CacheDir: cacheDir,
		Client: &http.Client{
			Timeout: 30 * time.Minute,
		},
		Log: log,
	}
}

// FetchAll downloads every file from every enabled source concurrently.
func (d *Downloader) FetchAll(ctx context.Context, sources []Source) ([]SourceFile, error) {
	if err := os.MkdirAll(d.CacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir cache: %w", err)
	}

	// Plan all fetches up front so we can parallelize across sources too.
	type plannedFetch struct {
		src  string
		dir  string
		spec FileSpec
	}
	var plan []plannedFetch
	for _, s := range sources {
		if !s.Enabled {
			continue
		}
		files, err := s.Files()
		if err != nil {
			return nil, err
		}
		dir := filepath.Join(d.CacheDir, s.Name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
		for _, f := range files {
			plan = append(plan, plannedFetch{src: s.Name, dir: dir, spec: f})
		}
	}

	type slot struct {
		idx int
		sf  SourceFile
		err error
	}
	results := make(chan slot, len(plan))

	// Bound parallelism per host more tightly than overall. RIRs aren't
	// always happy about parallel downloads. 6 concurrent is courteous.
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, p := range plan {
		i, p := i, p
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			dst := filepath.Join(p.dir, p.spec.LocalName)
			changed, err := d.fetchURL(ctx, p.spec.URL, dst)
			if err != nil {
				results <- slot{idx: i, err: err}
				return
			}
			results <- slot{
				idx: i,
				sf:  SourceFile{Source: p.src, Class: p.spec.Class, Path: dst, Changed: changed},
			}
		}()
	}
	go func() { wg.Wait(); close(results) }()

	out := make([]SourceFile, 0, len(plan))
	var firstErr error
	for r := range results {
		if r.err != nil {
			p := plan[r.idx]
			d.Log.Warn("dbase download failed", "src", p.src, "url", p.spec.URL, "err", r.err)
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		out = append(out, r.sf)
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// fetchURL fetches url to dst, honoring If-Modified-Since against the cached
// file's mtime. Returns whether the local file was actually replaced.
func (d *Downloader) fetchURL(ctx context.Context, url, dst string) (changed bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	if fi, err := os.Stat(dst); err == nil {
		req.Header.Set("If-Modified-Since", fi.ModTime().UTC().Format(http.TimeFormat))
	}

	resp, err := d.Client.Do(req)
	if err != nil {
		return false, fmt.Errorf("get %s: %w", url, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		d.Log.Debug("dbase cache hit", "url", url)
		return false, nil
	case http.StatusOK:
	default:
		return false, fmt.Errorf("get %s: %s", url, resp.Status)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".*.tmp")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	n, err := io.Copy(tmp, resp.Body)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		cleanup()
		return false, fmt.Errorf("write %s: %w", dst, err)
	}

	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if t, perr := http.ParseTime(lm); perr == nil {
			_ = os.Chtimes(tmpName, t, t)
		}
	}
	if err := os.Rename(tmpName, dst); err != nil {
		cleanup()
		return false, err
	}
	d.Log.Info("dbase downloaded", "url", url, "bytes", n)
	return true, nil
}
