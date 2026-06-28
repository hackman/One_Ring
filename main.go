package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/hackman/One_Ring/internal/acl"
	"github.com/hackman/One_Ring/internal/config"
	"github.com/hackman/One_Ring/internal/logx"
	"github.com/hackman/One_Ring/internal/ratelimit"
	"github.com/hackman/One_Ring/internal/ripe"
	"github.com/hackman/One_Ring/internal/server"
	"github.com/hackman/One_Ring/internal/stats"
)

func main() {
	var (
		cfgPath     string
		helpFlag    bool
		versionFlag bool
		statsFlag   bool
	)
	const defaultCfgPath = "/etc/whoisd.yaml"
	flag.StringVar(&cfgPath, "c", defaultCfgPath, "path to YAML config")
	flag.StringVar(&cfgPath, "config", defaultCfgPath, "path to YAML config")
	flag.BoolVar(&helpFlag, "h", false, "show this help and exit")
	flag.BoolVar(&helpFlag, "help", false, "show this help and exit")
	flag.BoolVar(&versionFlag, "v", false, "print version and exit")
	flag.BoolVar(&versionFlag, "version", false, "print version and exit")
	flag.BoolVar(&statsFlag, "s", false, "fetch live status from the running server and print it")
	flag.BoolVar(&statsFlag, "stats", false, "fetch live status from the running server and print it")

	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintf(out, "One Ring - whoisd %s. A multi-RIR WHOIS server that merges RIPE, ARIN, APNIC, LACNIC, AFRINIC DBs.\n", Version)
		fmt.Fprintf(out, "Usage:\n  %s [flags]\n\n", os.Args[0])
		fmt.Fprintf(out, "Flags:\n")
		fmt.Fprintf(out, "  -c, --config <path>   path to YAML config (default %q)\n", defaultCfgPath)
		fmt.Fprintf(out, "  -s, --stats           fetch live status from the running server and print it\n")
		fmt.Fprintf(out, "  -v, --version         print version and exit\n")
		fmt.Fprintf(out, "  -h, --help            show this help and exit\n\n")
		fmt.Fprintf(out, "Project:  https://github.com/hackman/One_Ring\n")
	}

	flag.Parse()

	if helpFlag {
		flag.Usage()
		return
	}
	if versionFlag {
		fmt.Printf("One Ring — whoisd %s\n", Version)
		return
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(2)
	}

	if statsFlag {
		if err := runStatsCLI(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "stats: %v\n", err)
			os.Exit(1)
		}
		return
	}

	logger := newLogger(cfg.Log.Level)
	logx.Notice(logger, "whoisd starting",
		"version", Version,
		"cores", runtime.GOMAXPROCS(0),
		"bind", cfg.Server.Bind,
		"sources", len(cfg.Dbase.Sources),
	)

	tree, err := buildACL(cfg.ACL)
	if err != nil {
		logger.Error("acl build failed", "err", err)
		os.Exit(2)
	}

	var lim *ratelimit.Limiter
	if cfg.RateLimit.Enabled {
		lim = ratelimit.New(ratelimit.Config{
			RPS:      cfg.RateLimit.RPS,
			Burst:    cfg.RateLimit.Burst,
			V4Prefix: cfg.RateLimit.V4Prefix,
			V6Prefix: cfg.RateLimit.V6Prefix,
			IdleTTL:  cfg.RateLimit.IdleTTL,
		})
	}

	manager := ripe.NewManager(logger)
	registry := stats.NewRegistry()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if _, err := refresh(ctx, cfg, manager, logger); err != nil {
		logger.Error("initial dbase load failed", "err", err)
		os.Exit(1)
	}
	go refreshLoop(ctx, cfg, manager, logger)

	if cfg.Stats.Enabled {
		dumper := &stats.Dumper{
			Path:     cfg.Stats.DumpPath,
			Interval: cfg.Stats.DumpInterval,
			Log:      logger,
			Snap: func() *stats.Snapshot {
				return registry.Snapshot(func(s *stats.Snapshot) {
					if t := manager.LastReload(); !t.IsZero() {
						s.RIPELoaded = t.UTC().Format(time.RFC3339)
					}
					s.RIPEClasses = manager.Current().Counts()
					s.SourceCounts = manager.Current().CountsBySource()
				})
			},
		}
		go func() {
			if err := dumper.Run(ctx); err != nil {
				logger.Error("stats dumper stopped", "err", err)
			}
		}()
		if cfg.Stats.HTTPBind != "" {
			httpSrv := &stats.HTTPServer{Bind: cfg.Stats.HTTPBind, Dumper: dumper, Log: logger}
			go func() {
				if err := httpSrv.Run(ctx); err != nil {
					logger.Error("stats http stopped", "err", err)
				}
			}()
		}
	}

	srv := server.New(server.Config{
		Bind:          cfg.Server.Bind,
		ReadTimeout:   cfg.Server.ReadTimeout,
		WriteTimeout:  cfg.Server.WriteTimeout,
		MaxConcurrent: cfg.Server.MaxConcurrent,
		MaxQueryBytes: cfg.Server.MaxQueryBytes,
	}, manager, tree, lim, statsOrNil(cfg.Stats.Enabled, registry), logger)

	if err := srv.Run(ctx); err != nil {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
	logger.Info("whoisd stopped")
}

func statsOrNil(enabled bool, r *stats.Registry) *stats.Registry {
	if !enabled {
		return nil
	}
	return r
}

// Version is bumped manually and intentionally uses a two-number scheme
// (MAJOR.MINOR). May be overridden at build time via
// `-ldflags "-X main.Version=1.2"`.
var Version = "1.0"

func newLogger(level string) *slog.Logger {
	// "none" disables logging entirely by sending records to io.Discard at
	// the highest possible severity so no record is ever emitted.
	if level == "none" || level == "off" || level == "silent" {
		h := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.Level(127)})
		return slog.New(h)
	}
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{
		Level: lvl,
		// Rename logx.LevelNotice to the human label "NOTICE" — slog's
		// default formatter would otherwise print "ERROR+4".
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.LevelKey {
				if lv, ok := a.Value.Any().(slog.Level); ok && lv == logx.LevelNotice {
					a.Value = slog.StringValue("NOTICE")
				}
			}
			return a
		},
	}
	h := slog.NewTextHandler(os.Stderr, opts)
	return slog.New(h)
}

func buildACL(c config.ACLConfig) (*acl.BERT, error) {
	def := acl.ActionAllow
	if c.Default == "deny" {
		def = acl.ActionDeny
	}
	t := acl.New(def)
	for _, p := range []string{"127.0.0.0/8", "::1/128"} {
		_ = t.Insert(mustPrefix(p), acl.ActionAllow)
	}
	if err := t.LoadCIDRs(c.Allow, acl.ActionAllow); err != nil {
		return nil, fmt.Errorf("allow list: %w", err)
	}
	if err := t.LoadCIDRs(c.Deny, acl.ActionDeny); err != nil {
		return nil, fmt.Errorf("deny list: %w", err)
	}
	return t, nil
}

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

// configSourcesToRIPE projects YAML config entries into ripe.Source values.
func configSourcesToRIPE(cs []config.SourceConfig) []ripe.Source {
	out := make([]ripe.Source, 0, len(cs))
	for _, s := range cs {
		out = append(out, ripe.Source{
			Name:    s.Name,
			Enabled: s.Enabled,
			Format:  ripe.Format(s.Format),
			URL:     s.URL,
			DBName:  s.DBName,
			Classes: s.Classes,
		})
	}
	return out
}

func refresh(ctx context.Context, cfg *config.Config, mgr *ripe.Manager, log *slog.Logger) (bool, error) {
	t0 := time.Now()
	dl := ripe.NewDownloader(cfg.Dbase.CacheDir, log)
	fetched, err := dl.FetchAll(ctx, configSourcesToRIPE(cfg.Dbase.Sources))
	if err != nil {
		return false, err
	}
	changed := 0
	for _, r := range fetched {
		if r.Changed {
			changed++
		}
	}
	rebuilt, err := mgr.Reload(ctx, fetched, mgr.IsEmpty())
	if err != nil {
		return false, err
	}
	if rebuilt {
		logx.Notice(log, "dbase ready",
			"elapsed", time.Since(t0),
			"changed_files", changed,
			"total_files", len(fetched),
			"per_source", mgr.Current().CountsBySource(),
		)
	} else {
		log.Info("dbase poll: no changes",
			"elapsed", time.Since(t0),
			"checked", len(fetched),
		)
	}
	return rebuilt, nil
}

func nextRefresh(now time.Time, cfg *config.Config, lastErr error) time.Time {
	if lastErr != nil {
		return now.Add(cfg.Dbase.RetryOnFailure)
	}
	candidate := now.Add(cfg.Dbase.PollInterval)
	if cfg.Dbase.DailyAt != "" {
		if d, err := config.ParseDailyAt(cfg.Dbase.DailyAt); err == nil {
			anchor := d.Next(now)
			if anchor.Before(candidate) {
				candidate = anchor
			}
		}
	}
	return candidate
}

func refreshLoop(ctx context.Context, cfg *config.Config, mgr *ripe.Manager, log *slog.Logger) {
	var lastErr error
	for {
		when := nextRefresh(time.Now(), cfg, lastErr)
		wait := time.Until(when)
		if wait < 0 {
			wait = 0
		}
		log.Info("dbase next refresh scheduled", "at", when.UTC().Format(time.RFC3339), "in", wait.Round(time.Second))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if _, err := refresh(ctx, cfg, mgr, log); err != nil {
			log.Warn("dbase refresh failed", "err", err)
			lastErr = err
		} else {
			lastErr = nil
		}
	}
}
