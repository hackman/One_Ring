package main

// SIGHUP-triggered configuration reload.
//
// Reloadable fields (everything else requires a restart):
//   - acl.*                  → swap the BERT pointer atomically
//   - rate_limit.*           → swap the limiter pointer atomically (incl.
//                              toggling between enabled/disabled)
//   - log.level              → adjust the slog.LevelVar in place
//   - stats.dump_interval    → nudge the Dumper to reset its ticker
//   - server.bind            → open a new listener, then close the old one
//
// Each sub-step is independent: if rebuilding the ACL fails, the limiter
// reload still runs (and vice versa). The reload is logged at NOTICE so it
// survives any log.level — including the new level the operator just set.

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"context"

	"github.com/hackman/One_Ring/internal/config"
	"github.com/hackman/One_Ring/internal/logx"
	"github.com/hackman/One_Ring/internal/server"
	"github.com/hackman/One_Ring/internal/stats"
)

// pidFilePaths are tried in order when locating the running pid. The first
// one that exists wins. Match this list to whatever your packaging uses.
var pidFilePaths = []string{
	"/run/whoisd.pid",
	"/var/run/whoisd.pid",
	"/var/whoisd/whoisd.pid",
	"/tmp/whoisd.pid",
}

// writePidFile writes the current process id to the first pid file path
// whose parent directory exists and is writable. Returns nil if no
// writable location is found — we keep running without one in that case.
func writePidFile() error {
	for _, p := range pidFilePaths {
		dir := filepath.Dir(p)
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			if err := os.WriteFile(p, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("no writable pid file location (tried %v)", pidFilePaths)
}

func removePidFile() {
	for _, p := range pidFilePaths {
		if data, err := os.ReadFile(p); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				if pid == os.Getpid() {
					_ = os.Remove(p)
					return
				}
			}
		}
	}
}

// sendReload looks up the running whoisd pid (via one of pidFilePaths) and
// sends SIGHUP to it. Called from the CLI when -r/--reload is passed.
func sendReload() error {
	for _, p := range pidFilePaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			return fmt.Errorf("%s: malformed pid: %w", p, err)
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("pid %d: %w", pid, err)
		}
		if err := proc.Signal(syscall.SIGHUP); err != nil {
			return fmt.Errorf("kill -HUP %d: %w", pid, err)
		}
		fmt.Printf("sent SIGHUP to pid %d (%s)\n", pid, p)
		return nil
	}
	return fmt.Errorf("no pid file found; tried %v", pidFilePaths)
}

// reloadLoop waits for SIGHUP and applies the reloadable subset of the
// configuration file. Runs until ctx is cancelled.
func reloadLoop(
	ctx context.Context,
	cfgPath string,
	logger *slog.Logger,
	levelVar *slog.LevelVar,
	srv *server.Server,
	dumper *stats.Dumper, // may be nil if stats disabled at startup
) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			applyReload(cfgPath, logger, levelVar, srv, dumper)
		}
	}
}

// applyReload reads the config file and applies the reloadable subset. Each
// sub-step is independent — a failure in one does not skip the others.
func applyReload(
	cfgPath string,
	logger *slog.Logger,
	levelVar *slog.LevelVar,
	srv *server.Server,
	dumper *stats.Dumper,
) {
	logx.Notice(logger, "reload requested", "path", cfgPath)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		logger.Error("reload: parse failed; keeping previous config", "err", err)
		return
	}

	// ACL
	if newACL, err := buildACL(cfg.ACL); err != nil {
		logger.Error("reload: acl build failed; keeping previous", "err", err)
	} else {
		srv.SetACL(newACL)
		logger.Info("reload: acl swapped",
			"default", cfg.ACL.Default,
			"allow_count", len(cfg.ACL.Allow),
			"deny_count", len(cfg.ACL.Deny),
		)
	}

	// Rate limiter
	if cfg.RateLimit.Enabled {
		srv.SetLimiter(buildLimiter(cfg.RateLimit))
		logger.Info("reload: rate limiter swapped",
			"rps", cfg.RateLimit.RPS,
			"burst", cfg.RateLimit.Burst,
		)
	} else {
		srv.SetLimiter(nil)
		logger.Info("reload: rate limiter disabled")
	}

	// log.level
	setLevelVar(levelVar, cfg.Log.Level)
	logger.Info("reload: log level changed", "level", cfg.Log.Level)

	// stats.dump_interval
	if dumper != nil && cfg.Stats.DumpInterval > 0 {
		dumper.SetInterval(cfg.Stats.DumpInterval)
	}

	// server.bind
	if cfg.Server.Bind != "" && cfg.Server.Bind != srv.BindAddr() {
		if err := srv.Rebind(cfg.Server.Bind); err != nil {
			logger.Error("reload: rebind failed; old listener still active",
				"want", cfg.Server.Bind, "err", err)
		}
	}

	logx.Notice(logger, "reload complete", "path", cfgPath)
}
