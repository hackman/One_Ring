// Package logx defines the project's custom slog level for lifecycle
// events. The level sits above slog.LevelError so the messages survive any
// standard verbosity filter (debug / info / warn / error) — operators need
// to see "starting / bound / ready" regardless of how strict the log level
// is set.
//
// In the text handler the level prints as "NOTICE" instead of an awkward
// "ERROR+4". main.go installs a ReplaceAttr that handles the rename.
package logx

import (
	"context"
	"log/slog"
)

// LevelNotice is reserved for the small set of lifecycle events that must
// always be emitted. Use sparingly — anything routine belongs at Info.
const LevelNotice slog.Level = 12

// Notice logs a lifecycle event on the given logger at LevelNotice. Safe to
// call with a nil logger (no-op).
func Notice(logger *slog.Logger, msg string, args ...any) {
	if logger == nil {
		return
	}
	logger.Log(context.Background(), LevelNotice, msg, args...)
}
