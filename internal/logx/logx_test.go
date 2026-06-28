package logx

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestNoticeSurvivesEveryLevel proves that records emitted via Notice() pass
// the standard slog filters at warn and error — the whole point of having a
// custom level above slog.LevelError.
func TestNoticeSurvivesEveryLevel(t *testing.T) {
	for _, filter := range []slog.Level{
		slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError,
	} {
		var buf bytes.Buffer
		opts := &slog.HandlerOptions{
			Level: filter,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.LevelKey {
					if lv, ok := a.Value.Any().(slog.Level); ok && lv == LevelNotice {
						a.Value = slog.StringValue("NOTICE")
					}
				}
				return a
			},
		}
		l := slog.New(slog.NewTextHandler(&buf, opts))
		Notice(l, "starting", "version", "1.0")
		out := buf.String()
		if !strings.Contains(out, "NOTICE") {
			t.Errorf("filter=%v: notice not rendered with NOTICE label: %q", filter, out)
		}
		if !strings.Contains(out, "starting") {
			t.Errorf("filter=%v: notice message dropped: %q", filter, out)
		}
	}
}

func TestNoticeIsAboveError(t *testing.T) {
	if LevelNotice <= slog.LevelError {
		t.Fatalf("LevelNotice (%d) must be > slog.LevelError (%d)",
			LevelNotice, slog.LevelError)
	}
}

func TestNoticeNilLoggerIsNoop(t *testing.T) {
	// Should not panic.
	Notice(nil, "ignored")
}
