package log

import (
	"log/slog"
	"os"
	"strings"
)

// InitLogging configures the default slog logger for the lab tooling: a text
// handler on stderr at INFO by default, or DEBUG when verbose is set. The
// LOG env var (debug|info|warn|error) overrides the verbose flag. The
// timestamp is dropped to keep CLI output readable.
func InitLogging(verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	if l, ok := parseLevel(os.Getenv("LOG")); ok {
		level = l
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})))
}

func parseLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	}
	return 0, false
}
