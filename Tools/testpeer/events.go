// SPDX-License-Identifier: MIT

package main

import (
	"io"
	"log/slog"
	"strings"
	"time"
)

// Events is the structured event log. Every record is one line; with JSON
// output each line is a single object whose "event" field names the event.
// Callers must never pass secret material as an attribute.
type Events struct {
	log *slog.Logger
}

func parseLevel(s string) (slog.Level, bool) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, true
	case "info", "":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	}
	return slog.LevelInfo, false
}

func newEvents(w io.Writer, asJSON bool, level slog.Level) *Events {
	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) != 0 {
				return a
			}
			switch a.Key {
			case slog.TimeKey:
				return slog.String("ts", a.Value.Time().UTC().Format(time.RFC3339Nano))
			case slog.MessageKey:
				a.Key = "event"
			}
			return a
		},
	}
	var h slog.Handler
	if asJSON {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return &Events{log: slog.New(h)}
}

// Emit records an informational event.
func (e *Events) Emit(event string, attrs ...any) { e.log.Info(event, attrs...) }

// Debug records a debug-level event.
func (e *Events) Debug(event string, attrs ...any) { e.log.Debug(event, attrs...) }

// Warn records a warning event.
func (e *Events) Warn(event string, attrs ...any) { e.log.Warn(event, attrs...) }

// Error records an error event.
func (e *Events) Error(event string, attrs ...any) { e.log.Error(event, attrs...) }
