// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package logging installs one process-wide logger for a Galactic binary. The
// same slog handler backs slog's default logger, the standard log package,
// controller-runtime's logger and klog, so every line a binary writes has one
// format and one level threshold. Production output is JSON at info level;
// readable debug output for local runs is the explicit opt-in
// --log-format=text --log-level=debug.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	// FormatJSON is the production format and the default.
	FormatJSON = "json"
	// FormatText is the human-readable format for local runs.
	FormatText = "text"

	// EnvLevel and EnvFormat supply the flags' defaults.
	EnvLevel  = "LOG_LEVEL"
	EnvFormat = "LOG_FORMAT"
)

// Options holds the --log-level and --log-format flag values.
type Options struct {
	Level  string
	Format string
}

// BindFlags adds --log-level and --log-format to fs, defaulting from
// LOG_LEVEL and LOG_FORMAT, then info and json.
func (o *Options) BindFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Level, "log-level", envOr(EnvLevel, "info"),
		"Log level: debug, info, warn, error (env "+EnvLevel+")")
	fs.StringVar(&o.Format, "log-format", envOr(EnvFormat, FormatJSON),
		"Log format: json or text (env "+EnvFormat+")")
}

// Setup installs the logger o describes, writing to stderr.
func (o *Options) Setup() error {
	return Setup(os.Stderr, o.Level, o.Format)
}

// Setup builds one slog handler writing to w and installs it as slog's
// default, which also routes the standard log package through it, and as
// controller-runtime's and klog's logger. controller-runtime's V(n) lines map
// to slog level -n, so they appear only at --log-level=debug or below.
// controller-runtime keeps the logger from its first SetLogger call, so a
// binary calls Setup once, before it builds a manager.
func Setup(w io.Writer, level, format string) error {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: l}
	var h slog.Handler
	switch format {
	case FormatJSON:
		h = slog.NewJSONHandler(w, opts)
	case FormatText:
		h = slog.NewTextHandler(w, opts)
	default:
		return fmt.Errorf("--log-format must be %s or %s, not %q", FormatJSON, FormatText, format)
	}
	logger := slog.New(h)
	slog.SetDefault(logger)
	ctrl.SetLogger(logr.FromSlogHandler(h))
	klog.SetSlogLogger(logger)
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
