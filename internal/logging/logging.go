// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package logging installs one process-wide logger for a Galactic binary,
// built by go.miloapis.com/instrumentation/logging. The same logger backs
// slog's default logger, the standard log package, controller-runtime's logger
// and klog, so every line a binary writes has one format and one level
// threshold. Production output is JSON at info level, with UTC timestamps and
// the binary's and the library's versions on every line. Console output for
// local runs is the explicit opt-in --zap-devel.
package logging

import (
	"context"
	goflag "flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	"go.miloapis.com/instrumentation/buildinfo"
	"go.miloapis.com/instrumentation/logging"
	uberzap "go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/klog/v2"
	crlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"go.datum.net/galactic/internal/metadata"
)

const (
	// EnvLevel supplies --log-level's default.
	EnvLevel = "LOG_LEVEL"

	// DevelFlag is the standard opt-in for console output at debug level.
	DevelFlag = "zap-devel"
)

// Levels are the documented --log-level values. ValidateLevel also accepts
// what slog parses beyond them: any case, and an offset such as info+2.
var Levels = []string{"debug", "info", "warn", "error"}

// Binaries are the commands under cmd/ that call Setup. A manifest check uses
// this list to find the containers whose LOG_LEVEL, --log-level and
// --zap-devel these rules govern: by image name, as most publish an image of
// their own, or by command, as fabric-config-agent ships in the fabric-router
// image.
var Binaries = []string{
	"fabric-api",
	"fabric-config-agent",
	"fabric-router-controller",
	"galactic-cni",
	"galactic-controller",
	"galactic-edge",
	"galactic-gateway",
	"galactic-nat",
	"galactic-router",
	"galactic-vrf",
	"masque-authority",
	"masque-provider",
}

// Options holds the --log-level value and controller-runtime's standard zap
// flags.
type Options struct {
	Level string
	zap   zap.Options
}

// BindFlags adds --log-level, defaulting from LOG_LEVEL then info, and the
// standard zap flags (--zap-devel, --zap-encoder, --zap-log-level,
// --zap-stacktrace-level and --zap-time-encoding) to fs. An explicit
// --zap-log-level takes precedence over --log-level.
func (o *Options) BindFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Level, "log-level", envOr(EnvLevel, "info"),
		"Log level: debug, info, warn, error (env "+EnvLevel+")")
	zfs := goflag.NewFlagSet("zap", goflag.ContinueOnError)
	o.zap.BindFlags(zfs)
	fs.AddGoFlagSet(zfs)
}

// Setup installs the logger o describes, writing to stderr.
func (o *Options) Setup() error {
	return o.setup(os.Stderr)
}

func (o *Options) setup(w io.Writer) error {
	opts := o.zap
	opts.DestWriter = w
	if opts.Level == nil {
		l, err := parseLevel(o.Level)
		if err != nil {
			return err
		}
		opts.Level = l
	}
	install(&opts)
	return nil
}

// SetupFile installs the production logger at level, writing to w. The CNI
// plugins use it to log to their own file.
func SetupFile(w io.Writer, level slog.Level) {
	install(&zap.Options{DestWriter: w, Level: zapLevel(level)})
}

// install sets the binary's version, builds the library's logger from opts
// and installs it as controller-runtime's and klog's logger and, through a
// slog bridge, as slog's default, which also routes the standard log package
// through it. controller-runtime keeps the logger from its first SetLogger
// call, so a binary installs it once, before it builds a manager.
func install(opts *zap.Options) {
	buildinfo.SetVersion(metadata.Version)
	opts.EncoderConfigOptions = append(opts.EncoderConfigOptions, verboseAsDebug)
	logger := logging.New(opts)
	crlog.SetLogger(logger)
	klog.SetLogger(logger)
	slog.SetDefault(slog.New(logr.ToSlogHandler(logr.New(wrap(logger.GetSink())))))
}

// slogSink passes slog's warn lines to zap whatever the threshold. logr has
// no warn level, so its slog bridge asks whether V(0) is enabled before it
// hands over a warn line, and at --log-level=warn it isn't. zap checks the
// level of every line the bridge hands over, so it still drops info lines.
type slogSink struct {
	logr.LogSink
	slog logr.SlogSink
}

func wrap(sink logr.LogSink) logr.LogSink {
	if ss, ok := sink.(logr.SlogSink); ok {
		return slogSink{sink, ss}
	}
	return sink
}

// Init does nothing: the wrapped sink was initialized when the library built
// it, and initializing it again would add a second caller skip.
func (slogSink) Init(logr.RuntimeInfo) {}

func (s slogSink) Enabled(level int) bool {
	return level == 0 || s.LogSink.Enabled(level)
}

func (s slogSink) WithValues(kv ...any) logr.LogSink { return wrap(s.LogSink.WithValues(kv...)) }
func (s slogSink) WithName(name string) logr.LogSink { return wrap(s.LogSink.WithName(name)) }

func (s slogSink) Handle(ctx context.Context, r slog.Record) error { return s.slog.Handle(ctx, r) }

func (s slogSink) WithAttrs(attrs []slog.Attr) logr.SlogSink {
	return wrap(s.slog.WithAttrs(attrs).(logr.LogSink)).(logr.SlogSink)
}

func (s slogSink) WithGroup(name string) logr.SlogSink {
	return wrap(s.slog.WithGroup(name).(logr.LogSink)).(logr.SlogSink)
}

// verboseAsDebug names every level below zap's debug level, which slog.Debug
// and controller-runtime's V(2) and up produce, debug instead of Level(-n).
func verboseAsDebug(c *zapcore.EncoderConfig) {
	encode := c.EncodeLevel
	c.EncodeLevel = func(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
		encode(max(l, zapcore.DebugLevel), enc)
	}
}

// ValidateLevel returns the error Setup returns for level, or nil if Setup
// accepts it.
func ValidateLevel(level string) error {
	_, err := parseLevel(level)
	return err
}

// parseLevel maps a --log-level value to the zap level that keeps its
// meaning.
func parseLevel(level string) (uberzap.AtomicLevel, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return uberzap.AtomicLevel{}, fmt.Errorf("--log-level: %w", err)
	}
	return zapLevel(l), nil
}

// zapLevel maps a slog level to the zap threshold that admits the same
// lines. Through the bridge, slog's info, warn and error become zap's info,
// warn and error, while a level below info passes through unchanged:
// slog.Debug arrives as zap level -4, and controller-runtime's V(n) as -n.
func zapLevel(l slog.Level) uberzap.AtomicLevel {
	if l < slog.LevelInfo {
		return uberzap.NewAtomicLevelAt(zapcore.Level(l))
	}
	return uberzap.NewAtomicLevelAt(zapcore.Level(l / 4))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
