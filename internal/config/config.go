// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config provides shared configuration defaults, environment variable
// keys, and typed resolvers for both galactic-cni and galactic-router.
//
// Each component gets its own resolver (CNIConfig, RouterConfig).
// Precedence: env var > conflist/flag > compiled-in default.
package config

import (
	"os"
	"strings"
)

// --- Shared defaults -------------------------------------------------------

const (
	DefaultConfFile   = "/etc/cni/net.d/10-galactic.conflist"
	DefaultKubeconfig = "/var/lib/galactic/kubeconfig"
	DefaultNamespace  = "galactic-system"
	DefaultLogFile    = "/var/log/galactic/galactic-cni.log"
	DefaultLogLevel   = "info"

	LogLevelDebug   = "debug"
	LogLevelWarn    = "warn"
	LogLevelWarning = "warning"
	LogLevelError   = "error"
)

// --- Shared helpers --------------------------------------------------------

// NormalizeLogLevel maps common log level aliases to canonical values.
// "warning" is normalized to "warn"; unrecognized values fall back to "info".
func NormalizeLogLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case LogLevelDebug:
		return LogLevelDebug
	case LogLevelWarn, LogLevelWarning:
		return LogLevelWarn
	case LogLevelError:
		return LogLevelError
	default:
		return DefaultLogLevel
	}
}

// resolveEnv checks an environment variable, then falls back to a conflist
// value, then to a default. Returns the first non-empty value.
func resolveEnv(envKey, conflistVal, defaultValue string) string {
	if val := os.Getenv(envKey); val != "" {
		return val
	}
	if conflistVal != "" {
		return conflistVal
	}
	return defaultValue
}
