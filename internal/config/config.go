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

// --- Shared CLI flag names --------------------------------------------

// FlagNodeName/FlagMetricsPort/FlagGRPCHealthPort are the CLI flag name
// strings every per-binary Config's BindFlags bindings table
// (RouterConfig, GatewayConfig, NAT66Config) binds verbatim -- pulled out
// to shared constants rather than left as three near-identical literal
// copies (one per binary), which is exactly what golangci-lint's goconst
// flags once a third copy exists.
const (
	FlagNodeName       = "node-name"
	FlagMetricsPort    = "metrics-port"
	FlagGRPCHealthPort = "grpc-health-port"
)

// --- Shared Viper key names ---------------------------------------------

// KeyNodeName/KeyMetricsPort/KeyGRPCHealthPort are the Viper key strings
// every per-binary Config's SetDefault/BindFlags/readFields trio uses for
// the same three fields FlagNodeName/FlagMetricsPort/FlagGRPCHealthPort
// bind -- pulled out for the same goconst-across-three-near-identical-
// binaries reason as the Flag* constants above.
const (
	KeyNodeName       = "node_name"
	KeyMetricsPort    = "metrics_port"
	KeyGRPCHealthPort = "grpc_health_port"
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
