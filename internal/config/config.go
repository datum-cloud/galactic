// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config provides the shared configuration defaults, environment
// variable names, and typed resolvers every galactic binary uses. Each gets its
// own resolver, all with the same precedence: environment variable, then
// conflist or flag, then compiled-in default.
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

	// flagMetricsPort is the CLI flag name several resolvers share, each
	// binding it to the same key.
	flagMetricsPort = "metrics-port"

	// keyMetricsPort is the Viper key each component's MetricsPort field
	// resolves from (SetDefault/BindFlags/GetInt).
	keyMetricsPort = "metrics_port"

	// errMetricsPortRange is the out-of-range validation message shared by
	// RouterConfig, GatewayConfig, and VRFConfig's Validate.
	errMetricsPortRange = "metrics port must be between 1 and 65535"
)

// --- Shared CLI flag names --------------------------------------------

// FlagNodeName, FlagMetricsPort, and FlagGRPCHealthPort are the CLI flag names
// every per-binary resolver binds verbatim, shared rather than repeated once
// per binary.
const (
	FlagNodeName       = "node-name"
	FlagMetricsPort    = "metrics-port"
	FlagGRPCHealthPort = "grpc-health-port"
)

// --- Shared Viper key names ---------------------------------------------

// KeyNodeName, KeyMetricsPort, and KeyGRPCHealthPort are the config keys every
// per-binary resolver uses for the three fields the flags above bind, shared for
// the same reason.
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
