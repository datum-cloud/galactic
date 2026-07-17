// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config holds shared defaults and Viper-based configuration
// resolution for galactic-cni. Both the CNI plugin (internal/cni) and the
// installer (internal/installer) import these constants and helpers to avoid
// duplicated defaults and env-var resolution logic.
package config

import (
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Default settings for galactic-cni. Defined once here so the CNI plugin and
// the installer always agree on the same values.
const (
	DefaultConfFile   = "/etc/cni/net.d/10-galactic.conflist"
	DefaultKubeconfig = "/var/lib/galactic/kubeconfig"
	DefaultNamespace  = "galactic-system"
	DefaultLogFile    = "/var/log/galactic/galactic-cni.log"
	DefaultLogLevel   = "info"
)

// Recognized log_level values.
const (
	LogLevelDebug   = "debug"
	LogLevelWarn    = "warn"
	LogLevelWarning = "warning"
	LogLevelError   = "error"
)

// Env var keys.
const (
	EnvNodeName        = "GALACTIC_CNI_NODE_NAME"
	EnvKubeconfig      = "GALACTIC_CNI_KUBECONFIG"
	EnvNamespace       = "GALACTIC_CNI_NAMESPACE"
	EnvLogFile         = "GALACTIC_CNI_LOG_FILE"
	EnvLogLevel        = "GALACTIC_CNI_LOG_LEVEL"
	EnvEnableLocalIPAM = "GALACTIC_CNI_ENABLE_LOCAL_IPAM"
	// Legacy fallback for node name (set by the DaemonSet).
	EnvNodeNameLegacy = "NODE_NAME"
)

// CNIViper wraps a viper instance pre-configured with AutomaticEnv and the
// GALACTIC_CNI prefix. Callers should obtain it once via NewCNI() and reuse
// it across the process lifetime.
type CNIViper struct {
	v        *viper.Viper
	prefix   string
	defaults map[string]string
}

// NewCNI returns a CNIViper with AutomaticEnv and the GALACTIC_CNI prefix.
// The returned instance is safe for concurrent reads.
func NewCNI() *CNIViper {
	v := viper.New()
	v.SetEnvPrefix("GALACTIC_CNI")
	v.AutomaticEnv()

	return &CNIViper{
		v:      v,
		prefix: "GALACTIC_CNI",
		defaults: map[string]string{
			"log_file":   DefaultLogFile,
			"log_level":  DefaultLogLevel,
			"kubeconfig": DefaultKubeconfig,
			"namespace":  DefaultNamespace,
		},
	}
}

// resolveEnv returns the env var value for a given Viper key.
// Keys use _ as separator (e.g. "log_file" → "GALACTIC_CNI_LOG_FILE").
// The special "node_name" key also checks the legacy "NODE_NAME" fallback.
func (c *CNIViper) resolveEnv(key string) string {
	if key == "node_name" {
		if val := os.Getenv(EnvNodeName); val != "" {
			return val
		}
		return os.Getenv(EnvNodeNameLegacy)
	}
	return os.Getenv(c.prefix + "_" + strings.ToUpper(key))
}

// Resolve returns the value for the given key, falling back to the provided
// conflist value when the env var is unset. This implements the standard
// precedence: env var > conflist field > default.
func (c *CNIViper) Resolve(key, conflistValue string) string {
	if val := c.resolveEnv(key); val != "" {
		return val
	}
	if conflistValue != "" {
		return conflistValue
	}
	return c.defaults[key]
}

// LogLevel returns the resolved log level string, with NormalizeLogLevel
// applied so that "warning" becomes "warn" and unrecognized values fall back
// to DefaultLogLevel.
func (c *CNIViper) LogLevel(conflistValue string) string {
	return NormalizeLogLevel(c.Resolve("log_level", conflistValue))
}

// Kubeconfig returns the resolved kubeconfig path.
func (c *CNIViper) Kubeconfig(conflistValue string) string {
	return c.Resolve("kubeconfig", conflistValue)
}

// Namespace returns the resolved namespace.
func (c *CNIViper) Namespace(conflistValue string) string {
	return c.Resolve("namespace", conflistValue)
}

// NodeName returns the resolved node name (env var or conflist, no default).
func (c *CNIViper) NodeName(conflistValue string) string {
	return c.Resolve("node_name", conflistValue)
}

// LogFile returns the resolved log file path.
func (c *CNIViper) LogFile(conflistValue string) string {
	return c.Resolve("log_file", conflistValue)
}

// EnableLocalIPAM returns whether the local IPAM allocator is enabled.
func (c *CNIViper) EnableLocalIPAM() bool {
	val := os.Getenv(EnvEnableLocalIPAM)
	return val == "true" || val == "1"
}

// NormalizeLogLevel validates and normalizes a log level string.
// "warning" is normalized to "warn". Unrecognized values return
// DefaultLogLevel and log a warning.
func NormalizeLogLevel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", DefaultLogLevel:
		return DefaultLogLevel
	case LogLevelDebug:
		return LogLevelDebug
	case LogLevelWarn:
		return LogLevelWarn
	case LogLevelWarning:
		return LogLevelWarn
	case LogLevelError:
		return LogLevelError
	default:
		slog.Warn("Unrecognized log level, falling back to info", "value", s)
		return DefaultLogLevel
	}
}
