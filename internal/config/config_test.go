// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"testing"
)

func TestNormalizeLogLevel(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty defaults to info", "", DefaultLogLevel},
		{"info", DefaultLogLevel, DefaultLogLevel},
		{"debug", LogLevelDebug, LogLevelDebug},
		{"warn", LogLevelWarn, LogLevelWarn},
		{"warning normalizes to warn", LogLevelWarning, LogLevelWarn},
		{"error", LogLevelError, LogLevelError},
		{"case insensitive DEBUG", "DEBUG", LogLevelDebug},
		{"case insensitive Warn", "Warn", LogLevelWarn},
		{"whitespace trimmed", "  debug  ", LogLevelDebug},
		{"unrecognized falls back to info", "trace", DefaultLogLevel},
		{"unrecognized falls back to info (foo)", "foo", DefaultLogLevel},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeLogLevel(tc.in)
			if got != tc.want {
				t.Errorf("NormalizeLogLevel(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCNIViperResolve(t *testing.T) {
	v := NewCNI()

	// Default values
	if got := v.Resolve("log_file", ""); got != DefaultLogFile {
		t.Errorf("Resolve(log_file, \"\") = %q, want %q", got, DefaultLogFile)
	}
	if got := v.Resolve("log_level", ""); got != DefaultLogLevel {
		t.Errorf("Resolve(log_level, \"\") = %q, want %q", got, DefaultLogLevel)
	}
	if got := v.Resolve("kubeconfig", ""); got != DefaultKubeconfig {
		t.Errorf("Resolve(kubeconfig, \"\") = %q, want %q", got, DefaultKubeconfig)
	}
	if got := v.Resolve("namespace", ""); got != DefaultNamespace {
		t.Errorf("Resolve(namespace, \"\") = %q, want %q", got, DefaultNamespace)
	}

	// Conflist value used when env var is empty
	if got := v.Resolve("log_file", "/custom/path.log"); got != "/custom/path.log" {
		t.Errorf("Resolve(log_file, \"/custom/path.log\") = %q, want %q", got, "/custom/path.log")
	}
}

func TestCNIViperEnvOverride(t *testing.T) {
	t.Setenv(EnvLogLevel, "debug")
	t.Setenv(EnvLogFile, "/env/log.txt")
	t.Setenv(EnvKubeconfig, "/env/kubeconfig")
	t.Setenv(EnvNamespace, "env-ns")
	t.Setenv(EnvNodeName, "env-node")

	v := NewCNI()

	// Env var takes precedence over conflist value
	if got := v.Resolve("log_level", "info"); got != "debug" {
		t.Errorf("Resolve(log_level) = %q, want %q (env override)", got, "debug")
	}
	if got := v.Resolve("log_file", "/conflist/path.log"); got != "/env/log.txt" {
		t.Errorf("Resolve(log_file) = %q, want %q (env override)", got, "/env/log.txt")
	}
	if got := v.Resolve("kubeconfig", "/conflist/kubeconfig"); got != "/env/kubeconfig" {
		t.Errorf("Resolve(kubeconfig) = %q, want %q (env override)", got, "/env/kubeconfig")
	}
	if got := v.Resolve("namespace", "conflist-ns"); got != "env-ns" {
		t.Errorf("Resolve(namespace) = %q, want %q (env override)", got, "env-ns")
	}
	if got := v.Resolve("node_name", "conflist-node"); got != "env-node" {
		t.Errorf("Resolve(node_name) = %q, want %q (env override)", got, "env-node")
	}
}

func TestCNIViperTypedGetters(t *testing.T) {
	t.Setenv(EnvLogLevel, LogLevelWarning)
	t.Setenv(EnvEnableLocalIPAM, "true")

	v := NewCNI()

	// LogLevel normalizes "warning" → "warn"
	if got := v.LogLevel("info"); got != LogLevelWarn {
		t.Errorf("LogLevel() = %q, want %q", got, LogLevelWarn)
	}

	// EnableLocalIPAM reads env var
	if got := v.EnableLocalIPAM(); !got {
		t.Error("EnableLocalIPAM() = false, want true")
	}
}

func TestCNIViperEnableLocalIPAMFalse(t *testing.T) {
	v := NewCNI()
	if got := v.EnableLocalIPAM(); got {
		t.Error("EnableLocalIPAM() = true, want false (env unset)")
	}
}

func TestCNIViperNodeNameLegacyFallback(t *testing.T) {
	// Set only the legacy NODE_NAME env var, not GALACTIC_CNI_NODE_NAME
	t.Setenv(EnvNodeNameLegacy, "legacy-node")

	v := NewCNI()
	if got := v.Resolve("node_name", ""); got != "legacy-node" {
		t.Errorf("Resolve(node_name) with NODE_NAME = %q, want %q", got, "legacy-node")
	}
}
