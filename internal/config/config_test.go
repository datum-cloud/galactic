// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import "testing"

// Shared test literals, factored out here so goconst doesn't need to be
// silenced once a third per-binary *_test.go file (gateway_test.go,
// router_test.go, nat66_test.go) repeats the same test-case name/error
// substring -- see config.go's identical "shared CLI flag names"
// rationale for the production-code half of this pattern.
const (
	testCaseValidConfig           = "valid config"
	testCaseMissingNodeName       = "missing node name"
	testErrNodeNameRequired       = "node name is required"
	testCaseInvalidMetricsPort    = "invalid metrics port"
	testErrMetricsPortRange       = "metrics port must be between"
	testCaseInvalidGRPCHealthPort = "invalid grpc health port"
	testErrGRPCHealthPortRange    = "grpc health port must be between"
	testIPv4Addr                  = "203.0.113.1"
	testErrMustBeNativeIPv6       = "must be a native IPv6 address"
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
