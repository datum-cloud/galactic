// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import "testing"

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
