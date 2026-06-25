// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"
)

func TestParseGrpcPort(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want int
	}{
		{
			name: "Unset",
			env:  "",
			want: defaultGrpcPort,
		},
		{
			name: "Default",
			env:  "50051",
			want: 50051,
		},
		{
			name: "CustomPort",
			env:  "9999",
			want: 9999,
		},
		{
			name: "Zero",
			env:  "0",
			want: defaultGrpcPort, // invalid, falls back to default
		},
		{
			name: "Negative",
			env:  "-1",
			want: defaultGrpcPort, // invalid, falls back to default
		},
		{
			name: "TooLarge",
			env:  "70000",
			want: defaultGrpcPort, // invalid, falls back to default
		},
		{
			name: "NonNumeric",
			env:  "abc",
			want: defaultGrpcPort, // invalid, falls back to default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GALACTIC_GOBGP_GRPC_PORT", tt.env)
			got := parseGrpcPort()
			if got != tt.want {
				t.Errorf("parseGrpcPort() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseGrpcListenAddress(t *testing.T) {
	tests := []struct {
		name        string
		enableEnv   string
		portEnv     string
		want        string
		wantHasPort bool
	}{
		{
			name:        "Disabled",
			enableEnv:   "false",
			portEnv:     "9999",
			want:        "",
			wantHasPort: false,
		},
		{
			name:        "EnabledDefaultPort",
			enableEnv:   grpcServerEnabled,
			portEnv:     "",
			want:        ":50051",
			wantHasPort: true,
		},
		{
			name:        "EnabledCustomPort",
			enableEnv:   grpcServerEnabled,
			portEnv:     "9999",
			want:        ":9999",
			wantHasPort: true,
		},
		{
			name:        "EnabledInvalidPort",
			enableEnv:   grpcServerEnabled,
			portEnv:     "abc",
			want:        ":50051",
			wantHasPort: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GALACTIC_ENABLE_GOBGP_GRPC_SERVER", tt.enableEnv)
			t.Setenv("GALACTIC_GOBGP_GRPC_PORT", tt.portEnv)
			got := parseGrpcListenAddress()
			if got != tt.want {
				t.Errorf("parseGrpcListenAddress() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseGrpcListenAddressIsolation(t *testing.T) {
	// Verify that one test's env var doesn't leak to another.
	t.Setenv("GALACTIC_ENABLE_GOBGP_GRPC_SERVER", "false")
	got := parseGrpcListenAddress()
	if got != "" {
		t.Errorf("parseGrpcListenAddress() = %q after setting false, want empty", got)
	}
}
