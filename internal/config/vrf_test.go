// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
	"time"
)

func TestVRFConfigDefaults(t *testing.T) {
	cfg := NewVRFConfig()

	if cfg.MetricsPort != DefaultVRFMetricsPort {
		t.Errorf("MetricsPort = %d, want %d", cfg.MetricsPort, DefaultVRFMetricsPort)
	}
	if cfg.TeardownGracePeriod != DefaultVRFTeardownGracePeriod {
		t.Errorf("TeardownGracePeriod = %v, want %v", cfg.TeardownGracePeriod, DefaultVRFTeardownGracePeriod)
	}
	if cfg.SweepInterval != DefaultVRFSweepInterval {
		t.Errorf("SweepInterval = %v, want %v", cfg.SweepInterval, DefaultVRFSweepInterval)
	}
	if cfg.NodeName != "" {
		t.Errorf("NodeName = %q, want empty (no generic default)", cfg.NodeName)
	}
	if cfg.GatewayPrefix != "" {
		t.Errorf("GatewayPrefix = %q, want empty (no generic default)", cfg.GatewayPrefix)
	}
}

func TestVRFConfigEnvOverride(t *testing.T) {
	t.Setenv(EnvVRFMetricsPort, "9999")
	t.Setenv(EnvVRFTeardownGracePeriod, "45s")
	t.Setenv(EnvVRFSweepInterval, "10s")
	t.Setenv(EnvVRFGatewayPrefix, "fd00:6741:7761::/48")

	cfg := NewVRFConfig()

	if cfg.MetricsPort != 9999 {
		t.Errorf("MetricsPort = %d, want 9999", cfg.MetricsPort)
	}
	if cfg.TeardownGracePeriod != 45*time.Second {
		t.Errorf("TeardownGracePeriod = %v, want 45s", cfg.TeardownGracePeriod)
	}
	if cfg.SweepInterval != 10*time.Second {
		t.Errorf("SweepInterval = %v, want 10s", cfg.SweepInterval)
	}
	if cfg.GatewayPrefix != "fd00:6741:7761::/48" {
		t.Errorf("GatewayPrefix = %q, want fd00:6741:7761::/48", cfg.GatewayPrefix)
	}
}

func TestVRFConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr string
	}{
		{
			name:    testCaseInvalidMetricsPort,
			envVars: map[string]string{EnvVRFMetricsPort: "0"},
			wantErr: testErrMetricsPortRange,
		},
		{
			name:    "non-positive grace period",
			envVars: map[string]string{EnvVRFTeardownGracePeriod: "0s"},
			wantErr: "teardown grace period must be positive",
		},
		{
			name:    "non-positive sweep interval",
			envVars: map[string]string{EnvVRFSweepInterval: "0s"},
			wantErr: "sweep interval must be positive",
		},
		{
			name: "sweep interval longer than grace period",
			envVars: map[string]string{
				EnvVRFTeardownGracePeriod: "5s",
				EnvVRFSweepInterval:       "10s",
			},
			wantErr: "sweep interval must not be greater than",
		},
		{
			name:    "invalid gateway prefix",
			envVars: map[string]string{EnvVRFGatewayPrefix: "not-a-cidr"},
			wantErr: "gateway prefix",
		},
		{
			name:    "gateway prefix must be IPv6",
			envVars: map[string]string{EnvVRFGatewayPrefix: "10.0.0.0/24"},
			wantErr: "must be an IPv6 CIDR",
		},
		{
			name:    "gateway prefix must be byte-aligned",
			envVars: map[string]string{EnvVRFGatewayPrefix: "fd00:6741:7761::/50"},
			wantErr: "byte-aligned",
		},
		{
			name:    "valid gateway prefix",
			envVars: map[string]string{EnvVRFGatewayPrefix: "fd00:6741:7761::/48"},
			wantErr: "",
		},
		{
			name:    testCaseValidConfig,
			envVars: map[string]string{},
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.envVars {
				t.Setenv(k, v)
			}
			cfg := NewVRFConfig()
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Errorf("Validate() = nil, want error containing %q", tc.wantErr)
				return
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate() = %q, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
