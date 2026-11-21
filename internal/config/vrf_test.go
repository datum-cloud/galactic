// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
	"time"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
)

// validVRFEnv sets the variables the sidecar requires.
func validVRFEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvVRFNodeName, "node-a")
	t.Setenv(EnvVRFPodNamespace, "envoy")
	t.Setenv(EnvVRFAttachmentSelector, "galactic.datumapis.com/proxy=envoy")
}

func TestVRFConfigDefaults(t *testing.T) {
	t.Setenv(EnvNodeNameLegacy, "")
	cfg := NewVRFConfig()

	if cfg.MetricsPort != DefaultVRFMetricsPort {
		t.Errorf("MetricsPort = %d, want %d", cfg.MetricsPort, DefaultVRFMetricsPort)
	}
	if cfg.HealthPort != DefaultVRFHealthPort {
		t.Errorf("HealthPort = %d, want %d", cfg.HealthPort, DefaultVRFHealthPort)
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
	if cfg.WorkerSocket != workerv1alpha1.DefaultSocketPath || cfg.WorkerTokenFile != DefaultVRFWorkerTokenFile {
		t.Errorf("Worker socket and token = %q, %q; want the defaults", cfg.WorkerSocket, cfg.WorkerTokenFile)
	}
}

func TestVRFConfigEnvOverride(t *testing.T) {
	t.Setenv(EnvVRFMetricsPort, "9999")
	t.Setenv(EnvVRFTeardownGracePeriod, "45s")
	t.Setenv(EnvVRFSweepInterval, "10s")
	t.Setenv(EnvVRFWorkerSocket, "/run/w.sock")
	validVRFEnv(t)

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
	if cfg.WorkerSocket != "/run/w.sock" || cfg.PodNamespace != "envoy" ||
		cfg.AttachmentSelector != "galactic.datumapis.com/proxy=envoy" || cfg.NodeName != "node-a" {
		t.Errorf("config = %+v, want the environment's values", cfg)
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
			name:    "health port equals metrics port",
			envVars: map[string]string{EnvVRFHealthPort: "9182"},
			wantErr: "health port",
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
			name:    "no node name",
			envVars: map[string]string{EnvVRFNodeName: "", EnvNodeNameLegacy: ""},
			wantErr: "node name is required",
		},
		{
			name:    "no pod namespace",
			envVars: map[string]string{EnvVRFPodNamespace: ""},
			wantErr: "pod namespace is required",
		},
		{
			name:    "no attachment selector",
			envVars: map[string]string{EnvVRFAttachmentSelector: ""},
			wantErr: "attachment selector is required",
		},
		{
			name:    "malformed attachment selector",
			envVars: map[string]string{EnvVRFAttachmentSelector: "a=b=c"},
			wantErr: "attachment selector",
		},
		{
			name:    testCaseValidConfig,
			envVars: map[string]string{},
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			validVRFEnv(t)
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
