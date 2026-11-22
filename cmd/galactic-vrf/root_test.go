// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/ingresssidecar"
	"go.datum.net/galactic/internal/metadata"
)

// testCmd returns the root command, whose flags BindFlags reads.
func testCmd(t *testing.T) *cobra.Command {
	t.Helper()
	return newRootCommand()
}

func TestFlagDefaults(t *testing.T) {
	// The settings that have no default.
	t.Setenv(config.EnvVRFNodeName, "node-a")
	t.Setenv(config.EnvVRFPodNamespace, "envoy")
	t.Setenv(config.EnvVRFAttachmentSelector, "galactic.datumapis.com/proxy=envoy")
	cfg := config.NewVRFConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())

	if cfg.MetricsPort != config.DefaultVRFMetricsPort {
		t.Errorf("MetricsPort = %d, want %d", cfg.MetricsPort, config.DefaultVRFMetricsPort)
	}
	if cfg.TeardownGracePeriod != config.DefaultVRFTeardownGracePeriod {
		t.Errorf("TeardownGracePeriod = %v, want %v", cfg.TeardownGracePeriod, config.DefaultVRFTeardownGracePeriod)
	}
	if cfg.SweepInterval != config.DefaultVRFSweepInterval {
		t.Errorf("SweepInterval = %v, want %v", cfg.SweepInterval, config.DefaultVRFSweepInterval)
	}
	if cfg.WorkerSocket == "" || cfg.WorkerTokenFile != config.DefaultVRFWorkerTokenFile {
		t.Errorf("Worker socket and token = %q, %q; want the defaults", cfg.WorkerSocket, cfg.WorkerTokenFile)
	}
	if cfg.InPodEncapsulation {
		t.Error("InPodEncapsulation = true, want false by default")
	}
	if cfg.HealthPort != config.DefaultVRFHealthPort {
		t.Errorf("HealthPort = %d, want %d", cfg.HealthPort, config.DefaultVRFHealthPort)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with defaults: %v", err)
	}
}

func TestFlagsOverrideEnv(t *testing.T) {
	t.Setenv(config.EnvVRFMetricsPort, "9000")
	t.Setenv(config.EnvVRFTeardownGracePeriod, "60s")

	cfg := config.NewVRFConfig()
	cmd := testCmd(t)
	if err := cmd.Flags().Set("metrics-port", "9500"); err != nil {
		t.Fatalf("set --metrics-port flag: %v", err)
	}
	cfg.BindFlags(cmd.Flags())

	if cfg.MetricsPort != 9500 {
		t.Errorf("MetricsPort = %d, want 9500 (flag should override env var)", cfg.MetricsPort)
	}
}

func TestInPodEncapsulationFlag(t *testing.T) {
	const on, off = "true", "false"
	tests := []struct {
		name string
		env  string
		flag string
		want bool
	}{
		{"Default", "", "", false},
		{"Env", on, "", true},
		{"Flag", "", on, true},
		{"FlagOverridesEnv", on, off, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(config.EnvVRFInPodEncapsulation, tt.env)
			cfg := config.NewVRFConfig()
			cmd := testCmd(t)
			if tt.flag != "" {
				if err := cmd.Flags().Set(config.FlagVRFInPodEncapsulation, tt.flag); err != nil {
					t.Fatalf("set --%s: %v", config.FlagVRFInPodEncapsulation, err)
				}
			}
			cfg.BindFlags(cmd.Flags())
			if cfg.InPodEncapsulation != tt.want {
				t.Errorf("InPodEncapsulation = %t, want %t", cfg.InPodEncapsulation, tt.want)
			}
		})
	}
}

// TestPartsFor checks that the flag chooses the components runCmd wires:
// the Store and the in-pod pod link with in-pod encapsulation, the startup
// prune and the routed pod link without.
func TestPartsFor(t *testing.T) {
	tests := []struct {
		name               string
		inPodEncapsulation bool
		want               sidecarParts
	}{
		{"InPodEncapsulation", true, sidecarParts{store: true, podLink: ingresssidecar.NewKernelPodLink()}},
		{"RoutedLink", false, sidecarParts{pruneInPodEncapsulation: true, podLink: ingresssidecar.NewRoutedPodLink()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.NewVRFConfig()
			cfg.InPodEncapsulation = tt.inPodEncapsulation
			if got := partsFor(cfg); got != tt.want {
				t.Errorf("partsFor(InPodEncapsulation=%t) = %+v, want %+v", tt.inPodEncapsulation, got, tt.want)
			}
		})
	}
	if ingresssidecar.NewKernelPodLink() == ingresssidecar.NewRoutedPodLink() {
		t.Error("the in-pod and routed pod links are indistinguishable")
	}
}

func TestVersionMetadata(t *testing.T) {
	if metadata.Version == "" {
		t.Error("metadata.Version should not be empty")
	}
}
