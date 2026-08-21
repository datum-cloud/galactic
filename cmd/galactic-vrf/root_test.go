// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/metadata"
)

// testCmd creates a cobra command with the same flags as newRootCommand.
func testCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().IntP("metrics-port", "", config.DefaultVRFMetricsPort, "Metrics listen port")
	cmd.Flags().DurationP("teardown-grace-period", "", config.DefaultVRFTeardownGracePeriod, "Teardown grace period")
	cmd.Flags().DurationP("sweep-interval", "", config.DefaultVRFSweepInterval, "Sweep interval")
	return cmd
}

func TestFlagDefaults(t *testing.T) {
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

func TestVersionMetadata(t *testing.T) {
	if metadata.Version == "" {
		t.Error("metadata.Version should not be empty")
	}
}
