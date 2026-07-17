// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/metadata"
)

const testCmdUse = "test"

// testCmd creates a cobra command with the same flags as newRootCommand.
func testCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: testCmdUse}
	cmd.Flags().StringP("node-name", "n", "", "Kubernetes node name (required)")
	cmd.Flags().StringP("mode", "m", "", "Operating mode")
	cmd.Flags().Bool("reflector", false, "Enable route reflector mode")
	cmd.Flags().IntP("bgp-listen-port", "p", config.DefaultRouterBGPListenPort, "BGP listen port")
	cmd.Flags().StringP("bgp-local-address", "", "", "BGP local address")
	cmd.Flags().IntP("metrics-port", "", config.DefaultRouterMetricsPort, "Metrics listen port")
	cmd.Flags().IntP("grpc-health-port", "", config.DefaultRouterGRPCHealthPort, "gRPC health check port")
	cmd.Flags().StringP("gc-namespace", "", config.DefaultRouterGCNamespace, "Namespace for orphaned CRD cleanup")
	cmd.Flags().DurationP("gc-interval", "", config.DefaultRouterGCInterval, "Cleanup interval")
	return cmd
}

func TestFlagDefaults(t *testing.T) {
	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())

	if cfg.BGPListenPort != config.DefaultRouterBGPListenPort {
		t.Errorf("BGPListenPort = %d, want %d", cfg.BGPListenPort, config.DefaultRouterBGPListenPort)
	}
	if cfg.MetricsPort != config.DefaultRouterMetricsPort {
		t.Errorf("MetricsPort = %d, want %d", cfg.MetricsPort, config.DefaultRouterMetricsPort)
	}
	if cfg.GRPCHealthPort != config.DefaultRouterGRPCHealthPort {
		t.Errorf("GRPCHealthPort = %d, want %d", cfg.GRPCHealthPort, config.DefaultRouterGRPCHealthPort)
	}
}

func TestRequiredFlags(t *testing.T) {
	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() with empty node-name and mode returned nil error")
	}
}

func TestEnvVarDefaults(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")
	t.Setenv(config.EnvRouterMode, config.ModeTenant)

	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with valid env vars: %v", err)
	}
}

func TestInvalidMode(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")
	t.Setenv(config.EnvRouterMode, "invalid")

	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() with invalid mode returned nil error")
	}
}

func TestBGPListenPortMinusOne(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")
	t.Setenv(config.EnvRouterMode, config.ModeTenant)
	t.Setenv(config.EnvRouterBGPListenPort, "-1")

	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with BGP listen port -1: %v", err)
	}
}

func TestBGPListenPortOverflow(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")
	t.Setenv(config.EnvRouterMode, config.ModeTenant)
	t.Setenv(config.EnvRouterBGPListenPort, "70000")

	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() with BGP listen port 70000 returned nil error")
	}
}

func TestNodeNameRequired(t *testing.T) {
	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() with empty node-name returned nil error")
	}
}

func TestModeRequired(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")

	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() with empty mode returned nil error")
	}
}

func TestValidModes(t *testing.T) {
	for _, mode := range []string{config.ModeTransit, config.ModeFabric, config.ModeTenant} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv(config.EnvRouterNodeName, "test-node")
			t.Setenv(config.EnvRouterMode, mode)

			cfg := config.NewRouterConfig()
			cmd := testCmd(t)
			cfg.BindFlags(cmd.Flags())

			if cfg.Mode != mode {
				t.Errorf("Mode = %q, want %q", cfg.Mode, mode)
			}
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate() with mode %q: %v", mode, err)
			}
		})
	}
}

func TestReflectorInvalidMode(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")
	t.Setenv(config.EnvRouterMode, config.ModeTransit)

	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	if err := cmd.Flags().Set("reflector", "true"); err != nil {
		t.Fatalf("set --reflector flag: %v", err)
	}
	cfg.BindFlags(cmd.Flags())

	if err := cfg.Validate(); err == nil {
		t.Error("Validate() with --reflector and --mode=transit returned nil error")
	}
}

func TestMetricsPortOverride(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")
	t.Setenv(config.EnvRouterMode, config.ModeTenant)
	t.Setenv(config.EnvRouterMetricsPort, "9090")

	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())
	if cfg.MetricsPort != 9090 {
		t.Errorf("MetricsPort = %d, want 9090", cfg.MetricsPort)
	}
}

func TestGRPCHealthPortOverride(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")
	t.Setenv(config.EnvRouterMode, config.ModeTenant)
	t.Setenv(config.EnvRouterGRPCHealthPort, "9091")

	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())
	if cfg.GRPCHealthPort != 9091 {
		t.Errorf("GRPCHealthPort = %d, want 9091", cfg.GRPCHealthPort)
	}
}

func TestModeFlagOverridesEnv(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")
	t.Setenv(config.EnvRouterMode, config.ModeFabric)

	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	if err := cmd.Flags().Set("mode", config.ModeTenant); err != nil {
		t.Fatalf("set --mode flag: %v", err)
	}
	cfg.BindFlags(cmd.Flags())

	if cfg.Mode != config.ModeTenant {
		t.Errorf("Mode = %q, want %q (flag should override env var)", cfg.Mode, config.ModeTenant)
	}
}

func TestGRPCHealthPortFlagOverridesEnv(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")
	t.Setenv(config.EnvRouterMode, config.ModeTenant)
	t.Setenv(config.EnvRouterGRPCHealthPort, "9091")

	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	if err := cmd.Flags().Set("grpc-health-port", "9092"); err != nil {
		t.Fatalf("set --grpc-health-port flag: %v", err)
	}
	cfg.BindFlags(cmd.Flags())

	if cfg.GRPCHealthPort != 9092 {
		t.Errorf("GRPCHealthPort = %d, want %d (flag should override env var)", cfg.GRPCHealthPort, 9092)
	}
}

func TestVersionFlag(t *testing.T) {
	if metadata.Version == "" {
		t.Error("metadata.Version should not be empty")
	}
}

func TestResolveBGPLocalAddress(t *testing.T) {
	const testBGPLocalAddr = "fc00:0:2::1"

	t.Run("explicit value wins, detect not called", func(t *testing.T) {
		called := false
		detect := func() (string, error) {
			called = true
			return "", nil
		}
		got, err := resolveBGPLocalAddress(testBGPLocalAddr, detect)
		if err != nil {
			t.Fatalf("resolveBGPLocalAddress() error = %v, want nil", err)
		}
		if got != testBGPLocalAddr {
			t.Errorf("resolveBGPLocalAddress() = %q, want %q", got, testBGPLocalAddr)
		}
		if called {
			t.Error("detect was called even though explicit value was set")
		}
	})

	t.Run("empty explicit value falls back to detect", func(t *testing.T) {
		detect := func() (string, error) {
			return testBGPLocalAddr, nil
		}
		got, err := resolveBGPLocalAddress("", detect)
		if err != nil {
			t.Fatalf("resolveBGPLocalAddress() error = %v, want nil", err)
		}
		if got != testBGPLocalAddr {
			t.Errorf("resolveBGPLocalAddress() = %q, want %q", got, testBGPLocalAddr)
		}
	})

	t.Run("detect failure is fatal", func(t *testing.T) {
		detect := func() (string, error) {
			return "", errors.New("no lo address")
		}
		_, err := resolveBGPLocalAddress("", detect)
		if err == nil {
			t.Fatal("resolveBGPLocalAddress() error = nil, want error")
		}
	})
}
