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
	cmd.Flags().Bool("reflector", false, "Enable route reflector mode")
	cmd.Flags().IntP("bgp-listen-port", "p", config.DefaultRouterBGPListenPort, "BGP listen port")
	cmd.Flags().StringP("bgp-local-address", "", "", "BGP local address")
	cmd.Flags().IntP("metrics-port", "", config.DefaultRouterMetricsPort, "Metrics listen port")
	cmd.Flags().IntP("grpc-health-port", "", config.DefaultRouterGRPCHealthPort, "gRPC health check port")
	cmd.Flags().StringP("gc-namespace", "", config.DefaultRouterGCNamespace, "Namespace for orphaned CRD cleanup")
	cmd.Flags().DurationP("gc-interval", "", config.DefaultRouterGCInterval, "Cleanup interval")
	cmd.Flags().Bool("webhook-enabled", false, "Enable the NetworkRule admission webhook")
	cmd.Flags().IntP("webhook-port", "", config.DefaultRouterWebhookPort, "Webhook server listen port")
	cmd.Flags().StringP("webhook-cert-dir", "", "", "Webhook server TLS cert/key directory")
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
		t.Error("Validate() with empty node-name returned nil error")
	}
}

func TestEnvVarDefaults(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")

	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with valid env vars: %v", err)
	}
}

func TestBGPListenPortMinusOne(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")
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

func TestMetricsPortOverride(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")
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
	t.Setenv(config.EnvRouterGRPCHealthPort, "9091")

	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())
	if cfg.GRPCHealthPort != 9091 {
		t.Errorf("GRPCHealthPort = %d, want 9091", cfg.GRPCHealthPort)
	}
}

func TestGRPCHealthPortFlagOverridesEnv(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")
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

func TestWebhookFlagsOverrideEnv(t *testing.T) {
	t.Setenv(config.EnvRouterNodeName, "test-node")
	t.Setenv(config.EnvRouterWebhookEnabled, "false")
	t.Setenv(config.EnvRouterWebhookPort, "9443")

	cfg := config.NewRouterConfig()
	cmd := testCmd(t)
	if err := cmd.Flags().Set("webhook-enabled", "true"); err != nil {
		t.Fatalf("set --webhook-enabled flag: %v", err)
	}
	if err := cmd.Flags().Set("webhook-port", "9444"); err != nil {
		t.Fatalf("set --webhook-port flag: %v", err)
	}
	cfg.BindFlags(cmd.Flags())

	if !cfg.WebhookEnabled {
		t.Error("WebhookEnabled = false, want true (flag should override env var)")
	}
	if cfg.WebhookPort != 9444 {
		t.Errorf("WebhookPort = %d, want 9444 (flag should override env var)", cfg.WebhookPort)
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
