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

const testCmdUse = "test"

// testCmd creates a cobra command with the same flags as newRootCommand.
func testCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: testCmdUse}
	cmd.Flags().StringP("node-name", "n", "", "Kubernetes node name (required)")
	cmd.Flags().IntP("metrics-port", "", config.DefaultGatewayMetricsPort, "Metrics listen port")
	cmd.Flags().IntP("grpc-health-port", "", config.DefaultGatewayGRPCHealthPort, "gRPC health check port")
	cmd.Flags().StringP("gateway-public-interface", "", "", "Edge gateway public interface")
	cmd.Flags().StringP("gateway-srv6-address", "", "", "Edge gateway SRv6 address")
	return cmd
}

func TestFlagDefaults(t *testing.T) {
	cfg := config.NewGatewayConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())

	if cfg.MetricsPort != config.DefaultGatewayMetricsPort {
		t.Errorf("MetricsPort = %d, want %d", cfg.MetricsPort, config.DefaultGatewayMetricsPort)
	}
	if cfg.GRPCHealthPort != config.DefaultGatewayGRPCHealthPort {
		t.Errorf("GRPCHealthPort = %d, want %d", cfg.GRPCHealthPort, config.DefaultGatewayGRPCHealthPort)
	}
}

func TestRequiredFlags(t *testing.T) {
	cfg := config.NewGatewayConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() with empty node-name/public-interface/srv6-address returned nil error")
	}
}

func TestEnvVarDefaults(t *testing.T) {
	t.Setenv(config.EnvGatewayNodeName, "test-node")
	t.Setenv(config.EnvGatewayPublicInterface, "eth0")
	t.Setenv(config.EnvGatewaySRv6Address, "2001:db8::1")

	cfg := config.NewGatewayConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with valid env vars: %v", err)
	}
}

func TestNodeNameRequired(t *testing.T) {
	t.Setenv(config.EnvGatewayPublicInterface, "eth0")
	t.Setenv(config.EnvGatewaySRv6Address, "2001:db8::1")

	cfg := config.NewGatewayConfig()
	cmd := testCmd(t)
	cfg.BindFlags(cmd.Flags())
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() with empty node-name returned nil error")
	}
}

func TestGatewayFlagsOverrideEnv(t *testing.T) {
	t.Setenv(config.EnvGatewayNodeName, "test-node")
	t.Setenv(config.EnvGatewayPublicInterface, "env-eth0")
	t.Setenv(config.EnvGatewaySRv6Address, "2001:db8:3::1")

	cfg := config.NewGatewayConfig()
	cmd := testCmd(t)
	if err := cmd.Flags().Set("gateway-public-interface", "flag-eth0"); err != nil {
		t.Fatalf("set --gateway-public-interface flag: %v", err)
	}
	if err := cmd.Flags().Set("gateway-srv6-address", "2001:db8:3::2"); err != nil {
		t.Fatalf("set --gateway-srv6-address flag: %v", err)
	}
	cfg.BindFlags(cmd.Flags())

	if cfg.PublicInterface != "flag-eth0" {
		t.Errorf("PublicInterface = %q, want %q (flag should override env var)", cfg.PublicInterface, "flag-eth0")
	}
	if cfg.SRv6Address != "2001:db8:3::2" {
		t.Errorf("SRv6Address = %q, want %q (flag should override env var)", cfg.SRv6Address, "2001:db8:3::2")
	}
}

func TestVersionFlag(t *testing.T) {
	if metadata.Version == "" {
		t.Error("metadata.Version should not be empty")
	}
}
