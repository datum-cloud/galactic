// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"go.datum.net/galactic/internal/metadata"
)

// cmdWithViper creates a cobra command with a fresh viper instance and
// binds all flags. This is used to test flag defaults and cobra integration.
func cmdWithViper(t *testing.T) *viper.Viper {
	t.Helper()
	v := newViper()
	cmd := &cobra.Command{
		Use: "test",
	}
	bindFlags(cmd, v)
	return v
}

func TestFlagDefaults(t *testing.T) {
	v := cmdWithViper(t)

	if v.GetInt("galactic_router.bgp_listen_port") != 179 {
		t.Errorf("bgp_listen_port default = %d, want 179", v.GetInt("galactic_router.bgp_listen_port"))
	}
	if v.GetInt("galactic_router.gobgp_grpc_port") != defaultGrpcPort {
		t.Errorf("gobgp_grpc_port default = %d, want %d", v.GetInt("galactic_router.gobgp_grpc_port"), defaultGrpcPort)
	}
	if v.GetBool("galactic_router.gobgp_grpc_server_enabled") != false {
		t.Errorf("gobgp_grpc_server_enabled default = %v, want false", v.GetBool("galactic_router.gobgp_grpc_server_enabled"))
	}
	if v.GetInt("galactic_router.metrics_port") != 8080 {
		t.Errorf("metrics_port default = %d, want 8080", v.GetInt("galactic_router.metrics_port"))
	}
	if v.GetInt("galactic_router.grpc_health_port") != 5000 {
		t.Errorf("grpc_health_port default = %d, want 5000", v.GetInt("galactic_router.grpc_health_port"))
	}
}

func TestRequiredFlags(t *testing.T) {
	v := cmdWithViper(t)
	err := validateConfig(v)
	if err == nil {
		t.Error("validateConfig with empty node-name and router-role returned nil error")
	}
}

func TestEnvVarDefaults(t *testing.T) {
	t.Setenv("NODE_NAME", "test-node")
	t.Setenv("ROUTER_ROLE", "tenant")
	t.Setenv("GALACTIC_GOBGP_GRPC_SERVER_ENABLED", "false")

	v := cmdWithViper(t)
	if err := validateConfig(v); err != nil {
		t.Errorf("validateConfig with valid env vars: %v", err)
	}
}

func TestGRPCPortEnvVar(t *testing.T) {
	t.Setenv("NODE_NAME", "test-node")
	t.Setenv("ROUTER_ROLE", "tenant")
	t.Setenv("GALACTIC_GOBGP_GRPC_SERVER_ENABLED", "true")
	t.Setenv("GALACTIC_GOBGP_GRPC_PORT", "9999")

	v := cmdWithViper(t)
	if err := validateConfig(v); err != nil {
		t.Errorf("validateConfig with GALACTIC_GOBGP_GRPC_PORT=9999: %v", err)
	}
}

func TestFlagOverridesEnv(t *testing.T) {
	t.Setenv("GALACTIC_GOBGP_GRPC_PORT", "9999")

	v := cmdWithViper(t)
	// Simulate a flag override by setting the viper key directly (v.Set
	// has higher precedence than env vars in viper).
	v.Set("galactic_router.gobgp_grpc_port", 12345)
	if got := v.GetInt("galactic_router.gobgp_grpc_port"); got != 12345 {
		t.Errorf("flag override: got %d, want 12345", got)
	}
}

func TestEnvVarOnly(t *testing.T) {
	t.Setenv("NODE_NAME", "env-node")
	t.Setenv("ROUTER_ROLE", "tenant")
	t.Setenv("GALACTIC_GOBGP_GRPC_SERVER_ENABLED", "true")
	t.Setenv("GALACTIC_GOBGP_GRPC_PORT", "7777")

	v := cmdWithViper(t)
	if v.GetString("galactic_router.node_name") != "env-node" {
		t.Errorf("node_name from env = %q, want %q", v.GetString("galactic_router.node_name"), "env-node")
	}
	if v.GetInt("galactic_router.gobgp_grpc_port") != 7777 {
		t.Errorf("gobgp_grpc_port from env = %d, want 7777", v.GetInt("galactic_router.gobgp_grpc_port"))
	}
}

func TestInvalidRouterRole(t *testing.T) {
	t.Setenv("NODE_NAME", "test-node")
	t.Setenv("ROUTER_ROLE", "invalid")

	v := cmdWithViper(t)
	err := validateConfig(v)
	if err == nil {
		t.Error("validateConfig with invalid router role returned nil error")
	}
}

func TestGRPCPortOverflow(t *testing.T) {
	t.Setenv("NODE_NAME", "test-node")
	t.Setenv("ROUTER_ROLE", "tenant")
	t.Setenv("GALACTIC_GOBGP_GRPC_SERVER_ENABLED", "true")
	t.Setenv("GALACTIC_GOBGP_GRPC_PORT", "70000")

	v := cmdWithViper(t)
	err := validateConfig(v)
	if err == nil {
		t.Error("validateConfig with port 70000 returned nil error")
	}
}

func TestGRPCPortZero(t *testing.T) {
	t.Setenv("NODE_NAME", "test-node")
	t.Setenv("ROUTER_ROLE", "tenant")
	t.Setenv("GALACTIC_GOBGP_GRPC_SERVER_ENABLED", "true")
	t.Setenv("GALACTIC_GOBGP_GRPC_PORT", "0")

	v := cmdWithViper(t)
	err := validateConfig(v)
	if err == nil {
		t.Error("validateConfig with port 0 returned nil error")
	}
}

func TestBGPListenPortMinusOne(t *testing.T) {
	t.Setenv("NODE_NAME", "test-node")
	t.Setenv("ROUTER_ROLE", "tenant")
	t.Setenv("BGP_LISTEN_PORT", "-1")

	v := cmdWithViper(t)
	if err := validateConfig(v); err != nil {
		t.Errorf("validateConfig with BGP_LISTEN_PORT=-1: %v", err)
	}
}

func TestBGPListenPortOverflow(t *testing.T) {
	t.Setenv("NODE_NAME", "test-node")
	t.Setenv("ROUTER_ROLE", "tenant")
	t.Setenv("BGP_LISTEN_PORT", "70000")

	v := cmdWithViper(t)
	err := validateConfig(v)
	if err == nil {
		t.Error("validateConfig with BGP_LISTEN_PORT=70000 returned nil error")
	}
}

func TestNodeNameRequired(t *testing.T) {
	v := cmdWithViper(t)
	err := validateConfig(v)
	if err == nil {
		t.Error("validateConfig with empty node-name returned nil error")
	}
}

func TestRouterRoleRequired(t *testing.T) {
	t.Setenv("NODE_NAME", "test-node")
	// ROUTER_ROLE unset

	v := cmdWithViper(t)
	err := validateConfig(v)
	if err == nil {
		t.Error("validateConfig with empty router-role returned nil error")
	}
}

func TestValidRoles(t *testing.T) {
	for _, role := range []string{"tenant", "fabric"} {
		t.Run(role, func(t *testing.T) {
			t.Setenv("NODE_NAME", "test-node")
			t.Setenv("ROUTER_ROLE", role)
			t.Setenv("GALACTIC_GOBGP_GRPC_SERVER_ENABLED", "false")

			v := cmdWithViper(t)
			// Verify the role is read correctly.
			if v.GetString("galactic_router.router_role") != role {
				t.Errorf("router_role = %q, want %q", v.GetString("galactic_router.router_role"), role)
			}
			// Verify validation passes.
			if err := validateConfig(v); err != nil {
				t.Errorf("validateConfig with role %q: %v", role, err)
			}
		})
	}
}

func TestMetricsPortOverride(t *testing.T) {
	t.Setenv("NODE_NAME", "test-node")
	t.Setenv("ROUTER_ROLE", "tenant")
	t.Setenv("METRICS_PORT", "9090")

	v := cmdWithViper(t)
	if v.GetInt("galactic_router.metrics_port") != 9090 {
		t.Errorf("metrics_port = %d, want 9090", v.GetInt("galactic_router.metrics_port"))
	}
}

func TestGRPCHealthPortOverride(t *testing.T) {
	t.Setenv("NODE_NAME", "test-node")
	t.Setenv("ROUTER_ROLE", "tenant")
	t.Setenv("GRPC_HEALTH_PORT", "9091")

	v := cmdWithViper(t)
	if v.GetInt("galactic_router.grpc_health_port") != 9091 {
		t.Errorf("grpc_health_port = %d, want 9091", v.GetInt("galactic_router.grpc_health_port"))
	}
}

func TestGRPCServerEnabled(t *testing.T) {
	t.Setenv("NODE_NAME", "test-node")
	t.Setenv("ROUTER_ROLE", "tenant")
	t.Setenv("GALACTIC_GOBGP_GRPC_SERVER_ENABLED", "true")
	t.Setenv("GALACTIC_GOBGP_GRPC_PORT", "50051")

	v := cmdWithViper(t)
	if !v.GetBool("galactic_router.gobgp_grpc_server_enabled") {
		t.Error("gobgp_grpc_server_enabled should be true")
	}
	if v.GetInt("galactic_router.gobgp_grpc_port") != 50051 {
		t.Errorf("gobgp_grpc_port = %d, want 50051", v.GetInt("galactic_router.gobgp_grpc_port"))
	}
}

func TestGRPCServerDisabled(t *testing.T) {
	t.Setenv("NODE_NAME", "test-node")
	t.Setenv("ROUTER_ROLE", "tenant")
	t.Setenv("GALACTIC_GOBGP_GRPC_SERVER_ENABLED", "false")
	t.Setenv("GALACTIC_GOBGP_GRPC_PORT", "9999")

	v := cmdWithViper(t)
	if v.GetBool("galactic_router.gobgp_grpc_server_enabled") {
		t.Error("gobgp_grpc_server_enabled should be false")
	}
}

func TestVersionFlag(t *testing.T) {
	if metadata.Version == "" {
		t.Error("metadata.Version should not be empty")
	}
}

func TestDefaults(t *testing.T) {
	// Clear all relevant env vars.
	_ = os.Unsetenv("NODE_NAME")
	_ = os.Unsetenv("ROUTER_ROLE")
	_ = os.Unsetenv("BGP_LISTEN_PORT")
	_ = os.Unsetenv("BGP_LOCAL_ADDRESS")
	_ = os.Unsetenv("GALACTIC_GOBGP_GRPC_SERVER_ENABLED")
	_ = os.Unsetenv("GALACTIC_GOBGP_GRPC_PORT")
	_ = os.Unsetenv("METRICS_PORT")
	_ = os.Unsetenv("GRPC_HEALTH_PORT")

	v := cmdWithViper(t)

	if v.GetInt("galactic_router.bgp_listen_port") != 179 {
		t.Errorf("bgp_listen_port = %d, want 179", v.GetInt("galactic_router.bgp_listen_port"))
	}
	if v.GetInt("galactic_router.gobgp_grpc_port") != defaultGrpcPort {
		t.Errorf("gobgp_grpc_port = %d, want %d", v.GetInt("galactic_router.gobgp_grpc_port"), defaultGrpcPort)
	}
	if v.GetBool("galactic_router.gobgp_grpc_server_enabled") != false {
		t.Error("gobgp_grpc_server_enabled default should be false")
	}
	if v.GetInt("galactic_router.metrics_port") != 8080 {
		t.Errorf("metrics_port = %d, want 8080", v.GetInt("galactic_router.metrics_port"))
	}
	if v.GetInt("galactic_router.grpc_health_port") != 5000 {
		t.Errorf("grpc_health_port = %d, want 5000", v.GetInt("galactic_router.grpc_health_port"))
	}
}
