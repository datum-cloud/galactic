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
	t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
	t.Setenv("GALACTIC_ROUTER_ROUTER_ROLE", "tenant")

	v := cmdWithViper(t)
	if err := validateConfig(v); err != nil {
		t.Errorf("validateConfig with valid env vars: %v", err)
	}
}

func TestInvalidRouterRole(t *testing.T) {
	t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
	t.Setenv("GALACTIC_ROUTER_ROUTER_ROLE", "invalid")

	v := cmdWithViper(t)
	err := validateConfig(v)
	if err == nil {
		t.Error("validateConfig with invalid router role returned nil error")
	}
}

func TestBGPListenPortMinusOne(t *testing.T) {
	t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
	t.Setenv("GALACTIC_ROUTER_ROUTER_ROLE", "tenant")
	t.Setenv("GALACTIC_ROUTER_BGP_LISTEN_PORT", "-1")

	v := cmdWithViper(t)
	if err := validateConfig(v); err != nil {
		t.Errorf("validateConfig with GALACTIC_ROUTER_BGP_LISTEN_PORT=-1: %v", err)
	}
}

func TestBGPListenPortOverflow(t *testing.T) {
	t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
	t.Setenv("GALACTIC_ROUTER_ROUTER_ROLE", "tenant")
	t.Setenv("GALACTIC_ROUTER_BGP_LISTEN_PORT", "70000")

	v := cmdWithViper(t)
	err := validateConfig(v)
	if err == nil {
		t.Error("validateConfig with GALACTIC_ROUTER_BGP_LISTEN_PORT=70000 returned nil error")
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
	t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
	// GALACTIC_ROUTER_ROUTER_ROLE unset

	v := cmdWithViper(t)
	err := validateConfig(v)
	if err == nil {
		t.Error("validateConfig with empty router-role returned nil error")
	}
}

func TestValidRoles(t *testing.T) {
	for _, role := range []string{"tenant", "fabric"} {
		t.Run(role, func(t *testing.T) {
			t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
			t.Setenv("GALACTIC_ROUTER_ROUTER_ROLE", role)

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
	t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
	t.Setenv("GALACTIC_ROUTER_ROUTER_ROLE", "tenant")
	t.Setenv("GALACTIC_ROUTER_METRICS_PORT", "9090")

	v := cmdWithViper(t)
	if v.GetInt("galactic_router.metrics_port") != 9090 {
		t.Errorf("metrics_port = %d, want 9090", v.GetInt("galactic_router.metrics_port"))
	}
}

func TestGRPCHealthPortOverride(t *testing.T) {
	t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
	t.Setenv("GALACTIC_ROUTER_ROUTER_ROLE", "tenant")
	t.Setenv("GALACTIC_ROUTER_GRPC_HEALTH_PORT", "9091")

	v := cmdWithViper(t)
	if v.GetInt("galactic_router.grpc_health_port") != 9091 {
		t.Errorf("grpc_health_port = %d, want 9091", v.GetInt("galactic_router.grpc_health_port"))
	}
}

func TestVersionFlag(t *testing.T) {
	if metadata.Version == "" {
		t.Error("metadata.Version should not be empty")
	}
}

func TestDefaults(t *testing.T) {
	// Clear all relevant env vars.
	_ = os.Unsetenv("GALACTIC_ROUTER_NODE_NAME")
	_ = os.Unsetenv("GALACTIC_ROUTER_ROUTER_ROLE")
	_ = os.Unsetenv("GALACTIC_ROUTER_BGP_LISTEN_PORT")
	_ = os.Unsetenv("GALACTIC_ROUTER_BGP_LOCAL_ADDRESS")
	_ = os.Unsetenv("GALACTIC_ROUTER_METRICS_PORT")
	_ = os.Unsetenv("GALACTIC_ROUTER_GRPC_HEALTH_PORT")

	v := cmdWithViper(t)

	if v.GetInt("galactic_router.bgp_listen_port") != 179 {
		t.Errorf("bgp_listen_port = %d, want 179", v.GetInt("galactic_router.bgp_listen_port"))
	}
	if v.GetInt("galactic_router.metrics_port") != 8080 {
		t.Errorf("metrics_port = %d, want 8080", v.GetInt("galactic_router.metrics_port"))
	}
	if v.GetInt("galactic_router.grpc_health_port") != 5000 {
		t.Errorf("grpc_health_port = %d, want 5000", v.GetInt("galactic_router.grpc_health_port"))
	}
}
