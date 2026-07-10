// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"os"
	"strings"
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
	t.Setenv("GALACTIC_ROUTER_ROUTER_MODE", "tenant")

	v := cmdWithViper(t)
	if err := validateConfig(v); err != nil {
		t.Errorf("validateConfig with valid env vars: %v", err)
	}
}

func TestInvalidMode(t *testing.T) {
	t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
	t.Setenv("GALACTIC_ROUTER_ROUTER_MODE", "invalid")

	v := cmdWithViper(t)
	err := validateConfig(v)
	if err == nil {
		t.Error("validateConfig with invalid mode returned nil error")
	}
}

func TestBGPListenPortMinusOne(t *testing.T) {
	t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
	t.Setenv("GALACTIC_ROUTER_ROUTER_MODE", "tenant")
	t.Setenv("GALACTIC_ROUTER_BGP_LISTEN_PORT", "-1")

	v := cmdWithViper(t)
	if err := validateConfig(v); err != nil {
		t.Errorf("validateConfig with GALACTIC_ROUTER_BGP_LISTEN_PORT=-1: %v", err)
	}
}

func TestBGPListenPortOverflow(t *testing.T) {
	t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
	t.Setenv("GALACTIC_ROUTER_ROUTER_MODE", "tenant")
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

func TestModeRequired(t *testing.T) {
	t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
	// GALACTIC_ROUTER_ROUTER_MODE unset

	v := cmdWithViper(t)
	err := validateConfig(v)
	if err == nil {
		t.Error("validateConfig with empty mode returned nil error")
	}
	if err != nil && !strings.Contains(err.Error(), "--mode is required") {
		t.Errorf("expected --mode required error, got: %v", err)
	}
}

func TestValidModes(t *testing.T) {
	for _, mode := range []string{"transit", "fabric", "tenant"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
			t.Setenv("GALACTIC_ROUTER_ROUTER_MODE", mode)

			v := cmdWithViper(t)
			// Verify the mode is read correctly.
			if v.GetString("galactic_router.router_mode") != mode {
				t.Errorf("router_mode = %q, want %q", v.GetString("galactic_router.router_mode"), mode)
			}
			// Verify validation passes.
			if err := validateConfig(v); err != nil {
				t.Errorf("validateConfig with mode %q: %v", mode, err)
			}
		})
	}
}

func TestReflectorInvalidMode(t *testing.T) {
	t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
	t.Setenv("GALACTIC_ROUTER_ROUTER_MODE", "transit")

	v := cmdWithViper(t)
	// Simulate --reflector being set via flag.
	cmd := &cobra.Command{Use: "test"}
	bindFlags(cmd, v)
	//nolint:errcheck // flag exists, setting it is safe
	cmd.Flags().Set("reflector", "true")
	_ = v.BindPFlags(cmd.Flags())

	err := validateConfig(v)
	if err == nil {
		t.Error("validateConfig with --reflector and --mode=transit returned nil error")
	}
	if err != nil && !strings.Contains(err.Error(), "--reflector is only valid") {
		t.Errorf("expected --reflector validation error, got: %v", err)
	}
}

func TestMetricsPortOverride(t *testing.T) {
	t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
	t.Setenv("GALACTIC_ROUTER_ROUTER_MODE", "tenant")
	t.Setenv("GALACTIC_ROUTER_METRICS_PORT", "9090")

	v := cmdWithViper(t)
	if v.GetInt("galactic_router.metrics_port") != 9090 {
		t.Errorf("metrics_port = %d, want 9090", v.GetInt("galactic_router.metrics_port"))
	}
}

func TestGRPCHealthPortOverride(t *testing.T) {
	t.Setenv("GALACTIC_ROUTER_NODE_NAME", "test-node")
	t.Setenv("GALACTIC_ROUTER_ROUTER_MODE", "tenant")
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
	_ = os.Unsetenv("GALACTIC_ROUTER_ROUTER_MODE")
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
