// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// --- Router defaults -------------------------------------------------------

const (
	DefaultRouterBGPListenPort  = 179
	DefaultRouterMetricsPort    = 8080
	DefaultRouterGRPCHealthPort = 5000
	DefaultRouterGCNamespace    = "galactic-system"
	DefaultRouterGCInterval     = 5 * time.Minute
)

// --- Router environment variable keys --------------------------------------

const (
	EnvRouterNodeName       = "GALACTIC_ROUTER_NODE_NAME"
	EnvRouterMode           = "GALACTIC_ROUTER_ROUTER_MODE"
	EnvRouterReflector      = "GALACTIC_ROUTER_REFLECTOR"
	EnvRouterBGPListenPort  = "GALACTIC_ROUTER_BGP_LISTEN_PORT"
	EnvRouterBGPLocalAddr   = "GALACTIC_ROUTER_BGP_LOCAL_ADDRESS"
	EnvRouterMetricsPort    = "GALACTIC_ROUTER_METRICS_PORT"
	EnvRouterGRPCHealthPort = "GALACTIC_ROUTER_GRPC_HEALTH_PORT"
	EnvRouterGCNamespace    = "GALACTIC_ROUTER_GC_NAMESPACE"
	EnvRouterGCInterval     = "GALACTIC_ROUTER_GC_INTERVAL"
)

// --- Router mode constants -------------------------------------------------

const (
	ModeTransit = "transit"
	ModeFabric  = "fabric"
	ModeTenant  = "tenant"
)

// --- RouterConfig ----------------------------------------------------------

// RouterConfig resolves router configuration with three-tier precedence: CLI
// flag > env var > compiled-in default. Create once via NewRouterConfig(),
// call BindFlags() to layer CLI flags, then read the exported fields.
type RouterConfig struct {
	v      *viper.Viper
	prefix string

	// Resolved fields.
	NodeName       string
	Mode           string
	Reflector      bool
	BGPListenPort  int
	BGPLocalAddr   string
	MetricsPort    int
	GRPCHealthPort int
	GCNamespace    string
	GCInterval     time.Duration
}

// NewRouterConfig creates a router config resolver with the GALACTIC_ROUTER
// env prefix and AutomaticEnv enabled. Exported fields are populated from env
// vars and defaults; call BindFlags() to layer CLI overrides.
func NewRouterConfig() *RouterConfig {
	v := viper.New()
	v.SetEnvPrefix("GALACTIC_ROUTER")
	v.AutomaticEnv()

	v.SetDefault("node_name", "")
	v.SetDefault("router_mode", "")
	v.SetDefault("reflector", false)
	v.SetDefault("bgp_listen_port", DefaultRouterBGPListenPort)
	v.SetDefault("bgp_local_address", "")
	v.SetDefault("metrics_port", DefaultRouterMetricsPort)
	v.SetDefault("grpc_health_port", DefaultRouterGRPCHealthPort)
	v.SetDefault("gc_namespace", DefaultRouterGCNamespace)
	v.SetDefault("gc_interval", DefaultRouterGCInterval.String())

	cfg := &RouterConfig{
		v:      v,
		prefix: "GALACTIC_ROUTER",
	}
	cfg.readFields()
	return cfg
}

// BindFlags binds Cobra/pflag flags to the config resolver and re-reads the
// exported fields. Each flag is bound to a Viper key using the key argument.
func (c *RouterConfig) BindFlags(flags *pflag.FlagSet) {
	bindings := []struct {
		flag string
		key  string
	}{
		{"node-name", "node_name"},
		{"mode", "router_mode"},
		{"reflector", "reflector"},
		{"bgp-listen-port", "bgp_listen_port"},
		{"bgp-local-address", "bgp_local_address"},
		{"metrics-port", "metrics_port"},
		{"grpc-health-port", "grpc_health_port"},
		{"gc-namespace", "gc_namespace"},
		{"gc-interval", "gc_interval"},
	}
	for _, b := range bindings {
		if flags.Changed(b.flag) {
			c.v.Set(b.key, flags.Lookup(b.flag).Value.String())
		} else {
			//nolint:errcheck // controlled keys, BindPFlag cannot fail here
			c.v.BindPFlag(b.key, flags.Lookup(b.flag))
		}
	}
	c.readFields()
}

// readFields populates the exported fields from the current Viper state.
func (c *RouterConfig) readFields() {
	c.NodeName = c.v.GetString("node_name")
	c.Mode = c.v.GetString("router_mode")
	c.Reflector = c.v.GetBool("reflector")
	c.BGPListenPort = c.v.GetInt("bgp_listen_port")
	c.BGPLocalAddr = c.v.GetString("bgp_local_address")
	c.MetricsPort = c.v.GetInt("metrics_port")
	c.GRPCHealthPort = c.v.GetInt("grpc_health_port")
	c.GCNamespace = c.v.GetString("gc_namespace")
	c.GCInterval = c.v.GetDuration("gc_interval")
}

// Validate checks that the required configuration fields are set and that
// mode/reflector constraints are satisfied.
func (c *RouterConfig) Validate() error {
	if c.NodeName == "" {
		return fmt.Errorf("node name is required (use --node-name flag or %s env var)", EnvRouterNodeName)
	}
	if c.Mode == "" {
		return fmt.Errorf("router mode is required (use --mode flag or %s env var)", EnvRouterMode)
	}
	switch c.Mode {
	case ModeTransit, ModeFabric, ModeTenant:
	default:
		return fmt.Errorf("invalid router mode %q: must be %s, %s, or %s",
			c.Mode, ModeTransit, ModeFabric, ModeTenant)
	}
	if c.Reflector && c.Mode != ModeFabric && c.Mode != ModeTenant {
		return fmt.Errorf("route reflector mode requires --mode=%s or --mode=%s", ModeFabric, ModeTenant)
	}
	if c.BGPListenPort != -1 && (c.BGPListenPort < 1 || c.BGPListenPort > 65535) {
		return errors.New("bgp listen port must be between 1 and 65535, or -1 for outbound-only mode")
	}
	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return errors.New("metrics port must be between 1 and 65535")
	}
	if c.GRPCHealthPort < 1 || c.GRPCHealthPort > 65535 {
		return errors.New("grpc health port must be between 1 and 65535")
	}
	return nil
}
