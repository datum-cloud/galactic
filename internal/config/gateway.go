// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// --- Gateway defaults --------------------------------------------------

const (
	// DefaultGatewayMetricsPort and DefaultGatewayGRPCHealthPort differ from
	// every other galactic binary's ports. An edge node runs several of them as
	// separate host-network DaemonSet pods, all sharing that node's network
	// namespace regardless of pod boundaries, so no port any of them binds may
	// collide with another's.
	DefaultGatewayMetricsPort    = 8081
	DefaultGatewayGRPCHealthPort = 5181
)

// --- Gateway environment variable keys -----------------------------------

const (
	EnvGatewayNodeName       = "GALACTIC_GATEWAY_NODE_NAME"
	EnvGatewayMetricsPort    = "GALACTIC_GATEWAY_METRICS_PORT"
	EnvGatewayGRPCHealthPort = "GALACTIC_GATEWAY_GRPC_HEALTH_PORT"

	// EnvGatewayPublicInterface names this node's underlay-facing uplink for
	// the edge gateway datapath. Required: this binary only ever runs the
	// gateway role, so there is no "not this role, skip the datapath" case.
	EnvGatewayPublicInterface = "GALACTIC_GATEWAY_PUBLIC_INTERFACE"

	// EnvGatewaySRv6Address is this node's plain SRv6-reachable address, used
	// as the outer-header source for every packet this datapath forwards. It is
	// never a translation source and is never compared against anything on a
	// receive path. Required.
	EnvGatewaySRv6Address = "GALACTIC_GATEWAY_SRV6_ADDRESS"
)

// --- GatewayConfig -----------------------------------------------------

// GatewayConfig resolves galactic-gateway configuration with three-tier
// precedence: CLI flag, then environment variable, then compiled-in default.
// Create one with NewGatewayConfig, call BindFlags to layer CLI flags, then read
// the exported fields.
type GatewayConfig struct {
	v      *viper.Viper
	prefix string

	// Resolved fields.
	NodeName       string
	MetricsPort    int
	GRPCHealthPort int

	// PublicInterface and SRv6Address configure the edge gateway datapath. Both
	// are required; Validate rejects either being empty.
	PublicInterface string
	SRv6Address     string
}

// NewGatewayConfig creates a config resolver reading the GALACTIC_GATEWAY
// environment prefix. Exported fields are populated from the environment and
// defaults; call BindFlags to layer CLI overrides.
func NewGatewayConfig() *GatewayConfig {
	v := viper.New()
	v.SetEnvPrefix("GALACTIC_GATEWAY")
	v.AutomaticEnv()

	v.SetDefault(KeyNodeName, "")
	v.SetDefault(KeyMetricsPort, DefaultGatewayMetricsPort)
	v.SetDefault(KeyGRPCHealthPort, DefaultGatewayGRPCHealthPort)
	v.SetDefault("public_interface", "")
	v.SetDefault("srv6_address", "")

	cfg := &GatewayConfig{
		v:      v,
		prefix: "GALACTIC_GATEWAY",
	}
	cfg.readFields()
	return cfg
}

// BindFlags binds Cobra/pflag flags to the config resolver and re-reads the
// exported fields. Each flag is bound to a Viper key using the key argument.
func (c *GatewayConfig) BindFlags(flags *pflag.FlagSet) {
	bindings := []struct {
		flag string
		key  string
	}{
		{FlagNodeName, KeyNodeName},
		{FlagMetricsPort, KeyMetricsPort},
		{FlagGRPCHealthPort, KeyGRPCHealthPort},
		{"gateway-public-interface", "public_interface"},
		{"gateway-srv6-address", "srv6_address"},
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
func (c *GatewayConfig) readFields() {
	c.NodeName = c.v.GetString(KeyNodeName)
	c.MetricsPort = c.v.GetInt(KeyMetricsPort)
	c.GRPCHealthPort = c.v.GetInt(KeyGRPCHealthPort)
	c.PublicInterface = c.v.GetString("public_interface")
	c.SRv6Address = c.v.GetString("srv6_address")
}

// Validate checks that the required configuration fields are set.
func (c *GatewayConfig) Validate() error {
	if c.NodeName == "" {
		return fmt.Errorf("node name is required (use --node-name flag or %s env var)", EnvGatewayNodeName)
	}
	if c.PublicInterface == "" {
		return fmt.Errorf(
			"public interface is required (use --gateway-public-interface flag or %s env var)",
			EnvGatewayPublicInterface)
	}
	if c.SRv6Address == "" {
		return fmt.Errorf(
			"SRv6 address is required (use --gateway-srv6-address flag or %s env var)", EnvGatewaySRv6Address)
	}
	addr, err := netip.ParseAddr(c.SRv6Address)
	if err != nil {
		return fmt.Errorf("SRv6 address %q is not a valid IP address: %w", c.SRv6Address, err)
	}
	// The datapath catches the same thing eventually, but only after it has
	// been loaded and attached. Rejecting it at startup names the actual
	// problem instead of surfacing as a deeper kernel-datapath error.
	if !addr.Is6() || addr.Is4In6() {
		return fmt.Errorf("SRv6 address %q must be a native IPv6 address, not IPv4", c.SRv6Address)
	}
	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return errors.New(errMetricsPortRange)
	}
	if c.GRPCHealthPort < 1 || c.GRPCHealthPort > 65535 {
		return errors.New("grpc health port must be between 1 and 65535")
	}
	return nil
}
