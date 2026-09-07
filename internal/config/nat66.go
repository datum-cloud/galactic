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

// --- NAT66 defaults ---------------------------------------------------

const (
	// DefaultNAT66MetricsPort and DefaultNAT66GRPCHealthPort are the next unused
	// values past every other host-network process on a node. This binary runs
	// on the same nodes as the router and CNI and disjoint from the gateway's,
	// but a node's role labels are not mutually exclusive by construction, so
	// these avoid every value already claimed rather than assume no overlap.
	DefaultNAT66MetricsPort    = 9182
	DefaultNAT66GRPCHealthPort = 5182
)

// --- NAT66 environment variable keys ------------------------------------

const (
	EnvNAT66NodeName       = "GALACTIC_NAT66_NODE_NAME"
	EnvNAT66MetricsPort    = "GALACTIC_NAT66_METRICS_PORT"
	EnvNAT66GRPCHealthPort = "GALACTIC_NAT66_GRPC_HEALTH_PORT"

	// EnvNAT66UplinkInterface names this shard's fabric-facing uplink, the
	// interface the NAT66 XDP program attaches to. Required: this binary only
	// ever runs as a dedicated shard, so there is no "not this role, skip the
	// datapath" case.
	EnvNAT66UplinkInterface = "GALACTIC_NAT66_UPLINK_INTERFACE"

	// EnvNAT66ShardSID is this shard's own SRv6 uSID, the outer destination a
	// tenant's egress packet is encapsulated toward. Required, and
	// operator-supplied: no in-cluster mechanism derives it yet, the same gap
	// the router locator and the gateway address both have.
	EnvNAT66ShardSID = "GALACTIC_NAT66_SHARD_SID"

	// EnvNAT66ShardPubAddr is this shard's publicly routable masquerade source.
	// Every flow this shard translates is given an address and port within it.
	// Required.
	EnvNAT66ShardPubAddr = "GALACTIC_NAT66_SHARD_PUB_ADDR"
)

// --- NAT66Config ---------------------------------------------------------

// NAT66Config resolves galactic-nat66 configuration with three-tier precedence:
// CLI flag, then environment variable, then compiled-in default. Create one with
// NewNAT66Config, call BindFlags to layer CLI flags, then read the exported
// fields.
type NAT66Config struct {
	v      *viper.Viper
	prefix string

	// Resolved fields.
	NodeName       string
	MetricsPort    int
	GRPCHealthPort int

	// UplinkInterface, ShardSID, and ShardPubAddr configure the egress shard
	// datapath. All three are required; Validate rejects any being empty.
	UplinkInterface string
	ShardSID        string
	ShardPubAddr    string
}

// NewNAT66Config creates a config resolver reading the GALACTIC_NAT66
// environment prefix. Exported fields are populated from the environment and
// defaults; call BindFlags to layer CLI overrides.
func NewNAT66Config() *NAT66Config {
	v := viper.New()
	v.SetEnvPrefix("GALACTIC_NAT66")
	v.AutomaticEnv()

	v.SetDefault(KeyNodeName, "")
	v.SetDefault(KeyMetricsPort, DefaultNAT66MetricsPort)
	v.SetDefault(KeyGRPCHealthPort, DefaultNAT66GRPCHealthPort)
	v.SetDefault("uplink_interface", "")
	v.SetDefault("shard_sid", "")
	v.SetDefault("shard_pub_addr", "")

	cfg := &NAT66Config{
		v:      v,
		prefix: "GALACTIC_NAT66",
	}
	cfg.readFields()
	return cfg
}

// BindFlags binds the CLI flags to the config resolver and re-reads the
// exported fields.
func (c *NAT66Config) BindFlags(flags *pflag.FlagSet) {
	bindings := []struct {
		flag string
		key  string
	}{
		{FlagNodeName, KeyNodeName},
		{FlagMetricsPort, KeyMetricsPort},
		{FlagGRPCHealthPort, KeyGRPCHealthPort},
		{"nat66-uplink-interface", "uplink_interface"},
		{"nat66-shard-sid", "shard_sid"},
		{"nat66-shard-pub-addr", "shard_pub_addr"},
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
func (c *NAT66Config) readFields() {
	c.NodeName = c.v.GetString(KeyNodeName)
	c.MetricsPort = c.v.GetInt(KeyMetricsPort)
	c.GRPCHealthPort = c.v.GetInt(KeyGRPCHealthPort)
	c.UplinkInterface = c.v.GetString("uplink_interface")
	c.ShardSID = c.v.GetString("shard_sid")
	c.ShardPubAddr = c.v.GetString("shard_pub_addr")
}

// validateShardAddr parses and range-checks a shard identity address, rejecting
// anything that is not a native IPv6 address.
//
// The map layer catches the same thing eventually, but only after the datapath
// has been loaded and attached. Rejecting it at startup names the actual field
// instead of surfacing as a deeper kernel-datapath error.
func validateShardAddr(field, value string) error {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return fmt.Errorf("%s %q is not a valid IP address: %w", field, value, err)
	}
	if !addr.Is6() || addr.Is4In6() {
		return fmt.Errorf("%s %q must be a native IPv6 address, not IPv4", field, value)
	}
	return nil
}

// Validate checks that the required configuration fields are set.
func (c *NAT66Config) Validate() error {
	if c.NodeName == "" {
		return fmt.Errorf("node name is required (use --node-name flag or %s env var)", EnvNAT66NodeName)
	}
	if c.UplinkInterface == "" {
		return fmt.Errorf(
			"uplink interface is required (use --nat66-uplink-interface flag or %s env var)", EnvNAT66UplinkInterface)
	}
	if c.ShardSID == "" {
		return fmt.Errorf(
			"shard SID is required (use --nat66-shard-sid flag or %s env var)", EnvNAT66ShardSID)
	}
	if err := validateShardAddr("shard SID", c.ShardSID); err != nil {
		return err
	}
	if c.ShardPubAddr == "" {
		return fmt.Errorf(
			"shard public address is required (use --nat66-shard-pub-addr flag or %s env var)", EnvNAT66ShardPubAddr)
	}
	if err := validateShardAddr("shard public address", c.ShardPubAddr); err != nil {
		return err
	}
	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return errors.New("metrics port must be between 1 and 65535")
	}
	if c.GRPCHealthPort < 1 || c.GRPCHealthPort > 65535 {
		return errors.New("grpc health port must be between 1 and 65535")
	}
	return nil
}
