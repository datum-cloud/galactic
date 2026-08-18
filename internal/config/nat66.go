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
	// DefaultNAT66MetricsPort/DefaultNAT66GRPCHealthPort are the next
	// unused values past every other hostNetwork: true galactic-* process
	// already running on a node: fabric-router's BGP listener (179),
	// galactic-router's grpc-health/metrics (5179/9179), galactic-cni's
	// (5180/9180), and galactic-gateway's (5181/8081 -- see
	// internal/config/gateway.go's own doc comment for why that pair
	// isn't a clean continuation of the 517x/917x pattern). galactic-nat66
	// is deployed on its own dedicated, hostNetwork: true shard nodes
	// (config/galactic-nat66/base/daemonset.yaml) -- disjoint from
	// galactic-gateway's own gateway-role nodes -- but a node's role
	// labels are not mutually exclusive by construction, so these still
	// avoid every value already claimed above rather than assuming no
	// overlap will ever happen.
	DefaultNAT66MetricsPort    = 9182
	DefaultNAT66GRPCHealthPort = 5182
)

// --- NAT66 environment variable keys ------------------------------------

const (
	EnvNAT66NodeName       = "GALACTIC_NAT66_NODE_NAME"
	EnvNAT66MetricsPort    = "GALACTIC_NAT66_METRICS_PORT"
	EnvNAT66GRPCHealthPort = "GALACTIC_NAT66_GRPC_HEALTH_PORT"

	// EnvNAT66UplinkInterface names this shard's single fabric-facing
	// uplink interface -- the interface
	// internal/plumbing/ebpf/nat66prog's XDP program attaches to. Required:
	// galactic-nat66 only ever runs as a dedicated NAT66 shard, so there is
	// no "not this role, skip the datapath" case to support, mirroring
	// config.EnvGatewayPublicInterface's identical reasoning.
	EnvNAT66UplinkInterface = "GALACTIC_NAT66_UPLINK_INTERFACE"

	// EnvNAT66ShardSID is this shard's own SRv6 uSID
	// (network.datumapis.com/v1alpha1's NAT66ShardStatus.ShardSID) --
	// the outer destination a tenant's egress packet is encapsulated
	// toward. Required -- see EnvNAT66UplinkInterface. Operator-supplied
	// today (no in-cluster derivation mechanism yet -- the same gap
	// BGPRouter.Spec.SRv6Locator/NodeID assignment and
	// GALACTIC_GATEWAY_SRV6_ADDRESS both have today; see
	// docs/agents/ARCHITECTURE-GATEWAY.md's "Argument-0 reservation"
	// section for the established precedent this follows).
	EnvNAT66ShardSID = "GALACTIC_NAT66_SHARD_SID"

	// EnvNAT66ShardPubAddr is this shard's own publicly-routable
	// masquerade source address (NAT66ShardStatus.ShardAddress) -- every
	// flow this shard NATs is SNAT'd to an address:port within it.
	// Required -- see EnvNAT66UplinkInterface.
	EnvNAT66ShardPubAddr = "GALACTIC_NAT66_SHARD_PUB_ADDR"
)

// --- NAT66Config ---------------------------------------------------------

// NAT66Config resolves galactic-nat66 configuration with three-tier
// precedence: CLI flag > env var > compiled-in default. Create once via
// NewNAT66Config(), call BindFlags() to layer CLI flags, then read the
// exported fields.
type NAT66Config struct {
	v      *viper.Viper
	prefix string

	// Resolved fields.
	NodeName       string
	MetricsPort    int
	GRPCHealthPort int

	// UplinkInterface/ShardSID/ShardPubAddr configure the NAT66 egress
	// shard datapath -- see EnvNAT66UplinkInterface's doc comment. All
	// three required; NAT66Config.Validate rejects any being empty.
	UplinkInterface string
	ShardSID        string
	ShardPubAddr    string
}

// NewNAT66Config creates a NAT66 config resolver with the GALACTIC_NAT66
// env prefix and AutomaticEnv enabled. Exported fields are populated from
// env vars and defaults; call BindFlags() to layer CLI overrides.
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

// BindFlags binds Cobra/pflag flags to the config resolver and re-reads
// the exported fields. Each flag is bound to a Viper key using the key
// argument.
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

// validateShardAddr parses and range-checks a shard identity address
// (ShardSID or ShardPubAddr), rejecting anything that isn't a native
// IPv6 address -- caught eventually anyway by
// internal/plumbing/ebpf/nat66map's identical check, but late: only once
// setupNat66Datapath has already loaded and attached the eBPF datapath.
// Reject it here instead, at startup, with a message that names the
// actual field rather than surfacing as a deeper, less obvious
// kernel-datapath error -- mirrors GatewayConfig.Validate's identical
// SRv6Address check.
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
