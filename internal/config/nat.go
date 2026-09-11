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

// --- NAT defaults -----------------------------------------------------

const (
	// DefaultNATMetricsPort and DefaultNATGRPCHealthPort are the next unused
	// values past every other host-network process on a node. This binary runs
	// on the same nodes as the router and CNI and disjoint from the gateway's,
	// but a node's role labels are not mutually exclusive by construction, so
	// these avoid every value already claimed rather than assume no overlap.
	DefaultNATMetricsPort    = 9182
	DefaultNATGRPCHealthPort = 5182

	// DefaultNATSessionLimit is the per-tenant translated-session ceiling a
	// shard applies when the operator sets none. Zero means unlimited, which is
	// deliberately the default: a limit that arrives without an operator
	// choosing it turns into an outage nobody can explain, since this design
	// collects the admission-failure counters but does not yet surface them
	// anywhere a tenant or an on-call engineer can read.
	DefaultNATSessionLimit = 0

	// DefaultNAT64PrefixLen is the only NAT64 prefix length the datapath
	// supports; see natmap's own constant for why a /96 specifically.
	DefaultNAT64PrefixLen = 96
)

// --- NAT environment variable keys ------------------------------------

const (
	EnvNATNodeName       = "GALACTIC_NAT_NODE_NAME"
	EnvNATMetricsPort    = "GALACTIC_NAT_METRICS_PORT"
	EnvNATGRPCHealthPort = "GALACTIC_NAT_GRPC_HEALTH_PORT"

	// EnvNATUplinkInterface names this shard's fabric-facing uplink, the
	// interface the XDP datapath attaches to. Required: this binary only ever
	// runs as a dedicated shard, so there is no "not this role, skip the
	// datapath" case.
	EnvNATUplinkInterface = "GALACTIC_NAT_UPLINK_INTERFACE"

	// EnvNATShardSID is this shard's own SRv6 uSID, the outer destination a
	// tenant's egress packet is encapsulated toward. Required, and
	// operator-supplied: no in-cluster mechanism derives it yet, the same gap
	// the router locator and the gateway address both have.
	//
	// One SID serves both address families. Which translation a packet gets is
	// decided from its inner destination, so enabling NAT64 on a shard needs no
	// second SID and no second route on any tenant VRF.
	EnvNATShardSID = "GALACTIC_NAT_SHARD_SID"

	// EnvNATShardPubAddr is this shard's publicly routable IPv6 masquerade
	// source. Every NAT66 flow this shard translates is given an address and
	// port within it. Optional: a shard may serve NAT64 alone.
	EnvNATShardPubAddr = "GALACTIC_NAT_SHARD_PUB_ADDR"

	// EnvNATShardPubAddr4 is this shard's publicly routable IPv4 masquerade
	// source, the address an IPv4-only destination sees. Setting it, together
	// with a NAT64 prefix, is what turns NAT64 on for this shard.
	//
	// Unlike the IPv6 address, nothing in this repo makes it reachable: a NAT64
	// reply arrives from the IPv4 internet, so the underlay or an upstream
	// announcement has to attract this address to this node. Setting it here
	// without that in place produces a shard that translates outbound traffic
	// and never sees a single reply.
	EnvNATShardPubAddr4 = "GALACTIC_NAT_SHARD_PUB_ADDR4"

	// EnvNAT64Prefix is the IPv6 /96 whose synthesized addresses this shard
	// translates to IPv4 -- one Datum-operated Network-Specific Prefix, shared
	// fabric-wide, never per-tenant. Required whenever the IPv4 address is set.
	//
	// It must be the same value DNS64 synthesizes into. A shard translating for
	// a different prefix than the resolver hands out is a blackhole with no
	// symptom on either side, which is why this value is echoed into
	// EgressShard status rather than living only here.
	EnvNAT64Prefix = "GALACTIC_NAT_NAT64_PREFIX"

	// EnvNATSessionLimit caps how many translated sessions one tenant may hold
	// on this shard, across both address families. Zero means unlimited.
	EnvNATSessionLimit = "GALACTIC_NAT_SESSION_LIMIT"
)

// --- NATConfig ---------------------------------------------------------

// NATConfig resolves galactic-nat configuration with three-tier precedence:
// CLI flag, then environment variable, then compiled-in default. Create one with
// NewNATConfig, call BindFlags to layer CLI flags, then read the exported
// fields.
type NATConfig struct {
	v      *viper.Viper
	prefix string

	// Resolved fields.
	NodeName       string
	MetricsPort    int
	GRPCHealthPort int

	// UplinkInterface and ShardSID configure the shard's identity and are
	// always required.
	UplinkInterface string
	ShardSID        string

	// ShardPubAddr enables NAT66; ShardPubAddr4 with NAT64Prefix enables NAT64.
	// Validate requires at least one family, and rejects half of either.
	ShardPubAddr  string
	ShardPubAddr4 string
	NAT64Prefix   string

	// SessionLimit is the per-tenant ceiling; zero is unlimited.
	SessionLimit int
}

// NewNATConfig creates a config resolver reading the GALACTIC_NAT
// environment prefix. Exported fields are populated from the environment and
// defaults; call BindFlags to layer CLI overrides.
func NewNATConfig() *NATConfig {
	v := viper.New()
	v.SetEnvPrefix("GALACTIC_NAT")
	v.AutomaticEnv()

	v.SetDefault(KeyNodeName, "")
	v.SetDefault(KeyMetricsPort, DefaultNATMetricsPort)
	v.SetDefault(KeyGRPCHealthPort, DefaultNATGRPCHealthPort)
	v.SetDefault("uplink_interface", "")
	v.SetDefault("shard_sid", "")
	v.SetDefault("shard_pub_addr", "")
	v.SetDefault("shard_pub_addr4", "")
	v.SetDefault("nat64_prefix", "")
	v.SetDefault("session_limit", DefaultNATSessionLimit)

	cfg := &NATConfig{
		v:      v,
		prefix: "GALACTIC_NAT",
	}
	cfg.readFields()
	return cfg
}

// BindFlags binds the CLI flags to the config resolver and re-reads the
// exported fields.
func (c *NATConfig) BindFlags(flags *pflag.FlagSet) {
	bindings := []struct {
		flag string
		key  string
	}{
		{FlagNodeName, KeyNodeName},
		{FlagMetricsPort, KeyMetricsPort},
		{FlagGRPCHealthPort, KeyGRPCHealthPort},
		{"nat-uplink-interface", "uplink_interface"},
		{"nat-shard-sid", "shard_sid"},
		{"nat-shard-pub-addr", "shard_pub_addr"},
		{"nat-shard-pub-addr4", "shard_pub_addr4"},
		{"nat64-prefix", "nat64_prefix"},
		{"nat-session-limit", "session_limit"},
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
func (c *NATConfig) readFields() {
	c.NodeName = c.v.GetString(KeyNodeName)
	c.MetricsPort = c.v.GetInt(KeyMetricsPort)
	c.GRPCHealthPort = c.v.GetInt(KeyGRPCHealthPort)
	c.UplinkInterface = c.v.GetString("uplink_interface")
	c.ShardSID = c.v.GetString("shard_sid")
	c.ShardPubAddr = c.v.GetString("shard_pub_addr")
	c.ShardPubAddr4 = c.v.GetString("shard_pub_addr4")
	c.NAT64Prefix = c.v.GetString("nat64_prefix")
	c.SessionLimit = c.v.GetInt("session_limit")
}

// ServesNAT66 and ServesNAT64 report which families this shard's configuration
// turns on. They are what the binary and the EgressShard reconciler both read,
// so "does this shard do NAT64" has one answer rather than each caller
// re-deriving it from which fields happen to be non-empty.
func (c *NATConfig) ServesNAT66() bool { return c.ShardPubAddr != "" }
func (c *NATConfig) ServesNAT64() bool { return c.ShardPubAddr4 != "" }

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

// validateNAT64 checks the IPv4 half of the configuration, which is all-or-
// nothing: an IPv4 address with no prefix has nothing to translate for, and a
// prefix with no address has nothing to translate into. Either half alone
// produces a shard that drops every NAT64 packet it is sent, so both are
// rejected at startup rather than at the first packet.
func (c *NATConfig) validateNAT64() error {
	if c.ShardPubAddr4 == "" && c.NAT64Prefix == "" {
		return nil
	}
	if c.ShardPubAddr4 == "" {
		return fmt.Errorf(
			"NAT64 prefix is set but shard public IPv4 address is not (use --nat-shard-pub-addr4 flag or %s env var)",
			EnvNATShardPubAddr4)
	}
	if c.NAT64Prefix == "" {
		return fmt.Errorf(
			"shard public IPv4 address is set but NAT64 prefix is not (use --nat64-prefix flag or %s env var)",
			EnvNAT64Prefix)
	}

	addr4, err := netip.ParseAddr(c.ShardPubAddr4)
	if err != nil {
		return fmt.Errorf("shard public IPv4 address %q is not a valid IP address: %w", c.ShardPubAddr4, err)
	}
	if !addr4.Is4() {
		return fmt.Errorf("shard public IPv4 address %q must be an IPv4 address", c.ShardPubAddr4)
	}

	prefix, err := netip.ParsePrefix(c.NAT64Prefix)
	if err != nil {
		return fmt.Errorf("NAT64 prefix %q is not a valid CIDR: %w", c.NAT64Prefix, err)
	}
	if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return fmt.Errorf("NAT64 prefix %q must be an IPv6 prefix", c.NAT64Prefix)
	}
	if prefix.Bits() != DefaultNAT64PrefixLen {
		return fmt.Errorf("NAT64 prefix %q must be a /%d", c.NAT64Prefix, DefaultNAT64PrefixLen)
	}
	if prefix.Masked() != prefix {
		return fmt.Errorf("NAT64 prefix %q has bits set below its prefix length", c.NAT64Prefix)
	}
	return nil
}

// Validate checks that the required configuration fields are set.
func (c *NATConfig) Validate() error {
	if c.NodeName == "" {
		return fmt.Errorf("node name is required (use --node-name flag or %s env var)", EnvNATNodeName)
	}
	if c.UplinkInterface == "" {
		return fmt.Errorf(
			"uplink interface is required (use --nat-uplink-interface flag or %s env var)", EnvNATUplinkInterface)
	}
	if c.ShardSID == "" {
		return fmt.Errorf(
			"shard SID is required (use --nat-shard-sid flag or %s env var)", EnvNATShardSID)
	}
	if err := validateShardAddr("shard SID", c.ShardSID); err != nil {
		return err
	}
	if c.ShardPubAddr != "" {
		if err := validateShardAddr("shard public address", c.ShardPubAddr); err != nil {
			return err
		}
	}
	if err := c.validateNAT64(); err != nil {
		return err
	}
	// A shard serving neither family loads a datapath that claims no packet at
	// all, which presents as a silent blackhole rather than as the
	// misconfiguration it is.
	if !c.ServesNAT66() && !c.ServesNAT64() {
		return fmt.Errorf(
			"a shard must serve at least one address family: set %s for NAT66, or %s and %s for NAT64",
			EnvNATShardPubAddr, EnvNATShardPubAddr4, EnvNAT64Prefix)
	}
	if c.SessionLimit < 0 {
		return errors.New("session limit must not be negative (zero means unlimited)")
	}
	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return errors.New("metrics port must be between 1 and 65535")
	}
	if c.GRPCHealthPort < 1 || c.GRPCHealthPort > 65535 {
		return errors.New("grpc health port must be between 1 and 65535")
	}
	return nil
}
