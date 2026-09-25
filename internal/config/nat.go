// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"fmt"

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
)

// --- NAT environment variable keys ------------------------------------

const (
	EnvNATNodeName       = "GALACTIC_NAT_NODE_NAME"
	EnvNATMetricsPort    = "GALACTIC_NAT_METRICS_PORT"
	EnvNATGRPCHealthPort = "GALACTIC_NAT_GRPC_HEALTH_PORT"

	// EnvNATUplinkInterfaces overrides the fabric-facing uplinks the XDP
	// datapath attaches to, comma-separated. Optional: unset, the uplinks are
	// auto-detected the way the CNI's SRv6 datapath detects its own (see
	// natattach.ResolveUplinks), so the shard and the CNI on one node converge
	// on the same interfaces with no per-node configuration.
	//
	// Set it only on a multi-homed node where that detection cannot be
	// confident, and then name every fabric uplink, not just the one a node's
	// traffic happens to use today. A shard claims a packet only on an
	// interface its program is attached to; an encapsulated tenant packet
	// arriving anywhere else reaches no translation program at all and is
	// forwarded untranslated and uncounted, with nothing on either side
	// reporting a fault.
	//
	// A bonding master may be named in place of its members: it is expanded
	// to its slaves at startup and the program attached to each, never to the
	// master itself.
	//
	// The shard's identity -- its SID, masquerade addresses and NAT64 prefix --
	// is not process configuration: it comes from its EgressShard's spec.
	EnvNATUplinkInterfaces = "GALACTIC_NAT_UPLINK_INTERFACES"

	// EnvNATXDPAttach selects how the datapath reaches its uplinks' XDP hook:
	// NATXDPAttachDirect or NATXDPAttachChain. Optional, defaulting to direct.
	//
	// An interface takes one native XDP program. On an edge node the gateway
	// already holds that hook on the interfaces this shard needs, so the shard
	// runs chained -- installed in the gateway's xdp_chain slot, receiving
	// every packet the gateway does not claim -- instead of attaching itself.
	// Direct mode there fails at attach; chain mode on a node with no gateway
	// waits for a map that never appears.
	EnvNATXDPAttach = "GALACTIC_NAT_XDP_ATTACH"
)

// NATXDPAttachDirect and NATXDPAttachChain are EnvNATXDPAttach's values.
const (
	NATXDPAttachDirect = "direct"
	NATXDPAttachChain  = "chain"
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

	// UplinkInterfaces is the optional override parsed from the
	// comma-separated EnvNATUplinkInterfaces. Empty means auto-detect.
	UplinkInterfaces []string

	// XDPAttach is NATXDPAttachDirect or NATXDPAttachChain, from
	// EnvNATXDPAttach.
	XDPAttach string
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
	v.SetDefault("uplink_interfaces", "")
	v.SetDefault("xdp_attach", NATXDPAttachDirect)

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
		{"nat-uplink-interfaces", "uplink_interfaces"},
		{"nat-xdp-attach", "xdp_attach"},
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
	c.UplinkInterfaces = splitInterfaceList(c.v.GetString("uplink_interfaces"))
	c.XDPAttach = c.v.GetString("xdp_attach")
}

// Validate checks that the required configuration fields are set.
func (c *NATConfig) Validate() error {
	if c.NodeName == "" {
		return fmt.Errorf("node name is required (use --node-name flag or %s env var)", EnvNATNodeName)
	}
	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return errors.New("metrics port must be between 1 and 65535")
	}
	if c.GRPCHealthPort < 1 || c.GRPCHealthPort > 65535 {
		return errors.New("grpc health port must be between 1 and 65535")
	}
	if c.XDPAttach != NATXDPAttachDirect && c.XDPAttach != NATXDPAttachChain {
		return fmt.Errorf("%s must be %q or %q, got %q",
			EnvNATXDPAttach, NATXDPAttachDirect, NATXDPAttachChain, c.XDPAttach)
	}
	return nil
}
