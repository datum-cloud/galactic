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
	// DefaultGatewayMetricsPort/DefaultGatewayGRPCHealthPort deliberately
	// differ from DefaultRouterMetricsPort (8080) and
	// DefaultRouterGRPCHealthPort (5000, overridden to 5179 on Talos by
	// config/router/base/daemonset.yaml) and from galactic-cni's
	// credential-refresh grpc-health port (5180,
	// config/cni/daemonset.yaml): galactic-gateway is deployed as a
	// second container in the same hostNetwork: true pod as
	// galactic-router, so every port it binds is on the same network
	// namespace as every other galactic-* process already running on
	// that node and must not collide with any of them.
	DefaultGatewayMetricsPort    = 8081
	DefaultGatewayGRPCHealthPort = 5181
)

// --- Gateway environment variable keys -----------------------------------

const (
	EnvGatewayNodeName       = "GALACTIC_GATEWAY_NODE_NAME"
	EnvGatewayMetricsPort    = "GALACTIC_GATEWAY_METRICS_PORT"
	EnvGatewayGRPCHealthPort = "GALACTIC_GATEWAY_GRPC_HEALTH_PORT"

	// EnvGatewayPublicInterface names this node's single public/underlay-
	// facing uplink interface for the edge NAT+LB gateway datapath
	// (internal/plumbing/ebpf/edgeprog). Unlike
	// config.EnvRouterGatewayPublicInterface's predecessor field, this is
	// required: galactic-gateway only ever runs as the gateway role, so
	// there is no "not gateway role, return gateway.NoopDatapath{}" case
	// to support — see GatewayConfig.Validate.
	EnvGatewayPublicInterface = "GALACTIC_GATEWAY_PUBLIC_INTERFACE"

	// EnvGatewaySRv6Address is this gateway node's own SRv6-reachable
	// address (network.datumapis.com/v1alpha1's NetworkGatewayStatus.
	// SRv6Address), used as the Full-NAT SNAT source for every ingress
	// flow this node translates. Required — see EnvGatewayPublicInterface.
	EnvGatewaySRv6Address = "GALACTIC_GATEWAY_SRV6_ADDRESS"

	// EnvGatewayEgressAddress is this gateway node's publicly-routable
	// masquerade SNAT source (network.datumapis.com/v1alpha1's
	// NetworkGatewayStatus.EgressAddress), for tenant VPC backends
	// reaching arbitrary internet destinations
	// (datum-cloud/enhancements#865). Unlike EnvGatewaySRv6Address, this
	// is optional — a gateway node not offering egress is a valid
	// deployment — but must be set together with EnvGatewayEgressSID; see
	// GatewayConfig.Validate.
	EnvGatewayEgressAddress = "GALACTIC_GATEWAY_EGRESS_ADDRESS"

	// EnvGatewayEgressSID is this gateway node's egress_sid uSID locator
	// — the reserved Argument *range* tenant VRF default routes point at
	// (design plan §3.1, a second reserved value alongside SRv6Address's
	// own Argument 0), resolved from operator config exactly the way
	// SRv6Address is today, not computed in-cluster (publishSelfAddress's
	// doc comment). Optional, paired with EnvGatewayEgressAddress.
	EnvGatewayEgressSID = "GALACTIC_GATEWAY_EGRESS_SID"
)

// --- GatewayConfig -----------------------------------------------------

// GatewayConfig resolves galactic-gateway configuration with three-tier
// precedence: CLI flag > env var > compiled-in default. Create once via
// NewGatewayConfig(), call BindFlags() to layer CLI flags, then read the
// exported fields.
type GatewayConfig struct {
	v      *viper.Viper
	prefix string

	// Resolved fields.
	NodeName       string
	MetricsPort    int
	GRPCHealthPort int

	// PublicInterface/SRv6Address configure the edge NAT+LB gateway
	// datapath -- see EnvGatewayPublicInterface's doc comment. Both
	// required; GatewayConfig.Validate rejects either being empty.
	PublicInterface string
	SRv6Address     string

	// EgressAddress/EgressSID configure the edge gateway's egress
	// (masquerade) datapath (datum-cloud/enhancements#865) -- see
	// EnvGatewayEgressAddress's doc comment. Both optional, but
	// GatewayConfig.Validate rejects setting only one of the pair: a
	// gateway node offering egress needs both, and a node not offering it
	// needs neither.
	EgressAddress string
	EgressSID     string
}

// NewGatewayConfig creates a gateway config resolver with the
// GALACTIC_GATEWAY env prefix and AutomaticEnv enabled. Exported fields are
// populated from env vars and defaults; call BindFlags() to layer CLI
// overrides.
func NewGatewayConfig() *GatewayConfig {
	v := viper.New()
	v.SetEnvPrefix("GALACTIC_GATEWAY")
	v.AutomaticEnv()

	v.SetDefault("node_name", "")
	v.SetDefault("metrics_port", DefaultGatewayMetricsPort)
	v.SetDefault("grpc_health_port", DefaultGatewayGRPCHealthPort)
	v.SetDefault("public_interface", "")
	v.SetDefault("srv6_address", "")
	v.SetDefault("egress_address", "")
	v.SetDefault("egress_sid", "")

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
		{"node-name", "node_name"},
		{"metrics-port", "metrics_port"},
		{"grpc-health-port", "grpc_health_port"},
		{"gateway-public-interface", "public_interface"},
		{"gateway-srv6-address", "srv6_address"},
		{"gateway-egress-address", "egress_address"},
		{"gateway-egress-sid", "egress_sid"},
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
	c.NodeName = c.v.GetString("node_name")
	c.MetricsPort = c.v.GetInt("metrics_port")
	c.GRPCHealthPort = c.v.GetInt("grpc_health_port")
	c.PublicInterface = c.v.GetString("public_interface")
	c.SRv6Address = c.v.GetString("srv6_address")
	c.EgressAddress = c.v.GetString("egress_address")
	c.EgressSID = c.v.GetString("egress_sid")
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
	// Caught eventually anyway by internal/gateway/kerneldatapath.go's own
	// identical Is6()/Is4In6() check, but late: only once setupGatewayDatapath
	// has already loaded and attached the eBPF datapath. Reject it here
	// instead, at startup, with a message that names the actual problem
	// rather than surfacing as a deeper, less obvious kernel-datapath error.
	if !addr.Is6() || addr.Is4In6() {
		return fmt.Errorf("SRv6 address %q must be a native IPv6 address, not IPv4", c.SRv6Address)
	}
	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return errors.New("metrics port must be between 1 and 65535")
	}
	if c.GRPCHealthPort < 1 || c.GRPCHealthPort > 65535 {
		return errors.New("grpc health port must be between 1 and 65535")
	}

	// EgressAddress/EgressSID are optional, but only together: a gateway
	// node offering egress needs both to populate egress_config_table; a
	// node not offering it needs neither (design plan §5).
	if (c.EgressAddress == "") != (c.EgressSID == "") {
		return fmt.Errorf(
			"gateway egress address and egress SID must be set together, or neither (use %s and %s env vars)",
			EnvGatewayEgressAddress, EnvGatewayEgressSID)
	}
	if c.EgressAddress != "" {
		addr, err := netip.ParseAddr(c.EgressAddress)
		if err != nil {
			return fmt.Errorf("egress address %q is not a valid IP address: %w", c.EgressAddress, err)
		}
		if !addr.Is6() || addr.Is4In6() {
			return fmt.Errorf("egress address %q must be a native IPv6 address, not IPv4", c.EgressAddress)
		}
	}
	if c.EgressSID != "" {
		addr, err := netip.ParseAddr(c.EgressSID)
		if err != nil {
			return fmt.Errorf("egress SID %q is not a valid IP address: %w", c.EgressSID, err)
		}
		if !addr.Is6() || addr.Is4In6() {
			return fmt.Errorf("egress SID %q must be a native IPv6 address, not IPv4", c.EgressSID)
		}
	}
	return nil
}
