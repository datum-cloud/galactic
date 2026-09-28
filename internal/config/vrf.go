// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// --- VRF sidecar defaults ---------------------------------------------

const (
	// DefaultVRFMetricsPort avoids the ports the other binaries here use. This
	// binary runs as a second container sharing its pod's network namespace
	// with Envoy rather than the host's, so it only has to avoid Envoy's own
	// ports within that pod, not every other process on the node.
	DefaultVRFMetricsPort = 9182

	// DefaultVRFTeardownGracePeriod is a conservative placeholder, not a tuned
	// value: long enough to plausibly cover a config-push and drain window,
	// short enough not to wedge normal-churn testing.
	DefaultVRFTeardownGracePeriod = 30 * time.Second

	// DefaultVRFSweepInterval controls how often pending teardowns are
	// re-checked. It is the granularity of the grace-period clock, not the
	// grace period itself, so it is deliberately much shorter than
	// DefaultVRFTeardownGracePeriod.
	DefaultVRFSweepInterval = 5 * time.Second
)

// --- VRF sidecar environment variable keys -----------------------------

const (
	EnvVRFMetricsPort         = "GALACTIC_VRF_METRICS_PORT"
	EnvVRFTeardownGracePeriod = "GALACTIC_VRF_TEARDOWN_GRACE_PERIOD"
	EnvVRFSweepInterval       = "GALACTIC_VRF_SWEEP_INTERVAL"

	// EnvVRFNodeName and EnvVRFNamespace configure the return-path gateway
	// advertisement publisher. Unset by default, and unlike the others
	// NodeName has no compiled-in default: no generic value could be right for
	// "which node is this".
	EnvVRFNodeName  = "GALACTIC_VRF_NODE_NAME"
	EnvVRFNamespace = "GALACTIC_VRF_NAMESPACE"

	// EnvVRFGatewayPrefix configures return-path gateway address provisioning.
	// Unset by default and with no compiled-in value, for the same reason: no
	// generic value could be right for which address space a platform
	// reserves.
	EnvVRFGatewayPrefix = "GALACTIC_VRF_GATEWAY_PREFIX"
)

// --- VRFConfig -----------------------------------------------------------

// VRFConfig resolves galactic-vrf configuration with three-tier precedence: CLI
// flag, then environment variable, then compiled-in default. Create one with
// NewVRFConfig, call BindFlags to layer CLI flags, then read the exported
// fields.
//
// NodeName and Namespace are exceptions to that precedence. Route
// reconciliation needs neither, deriving desired state entirely from the
// EndpointSlice watch, but publishing this node's return-path gateway
// advertisement needs to know which BGPRouter to attribute it to. NodeName
// defaults to "", which disables that publisher rather than failing
// validation, since most deployments do not set it.
type VRFConfig struct {
	v      *viper.Viper
	prefix string

	// Resolved fields.
	MetricsPort         int
	TeardownGracePeriod time.Duration
	SweepInterval       time.Duration
	// NodeName is this node's name as it appears in a BGPRouter's target
	// reference. It is required only to enable the gateway-advertisement
	// publisher; "" leaves that disabled. Resolved from EnvVRFNodeName, falling
	// back to the same downward-API variable the CNI config uses.
	NodeName string
	// Namespace is where this sidecar reads BGPRouter and BGPVRFInstance and
	// writes BGPAdvertisement CRDs when the publisher is enabled. Defaults to
	// DefaultNamespace, matching every other binary here.
	Namespace string
	// GatewayPrefix is a reserved, byte-aligned IPv6 CIDR this sidecar derives
	// its per-VPC return-path gateway address from and assigns to the VRF-slave
	// interface it creates for usid_egress.
	//
	// It must be address space nothing else ever hands out as a tenant pool,
	// neither this repo's own IPAM nor whatever external system allocates a
	// VPC's real subnets. It is deliberately not carved out of any tenant VPC's
	// subnet: that space is owned by an allocator outside this repo's
	// visibility, so nothing here can prove a reserved sub-range of it is safe,
	// and only a structurally disjoint prefix guarantees no collision.
	//
	// "" disables gateway-address provisioning entirely, and there is
	// deliberately no compiled-in value: this is a platform addressing decision
	// for whoever owns the deployment's IPAM plan. It takes effect only when
	// NodeName is also set, since a prefix alone derives one unadvertisable
	// address, and an empty node identity makes every replica derive the same
	// address for a given VPC.
	GatewayPrefix string
}

// NewVRFConfig creates a config resolver reading the GALACTIC_VRF environment
// prefix. Exported fields are populated from the environment and defaults; call
// BindFlags to layer CLI overrides.
func NewVRFConfig() *VRFConfig {
	v := viper.New()
	v.SetEnvPrefix("GALACTIC_VRF")
	v.AutomaticEnv()

	v.SetDefault(keyMetricsPort, DefaultVRFMetricsPort)
	v.SetDefault("teardown_grace_period", DefaultVRFTeardownGracePeriod.String())
	v.SetDefault("sweep_interval", DefaultVRFSweepInterval.String())
	v.SetDefault("namespace", DefaultNamespace)

	cfg := &VRFConfig{
		v:      v,
		prefix: "GALACTIC_VRF",
	}
	cfg.readFields()
	return cfg
}

// BindFlags binds Cobra/pflag flags to the config resolver and re-reads the
// exported fields. Each flag is bound to a Viper key using the key argument.
func (c *VRFConfig) BindFlags(flags *pflag.FlagSet) {
	bindings := []struct {
		flag string
		key  string
	}{
		{flagMetricsPort, keyMetricsPort},
		{"teardown-grace-period", "teardown_grace_period"},
		{"sweep-interval", "sweep_interval"},
		{"node-name", "node_name"},
		{"namespace", "namespace"},
		{"gateway-prefix", "gateway_prefix"},
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
func (c *VRFConfig) readFields() {
	c.MetricsPort = c.v.GetInt(keyMetricsPort)
	c.TeardownGracePeriod = c.v.GetDuration("teardown_grace_period")
	c.SweepInterval = c.v.GetDuration("sweep_interval")
	c.Namespace = c.v.GetString("namespace")

	c.NodeName = c.v.GetString("node_name")
	if c.NodeName == "" {
		// The same downward-API fallback the CNI config uses. A plain Getenv
		// rather than viper, since this variable carries no prefix for the
		// automatic binding to match.
		c.NodeName = os.Getenv(EnvNodeNameLegacy)
	}
	c.GatewayPrefix = c.v.GetString("gateway_prefix")
}

// Validate checks that the resolved configuration is usable.
func (c *VRFConfig) Validate() error {
	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return errors.New(errMetricsPortRange)
	}
	if c.TeardownGracePeriod <= 0 {
		return errors.New("teardown grace period must be positive")
	}
	if c.SweepInterval <= 0 {
		return errors.New("sweep interval must be positive")
	}
	if c.SweepInterval > c.TeardownGracePeriod {
		return errors.New("sweep interval must not be greater than the teardown grace period")
	}
	if c.GatewayPrefix != "" {
		ip, network, err := net.ParseCIDR(c.GatewayPrefix)
		if err != nil {
			return fmt.Errorf("gateway prefix %q: %w", c.GatewayPrefix, err)
		}
		if ip.To4() != nil {
			return fmt.Errorf("gateway prefix %q must be an IPv6 CIDR", c.GatewayPrefix)
		}
		if ones, _ := network.Mask.Size(); ones%8 != 0 {
			return fmt.Errorf("gateway prefix %q must be byte-aligned (a multiple of /8)", c.GatewayPrefix)
		}
	}
	return nil
}
