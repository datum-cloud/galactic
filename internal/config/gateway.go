// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

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

	// EnvGatewayInternalInterfaces names this node's compute-facing interfaces,
	// comma-separated, for the return path: a backend's reply to a VIP crosses
	// this node on its way to the fabric wherever the compute tier routes
	// through it, and the edge_return program forwards those replies before
	// netfilter sees them. Optional -- a node with no compute tier behind it
	// sets nothing and attaches no return program.
	//
	// Deliberately not the same value as the public uplink, even where an
	// operator could name it: on the uplink an external client could source a
	// packet from a VIP address and have it forwarded unexamined.
	EnvGatewayInternalInterfaces = "GALACTIC_GATEWAY_INTERNAL_INTERFACES"

	// EnvGatewaySRv6Address is this node's plain SRv6-reachable address, used
	// as the outer-header source for every packet this datapath forwards. It is
	// never a translation source and is never compared against anything on a
	// receive path.
	//
	// Optional. Left unset, galactic-gateway derives it at startup from the
	// BGPRouter targeting this node: the node's locator address, its SRv6
	// locator's Block and its node ID with nothing after them
	// (srv6.NodeLocatorAddress). Set, it wins, for a node that needs an
	// override.
	EnvGatewaySRv6Address = "GALACTIC_GATEWAY_SRV6_ADDRESS"

	// EnvGatewayXDPAttach selects how the datapath reaches its interfaces' XDP
	// hook: GatewayXDPAttachDispatch, the default, or GatewayXDPAttachDirect.
	//
	// Dispatch runs edge_lb and edge_return from the gateway slots of the
	// node's shared XDP dispatcher (xdpdispatch), whose attachments are pinned:
	// a restart swaps the programs in place without detaching anything, and the
	// egress shard can share the same uplinks. Direct attaches the programs
	// themselves, unpinned, so they detach when the process exits; it releases
	// an idle dispatcher first and refuses to start while another datapath's
	// slot is live, since taking the hook would cut that datapath's traffic.
	EnvGatewayXDPAttach = "GALACTIC_GATEWAY_XDP_ATTACH"

	// EnvGatewayDatapathEnabled turns the gateway's load balancing on or off.
	// Optional, defaulting to true. Off, the process stays up and healthy,
	// empties its load-balancing dispatcher slot, and withdraws this node's
	// VIP advertisements, so no traffic is drawn to a node that will not
	// load-balance it. A backend node can still send VIP replies through it,
	// so with EnvGatewayInternalInterfaces set it keeps edge_return on those
	// interfaces, claiming replies from every rule's VIPs; with none set it
	// attaches nothing. Every other datapath on the node keeps running. The
	// public interface is not required while it is off.
	EnvGatewayDatapathEnabled = "GALACTIC_GATEWAY_DATAPATH_ENABLED"

	// EnvGatewayIPv4VIPs turns on serving IPv4 VIPs. Optional, defaulting to
	// false. Off, the gateway leaves every IPv4 VIP out of the datapath and
	// advertises none. On, it loads each rule's IPv4 VIP over the rule's
	// IPv6 backends, whose nodes translate its flows, and advertises it once
	// those backends' ServiceVIPBindings are Bound. The IPv4 forwarding the
	// FIB lookups of edge_return and the Fragmentation Needed reply need is
	// turned on only once the first IPv4 VIP is due to load, and then left
	// on. Turning the switch off withdraws every IPv4 VIP this node
	// advertises and leaves IPv6 VIPs alone. A gateway that cannot list and
	// watch ServiceVIPBindings runs as if it were off.
	EnvGatewayIPv4VIPs = "GALACTIC_GATEWAY_IPV4_VIPS"

	// EnvGatewayBackendHealth turns on taking unhealthy backends out of the
	// Maglev table. Optional, defaulting to false. On, the gateway reads the
	// health galactic-router publishes on each ServiceVIPBinding and, for a
	// NetworkService with a healthCheck, leaves a backend reported Unhealthy
	// out of the rule's table, keeping every backend when all are Unhealthy.
	// It applies health only while every NetworkGateway in its namespace
	// reports doing so, so every gateway builds the same table. A gateway that
	// cannot list and watch ServiceVIPBindings runs as if it were off.
	EnvGatewayBackendHealth = "GALACTIC_GATEWAY_BACKEND_HEALTH"

	// EnvGatewayProcSysPath is the procfs sysctl root the datapath writes its
	// interfaces' forwarding sysctls under. Optional, defaulting to
	// DefaultProcSysPath. An unprivileged pod gets /proc/sys read-only, so the
	// DaemonSet mounts the host's /proc/sys/net at /host/proc/sys/net and sets
	// this to /host/proc/sys.
	EnvGatewayProcSysPath = "GALACTIC_GATEWAY_PROC_SYS_PATH"
)

// EnvGatewayXDPAttach's values.
const (
	GatewayXDPAttachDispatch = "dispatch"
	GatewayXDPAttachDirect   = "direct"
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

	// PublicInterface and SRv6Address configure the edge gateway datapath.
	// PublicInterface is required. SRv6Address is optional: empty means derive
	// it from this node's BGPRouter at startup. See EnvGatewaySRv6Address.
	PublicInterface string
	SRv6Address     string

	// InternalInterfaces are this node's compute-facing interfaces, parsed from
	// the comma-separated environment value. Empty is valid and means this node
	// carries no return traffic -- see EnvGatewayInternalInterfaces.
	InternalInterfaces []string

	// XDPAttach is one of the GatewayXDPAttach values, from EnvGatewayXDPAttach.
	XDPAttach string

	// DatapathEnabled is EnvGatewayDatapathEnabled.
	DatapathEnabled bool

	// IPv4VIPs is EnvGatewayIPv4VIPs.
	IPv4VIPs bool

	// BackendHealth is EnvGatewayBackendHealth.
	BackendHealth bool

	// ProcSysPath is EnvGatewayProcSysPath.
	ProcSysPath string
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
	v.SetDefault("xdp_attach", GatewayXDPAttachDispatch)
	v.SetDefault("datapath_enabled", true)
	v.SetDefault("ipv4_vips", false)
	v.SetDefault("backend_health", false)
	v.SetDefault("proc_sys_path", DefaultProcSysPath)

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
		{"gateway-internal-interfaces", "internal_interfaces"},
		{"gateway-srv6-address", "srv6_address"},
		{"gateway-xdp-attach", "xdp_attach"},
		{"gateway-datapath-enabled", "datapath_enabled"},
		{"gateway-ipv4-vips", "ipv4_vips"},
		{"gateway-backend-health", "backend_health"},
		{"gateway-proc-sys-path", "proc_sys_path"},
	}
	for _, b := range bindings {
		if flags.Changed(b.flag) {
			c.v.Set(b.key, flags.Lookup(b.flag).Value.String())
		} else if f := flags.Lookup(b.flag); f != nil {
			//nolint:errcheck // controlled keys, BindPFlag cannot fail here
			c.v.BindPFlag(b.key, f)
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
	c.InternalInterfaces = splitCommaList(c.v.GetString("internal_interfaces"))
	c.SRv6Address = c.v.GetString("srv6_address")
	c.XDPAttach = c.v.GetString("xdp_attach")
	c.DatapathEnabled = c.v.GetBool("datapath_enabled")
	c.IPv4VIPs = c.v.GetBool("ipv4_vips")
	c.BackendHealth = c.v.GetBool("backend_health")
	c.ProcSysPath = c.v.GetString("proc_sys_path")
}

// splitCommaList parses a comma-separated list, such as interface names or BMP
// stations, dropping blank entries so a trailing comma or a stray space does
// not produce an entry nothing could ever resolve.
func splitCommaList(raw string) []string {
	var names []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			names = append(names, part)
		}
	}
	return names
}

// Validate checks that the required configuration fields are set.
func (c *GatewayConfig) Validate() error {
	if c.NodeName == "" {
		return fmt.Errorf("node name is required (use --node-name flag or %s env var)", EnvGatewayNodeName)
	}
	switch c.XDPAttach {
	case GatewayXDPAttachDispatch, GatewayXDPAttachDirect:
	default:
		return fmt.Errorf("%s must be %q or %q, got %q", EnvGatewayXDPAttach,
			GatewayXDPAttachDispatch, GatewayXDPAttachDirect, c.XDPAttach)
	}
	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return errors.New(errMetricsPortRange)
	}
	if c.GRPCHealthPort < 1 || c.GRPCHealthPort > 65535 {
		return errors.New("grpc health port must be between 1 and 65535")
	}
	if !c.DatapathEnabled {
		return nil
	}
	if c.PublicInterface == "" {
		return fmt.Errorf(
			"public interface is required (use --gateway-public-interface flag or %s env var)",
			EnvGatewayPublicInterface)
	}
	if c.SRv6Address == "" {
		return nil
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
	return nil
}
