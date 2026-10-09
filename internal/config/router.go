// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// --- Router defaults -------------------------------------------------------

const (
	DefaultRouterBGPListenPort = 179
	DefaultRouterMetricsPort   = 9179
	// DefaultRouterGRPCHealthPort avoids 5000, one of the most overloaded dev
	// ports there is, and permanently bound on the loopback interface by some
	// host operating systems.
	DefaultRouterGRPCHealthPort = 5179
	DefaultRouterGCNamespace    = "galactic-system"
	DefaultRouterGCInterval     = 5 * time.Minute

	// DefaultRouterBMPPolicy streams each peer's Adj-RIB-In before import
	// policy, the full record of what every peer sent. On a route reflector
	// that is every node's advertisements.
	DefaultRouterBMPPolicy = "pre-policy"
	// DefaultRouterBMPStatisticsInterval is how often a BMP statistics report
	// is sent per established peer.
	DefaultRouterBMPStatisticsInterval = 60 * time.Second

	// maxBMPStatisticsInterval is the largest interval GoBGP can carry: it
	// holds the interval as a 16-bit count of seconds.
	maxBMPStatisticsInterval = 65535 * time.Second
)

// RouterBMPPolicies lists the accepted GALACTIC_ROUTER_BMP_POLICY values.
var RouterBMPPolicies = []string{"pre-policy", "post-policy", "local-rib", "all"}

// --- Router environment variable keys --------------------------------------

const (
	EnvRouterNodeName               = "GALACTIC_ROUTER_NODE_NAME"
	EnvRouterReflector              = "GALACTIC_ROUTER_REFLECTOR"
	EnvRouterBGPListenPort          = "GALACTIC_ROUTER_BGP_LISTEN_PORT"
	EnvRouterBGPLocalAddr           = "GALACTIC_ROUTER_BGP_LOCAL_ADDRESS"
	EnvRouterMetricsPort            = "GALACTIC_ROUTER_METRICS_PORT"
	EnvRouterGRPCHealthPort         = "GALACTIC_ROUTER_GRPC_HEALTH_PORT"
	EnvRouterGCNamespace            = "GALACTIC_ROUTER_GC_NAMESPACE"
	EnvRouterGCInterval             = "GALACTIC_ROUTER_GC_INTERVAL"
	EnvRouterServiceFrontendEnabled = "GALACTIC_ROUTER_SERVICE_FRONTEND_ENABLED"

	// EnvRouterBMPStations lists the BMP collectors to stream to, as a
	// comma-separated list of host:port. Empty, the default, disables BMP.
	EnvRouterBMPStations           = "GALACTIC_ROUTER_BMP_STATIONS"
	EnvRouterBMPPolicy             = "GALACTIC_ROUTER_BMP_POLICY"
	EnvRouterBMPStatisticsInterval = "GALACTIC_ROUTER_BMP_STATISTICS_INTERVAL"
)

// --- RouterConfig ----------------------------------------------------------

// RouterConfig resolves router configuration with three-tier precedence: CLI
// flag, then environment variable, then compiled-in default. Create one with
// NewRouterConfig, call BindFlags to layer CLI flags, then read the exported
// fields.
type RouterConfig struct {
	v      *viper.Viper
	prefix string

	// Resolved fields.
	NodeName string
	// Reflector marks every peer this router adds as an iBGP route-reflector
	// client, so this node reflects paths to them instead of requiring a full
	// mesh. A distinct signal from the listen port: whether a node accepts
	// inbound connections is not the same property as whether it is the
	// fabric's route reflector.
	Reflector              bool
	BGPListenPort          int
	BGPLocalAddr           string
	MetricsPort            int
	GRPCHealthPort         int
	GCNamespace            string
	GCInterval             time.Duration
	ServiceFrontendEnabled bool

	// BMPStations, BMPPolicy, and BMPStatisticsInterval configure BMP export to
	// collectors. BMPStations holds each collector as host:port; empty
	// disables BMP.
	BMPStations           []string
	BMPPolicy             string
	BMPStatisticsInterval time.Duration
}

// NewRouterConfig creates a config resolver reading the GALACTIC_ROUTER
// environment prefix. Exported fields are populated from the environment and
// defaults; call BindFlags to layer CLI overrides.
func NewRouterConfig() *RouterConfig {
	v := viper.New()
	v.SetEnvPrefix("GALACTIC_ROUTER")
	v.AutomaticEnv()

	v.SetDefault(KeyNodeName, "")
	v.SetDefault("reflector", false)
	v.SetDefault("bgp_listen_port", DefaultRouterBGPListenPort)
	v.SetDefault("bgp_local_address", "")
	v.SetDefault(KeyMetricsPort, DefaultRouterMetricsPort)
	v.SetDefault(KeyGRPCHealthPort, DefaultRouterGRPCHealthPort)
	v.SetDefault("gc_namespace", DefaultRouterGCNamespace)
	v.SetDefault("gc_interval", DefaultRouterGCInterval.String())
	v.SetDefault("service_frontend_enabled", false)
	v.SetDefault("bmp_stations", "")
	v.SetDefault("bmp_policy", DefaultRouterBMPPolicy)
	v.SetDefault("bmp_statistics_interval", DefaultRouterBMPStatisticsInterval.String())

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
		{FlagNodeName, KeyNodeName},
		{"reflector", "reflector"},
		{"bgp-listen-port", "bgp_listen_port"},
		{"bgp-local-address", "bgp_local_address"},
		{FlagMetricsPort, KeyMetricsPort},
		{FlagGRPCHealthPort, KeyGRPCHealthPort},
		{"gc-namespace", "gc_namespace"},
		{"gc-interval", "gc_interval"},
		{"service-frontend-enabled", "service_frontend_enabled"},
		{"bmp-stations", "bmp_stations"},
		{"bmp-policy", "bmp_policy"},
		{"bmp-statistics-interval", "bmp_statistics_interval"},
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
	c.NodeName = c.v.GetString(KeyNodeName)
	c.Reflector = c.v.GetBool("reflector")
	c.BGPListenPort = c.v.GetInt("bgp_listen_port")
	c.BGPLocalAddr = c.v.GetString("bgp_local_address")
	c.MetricsPort = c.v.GetInt(KeyMetricsPort)
	c.GRPCHealthPort = c.v.GetInt(KeyGRPCHealthPort)
	c.GCNamespace = c.v.GetString("gc_namespace")
	c.GCInterval = c.v.GetDuration("gc_interval")
	c.ServiceFrontendEnabled = c.v.GetBool("service_frontend_enabled")
	c.BMPStations = splitCommaList(c.v.GetString("bmp_stations"))
	c.BMPPolicy = c.v.GetString("bmp_policy")
	c.BMPStatisticsInterval = c.v.GetDuration("bmp_statistics_interval")
}

// Validate checks that the required configuration fields are set and within
// range.
func (c *RouterConfig) Validate() error {
	if c.NodeName == "" {
		return fmt.Errorf("node name is required (use --node-name flag or %s env var)", EnvRouterNodeName)
	}
	if c.BGPListenPort != -1 && (c.BGPListenPort < 1 || c.BGPListenPort > 65535) {
		return errors.New("bgp listen port must be between 1 and 65535, or -1 for outbound-only mode")
	}
	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return errors.New(errMetricsPortRange)
	}
	if c.GRPCHealthPort < 1 || c.GRPCHealthPort > 65535 {
		return errors.New("grpc health port must be between 1 and 65535")
	}
	return c.validateBMP()
}

// validateBMP checks every BMP station is a host:port with a port in range,
// that the policy is one of RouterBMPPolicies, and that the statistics
// interval is a whole number of seconds GoBGP can carry.
func (c *RouterConfig) validateBMP() error {
	for _, st := range c.BMPStations {
		if _, _, err := ParseBMPStation(st); err != nil {
			return fmt.Errorf("%s: %w", EnvRouterBMPStations, err)
		}
	}
	valid := false
	for _, p := range RouterBMPPolicies {
		valid = valid || c.BMPPolicy == p
	}
	if !valid {
		return fmt.Errorf("%s must be one of %s, got %q",
			EnvRouterBMPPolicy, strings.Join(RouterBMPPolicies, ", "), c.BMPPolicy)
	}
	if c.BMPStatisticsInterval < 0 || c.BMPStatisticsInterval > maxBMPStatisticsInterval ||
		c.BMPStatisticsInterval%time.Second != 0 {
		return fmt.Errorf("%s must be a whole number of seconds from 0s to %s, got %s",
			EnvRouterBMPStatisticsInterval, maxBMPStatisticsInterval, c.BMPStatisticsInterval)
	}
	return nil
}

// ParseBMPStation splits a BMP station given as host:port, where host is an IP
// address or a DNS name and an IPv6 host is bracketed. It returns an error
// when the host is empty or the port is not between 1 and 65535.
func ParseBMPStation(s string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("BMP station %q: %w", s, err)
	}
	if host == "" {
		return "", 0, fmt.Errorf("BMP station %q has no host", s)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("BMP station %q: port must be between 1 and 65535", s)
	}
	return host, uint16(port), nil
}
