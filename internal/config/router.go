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
	DefaultRouterBGPListenPort = 179
	DefaultRouterMetricsPort   = 9179
	// DefaultRouterGRPCHealthPort avoids 5000: one of the most overloaded
	// dev ports in existence (macOS AirPlay Receiver, Flask's dev server,
	// Docker Registry), and on Talos specifically /sbin/dashboard
	// permanently binds 127.0.0.1:5000 -- see docs/router/configuration.md.
	DefaultRouterGRPCHealthPort = 5179
	DefaultRouterGCNamespace    = "galactic-system"
	DefaultRouterGCInterval     = 5 * time.Minute

	// DefaultRouterWebhookPort matches sigs.k8s.io/controller-runtime/pkg/webhook's
	// own DefaultPort, named here so callers don't need that import just to
	// read the default.
	DefaultRouterWebhookPort = 9443
)

// --- Router environment variable keys --------------------------------------

const (
	EnvRouterNodeName       = "GALACTIC_ROUTER_NODE_NAME"
	EnvRouterReflector      = "GALACTIC_ROUTER_REFLECTOR"
	EnvRouterBGPListenPort  = "GALACTIC_ROUTER_BGP_LISTEN_PORT"
	EnvRouterBGPLocalAddr   = "GALACTIC_ROUTER_BGP_LOCAL_ADDRESS"
	EnvRouterMetricsPort    = "GALACTIC_ROUTER_METRICS_PORT"
	EnvRouterGRPCHealthPort = "GALACTIC_ROUTER_GRPC_HEALTH_PORT"
	EnvRouterGCNamespace    = "GALACTIC_ROUTER_GC_NAMESPACE"
	EnvRouterGCInterval     = "GALACTIC_ROUTER_GC_INTERVAL"

	// EnvRouterWebhookEnabled gates the NetworkRule admission webhook
	// (internal/webhook). Defaults to false: this is the first webhook in
	// this codebase, and enabling it requires TLS cert material
	// (config/webhook/'s kustomization.yaml documents the cert-manager-or-
	// equivalent prerequisite this repo does not itself provision) plus the
	// ValidatingWebhookConfiguration/Service manifests to actually be
	// applied — turning it on without both is a broken deployment, not a
	// safe default.
	EnvRouterWebhookEnabled = "GALACTIC_ROUTER_WEBHOOK_ENABLED"
	EnvRouterWebhookPort    = "GALACTIC_ROUTER_WEBHOOK_PORT"
	EnvRouterWebhookCertDir = "GALACTIC_ROUTER_WEBHOOK_CERT_DIR"
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
	Reflector      bool
	BGPListenPort  int
	BGPLocalAddr   string
	MetricsPort    int
	GRPCHealthPort int
	GCNamespace    string
	GCInterval     time.Duration

	// WebhookEnabled/WebhookPort/WebhookCertDir configure the NetworkRule
	// admission webhook (internal/webhook) -- see
	// EnvRouterWebhookEnabled's doc comment. Disabled by default.
	WebhookEnabled bool
	WebhookPort    int
	WebhookCertDir string
}

// NewRouterConfig creates a router config resolver with the GALACTIC_ROUTER
// env prefix and AutomaticEnv enabled. Exported fields are populated from env
// vars and defaults; call BindFlags() to layer CLI overrides.
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
	v.SetDefault("webhook_enabled", false)
	v.SetDefault("webhook_port", DefaultRouterWebhookPort)
	v.SetDefault("webhook_cert_dir", "")

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
		{"webhook-enabled", "webhook_enabled"},
		{"webhook-port", "webhook_port"},
		{"webhook-cert-dir", "webhook_cert_dir"},
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
	c.WebhookEnabled = c.v.GetBool("webhook_enabled")
	c.WebhookPort = c.v.GetInt("webhook_port")
	c.WebhookCertDir = c.v.GetString("webhook_cert_dir")
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
	if c.WebhookPort < 1 || c.WebhookPort > 65535 {
		return errors.New("webhook port must be between 1 and 65535")
	}
	return nil
}
