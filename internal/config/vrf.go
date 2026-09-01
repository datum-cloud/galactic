// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"os"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// --- VRF sidecar defaults ---------------------------------------------

const (
	// DefaultVRFMetricsPort deliberately avoids the port ranges the other
	// binaries in this repo already use (9179 router, 8081 gateway, 9180
	// CNI credential-refresh) for the same reason config.go's own
	// DefaultGatewayMetricsPort comment gives: unlike those, though, this
	// binary runs as a second container sharing its *pod's* network
	// namespace with Envoy (not hostNetwork: true, see §1.5 of the #855
	// plan), so the port only has to avoid Envoy's own well-known ports
	// (9901 admin, 10000 default listener) within that one pod, not every
	// other galactic-* process on the node.
	DefaultVRFMetricsPort = 9182

	// DefaultVRFTeardownGracePeriod is a conservative placeholder, not a
	// tuned value: long enough to plausibly cover a typical Envoy Gateway
	// extension server (#856/#857) config-push-plus-drain window, short
	// enough not to wedge normal-churn testing. See §9 item 1's
	// 2026-08-18 decision in docs/plans/855-ingress-sidecar-vpc-backend-
	// connectivity.md -- revisit once #857 exists and its latency is
	// observable.
	DefaultVRFTeardownGracePeriod = 30 * time.Second

	// DefaultVRFSweepInterval controls how often Store.Sweep re-checks
	// pending teardowns -- see internal/ingresssidecar.RunSweeper's doc
	// comment for why this has to be polling-driven. Independent of (and
	// deliberately much shorter than) DefaultVRFTeardownGracePeriod: this
	// is the granularity of the grace-period clock, not the grace period
	// itself.
	DefaultVRFSweepInterval = 5 * time.Second
)

// --- VRF sidecar environment variable keys -----------------------------

const (
	EnvVRFMetricsPort         = "GALACTIC_VRF_METRICS_PORT"
	EnvVRFTeardownGracePeriod = "GALACTIC_VRF_TEARDOWN_GRACE_PERIOD"
	EnvVRFSweepInterval       = "GALACTIC_VRF_SWEEP_INTERVAL"

	// EnvVRFNodeName and EnvVRFNamespace configure the return-path gateway
	// BGPAdvertisement publisher (see NodeName/Namespace's own doc
	// comments below) -- unset by default, matching every env var above,
	// but unlike them this pair has no compiled-in default for NodeName:
	// there is no generic value that could ever be right for "which node
	// is this", the same reason GALACTIC_ROUTER_NODE_NAME/
	// GALACTIC_GATEWAY_NODE_NAME have none either.
	EnvVRFNodeName  = "GALACTIC_VRF_NODE_NAME"
	EnvVRFNamespace = "GALACTIC_VRF_NAMESPACE"
)

// --- VRFConfig -----------------------------------------------------------

// VRFConfig resolves galactic-vrf (the #855 ingress sidecar) configuration
// with three-tier precedence: CLI flag > env var > compiled-in default.
// Create once via NewVRFConfig(), call BindFlags() to layer CLI flags, then
// read the exported fields.
//
// NodeName/Namespace are the exception to that precedence and to
// RouterConfig/GatewayConfig's own pattern: this sidecar's *route*
// reconciliation still has no CRD identity keyed by node and no
// ConfigMap/CRD configuration surface (desired state derives entirely from
// the EndpointSlice watch, per §1 of docs/plans/855-ingress-sidecar-vpc-
// backend-connectivity.md's acceptance-criteria table) -- but publishing
// this node's own return-path gateway advertisement (docs/plans/855-
// return-path-gateway-advertisement.md) does need to know which BGPRouter
// to attribute it to. NodeName's default is "" (feature disabled -- see
// cmd/galactic-vrf's own startup logic, which only wires up a
// GatewayPublisher when NodeName is non-empty), not a Validate failure,
// since most deployments of this sidecar don't set it at all yet.
type VRFConfig struct {
	v      *viper.Viper
	prefix string

	// Resolved fields.
	MetricsPort         int
	TeardownGracePeriod time.Duration
	SweepInterval       time.Duration
	// NodeName is this node's name, as it appears in a BGPRouter's
	// spec.targetRef.name -- required only to enable the return-path
	// gateway-advertisement publisher (see this type's own doc comment);
	// "" leaves that feature disabled. Resolved from EnvVRFNodeName,
	// falling back to the same EnvNodeNameLegacy ("NODE_NAME") downward-API
	// convention internal/config.CNIConfig's own NodeName uses.
	NodeName string
	// Namespace is where this sidecar reads BGPRouter/BGPVRFInstance and
	// writes BGPAdvertisement CRDs when the gateway-advertisement publisher
	// is enabled -- defaults to DefaultNamespace ("galactic-system"),
	// matching every other galactic-* binary's own default.
	Namespace string
}

// NewVRFConfig creates a config resolver with the GALACTIC_VRF env prefix
// and AutomaticEnv enabled. Exported fields are populated from env vars and
// defaults; call BindFlags() to layer CLI overrides.
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
		// Same downward-API fallback internal/config.CNIConfig's own
		// NodeName resolution uses -- a plain os.Getenv, not viper, since
		// EnvNodeNameLegacy ("NODE_NAME") deliberately carries no
		// GALACTIC_VRF prefix for AutomaticEnv to match.
		c.NodeName = os.Getenv(EnvNodeNameLegacy)
	}
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
	return nil
}
