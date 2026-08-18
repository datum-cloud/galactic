// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
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
)

// --- VRFConfig -----------------------------------------------------------

// VRFConfig resolves galactic-vrf (the #855 ingress sidecar) configuration
// with three-tier precedence: CLI flag > env var > compiled-in default.
// Create once via NewVRFConfig(), call BindFlags() to layer CLI flags, then
// read the exported fields.
//
// Unlike RouterConfig/GatewayConfig, there is no NodeName field: this
// sidecar has no CRD identity keyed by node (no BGPRouter TargetRef to
// match) and no ConfigMap/CRD configuration surface at all -- desired state
// derives entirely from the EndpointSlice watch (see §1 of the plan's
// acceptance-criteria table).
type VRFConfig struct {
	v      *viper.Viper
	prefix string

	// Resolved fields.
	MetricsPort         int
	TeardownGracePeriod time.Duration
	SweepInterval       time.Duration
}

// NewVRFConfig creates a config resolver with the GALACTIC_VRF env prefix
// and AutomaticEnv enabled. Exported fields are populated from env vars and
// defaults; call BindFlags() to layer CLI overrides.
func NewVRFConfig() *VRFConfig {
	v := viper.New()
	v.SetEnvPrefix("GALACTIC_VRF")
	v.AutomaticEnv()

	v.SetDefault("metrics_port", DefaultVRFMetricsPort)
	v.SetDefault("teardown_grace_period", DefaultVRFTeardownGracePeriod.String())
	v.SetDefault("sweep_interval", DefaultVRFSweepInterval.String())

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
		{"metrics-port", "metrics_port"},
		{"teardown-grace-period", "teardown_grace_period"},
		{"sweep-interval", "sweep_interval"},
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
	c.MetricsPort = c.v.GetInt("metrics_port")
	c.TeardownGracePeriod = c.v.GetDuration("teardown_grace_period")
	c.SweepInterval = c.v.GetDuration("sweep_interval")
}

// Validate checks that the resolved configuration is usable.
func (c *VRFConfig) Validate() error {
	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return errors.New("metrics port must be between 1 and 65535")
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
