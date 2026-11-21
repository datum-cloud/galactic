// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/labels"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
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

	// DefaultVRFHealthPort serves /healthz and /readyz, beside the metrics
	// port in the proxy pod.
	DefaultVRFHealthPort = 9183

	// DefaultVRFWorkerTokenFile is where the pod mounts its projected
	// Galactic Worker token.
	DefaultVRFWorkerTokenFile = "/var/run/secrets/galactic-worker/token"
)

// --- VRF sidecar environment variable keys -----------------------------

const (
	EnvVRFMetricsPort         = "GALACTIC_VRF_METRICS_PORT"
	EnvVRFHealthPort          = "GALACTIC_VRF_HEALTH_PORT"
	EnvVRFTeardownGracePeriod = "GALACTIC_VRF_TEARDOWN_GRACE_PERIOD"
	EnvVRFSweepInterval       = "GALACTIC_VRF_SWEEP_INTERVAL"

	// EnvVRFNodeName names this node, and EnvVRFNamespace the namespace of
	// its BGPRouter, which gives the node's SRv6 source address.
	EnvVRFNodeName  = "GALACTIC_VRF_NODE_NAME"
	EnvVRFNamespace = "GALACTIC_VRF_NAMESPACE"

	// EnvVRFPodNamespace is the proxy pod's namespace, which holds its
	// VPCAttachments, and EnvVRFAttachmentSelector the label selector that
	// picks them out.
	EnvVRFPodNamespace       = "GALACTIC_VRF_POD_NAMESPACE"
	EnvVRFAttachmentSelector = "GALACTIC_VRF_ATTACHMENT_SELECTOR"

	// EnvVRFWorkerSocket and EnvVRFWorkerTokenFile reach Galactic Worker.
	EnvVRFWorkerSocket    = "GALACTIC_VRF_WORKER_SOCKET"
	EnvVRFWorkerTokenFile = "GALACTIC_VRF_WORKER_TOKEN_FILE"
)

// --- VRFConfig -----------------------------------------------------------

// VRFConfig resolves galactic-vrf configuration with three-tier precedence: CLI
// flag, then environment variable, then compiled-in default. Create one with
// NewVRFConfig, call BindFlags to layer CLI flags, then read the exported
// fields.
type VRFConfig struct {
	v      *viper.Viper
	prefix string

	// Resolved fields.
	MetricsPort         int
	HealthPort          int
	TeardownGracePeriod time.Duration
	SweepInterval       time.Duration
	// NodeName is this node's name, as Worker, the proxy's VPCAttachments and
	// the node's BGPRouter record it. Resolved from EnvVRFNodeName, falling
	// back to the same downward-API variable the CNI config uses. Required.
	NodeName string
	// Namespace is where this sidecar reads the node's BGPRouter. Defaults to
	// DefaultNamespace, matching every other binary here.
	Namespace string
	// PodNamespace is the proxy pod's namespace, where its VPCAttachments
	// are. Required.
	PodNamespace string
	// AttachmentSelector is the label selector of the proxy's own
	// VPCAttachments, one per VPC and node it serves. NSO creates them; the
	// replacement of a proxy pod keeps the same attachments, which is what
	// serializes the replacement in Worker. Required.
	AttachmentSelector string
	// WorkerSocket is Galactic Worker's unix socket, mounted from the host.
	WorkerSocket string
	// WorkerTokenFile is the pod's projected token for Worker.
	WorkerTokenFile string
}

// NewVRFConfig creates a config resolver reading the GALACTIC_VRF environment
// prefix. Exported fields are populated from the environment and defaults; call
// BindFlags to layer CLI overrides.
func NewVRFConfig() *VRFConfig {
	v := viper.New()
	v.SetEnvPrefix("GALACTIC_VRF")
	v.AutomaticEnv()

	v.SetDefault(keyMetricsPort, DefaultVRFMetricsPort)
	v.SetDefault("health_port", DefaultVRFHealthPort)
	v.SetDefault("teardown_grace_period", DefaultVRFTeardownGracePeriod.String())
	v.SetDefault("sweep_interval", DefaultVRFSweepInterval.String())
	v.SetDefault("namespace", DefaultNamespace)
	v.SetDefault(keyWorkerSocket, workerv1alpha1.DefaultSocketPath)
	v.SetDefault(keyWorkerTokenFile, DefaultVRFWorkerTokenFile)

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
		{"health-port", "health_port"},
		{"teardown-grace-period", "teardown_grace_period"},
		{"sweep-interval", "sweep_interval"},
		{"node-name", "node_name"},
		{"namespace", "namespace"},
		{"pod-namespace", "pod_namespace"},
		{"attachment-selector", "attachment_selector"},
		{flagWorkerSocket, keyWorkerSocket},
		{flagWorkerTokenFile, keyWorkerTokenFile},
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
	c.HealthPort = c.v.GetInt("health_port")
	c.TeardownGracePeriod = c.v.GetDuration("teardown_grace_period")
	c.SweepInterval = c.v.GetDuration("sweep_interval")
	c.Namespace = c.v.GetString("namespace")
	c.PodNamespace = c.v.GetString("pod_namespace")
	c.AttachmentSelector = c.v.GetString("attachment_selector")
	c.WorkerSocket = c.v.GetString(keyWorkerSocket)
	c.WorkerTokenFile = c.v.GetString(keyWorkerTokenFile)

	c.NodeName = c.v.GetString("node_name")
	if c.NodeName == "" {
		// The same downward-API fallback the CNI config uses. A plain Getenv
		// rather than viper, since this variable carries no prefix for the
		// automatic binding to match.
		c.NodeName = os.Getenv(EnvNodeNameLegacy)
	}
}

// Validate checks that the resolved configuration is usable.
func (c *VRFConfig) Validate() error {
	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return errors.New(errMetricsPortRange)
	}
	if c.HealthPort < 1 || c.HealthPort > 65535 || c.HealthPort == c.MetricsPort {
		return errors.New("health port must be in 1-65535 and differ from the metrics port")
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
	if c.NodeName == "" {
		return fmt.Errorf("node name is required (%s)", EnvVRFNodeName)
	}
	if c.PodNamespace == "" {
		return fmt.Errorf("pod namespace is required (%s)", EnvVRFPodNamespace)
	}
	if c.AttachmentSelector == "" {
		return fmt.Errorf("attachment selector is required (%s)", EnvVRFAttachmentSelector)
	}
	sel, err := labels.Parse(c.AttachmentSelector)
	if err != nil {
		return fmt.Errorf("attachment selector %q: %w", c.AttachmentSelector, err)
	}
	if sel.Empty() {
		return fmt.Errorf("attachment selector %q selects every VPCAttachment", c.AttachmentSelector)
	}
	if c.WorkerSocket == "" {
		return errors.New("worker socket must not be empty")
	}
	return nil
}
