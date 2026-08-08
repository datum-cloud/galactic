// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
)

// --- CNI environment variable keys -----------------------------------------

const (
	EnvCNINodeName         = "GALACTIC_CNI_NODE_NAME"
	EnvCNIKubeconfig       = "GALACTIC_CNI_KUBECONFIG"
	EnvCNIKubernetesConfig = "GALACTIC_CNI_KUBERNETES_CONFIG"
	EnvLogLevel            = "GALACTIC_CNI_LOG_LEVEL"
	EnvLogFile             = "GALACTIC_CNI_LOG_FILE"
	EnvNamespace           = "GALACTIC_CNI_NAMESPACE"
	EnvNodeNameLegacy      = "NODE_NAME"

	// EnvCNIEBPFInterfaces overrides auto-detection of the interface(s)
	// the eBPF uSID datapath attaches its TC-BPF ingress hook to -- a
	// comma-separated list of interface names, for multi-homed nodes
	// where auto-detection (the interface(s) carrying the default IPv6
	// route) is ambiguous.
	EnvCNIEBPFInterfaces = "GALACTIC_CNI_EBPF_INTERFACES"

	// EnvCNIEBPFFilterPriority overrides the tc priority the eBPF uSID
	// datapath's own ingress filter attaches at (default: 1, the
	// highest/lowest-numbered priority tc allows). Cilium also runs its
	// own tc/bpf programs on the same native device ingress hook these
	// interfaces use, and this package's priority-1 default has not been
	// validated against every Cilium version/datapath mode for a
	// collision -- see the same class of caveat internal/vmtap/config.go
	// documents for its own filter_priority knob. Override here if a
	// deployment's Cilium install needs this filter at a different
	// priority to run in the intended order relative to Cilium's own.
	EnvCNIEBPFFilterPriority = "GALACTIC_CNI_EBPF_FILTER_PRIORITY"
)

// --- CNIConfig -------------------------------------------------------------

// CNIConfig resolves CNI configuration with three-tier precedence: env var >
// conflist field > compiled-in default. Create once via NewCNIConfig() and
// call Resolve() with conflist values to populate the exported fields.
type CNIConfig struct {
	// Resolved fields (populated by Resolve).
	NodeName   string
	Kubeconfig string
	Namespace  string
	LogFile    string
	LogLevel   string
}

// NewCNIConfig creates a new CNI config resolver. Callers should invoke this
// once at process startup.
func NewCNIConfig() *CNIConfig {
	return &CNIConfig{}
}

// Resolve populates the exported fields from the conflist values, overridden
// by any matching environment variables. The conflist values act as the
// "middle tier" between env vars and compiled-in defaults.
func (c *CNIConfig) Resolve(conflist *ConflistValues) {
	var cnflistNode, cnflistKube, cnflistNS, cnflistLog, cnflistLevel string
	if conflist != nil {
		cnflistNode = conflist.NodeName
		cnflistKube = conflist.Kubeconfig
		cnflistNS = conflist.Namespace
		cnflistLog = conflist.LogFile
		cnflistLevel = conflist.LogLevel
	}

	// NodeName: env > conflist > legacy fallback > (no default)
	c.NodeName = resolveEnv(EnvCNINodeName, cnflistNode, "")
	if c.NodeName == "" {
		c.NodeName = os.Getenv(EnvNodeNameLegacy)
	}

	// Kubeconfig: env > conflist > default
	c.Kubeconfig = resolveEnv(EnvCNIKubeconfig, cnflistKube, DefaultKubeconfig)
	if c.Kubeconfig == DefaultKubeconfig {
		c.Kubeconfig = resolveEnv(EnvCNIKubernetesConfig, cnflistKube, DefaultKubeconfig)
	}

	// Namespace: env > conflist > default
	c.Namespace = resolveEnv(EnvNamespace, cnflistNS, DefaultNamespace)

	// LogFile: env > conflist > default
	c.LogFile = resolveEnv(EnvLogFile, cnflistLog, DefaultLogFile)

	// LogLevel: env > conflist > default
	c.LogLevel = resolveEnv(EnvLogLevel, cnflistLevel, DefaultLogLevel)
}

// ConflistValues holds the raw values read from the CNI conflist file.
// Passed to CNIConfig.Resolve() as the middle tier between env vars and defaults.
type ConflistValues struct {
	NodeName   string
	Kubeconfig string
	Namespace  string
	LogFile    string
	LogLevel   string
}
