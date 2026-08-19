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

	// EnvCNINAT66ShardSIDs is a comma-separated list of every live
	// galactic-nat66 shard's Status.ShardSID (see NAT66ShardStatus's own
	// doc comment in datum-cloud/network) -- the fabric-wide membership
	// list internal/plumbing/srv6.EgressDefaultRouteAdd needs to install a
	// tenant VRF's default egress route across every shard, since no
	// single Kubernetes CRD is visible across this multi-cluster fabric's
	// separate clusters/API servers the way BGP itself is (see that
	// function's own doc comment for why membership is operator-supplied
	// rather than learned from the BGP RIB in this phase). Same
	// "operator-supplied, no in-cluster derivation yet" status as
	// GALACTIC_GATEWAY_SRV6_ADDRESS and NAT66ShardStatus.ShardAddress/SID
	// themselves. galactic-cni's own installer resolves this once at
	// startup (its own real pod env, unlike a CNI plugin's minimal exec
	// environment) and writes it into the static per-node conflist
	// (HostConf.NAT66ShardSIDs) so internal/cnibgp -- invoked per-pod by
	// the CNI runtime, not a long-lived process with configurable env --
	// can read it the same way it reads NodeName/Namespace/etc. Unset or
	// empty means no shard configured yet: a VRF gets no default route,
	// the same "no egress capability" behavior as before this mechanism
	// existed, not an error.
	EnvCNINAT66ShardSIDs = "GALACTIC_CNI_NAT66_SHARD_SIDS"
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

	// NAT66ShardSIDs is the raw, comma-separated NAT66 shard SID list --
	// see EnvCNINAT66ShardSIDs's own doc comment. Left unparsed here
	// (internal/cnibgp splits and validates it) since this package has no
	// IP-address type of its own to return.
	NAT66ShardSIDs string

	// EBPFInterfaces is the raw, comma-separated interface list -- see
	// EnvCNIEBPFInterfaces' own doc comment and hostconf.HostConf.
	// EBPFInterfaces' identical one for why this needs the same env >
	// conflist > default resolution as NAT66ShardSIDs above, not just a
	// plain os.Getenv at the call site.
	EBPFInterfaces string
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
	var cnflistNode, cnflistKube, cnflistNS, cnflistLog, cnflistLevel, cnflistShardSIDs, cnflistEBPFIfaces string
	if conflist != nil {
		cnflistNode = conflist.NodeName
		cnflistKube = conflist.Kubeconfig
		cnflistNS = conflist.Namespace
		cnflistLog = conflist.LogFile
		cnflistLevel = conflist.LogLevel
		cnflistShardSIDs = conflist.NAT66ShardSIDs
		cnflistEBPFIfaces = conflist.EBPFInterfaces
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

	// NAT66ShardSIDs: env > conflist > (no default -- empty means "no
	// shard configured", not an error; see EnvCNINAT66ShardSIDs's doc
	// comment).
	c.NAT66ShardSIDs = resolveEnv(EnvCNINAT66ShardSIDs, cnflistShardSIDs, "")

	// EBPFInterfaces: env > conflist > (no default -- empty means "fall
	// back to attach.ResolveInterfaces' own auto-detection," the
	// pre-existing behavior, not an error; see EnvCNIEBPFInterfaces' own
	// doc comment).
	c.EBPFInterfaces = resolveEnv(EnvCNIEBPFInterfaces, cnflistEBPFIfaces, "")
}

// ConflistValues holds the raw values read from the CNI conflist file.
// Passed to CNIConfig.Resolve() as the middle tier between env vars and defaults.
type ConflistValues struct {
	NodeName       string
	Kubeconfig     string
	Namespace      string
	LogFile        string
	LogLevel       string
	NAT66ShardSIDs string
	EBPFInterfaces string
}
