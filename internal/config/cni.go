// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"

	"go.datum.net/galactic/internal/plumbing/dan"
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

	// EnvCNIEBPFInterfaces overrides auto-detection of the interfaces the eBPF
	// uSID datapath attaches its ingress hook to: a comma-separated list, for
	// multi-homed nodes where detecting from the default IPv6 route is
	// ambiguous.
	EnvCNIEBPFInterfaces = "GALACTIC_CNI_EBPF_INTERFACES"

	// EnvCNIEBPFFilterPriority overrides the tc priority the uSID datapath's
	// ingress filter attaches at, the default being the highest tc allows. A
	// cluster CNI may run its own programs on the same hook, and that default
	// has not been validated against every version for a collision. Override it
	// where a deployment needs this filter ordered differently.
	EnvCNIEBPFFilterPriority = "GALACTIC_CNI_EBPF_FILTER_PRIORITY"

	// EnvCNIEgressShardSIDs is a comma-separated list of every live egress
	// shard's SID: the fabric-wide membership a tenant VRF's egress routes need.
	// One SID per shard covers both address families -- a shard decides which
	// translation a packet gets from its inner destination -- so enabling NAT64
	// adds no entry here.
	// It is operator-supplied because no single CRD is visible across this
	// fabric's separate clusters the way BGP itself is.
	//
	// The installer resolves it once at startup, from its real pod environment
	// rather than a plugin's minimal exec environment, and writes it into the
	// static per-node conflist, so the BGP plugin can read it the way it reads
	// every other node-level setting.
	//
	// Unset or empty means no shard is configured yet: a VRF gets no egress
	// route, which is no egress capability rather than an error.
	EnvCNIEgressShardSIDs = "GALACTIC_CNI_EGRESS_SHARD_SIDS"

	// EnvCNIDANDir overrides where Directly Attachable Network files are
	// written, for a node whose shim reads somewhere other than the default.
	//
	// Only the location is node-level. Whether an attachment gets a file at all
	// is stated in its own CNI config, that being a property of the workload.
	EnvCNIDANDir = "GALACTIC_CNI_DAN_DIR"

	// EnvCNINAT64Prefix is the fabric-wide NAT64 prefix, and setting it is what
	// gives a tenant VRF a route toward IPv4 reachability.
	//
	// It has to be installed as its own more-specific route rather than relying
	// on the ::/0 default, because the two are independent: a VRF may have NAT64
	// egress without NAT66 egress, in which case no default route exists for
	// this traffic to fall into. Where both exist they point at the same shard
	// SID and longest-prefix match picks this one, which changes nothing.
	//
	// Unset or empty means this fabric has no NAT64, and a VRF gets no such
	// route -- not an error.
	EnvCNINAT64Prefix = "GALACTIC_CNI_NAT64_PREFIX"
)

// --- CNIConfig -------------------------------------------------------------

// CNIConfig resolves CNI configuration with three-tier precedence: environment
// variable, then conflist field, then compiled-in default. Create one with
// NewCNIConfig and call Resolve with the conflist values.
type CNIConfig struct {
	// Resolved fields (populated by Resolve).
	NodeName   string
	Kubeconfig string
	Namespace  string
	LogFile    string
	LogLevel   string

	// EgressShardSIDs is the raw comma-separated shard SID list, left unparsed
	// here since this package has no IP type of its own to return. The BGP
	// plugin splits and validates it.
	EgressShardSIDs string

	// NAT64Prefix is the raw fabric-wide NAT64 prefix, unparsed for the same
	// reason. Empty means this fabric has no NAT64.
	NAT64Prefix string

	// DANDir is where Directly Attachable Network files are written.
	DANDir string

	// EBPFInterfaces is the raw comma-separated interface list. It needs the
	// same environment-over-conflist-over-default resolution as EgressShardSIDs,
	// not a plain environment read at the call site.
	EBPFInterfaces string
}

// NewCNIConfig creates a new CNI config resolver. Callers should invoke this
// once at process startup.
func NewCNIConfig() *CNIConfig {
	return &CNIConfig{}
}

// Resolve populates the exported fields from the conflist values, overridden by
// any matching environment variable. The conflist is the middle tier between
// the environment and the compiled-in defaults.
func (c *CNIConfig) Resolve(conflist *ConflistValues) {
	var (
		cnflistNode, cnflistKube, cnflistNS, cnflistLog, cnflistLevel string
		cnflistShardSIDs, cnflistNAT64Prefix, cnflistEBPFIfaces       string
		cnflistDANDir                                                 string
	)
	if conflist != nil {
		cnflistNode = conflist.NodeName
		cnflistKube = conflist.Kubeconfig
		cnflistNS = conflist.Namespace
		cnflistLog = conflist.LogFile
		cnflistLevel = conflist.LogLevel
		cnflistShardSIDs = conflist.EgressShardSIDs
		cnflistNAT64Prefix = conflist.NAT64Prefix
		cnflistEBPFIfaces = conflist.EBPFInterfaces
		cnflistDANDir = conflist.DANDir
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

	// No default: empty means no shard configured, not an error.
	c.EgressShardSIDs = resolveEnv(EnvCNIEgressShardSIDs, cnflistShardSIDs, "")

	// No default: empty means this fabric has no NAT64, not an error.
	c.NAT64Prefix = resolveEnv(EnvCNINAT64Prefix, cnflistNAT64Prefix, "")

	// No default: empty means fall back to the datapath's own interface
	// auto-detection, not an error.
	c.EBPFInterfaces = resolveEnv(EnvCNIEBPFInterfaces, cnflistEBPFIfaces, "")

	c.DANDir = resolveEnv(EnvCNIDANDir, cnflistDANDir, dan.DefaultDir)
}

// ConflistValues holds the raw values read from the CNI conflist file.
// Passed to CNIConfig.Resolve() as the middle tier between env vars and defaults.
type ConflistValues struct {
	NodeName        string
	Kubeconfig      string
	Namespace       string
	LogFile         string
	LogLevel        string
	EgressShardSIDs string
	NAT64Prefix     string
	EBPFInterfaces  string
	DANDir          string
}
