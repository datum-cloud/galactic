// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"strings"
)

// --- CNI environment variable keys -----------------------------------------

const (
	EnvCNINodeName         = "GALACTIC_CNI_NODE_NAME"
	EnvCNIKubeconfig       = "GALACTIC_CNI_KUBECONFIG"
	EnvCNIKubernetesConfig = "GALACTIC_CNI_KUBERNETES_CONFIG"
	EnvCNIEnableLocalIPAM  = "GALACTIC_CNI_ENABLE_LOCAL_IPAM"
	EnvLogLevel            = "GALACTIC_CNI_LOG_LEVEL"
	EnvLogFile             = "GALACTIC_CNI_LOG_FILE"
	EnvNamespace           = "GALACTIC_CNI_NAMESPACE"
	EnvNodeNameLegacy      = "NODE_NAME"
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

// CNIGetEnableLocalIPAM reports whether local (in-memory) IPAM is enabled via
// environment variable. Returns false if the variable is unset or not "true".
func CNIGetEnableLocalIPAM() bool {
	val := os.Getenv(EnvCNIEnableLocalIPAM)
	return strings.EqualFold(val, "true")
}
