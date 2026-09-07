// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"go.datum.net/galactic/internal/cnimaster"
	"go.datum.net/galactic/internal/config"
)

var ConfFile = config.DefaultConfFile

// cniConfig is the shared config resolver for env var resolution.
// Initialized by InitCNIConfig() (called from cmd/galactic-veth/main.go).
var cniConfig *config.CNIConfig

// InitCNIConfig initializes the shared config resolver. Call it once at process
// startup, before any config lookup.
func InitCNIConfig() {
	cniConfig = config.NewCNIConfig()
}

// parseConf unmarshals the CNI configuration from data, validates the base62
// identifier fields, and resolves logging. The logic is shared with the tap
// plugin, none of it being veth-specific; this binds it to this binary's own
// resolver and conflist path.
func parseConf(data []byte) (*PluginConf, error) {
	return cnimaster.ParseConf(data, cniConfig, ConfFile)
}
