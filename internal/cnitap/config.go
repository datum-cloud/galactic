// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"go.datum.net/galactic/internal/cnimaster"
	"go.datum.net/galactic/internal/config"
)

var ConfFile = config.DefaultConfFile

// cniConfig is the shared config resolver for env var resolution.
// Initialized by InitCNIConfig() (called from cmd/galactic-tap-cni/main.go).
var cniConfig *config.CNIConfig

// InitCNIConfig initializes the shared config resolver for CNI env var
// resolution. Callers should invoke this once at process startup before any
// config lookups.
func InitCNIConfig() {
	cniConfig = config.NewCNIConfig()
}

// parseConf unmarshals the CNI configuration from stdin data, validates the
// base62-encoded identifier fields, and resolves logging. The actual logic
// is shared with galactic-cni — see internal/cnimaster.ParseConf — since
// none of it is tap-specific; this is a thin wrapper binding it to this
// binary's own cniConfig/ConfFile.
func parseConf(data []byte) (*PluginConf, error) {
	return cnimaster.ParseConf(data, cniConfig, ConfFile)
}
