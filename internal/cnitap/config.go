// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"encoding/json"
	"fmt"

	"go.datum.net/galactic/internal/cnimaster"
	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
)

var ConfFile = config.DefaultConfFile

// cniConfig is the shared config resolver for env var resolution.
// Initialized by InitCNIConfig() (called from cmd/galactic-tap/main.go).
var cniConfig *config.CNIConfig

// InitCNIConfig initializes the shared config resolver. Call it once at process
// startup, before any config lookup.
func InitCNIConfig() {
	cniConfig = config.NewCNIConfig()
}

// parseConf unmarshals the CNI configuration from data, validates the base62
// identifier fields, and resolves logging. The logic is shared with the veth
// plugin, none of it being tap-specific; this binds it to this binary's own
// resolver and conflist path.
func parseConf(data []byte) (*PluginConf, error) {
	return cnimaster.ParseConf(data, cniConfig, ConfFile)
}

// danRequested reports whether this attachment's guest adopts the tap through a
// Directly Attachable Network file, rather than having its network discovered
// by the runtime.
//
// The decision follows the workload rather than the node, because a cell runs
// guests of several runtimes over the same tap master plugin. The CNI config
// carries it, that being the one channel delivered identically to ADD, DEL, and
// CHECK.
//
// It is read from the raw config rather than the shared master-plugin struct,
// this being the one master plugin that acts on it.
func danRequested(data []byte) bool {
	var conf struct {
		DAN bool `json:"dan"`
	}
	// A decode error needs no report. The caller unmarshals the same bytes into
	// the full config first, so malformed JSON is already rejected.
	if err := json.Unmarshal(data, &conf); err != nil {
		return false
	}
	return conf.DAN
}

// hostOnlyPorts returns the TCP ports this attachment's guest serves only to
// the node, such as a runtime's in-guest agent. Like dan it follows the
// workload, so it rides the CNI config. An invalid list fails ADD rather than
// leaving a port open.
func hostOnlyPorts(data []byte) ([]uint16, error) {
	var conf struct {
		HostOnlyPorts []uint16 `json:"hostOnlyPorts"`
	}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("parse hostOnlyPorts: %w", err)
	}
	if err := ifindexvrfmap.ValidateHostOnlyPorts(conf.HostOnlyPorts); err != nil {
		return nil, fmt.Errorf("hostOnlyPorts: %w", err)
	}
	return conf.HostOnlyPorts, nil
}
