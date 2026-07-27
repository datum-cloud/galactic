// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vmtap

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
)

// defaultTapName is the tap device name used when PluginConf.TapName is unset.
const defaultTapName = "tap0"

// defaultFilterPriority is the tc filter priority used for the mirred
// redirect filters when PluginConf.FilterPriority is unset. Priority 1 is
// the highest (lowest-numbered) priority tc allows; this has not been
// validated against Cilium's own clsact priority on any specific
// version/datapath mode — see the tc/bpf hook ordering caveat in
// docs/vmtap-cni/configuration.md. Override via filter_priority if it
// collides.
const defaultFilterPriority = 1

// errNoPrevResult is returned when the plugin config carries no prevResult.
// vmtap-cni only makes sense chained after a plugin (Cilium) that has
// already configured the pod's primary interface — mirrors
// awslabs/tc-redirect-tap's NoPreviousResultError.
var errNoPrevResult = errors.New("vmtap-cni must be chained after a plugin that sets prevResult (e.g. cilium-cni)")

// parseConf unmarshals the CNI configuration from stdin data, defaults
// optional fields, and parses prevResult into conf.PrevResult. Returns
// errNoPrevResult if no prevResult is present.
func parseConf(data []byte) (*PluginConf, error) {
	conf := &PluginConf{}
	if err := json.Unmarshal(data, conf); err != nil {
		return nil, &types.Error{Code: 7, Msg: "invalid CNI config", Details: err.Error()}
	}

	if conf.TapName == "" {
		conf.TapName = defaultTapName
	}
	if conf.FilterPriority == 0 {
		conf.FilterPriority = defaultFilterPriority
	}

	if conf.RawPrevResult == nil {
		return nil, &types.Error{Code: 7, Msg: errNoPrevResult.Error()}
	}
	if err := version.ParsePrevResult(&conf.PluginConf); err != nil {
		return nil, &types.Error{Code: 6, Msg: fmt.Sprintf("parse prevResult: %v", err)}
	}
	if conf.PrevResult == nil {
		return nil, &types.Error{Code: 7, Msg: errNoPrevResult.Error()}
	}

	return conf, nil
}
