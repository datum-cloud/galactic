// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniroute

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"

	"go.datum.net/galactic/internal/cni/route"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// cmdAdd installs each of pluginConf's termination routes into the VRF
// routing table the preceding master plugin (galactic-veth/galactic-tap)
// already created, then passes prevResult through unchanged — galactic-
// route adds no interfaces or IPs of its own, only kernel routes alongside
// whatever came before it in the chain.
func cmdAdd(args *skel.CmdArgs) (err error) {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	prevResult, prevErr := parsePrevResult(pluginConf.RawPrevResult)
	if prevErr != nil {
		return &types.Error{Code: 6, Msg: fmt.Sprintf("parse prevResult: %v", prevErr)}
	}

	slog.Info("ADD: starting", "containerID", args.ContainerID,
		"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment,
		"terminations", len(pluginConf.Terminations))

	// The host interface name is derived from (vpc, vpcAttachment) alone —
	// identical for a veth master's host end and a tap master's tap device
	// (both call intf.GenerateInterfaceNameHost), so galactic-route needs no
	// interface-kind inference the way galactic-bgp does.
	dev := intf.GenerateInterfaceNameHost(pluginConf.VPC, pluginConf.VPCAttachment)

	tracker := &resourceTracker{vpc: pluginConf.VPC, vpcAttachment: pluginConf.VPCAttachment, dev: dev}
	defer func() {
		if err != nil {
			slog.Error("ADD: failed, rolling back created resources", "err", err,
				"containerID", args.ContainerID, "vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
			tracker.cleanup()
		}
	}()

	for _, termination := range pluginConf.Terminations {
		if err := route.Add(pluginConf.VPC, termination.Network, termination.Via, dev); err != nil {
			return fmt.Errorf("add route %s: %w", termination.Network, err)
		}
		tracker.added = append(tracker.added, termination)
	}
	if len(tracker.added) > 0 {
		slog.Debug("ADD: termination routes installed", "count", len(tracker.added), "dev", dev)
	}

	return types.PrintResult(prevResult, pluginConf.CNIVersion)
}

// parsePrevResult parses rawPrevResult (PluginConf.RawPrevResult; the typed
// PluginConf.PrevResult field is never populated by plain JSON unmarshal,
// per its "json:\"-\"" tag) into a versioned CNI result galactic-route can
// pass straight back through as its own ADD result. galactic-route is
// optional in the chain, but when present it must be chained after a
// master plugin, which always produces a prevResult.
func parsePrevResult(rawPrevResult map[string]interface{}) (types.Result, error) {
	if rawPrevResult == nil {
		return nil, errors.New("no prevResult: galactic-route must be chained after a master plugin")
	}
	jsonBytes, err := json.Marshal(rawPrevResult)
	if err != nil {
		return nil, fmt.Errorf("marshal prevResult: %w", err)
	}
	parsed, err := type100.NewResult(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("parse prevResult: %w", err)
	}
	return parsed, nil
}
