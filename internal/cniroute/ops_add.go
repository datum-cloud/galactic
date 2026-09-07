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

// cmdAdd installs each configured termination route into the VRF routing table
// the master plugin already created, then passes the previous result through
// unchanged. This plugin adds no interfaces or addresses of its own, only kernel
// routes.
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

	// The host interface name derives from the identifiers alone and is
	// identical for a veth master's host end and a tap master's device, so this
	// plugin needs none of the interface-kind inference the BGP plugin does.
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

// parsePrevResult parses the raw previous result into a versioned CNI result
// this plugin can pass straight back as its own. The typed field is never
// populated by a plain unmarshal, so the raw form is the one to read. This
// plugin is optional in the chain, but when present it is chained after a master
// plugin, which always produces a result.
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
