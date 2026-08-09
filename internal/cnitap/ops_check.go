// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ipam"

	"go.datum.net/galactic/internal/cnimaster"
)

// cmdCheck validates that the node's tap-side networking state matches what
// was established during cmdAdd. Unlike internal/cni's own cmdCheck, there
// is no guest interface to verify — tap mode never enters a container
// netns.
func cmdCheck(args *skel.CmdArgs) error {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}
	slog.Info("CHECK: starting", "containerID", args.ContainerID,
		"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)

	var errs []error

	hostName, nodeErrs := cnimaster.CheckNodeLevelState(pluginConf.VPC, pluginConf.VPCAttachment)
	errs = append(errs, nodeErrs...)

	// Termination routes are galactic-route's own CHECK now (see
	// internal/cniroute's checkTerminationRoutes) — this plugin's CHECK no
	// longer verifies them.

	if pluginConf.RawPrevResult != nil {
		if err := checkPrevResult(pluginConf.RawPrevResult, hostName); err != nil {
			errs = append(errs, fmt.Errorf("prevResult validation: %w", err))
		}
	}

	// Delegate CHECK to the IPAM plugin so a lost or corrupted allocation
	// marker file is caught here too, not just at ADD/DEL time.
	if pluginConf.IPAM != nil {
		if err := ipam.ExecCheck(pluginConf.IPAM.Type, args.StdinData); err != nil {
			errs = append(errs, fmt.Errorf("IPAM CHECK: %w", err))
		}
	}

	if len(errs) > 0 {
		err := fmt.Errorf("CHECK failed: %w", errors.Join(errs...))
		slog.Error("CHECK: failed", "err", err, "containerID", args.ContainerID,
			"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
		return err
	}
	slog.Info("CHECK: passed", "containerID", args.ContainerID,
		"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
	return nil
}

// cmdStatus implements the CNI spec STATUS operation — see
// internal/cnimaster.RunStatus for the full reasoning, shared verbatim with
// galactic-cni.
func cmdStatus(args *skel.CmdArgs) error {
	return cnimaster.RunStatus(args.StdinData, cniConfig, ConfFile)
}

// checkPrevResult validates that kernel state matches the host interface
// recorded in the prevResult returned by the most recent ADD. Tap mode has
// no guest-side interface or netns to validate against.
func checkPrevResult(rawPrevResult map[string]interface{}, _ string) error {
	jsonBytes, err := json.Marshal(rawPrevResult)
	if err != nil {
		return fmt.Errorf("marshal prevResult: %w", err)
	}
	res, err := type100.NewResult(jsonBytes)
	if err != nil {
		return fmt.Errorf("parse prevResult: %w", err)
	}
	result, err := type100.GetResult(res)
	if err != nil {
		return fmt.Errorf("get prevResult: %w", err)
	}

	for _, iface := range result.Interfaces {
		if iface.Name == "" || iface.Sandbox != "" {
			continue
		}
		if err := cnimaster.ValidateHostInterface(iface.Name, iface.Mac, iface.Mtu); err != nil {
			return fmt.Errorf("interface %q (host): %w", iface.Name, err)
		}
	}
	return nil
}
