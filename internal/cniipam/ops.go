// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniipam

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
)

// cmdAdd implements the CNI IPAM delegation ADD path. Being invoked at all
// is the master plugin's own signal that its "ipam" block was present —
// this function always allocates, it never re-checks whether it should.
func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	slog.Info("ADD: starting", "containerID", args.ContainerID, "type", conf.IPAM.Type)

	result, err := allocate(args, conf.IPAM)
	if err != nil {
		return fmt.Errorf("allocate: %w", err)
	}

	cniResult := BuildCNIResult(conf.CNIVersion, result)
	if err := types.PrintResult(cniResult, conf.CNIVersion); err != nil {
		return fmt.Errorf("print CNI result: %w", err)
	}
	slog.Info("ADD: allocated", "containerID", args.ContainerID,
		"ipv6Subnet", result.IPv6Subnet, "ipv4Address", result.IPv4Address)
	return nil
}

// cmdDel implements the CNI IPAM delegation DEL path. Per the CNI spec,
// DEL is idempotent: a config parse failure or a missing allocation is not
// an error, since there may be nothing left to clean up.
func cmdDel(args *skel.CmdArgs) error {
	slog.Info("DEL: starting", "containerID", args.ContainerID)

	conf, err := parseConf(args.StdinData)
	if err != nil {
		slog.Warn("DEL: failed to parse CNI config, skipping deallocation", "err", err,
			"containerID", args.ContainerID)
		return nil
	}

	deallocate(args.ContainerID, conf.IPAM)
	return nil
}

// cmdCheck implements the CNI IPAM delegation CHECK path: confirm the
// containerID's allocation, if any, is still present in each family conf
// configures.
func cmdCheck(args *skel.CmdArgs) error {
	conf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	if errs := checkAllocation(args.ContainerID, conf.IPAM); len(errs) > 0 {
		err := fmt.Errorf("CHECK failed: %w", errors.Join(errs...))
		slog.Error("CHECK: failed", "err", err, "containerID", args.ContainerID)
		return err
	}
	slog.Info("CHECK: passed", "containerID", args.ContainerID)
	return nil
}

// cmdStatus implements the CNI spec STATUS operation. galactic-ipam has no
// API server or attachment-specific state to probe — it either parses a
// well-formed config or it doesn't.
func cmdStatus(args *skel.CmdArgs) error {
	if err := parseStatusConf(args.StdinData); err != nil {
		return err
	}
	slog.Info("STATUS: ready")
	return nil
}
