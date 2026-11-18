// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnitap

import (
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ipam"

	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/plumbing/dan"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/radv"
)

// cmdDel mirrors the veth plugin's own, minus everything guest-namespace
// specific: tap mode never touches a container namespace at all.
func cmdDel(args *skel.CmdArgs) error {
	// DEL is idempotent per the CNI spec: always return success.
	slog.Info("DEL: starting", "containerID", args.ContainerID, "netns", args.Netns)

	pluginConf, parseErr := parseConf(args.StdinData)
	if parseErr != nil {
		slog.Error("DEL: failed to parse CNI config, skipping cleanup", "err", parseErr,
			"containerID", args.ContainerID)
		result := &type100.Result{}
		_ = types.PrintResult(result, "1.0.0")
		return nil
	}
	vpc, vpcAtt := pluginConf.VPC, pluginConf.VPCAttachment

	if pluginConf.IPAM != nil {
		if err := ipam.ExecDel(pluginConf.IPAM.Type, args.StdinData); err != nil {
			slog.Warn("DEL: IPAM delegation failed, allocation may not have been released", "err", err,
				"containerID", args.ContainerID)
		}
	}

	// Remove this attachment's ifindex-keyed map rows and its tap, but only
	// while the tap still belongs to this container: the host name is keyed
	// by (vpc, vpcAttachment) alone, so a replacement container's ADD can
	// already have taken this same device over by the time this DEL, for a
	// predecessor still terminating, arrives. The rows are removed before the
	// tap, since there is nothing to resolve its ifindex from afterward. A VMM
	// still holding the device's descriptor open can make the kernel delete
	// lazily rather than immediately, but never blocks or fails this call.
	owned, err := tap.Release(vpc, vpcAtt, args.ContainerID, func(ifindex uint32) error {
		return attachreg.UnregisterInterface(attach.PinDir, ifindex)
	})
	if err != nil {
		slog.Warn("DEL: failed to delete tap device", "err", err,
			"containerID", args.ContainerID, "vpc", vpc, "vpcAttachment", vpcAtt)
	}

	// Stop the node daemon resending Router Advertisements for this
	// attachment, unless a successor owns the tap and its advertisements.
	// Best-effort: a missing record, from an attachment that never had an IPv6
	// gateway allocated, is not an error, and DEL must stay idempotent.
	if owned {
		removeRadvState(vpc, vpcAtt, args.ContainerID)
	}

	// Remove the sandbox's DAN file. Nothing in Kata deletes it, so files would
	// accumulate in a tmpfs directory for the node's uptime.
	//
	// Removal is unconditional because it is idempotent, so a misread opt-in
	// cannot strand state. Failures are logged rather than returned, because
	// DEL is required to succeed.
	if err := dan.Remove(cniConfig.DANDir, args.ContainerID); err != nil {
		slog.Warn("DEL: failed to remove DAN file", "err", err,
			"containerID", args.ContainerID, "dir", cniConfig.DANDir)
	}

	// Shared resources, the VRF and the BGP CRDs, are keyed by attachment or by
	// node and may still be in use by another VM. Deleting them here races
	// cmdAdd during a restart, so cleanup is left to garbage collection.
	slog.Info("DEL: skipping shared resource cleanup (handled by GC)",
		"containerID", args.ContainerID, "vpc", vpc, "vpcAttachment", vpcAtt)

	result := &type100.Result{}
	_ = types.PrintResult(result, pluginConf.CNIVersion)

	return nil
}

// removeRadvState removes this attachment's router-advertisement resend record,
// if any. Private to this attachment's own host interface, so it belongs
// alongside the device deletion rather than the shared cleanup deferred to
// GC.
func removeRadvState(vpc, vpcAttachment, containerID string) {
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	if err := radv.RemoveAttachment(radv.DefaultStateDir, hostName); err != nil {
		slog.Warn("DEL: failed to remove router advertisement state", "err", err,
			"containerID", containerID, "vpc", vpc, "vpcAttachment", vpcAttachment, "hostInterface", hostName)
	}
}

// removeHostOnlyPorts removes ifindex's host-only port entry if there is one.
// Left behind, it would close those ports on whatever attachment next reuses
// the ifindex.
func removeHostOnlyPorts(ifindex uint32) {
	table, closer, err := ifindexvrfmap.OpenPinnedHostOnlyPorts(attach.PinDir)
	if err != nil {
		return
	}
	defer func() { _ = closer.Close() }()

	if err := table.Unregister(ifindex); err != nil {
		slog.Warn("failed to remove host-only ports", "err", err, "ifindex", ifindex)
	}
}
