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
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// cmdDel mirrors internal/cni's own cmdDel, minus everything guest-netns
// specific (no flushGuestNetnsConfig, no host-device DEL delegation — tap
// mode never touches a container netns at all).
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

	// Unregister this attachment's own ifindex_vrf_table entry -- mirrors
	// internal/cni's own cmdDel (same reasoning: genuinely private to this
	// one attachment's own ifindex, so it belongs alongside tap.Delete
	// below, not the shared VRF/BGP CRD cleanup deferred further down).
	// Resolved and removed *before* tap.Delete tears the interface down,
	// since there is nothing left to resolve an ifindex from afterward.
	unregisterIfindexVRFEntry(vpc, vpcAtt, args.ContainerID)

	// Delete this attachment's own tap device. Unlike the VRF and BGP CRDs
	// below, the tap device is genuinely private to this attachment (see
	// resourceTracker.cleanup's doc comment) — no sibling VM can ever still
	// be depending on it, so there is no ADD-race to defer to GC for.
	//
	// A VMM (Kata/Firecracker/QEMU) that still holds the tap's fd open at
	// this point can make the kernel delete lazily rather than immediately,
	// but never blocks or fails this call — tap.Delete is best-effort and
	// idempotent either way, matching every other step in this function.
	if err := tap.Delete(vpc, vpcAtt); err != nil {
		slog.Warn("DEL: failed to delete tap device", "err", err,
			"containerID", args.ContainerID, "vpc", vpc, "vpcAttachment", vpcAtt)
	}

	// Shared resources (VRF, BGPAdvertisement, BGPVRFInstance) are keyed by
	// (vpc, vpcAttachment) or (vpc, node) and may still be in use by another
	// VM. Deleting them here races with cmdAdd during restarts, so cleanup
	// is left to galactic-router's GC controller — see internal/cni's own
	// cmdDel for the full reasoning.
	slog.Info("DEL: skipping shared resource cleanup (handled by GC)",
		"containerID", args.ContainerID, "vpc", vpc, "vpcAttachment", vpcAtt)

	result := &type100.Result{}
	_ = types.PrintResult(result, pluginConf.CNIVersion)

	return nil
}

// unregisterIfindexVRFEntry removes this attachment's own ifindex_vrf_table
// entry (internal/plumbing/ebpf/ifindexvrfmap), if one exists -- mirrors
// internal/cni's own identical helper (see its doc comment for the full
// reasoning), adapted to a tap device's own host-side interface instead of
// a veth pair's.
func unregisterIfindexVRFEntry(vpc, vpcAttachment, containerID string) {
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	link, err := netlink.LinkByName(hostName)
	if err != nil {
		return
	}

	table, closer, err := ifindexvrfmap.OpenPinned(attach.PinDir)
	if err != nil {
		return
	}
	defer func() { _ = closer.Close() }()

	if err := table.Unregister(uint32(link.Attrs().Index)); err != nil {
		slog.Warn("DEL: failed to unregister eBPF ifindex_vrf_table entry", "err", err,
			"containerID", containerID, "vpc", vpc, "vpcAttachment", vpcAttachment, "hostInterface", hostName)
	}
}
