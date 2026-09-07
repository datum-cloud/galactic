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

	// Unregister this attachment's ifindex_vrf_table entry. Private to this
	// attachment's own ifindex, so it belongs alongside the device deletion
	// below rather than the shared cleanup deferred to GC. Resolved and removed
	// before the interface is torn down, since there is nothing to resolve an
	// ifindex from afterward.
	unregisterIfindexVRFEntry(vpc, vpcAtt, args.ContainerID)

	// Stop the node daemon resending Router Advertisements for this attachment.
	// Best-effort and unconditional: a missing record, from an attachment that
	// never had an IPv6 gateway allocated, is not an error, and DEL must stay
	// idempotent.
	removeRadvState(vpc, vpcAtt, args.ContainerID)

	// Delete this attachment's tap device. Unlike the VRF and CRDs below it is
	// private to this attachment, so no sibling VM can still depend on it and
	// there is no race to defer to GC.
	//
	// A VMM still holding the device's descriptor open can make the kernel
	// delete lazily rather than immediately, but never blocks or fails this
	// call.
	if err := tap.Delete(vpc, vpcAtt); err != nil {
		slog.Warn("DEL: failed to delete tap device", "err", err,
			"containerID", args.ContainerID, "vpc", vpc, "vpcAttachment", vpcAtt)
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

// unregisterIfindexVRFEntry removes this attachment's ifindex_vrf_table entry
// if one exists, mirroring the veth plugin's identical helper but resolving a
// tap device's host-side interface rather than a veth pair's.
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
