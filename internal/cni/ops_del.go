// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/cni/veth"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

func cmdDel(args *skel.CmdArgs) error {
	// DEL is idempotent per the CNI spec: always return success.
	// Missing resources are not errors.
	slog.Info("DEL: starting", "containerID", args.ContainerID, "netns", args.Netns)

	// Parse config — if we can't parse it we still return success but
	// won't be able to clean up any resources.
	pluginConf, parseErr := parseConf(args.StdinData)
	if parseErr != nil {
		slog.Error("DEL: failed to parse CNI config, skipping cleanup", "err", parseErr,
			"containerID", args.ContainerID)
		result := &type100.Result{}
		_ = types.PrintResult(result, "1.0.0")
		return nil
	}
	vpc, vpcAtt := pluginConf.VPC, pluginConf.VPCAttachment

	// Deallocate the pod's IPAM subnet, which is pod-specific and safe to
	// release immediately. Whether to delegate at all is decided purely by the
	// presence of the ipam block, and needs no Kubernetes client now that the
	// IPAM plugin's own DEL looks its allocation up locally.
	if pluginConf.IPAM != nil {
		if err := ipam.ExecDel(pluginConf.IPAM.Type, args.StdinData); err != nil {
			slog.Warn("DEL: IPAM delegation failed, allocation may not have been released", "err", err,
				"containerID", args.ContainerID)
		}
	}

	// Flush the address and default route the IPAM step installed on the guest
	// interface, ahead of host-device delegation. Moving the guest end back out
	// of the container namespace normally flushes them as a side effect of
	// crossing a namespace boundary, but that never happens when the target is
	// the namespace the link already lives in, as for a host-network pod with a
	// secondary attachment. The move is then a no-op, and with no ephemeral
	// sandbox namespace to reclaim it the leftover route survives and wedges
	// the next ADD.
	if err := flushGuestNetnsConfig(args.Netns, args.IfName); err != nil {
		slog.Warn("DEL: failed to flush guest interface address/route, may still be in the netns",
			"err", err, "containerID", args.ContainerID, "netns", args.Netns)
	}

	// Forward DEL to the delegated host-device plugin, which moves the guest
	// end back out of the container namespace and restores its original name.
	//
	// DEL must always return success per the CNI spec, so an error here, such
	// as the device never having been moved because ADD failed earlier or the
	// namespace already being gone, is logged rather than propagated.
	if err := hostDevice("DEL", args, pluginConf); err != nil {
		slog.Warn("DEL: host-device DEL failed, guest interface may still be in the netns",
			"err", err, "containerID", args.ContainerID, "netns", args.Netns)
	}

	// Unregister this attachment's ifindex_vrf_table entry, right before the
	// interface itself is destroyed. Like the veth pair, that row is private to
	// this attachment's own ifindex and no sibling can share it, so it belongs
	// with the immediate cleanup below rather than the shared state deferred to
	// GC. Best-effort and log-only, since DEL must always succeed.
	unregisterIfindexVRFEntry(vpc, vpcAtt, args.ContainerID)

	// Delete this attachment's veth pair. Unlike the VRF and CRDs below, it is
	// private to this attachment, so no sibling pod can still depend on it and
	// there is no race to defer to GC. Deleting the host end removes both ends
	// whichever namespace the guest end is in, so this reclaims the interface
	// even when the delegated DEL above failed or did nothing.
	if err := veth.Delete(vpc, vpcAtt); err != nil {
		slog.Warn("DEL: failed to delete host/guest veth pair", "err", err,
			"containerID", args.ContainerID, "vpc", vpc, "vpcAttachment", vpcAtt)
	}

	// Shared resources, the VRF and the BGP CRDs, are keyed by attachment or by
	// node and may still be in use by another pod. Deleting them here races
	// cmdAdd during a pod restart, letting the old pod's DEL destroy what the
	// new pod just created.
	//
	// GC removes them safely instead, on its own schedule, by checking whether
	// any live container still references them.
	slog.Info("DEL: skipping shared resource cleanup (handled by GC)",
		"containerID", args.ContainerID, "vpc", vpc, "vpcAttachment", vpcAtt)

	result := &type100.Result{}
	_ = types.PrintResult(result, pluginConf.CNIVersion)

	return nil
}

// unregisterIfindexVRFEntry removes this attachment's ifindex_vrf_table entry
// if one exists. The interface's ifindex is resolved by its deterministic name,
// the same name the ADD path resolved it by, and before the interface is torn
// down, since there is nothing to resolve from afterward.
//
// Every failure, whether the interface is already gone or the pinned map is
// absent because the datapath is not enabled, is logged and swallowed: DEL must
// always succeed.
func unregisterIfindexVRFEntry(vpc, vpcAttachment, containerID string) {
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	link, err := netlink.LinkByName(hostName)
	if err != nil {
		// Nothing to unregister when the host interface is already gone, from a
		// prior DEL attempt or an ADD that never got far enough to create
		// it.
		return
	}

	table, closer, err := ifindexvrfmap.OpenPinned(attach.PinDir)
	if err != nil {
		// No pinned map to clean up — eBPF datapath not enabled, or the
		// "run" container hasn't finished loading it yet. Not an error.
		return
	}
	defer func() { _ = closer.Close() }()

	if err := table.Unregister(uint32(link.Attrs().Index)); err != nil {
		slog.Warn("DEL: failed to unregister eBPF ifindex_vrf_table entry", "err", err,
			"containerID", containerID, "vpc", vpc, "vpcAttachment", vpcAttachment, "hostInterface", hostName)
	}
}
