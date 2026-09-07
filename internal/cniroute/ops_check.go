// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniroute

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// cmdCheck verifies that the termination routes ADD installed are still present
// in the VRF routing table. That is this plugin's entire CHECK story.
func cmdCheck(args *skel.CmdArgs) error {
	pluginConf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}
	slog.Info("CHECK: starting", "containerID", args.ContainerID,
		"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)

	if err := checkTerminationRoutes(pluginConf.VPC, pluginConf.VPCAttachment, pluginConf.Terminations); err != nil {
		err = fmt.Errorf("CHECK failed: termination routes: %w", err)
		slog.Error("CHECK: failed", "err", err, "containerID", args.ContainerID,
			"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
		return err
	}
	slog.Info("CHECK: passed", "containerID", args.ContainerID,
		"vpc", pluginConf.VPC, "vpcAttachment", pluginConf.VPCAttachment)
	return nil
}

// cmdStatus implements the CNI STATUS operation. This plugin has no API server
// or attachment-specific state to probe: it either parses a well-formed config
// or it does not. Implemented for uniformity across the chain rather than
// skipped.
func cmdStatus(args *skel.CmdArgs) error {
	if err := parseStatusConf(args.StdinData); err != nil {
		return err
	}
	slog.Info("STATUS: ready")
	return nil
}

// checkTerminationRoutes verifies that all termination routes exist in the
// VRF table for the given VPC/VPCAttachment pair.
func checkTerminationRoutes(vpc, vpcAttachment string, terminations []Termination) error {
	tableID, err := vrf.TableID(vpc)
	if err != nil {
		return fmt.Errorf("get VRF table ID: %w", err)
	}

	handle, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("create netlink handle: %w", err)
	}
	defer handle.Close() //nolint:errcheck // netlink cleanup on teardown

	routes, err := handle.RouteListFiltered(
		netlink.FAMILY_V6,
		&netlink.Route{Table: int(tableID)},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}

	dev := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	for _, term := range terminations {
		// An empty via is not an error: the route assembly installs a valid
		// on-link, device-scoped route for it, and ADD installs it fine.
		// Only a non-empty via that fails to parse is rejected.
		var viaIP net.IP
		if term.Via != "" {
			viaIP = net.ParseIP(term.Via)
			if viaIP == nil {
				return fmt.Errorf("invalid termination gateway %q", term.Via)
			}
		}
		found := false
		for _, r := range routes {
			if r.Dst == nil || r.Dst.String() != term.Network || r.LinkIndex <= 0 {
				continue
			}
			if viaIP != nil {
				if r.Gw == nil || !r.Gw.Equal(viaIP) {
					continue
				}
			} else if r.Gw != nil {
				continue
			}
			// Verify the link name matches (defers to the veth/tap device).
			if link, linkErr := handle.LinkByIndex(r.LinkIndex); linkErr == nil && link.Attrs().Name == dev {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing route %s via %q in VRF table %d", term.Network, term.Via, tableID)
		}
	}
	return nil
}
