// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vmtap

import (
	"fmt"
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// cmdAdd creates a tap device in the pod's network namespace and installs
// bidirectional tc-mirred redirects between it and the interface the
// preceding plugin (Cilium) already configured, without ever modifying that
// interface. See doc.go and .local/kraftlet-cilium-tap-plan.md section 3.
func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}

	slog.Info("ADD: starting", "containerID", args.ContainerID, "netns", args.Netns, "ifName", args.IfName)

	if !conf.enabled() {
		slog.Info("ADD: plugin disabled via config, passing prevResult through unchanged",
			"containerID", args.ContainerID)
		return types.PrintResult(conf.PrevResult, conf.CNIVersion)
	}

	var result *type100.Result
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		info, err := resolveRedirectInterface(conf, args.IfName)
		if err != nil {
			return fmt.Errorf("resolve redirect interface %q: %w", args.IfName, err)
		}

		redirectLink, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return fmt.Errorf("find redirect interface %q: %w", args.IfName, err)
		}

		// Tap MTU is the resolved route MTU, not eth0's link MTU — this is
		// what fixes the Cilium/Kata MTU mismatch caveat (section 4 of the
		// plan) without needing a dedicated schema field: the tap's own Mtu
		// in the CNI result is already the corrected value.
		tapLink, err := addTap(conf.TapName, info.routeMTU, conf.OwnerUID, conf.OwnerGID)
		if err != nil {
			return fmt.Errorf("create tap %q: %w", conf.TapName, err)
		}

		if err := addRedirect(redirectLink, tapLink, conf.FilterPriority); err != nil {
			return fmt.Errorf("add redirect %s->%s: %w", args.IfName, conf.TapName, err)
		}
		if err := addRedirect(tapLink, redirectLink, conf.FilterPriority); err != nil {
			return fmt.Errorf("add redirect %s->%s: %w", conf.TapName, args.IfName, err)
		}
		slog.Debug("ADD: redirect installed", "containerID", args.ContainerID,
			"redirect", args.IfName, "tap", conf.TapName, "routeMTU", info.routeMTU)

		result, err = buildResult(conf, tapLink, args.ContainerID)
		return err
	})
	if err != nil {
		return fmt.Errorf("ADD in netns %q: %w", args.Netns, err)
	}

	slog.Info("ADD: tap and redirect ready", "containerID", args.ContainerID, "tap", conf.TapName)
	return types.PrintResult(result, conf.CNIVersion)
}
