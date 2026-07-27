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

// cmdDel removes the redirect filter and tap device this plugin created.
// DEL is idempotent per the CNI spec: a missing netns, tap, or filter is not
// an error. The redirect interface (eth0) is never touched — it was never
// modified by ADD, so there is nothing to restore on it.
func cmdDel(args *skel.CmdArgs) error {
	slog.Info("DEL: starting", "containerID", args.ContainerID, "netns", args.Netns)

	conf, err := parseConf(args.StdinData)
	if err != nil {
		// Config didn't parse (or carries no prevResult) — nothing to
		// identify which tap/priority to clean up. Still return success:
		// DEL must be idempotent even against garbage state.
		slog.Warn("DEL: failed to parse config, skipping cleanup", "err", err, "containerID", args.ContainerID)
		return types.PrintResult(&type100.Result{}, "1.0.0")
	}

	if err := ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		if link, linkErr := netlink.LinkByName(args.IfName); linkErr == nil {
			if err := deleteRedirect(link, conf.FilterPriority); err != nil {
				return fmt.Errorf("remove redirect on %q: %w", args.IfName, err)
			}
		}
		return deleteTap(conf.TapName)
	}); err != nil {
		// Netns is commonly already gone by the time DEL runs (the runtime
		// tears it down before or concurrently with calling DEL) — that is
		// the expected, non-error case, not a real cleanup failure.
		if _, statErr := ns.GetNS(args.Netns); statErr != nil {
			slog.Debug("DEL: netns already gone, nothing to clean up", "containerID", args.ContainerID, "netns", args.Netns)
			return types.PrintResult(&type100.Result{}, conf.CNIVersion)
		}
		return fmt.Errorf("DEL in netns %q: %w", args.Netns, err)
	}

	slog.Info("DEL: done", "containerID", args.ContainerID)
	return types.PrintResult(&type100.Result{}, conf.CNIVersion)
}
