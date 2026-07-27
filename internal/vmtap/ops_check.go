// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vmtap

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// cmdCheck validates that the tap device and both redirect filters are
// still present, and that the redirect interface (eth0) has not drifted
// from what prevResult recorded — the strongest guarantee this plugin can
// give that it is still leaving Cilium's interface alone.
func cmdCheck(args *skel.CmdArgs) error {
	conf, err := parseConf(args.StdinData)
	if err != nil {
		return err
	}
	slog.Info("CHECK: starting", "containerID", args.ContainerID)

	if !conf.enabled() {
		slog.Info("CHECK: plugin disabled via config, nothing to check", "containerID", args.ContainerID)
		return nil
	}

	var errs []error
	if nsErr := ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		checkInNetns(conf, args, &errs)
		return nil
	}); nsErr != nil {
		errs = append(errs, fmt.Errorf("enter netns %q: %w", args.Netns, nsErr))
	}

	if len(errs) > 0 {
		err := fmt.Errorf("CHECK failed: %w", errors.Join(errs...))
		slog.Error("CHECK: failed", "err", err, "containerID", args.ContainerID)
		return err
	}
	slog.Info("CHECK: passed", "containerID", args.ContainerID)
	return nil
}

// checkInNetns runs the actual state checks once inside the pod netns,
// appending any failures to errs so cmdCheck can report all of them at once
// rather than stopping at the first.
func checkInNetns(conf *PluginConf, args *skel.CmdArgs, errs *[]error) {
	redirectLink, err := netlink.LinkByName(args.IfName)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("redirect interface %q: %w", args.IfName, err))
		return
	}

	tapLink, err := netlink.LinkByName(conf.TapName)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("tap %q: %w", conf.TapName, err))
		return
	}

	if ok, err := hasRedirectFilter(redirectLink, conf.FilterPriority); err != nil {
		*errs = append(*errs, fmt.Errorf("check redirect filter on %q: %w", args.IfName, err))
	} else if !ok {
		*errs = append(*errs, fmt.Errorf("missing redirect filter on %q at priority %d", args.IfName, conf.FilterPriority))
	}

	if ok, err := hasRedirectFilter(tapLink, conf.FilterPriority); err != nil {
		*errs = append(*errs, fmt.Errorf("check redirect filter on %q: %w", conf.TapName, err))
	} else if !ok {
		*errs = append(*errs, fmt.Errorf("missing redirect filter on %q at priority %d", conf.TapName, conf.FilterPriority))
	}

	info, err := resolveRedirectInterface(conf, args.IfName)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("resolve prevResult interface %q: %w", args.IfName, err))
		return
	}
	if info.mac != "" && redirectLink.Attrs().HardwareAddr.String() != info.mac {
		*errs = append(*errs, fmt.Errorf("interface %q MAC changed: expected %q, got %q",
			args.IfName, info.mac, redirectLink.Attrs().HardwareAddr.String()))
	}
	if info.mtu > 0 && redirectLink.Attrs().MTU != info.mtu {
		*errs = append(*errs, fmt.Errorf("interface %q MTU changed: expected %d, got %d",
			args.IfName, info.mtu, redirectLink.Attrs().MTU))
	}
}
