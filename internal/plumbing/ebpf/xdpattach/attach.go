// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpattach

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
)

// linkByNameFn is an override point, as elsewhere in this codebase, so the
// bond-membership lookup can be faked in tests without touching the host
// network stack.
var linkByNameFn = netlink.LinkByName

// Attach attaches program to the XDP hook of every interface in ifaceNames, in
// mode, returning the resulting link for each in the same order for the caller
// to hold open and close on shutdown. Callers resolve bonding masters to their
// slaves first, so a master never reaches here.
//
// In native mode every interface is checked for native XDP support before any
// of them is touched. In either mode a bond slave is waited back into its
// aggregate before the next interface is attached, so a bonded uplink never
// loses every member at once. An attach that fails in mode is returned as an
// error, never retried in the other mode.
//
// If attaching one interface fails partway through, every link already attached
// in this call is closed before returning, so a caller that gets an error holds
// no partial attachment to clean up.
func Attach(program *ebpf.Program, ifaceNames []string, mode xdpmode.Mode) ([]link.Link, error) {
	if program == nil {
		return nil, errors.New("xdpattach: program is nil")
	}
	if len(ifaceNames) == 0 {
		return nil, errors.New("xdpattach: no interfaces to attach to")
	}

	return attachSequentially(ifaceNames, mode, func(ifaceName string) (link.Link, error) {
		return attachOne(program, ifaceName, mode)
	})
}

// attachSequentially is Attach's ordering, with the attach step itself passed
// in so tests can drive the sequence without a real program or a real NIC.
//
// Nothing is attached until every interface has been checked, and each bond
// slave is waited back into its aggregate before the next interface is
// touched. On a bonded uplink, skipping either ordering can take every member
// down at once.
func attachSequentially(ifaceNames []string, mode xdpmode.Mode,
	attach func(string) (link.Link, error),
) ([]link.Link, error) {
	if err := checkModeSupport(ifaceNames, mode); err != nil {
		return nil, err
	}

	links := make([]link.Link, 0, len(ifaceNames))
	for _, ifaceName := range ifaceNames {
		xdpLink, err := attach(ifaceName)
		if err != nil {
			closeAttached(links)
			return nil, err
		}
		links = append(links, xdpLink)

		if err := waitBondSlaveReady(ifaceName, BondReadyTimeout); err != nil {
			closeAttached(links)
			return nil, err
		}
	}
	return links, nil
}

// closeAttached unwinds the links attached so far in one Attach call.
func closeAttached(links []link.Link) {
	for _, already := range links {
		if already == nil {
			continue
		}
		_ = already.Close()
	}
}

// attachOne attaches program to ifaceName's XDP hook in mode, the
// single-interface mechanism Attach applies across its list.
func attachOne(program *ebpf.Program, ifaceName string, mode xdpmode.Mode) (link.Link, error) {
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("xdpattach: find link %q: %w", ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   program,
		Interface: iface.Attrs().Index,
		Flags:     mode.AttachFlags(),
	})
	if err != nil {
		return nil, fmt.Errorf("xdpattach: attach XDP program to %q in %s mode: %w (the other mode is not attempted)",
			ifaceName, mode, err)
	}
	return xdpLink, nil
}

// checkModeSupport is the pre-attach support check for mode. Only native mode
// needs the driver's support; generic mode runs on any interface.
func checkModeSupport(ifaceNames []string, mode xdpmode.Mode) error {
	if mode != xdpmode.Native {
		return nil
	}
	return checkNativeXDPSupport(ifaceNames)
}

// attachedInMode reports whether ifaceName's XDP hook holds a program attached
// in mode, read back from the kernel rather than assumed from how it was
// attached.
func attachedInMode(ifaceName string, mode xdpmode.Mode) (bool, error) {
	l, err := linkByNameFn(ifaceName)
	if err != nil {
		return false, fmt.Errorf("xdpattach: find link %q: %w", ifaceName, err)
	}
	xdp := l.Attrs().Xdp
	return xdp != nil && xdp.Attached && mode.Matches(xdp.AttachMode), nil
}
