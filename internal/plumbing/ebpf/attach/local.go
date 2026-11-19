// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// Worker's Local module (internal/worker/local) attaches its own tc ingress
// programs to tenant interfaces, to the receiving devices of a public handoff
// and to the links it creates. It is the only writer of those filters
// (docs/worker/ownership.md). They sit after galactic-cni's own filters, so
// on a tenant interface a Local program sees only what usid_egress passed on,
// and they take galactic-cni's per-interface lock, so neither replaces the
// other's filter mid-change.

// LocalFilterPrefix starts the name of every Local filter.
const LocalFilterPrefix = "galactic_local_"

// localFilterHandle is the tc handle of every Local filter. galactic-cni uses
// handles 1 and 2.
var localFilterHandle = netlink.MakeHandle(0, 0x4c)

// LocalFilterPriority is the tc priority of every Local filter: the first
// after galactic-cni's ingress filters, which take the configured priority
// and the one after it.
func LocalFilterPriority() uint16 { return filterPriorityFn() + 2 }

// AttachLocal attaches program to ifaceName's tc ingress as the Local filter
// named name, replacing a Local filter already there.
func AttachLocal(program *ebpf.Program, ifaceName, name string) error {
	if program == nil {
		return errors.New("attach: Local program is nil")
	}
	if !strings.HasPrefix(name, LocalFilterPrefix) {
		return fmt.Errorf("attach: Local filter name %q lacks prefix %q", name, LocalFilterPrefix)
	}
	return withInterfaceLockFn(ifaceName, func() error {
		link, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return fmt.Errorf("find link %q: %w", ifaceName, err)
		}
		// One Local filter per interface: a filter of another name at
		// Local's slot is a Local program this one replaces.
		if err := deleteLocalFilters(link, func(n string) bool { return n != name }); err != nil {
			return err
		}
		return attachOneAtPriorityFn(program, name, ifaceName, netlink.HANDLE_MIN_INGRESS,
			LocalFilterPriority(), localFilterHandle)
	})
}

// DetachLocal removes every Local filter from ifaceName's tc ingress. An
// interface that no longer exists is not an error.
func DetachLocal(ifaceName string) error {
	return withInterfaceLockFn(ifaceName, func() error {
		link, err := netlink.LinkByName(ifaceName)
		if err != nil {
			var notFound netlink.LinkNotFoundError
			if errors.As(err, &notFound) {
				return nil
			}
			return fmt.Errorf("find link %q: %w", ifaceName, err)
		}
		return deleteLocalFilters(link, func(string) bool { return true })
	})
}

// LocalFilter returns the name and program ID of the Local filter on
// ifindex's tc ingress, and false when it carries none at Local's slot.
func LocalFilter(ifindex int) (string, ebpf.ProgramID, bool, error) {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			// A link that is gone carries no filter.
			return "", 0, false, nil
		}
		return "", 0, false, fmt.Errorf("find link %d: %w", ifindex, err)
	}
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return "", 0, false, fmt.Errorf("list tc ingress filters on %d: %w", ifindex, err)
	}
	for _, f := range filters {
		bf, ok := f.(*netlink.BpfFilter)
		if !ok || !strings.HasPrefix(bf.Name, LocalFilterPrefix) || bf.Priority != LocalFilterPriority() ||
			bf.Handle != localFilterHandle {
			continue
		}
		return bf.Name, ebpf.ProgramID(bf.Id), true, nil
	}
	return "", 0, false, nil
}

// LastCNIIngressPriority returns the highest priority a galactic-cni filter
// holds on ifindex's tc ingress, and false when it holds none. A Local
// filter must sit after it.
func LastCNIIngressPriority(ifindex int) (uint16, bool, error) {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return 0, false, fmt.Errorf("find link %d: %w", ifindex, err)
	}
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return 0, false, fmt.Errorf("list tc ingress filters on %d: %w", ifindex, err)
	}
	var (
		last  uint16
		found bool
	)
	for _, f := range filters {
		bf, ok := f.(*netlink.BpfFilter)
		if !ok || !strings.HasPrefix(bf.Name, "galactic_") || strings.HasPrefix(bf.Name, LocalFilterPrefix) {
			continue
		}
		if !found || bf.Priority > last {
			last, found = bf.Priority, true
		}
	}
	return last, found, nil
}

func deleteLocalFilters(link netlink.Link, match func(name string) bool) error {
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return fmt.Errorf("list tc ingress filters on %q: %w", link.Attrs().Name, err)
	}
	var errs []error
	for _, f := range filters {
		bf, ok := f.(*netlink.BpfFilter)
		if !ok || !strings.HasPrefix(bf.Name, LocalFilterPrefix) || !match(bf.Name) {
			continue
		}
		if err := filterDeleteFn(f); err != nil {
			errs = append(errs, fmt.Errorf("delete Local filter %s on %q: %w", bf.Name, link.Attrs().Name, err))
		}
	}
	return errors.Join(errs...)
}
