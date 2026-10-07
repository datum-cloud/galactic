// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ReattachEgress moves every usid_egress filter on this node's veths and taps
// onto program, the usid_egress just loaded, and returns how many filters it
// replaced.
//
// A filter is recognized by egressFilterName on a link's ingress hook and is
// replaced in place, keeping its handle and priority. A filter already running
// program is left alone, and a link deleted during the scan is skipped. Every
// link is attempted, and the failures are joined and returned together.
func ReattachEgress(program *ebpf.Program) (int, error) {
	if program == nil {
		return 0, errors.New("attach: program is nil")
	}
	info, err := program.Info()
	if err != nil {
		return 0, fmt.Errorf("attach: read usid_egress program info: %w", err)
	}
	wantID, ok := info.ID()
	if !ok {
		return 0, errors.New("attach: kernel did not report usid_egress's program id")
	}

	links, err := listLinksFn()
	if err != nil {
		return 0, fmt.Errorf("attach: list links: %w", err)
	}

	replaced := 0
	var errs []error
	for _, link := range links {
		// CNI ADD attaches usid_egress only to a veth or a tap, so nothing
		// else needs a filter dump.
		switch link.Type() {
		case "veth", "tuntap":
		default:
			continue
		}
		filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			if linkGone(err) {
				continue
			}
			errs = append(errs, fmt.Errorf("interface %q: list ingress filters: %w", link.Attrs().Name, err))
			continue
		}
		for _, f := range filters {
			bpf, ok := f.(*netlink.BpfFilter)
			if !ok || bpf.Name != egressFilterName || uint32(bpf.Id) == uint32(wantID) {
				continue
			}
			replacement := &netlink.BpfFilter{
				FilterAttrs:  bpf.FilterAttrs,
				Fd:           program.FD(),
				Name:         egressFilterName,
				DirectAction: true,
			}
			if err := netlink.FilterReplace(replacement); err != nil {
				if linkGone(err) {
					continue
				}
				errs = append(errs, fmt.Errorf("interface %q: replace usid_egress filter: %w", link.Attrs().Name, err))
				continue
			}
			replaced++
		}
	}
	return replaced, errors.Join(errs...)
}

// linkGone reports whether err means the link was deleted after it was
// listed, which a pod or VM being torn down during the scan causes. That
// attachment needs no new program, so it is skipped rather than reported.
func linkGone(err error) bool {
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT)
}

// listLinksFn indirects netlink.LinkList so a test can confine ReattachEgress
// to its own namespace's links.
var listLinksFn = netlink.LinkList
