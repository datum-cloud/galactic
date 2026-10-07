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

	"go.datum.net/galactic/internal/plumbing/ebpf/attachmentidentity"
)

// ReattachEgress moves every usid_egress attachment on this node's veths and
// taps onto the service classifier followed by the legacy egress program, and
// returns how many attachment chains it replaced.
//
// An attachment is recognized by egressFilterName on a link's ingress hook.
// Links already running both programs are left alone, and a link deleted
// during the scan is skipped. Every link is attempted, and failures are joined
// and returned together.
func ReattachEgress(serviceProgram, legacyProgram *ebpf.Program, identityMap *ebpf.Map) (int, error) {
	if identityMap == nil {
		return 0, errors.New("attach: attachment identity map is nil")
	}
	var replaced int
	err := withIdentityLockFn(func() error {
		var err error
		replaced, err = reattachEgressLocked(serviceProgram, legacyProgram, identityMap)
		return err
	})
	return replaced, err
}

func reattachEgressLocked(serviceProgram, legacyProgram *ebpf.Program, identityMap *ebpf.Map) (int, error) {
	serviceID, err := egressProgramID(serviceProgram, "usid_service_egress")
	if err != nil {
		return 0, err
	}
	legacyID, err := egressProgramID(legacyProgram, "usid_egress")
	if err != nil {
		return 0, err
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
		name := link.Attrs().Name
		didReplace := false
		err := withInterfaceLockFn(name, func() error {
			var lockErr error
			didReplace, lockErr = reattachEgressLinkLocked(link, serviceProgram, legacyProgram, identityMap,
				serviceID, legacyID)
			return lockErr
		})
		if err != nil {
			if linkGone(err) {
				continue
			}
			errs = append(errs, fmt.Errorf("interface %q: %w", name, err))
			continue
		}
		if didReplace {
			replaced++
		}
	}
	if _, err := sweepAttachmentIdentitiesLocked(identityMap); err != nil {
		errs = append(errs, fmt.Errorf("sweep attachment identities: %w", err))
	}
	return replaced, errors.Join(errs...)
}

func reattachEgressLinkLocked(link netlink.Link, serviceProgram, legacyProgram *ebpf.Program, identityMap *ebpf.Map,
	serviceID, legacyID uint32,
) (bool, error) {
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return false, fmt.Errorf("list ingress filters: %w", err)
	}
	serviceMatches := 0
	legacyMatches := 0
	managedCount := 0
	for _, f := range filters {
		bpf, ok := f.(*netlink.BpfFilter)
		if !ok {
			continue
		}
		switch bpf.Name {
		case serviceEgressFilterName:
			managedCount++
			if uint32(bpf.Id) == serviceID && bpf.Priority == filterPriorityFn() &&
				bpf.Handle == netlink.MakeHandle(0, 1) {
				serviceMatches++
			}
		case egressFilterName:
			managedCount++
			if uint32(bpf.Id) == legacyID && bpf.Priority == filterPriorityFn()+1 &&
				bpf.Handle == netlink.MakeHandle(0, 2) {
				legacyMatches++
			}
		}
	}
	if managedCount == 0 {
		return false, nil
	}
	// Rotate on every startup, including an already-current chain. Policy
	// remains disabled until the controller rebuilds values with this token.
	if _, err := attachmentidentity.RotateMap(identityMap, uint32(link.Attrs().Index)); err != nil {
		return false, fmt.Errorf("rotate attachment identity: %w", err)
	}
	if serviceMatches == 1 && legacyMatches == 1 && managedCount == 2 {
		return false, nil
	}
	if err := attachEgressLocked(serviceProgram, legacyProgram, link.Attrs().Name); err != nil {
		return false, fmt.Errorf("replace egress filter chain: %w", err)
	}
	return true, nil
}

func egressProgramID(program *ebpf.Program, name string) (uint32, error) {
	if program == nil {
		return 0, fmt.Errorf("attach: %s program is nil", name)
	}
	info, err := program.Info()
	if err != nil {
		return 0, fmt.Errorf("attach: read %s program info: %w", name, err)
	}
	id, ok := info.ID()
	if !ok {
		return 0, fmt.Errorf("attach: kernel did not report %s's program id", name)
	}
	return uint32(id), nil
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
