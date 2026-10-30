// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/attachmentidentity"
	"go.datum.net/galactic/internal/plumbing/nldump"
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
		case linkTypeVeth, linkTypeTuntap:
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
	// A program replacement is not a new interface incarnation. Keep its
	// authorization only when the complete old chain shares the new programs'
	// map generation. Orphaned maps and incomplete chains require a new token.
	preserve, err := canPreserveEgressIdentity(filters, serviceProgram, legacyProgram, identityMap)
	if err != nil {
		return false, err
	}
	var token uint64
	if err := identityMap.Lookup(uint32(link.Attrs().Index), &token); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("lookup attachment identity: %w", err)
	}
	if !preserve || token == 0 {
		if _, err := attachmentidentity.RotateMap(identityMap, uint32(link.Attrs().Index)); err != nil {
			return false, fmt.Errorf("rotate attachment identity: %w", err)
		}
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

// listLinksFn indirects nldump.LinkList so a test can confine ReattachEgress
// to its own namespace's links.
var listLinksFn = nldump.LinkList

// ReattachDeliver attaches tp_deliver to the tc egress of every interface
// carrying the managed egress chain, replacing any filter there in place, and
// returns how many it attached. Every link is attempted, and failures are
// joined and returned together.
func ReattachDeliver(program *ebpf.Program) (int, error) {
	links, err := listLinksFn()
	if err != nil {
		return 0, fmt.Errorf("attach: list links: %w", err)
	}
	attached := 0
	var errs []error
	for _, link := range links {
		switch link.Type() {
		case linkTypeVeth, linkTypeTuntap:
		default:
			continue
		}
		managed, err := hasManagedEgressChain(link)
		if err != nil {
			if !linkGone(err) {
				errs = append(errs, fmt.Errorf("interface %q: %w", link.Attrs().Name, err))
			}
			continue
		}
		if !managed {
			continue
		}
		if err := AttachDeliver(program, link.Attrs().Name); err != nil {
			if !linkGone(err) {
				errs = append(errs, fmt.Errorf("interface %q: %w", link.Attrs().Name, err))
			}
			continue
		}
		attached++
	}
	return attached, errors.Join(errs...)
}

func hasManagedEgressChain(link netlink.Link) (bool, error) {
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return false, fmt.Errorf("list ingress filters: %w", err)
	}
	for _, f := range filters {
		if bpf, ok := f.(*netlink.BpfFilter); ok && isManagedEgressFilter(bpf.Name) {
			return true, nil
		}
	}
	return false, nil
}

// HasEgressChain reports whether ifaceName's tc ingress carries both the
// service and the egress program.
func HasEgressChain(ifaceName string) (bool, error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return false, fmt.Errorf("find link %q: %w", ifaceName, err)
	}
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return false, fmt.Errorf("list ingress filters on %q: %w", ifaceName, err)
	}
	var service, egress bool
	for _, f := range filters {
		if bpf, ok := f.(*netlink.BpfFilter); ok {
			service = service || bpf.Name == serviceEgressFilterName
			egress = egress || bpf.Name == egressFilterName
		}
	}
	return service && egress, nil
}

// ManagedInterfaces returns every veth and tap carrying the managed egress
// chain: the interfaces Galactic attached a workload or the ingress sidecar
// through.
func ManagedInterfaces() ([]netlink.Link, error) {
	links, err := listLinksFn()
	if err != nil {
		return nil, fmt.Errorf("attach: list links: %w", err)
	}
	var out []netlink.Link
	for _, link := range links {
		switch link.Type() {
		case linkTypeVeth, linkTypeTuntap:
		default:
			continue
		}
		managed, err := hasManagedEgressChain(link)
		if err != nil {
			if linkGone(err) {
				continue
			}
			return nil, fmt.Errorf("interface %q: %w", link.Attrs().Name, err)
		}
		if managed {
			out = append(out, link)
		}
	}
	return out, nil
}

// netlink's link types for the two kinds of managed interface.
const (
	linkTypeVeth   = "veth"
	linkTypeTuntap = "tuntap"
)

// canPreserveEgressIdentity checks the live chain's ownership and map generation.
func canPreserveEgressIdentity(
	filters []netlink.Filter, service, legacy *ebpf.Program, identities *ebpf.Map,
) (bool, error) {
	var oldService, oldLegacy *netlink.BpfFilter
	for _, filter := range filters {
		f, ok := filter.(*netlink.BpfFilter)
		if !ok {
			continue
		}
		switch f.Name {
		case serviceEgressFilterName:
			if oldService != nil || f.Priority != filterPriorityFn() || f.Handle != netlink.MakeHandle(0, 1) {
				return false, nil
			}
			oldService = f
		case egressFilterName:
			if oldLegacy != nil || f.Priority != filterPriorityFn()+1 || f.Handle != netlink.MakeHandle(0, 2) {
				return false, nil
			}
			oldLegacy = f
		}
	}
	if oldService == nil || oldLegacy == nil {
		return false, nil
	}
	info, err := identities.Info()
	if err != nil {
		return false, fmt.Errorf("inspect attachment identity map: %w", err)
	}
	identityID, ok := info.ID()
	if !ok {
		return false, errors.New("attachment identity map ID unavailable")
	}
	for _, pair := range []struct {
		old              int
		current          *ebpf.Program
		identityRequired bool
	}{
		{oldService.Id, service, true}, {oldLegacy.Id, legacy, false},
	} {
		previous, err := ebpf.NewProgramFromID(ebpf.ProgramID(pair.old))
		if err != nil {
			return false, fmt.Errorf("open previous egress program: %w", err)
		}
		same, err := sameProgramMaps(previous, pair.current, identityID, pair.identityRequired)
		_ = previous.Close()
		if err != nil || !same {
			return false, err
		}
	}
	return true, nil
}

func sameProgramMaps(previous, current *ebpf.Program, identityID ebpf.MapID, identityRequired bool) (bool, error) {
	oldInfo, err := previous.Info()
	if err != nil {
		return false, fmt.Errorf("inspect previous egress program: %w", err)
	}
	newInfo, err := current.Info()
	if err != nil {
		return false, fmt.Errorf("inspect replacement egress program: %w", err)
	}
	oldIDs, oldOK := oldInfo.MapIDs()
	newIDs, newOK := newInfo.MapIDs()
	if !oldOK || !newOK {
		return false, errors.New("egress program map IDs unavailable")
	}
	if identityRequired && !slices.Contains(newIDs, identityID) {
		return false, nil
	}
	slices.Sort(oldIDs)
	slices.Sort(newIDs)
	return slices.Equal(oldIDs, newIDs), nil
}
