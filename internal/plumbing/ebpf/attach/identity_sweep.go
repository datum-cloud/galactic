// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// SweepAttachmentIdentities removes identities that no longer belong to a
// live Galactic-managed interface. Each ownership check shares the same lock
// as CNI attach and startup reattach, so a concurrent new incarnation either
// completes first and is retained or rotates a fresh token after deletion.
func SweepAttachmentIdentities(identityMap *ebpf.Map) (int, error) {
	if identityMap == nil {
		return 0, errors.New("attach: attachment identity map is nil")
	}
	var removed int
	var sweepErr error
	err := withIdentityLockFn(func() error {
		removed, sweepErr = sweepAttachmentIdentitiesLocked(identityMap)
		return sweepErr
	})
	return removed, err
}

func sweepAttachmentIdentitiesLocked(identityMap *ebpf.Map) (int, error) {
	var keys []uint32
	iterator := identityMap.Iterate()
	var key uint32
	var token uint64
	for iterator.Next(&key, &token) {
		keys = append(keys, key)
	}
	if err := iterator.Err(); err != nil {
		return 0, fmt.Errorf("attach: iterate attachment identities: %w", err)
	}
	removed := 0
	var errs []error
	for _, ifindex := range keys {
		link, err := netlink.LinkByIndex(int(ifindex))
		if err != nil {
			if linkGone(err) {
				if err := identityMap.Delete(ifindex); err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
					removed++
				} else {
					errs = append(errs, fmt.Errorf("delete identity ifindex=%d: %w", ifindex, err))
				}
				continue
			}
			errs = append(errs, fmt.Errorf("resolve identity ifindex=%d: %w", ifindex, err))
			continue
		}
		name := link.Attrs().Name
		err = withInterfaceLockFn(name, func() error {
			current, err := netlink.LinkByIndex(int(ifindex))
			if err != nil {
				if linkGone(err) {
					return identityMap.Delete(ifindex)
				}
				return err
			}
			filters, err := netlink.FilterList(current, netlink.HANDLE_MIN_INGRESS)
			if err != nil {
				return err
			}
			for _, filter := range filters {
				if bpfFilter, ok := filter.(*netlink.BpfFilter); ok && isManagedEgressFilter(bpfFilter.Name) {
					return nil
				}
			}
			return identityMap.Delete(ifindex)
		})
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("sweep identity ifindex=%d: %w", ifindex, err))
			continue
		}
		// Recheck existence to count only actual removals.
		var remaining uint64
		if lookupErr := identityMap.Lookup(ifindex, &remaining); errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
			removed++
		}
	}
	return removed, errors.Join(errs...)
}
