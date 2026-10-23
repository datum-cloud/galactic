// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachment

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// errPoolExhausted is returned when every address of a pool is held.
var errPoolExhausted = errors.New("client pool exhausted")

// maxAllocations bounds the addresses one service hands out; it is the
// MaxItems of EdgeServiceStatus.Allocations.
const maxAllocations = 1024

// parsePool parses an EdgeService's client pool. The API already refuses
// anything but a masked IPv6 CIDR from /64 to /120.
func parsePool(raw string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(raw)
	if err != nil || !p.Addr().Is6() || p != p.Masked() || p.Bits() < 64 || p.Bits() > 120 {
		return netip.Prefix{}, fmt.Errorf("client pool %q is not a masked IPv6 CIDR from /64 to /120", raw)
	}
	return p, nil
}

// overlaps reports whether either prefix contains the other.
func overlaps(a, b netip.Prefix) bool {
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}

// insideAny reports whether p lies entirely within one of nets.
func insideAny(p netip.Prefix, nets []netip.Prefix) bool {
	for _, n := range nets {
		if n.Addr().Is6() && n.Bits() <= p.Bits() && n.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// allocationFor returns the address that allocations records for the attachment
// with uid, if any.
func allocationFor(allocations []galacticv1alpha1.EdgeAllocation, uid string) (string, bool) {
	for _, a := range allocations {
		if a.AttachmentUID == uid {
			return a.Address, true
		}
	}
	return "", false
}

// nextFree returns the lowest address of pool that allocations do not hold,
// skipping the pool's first address, the Subnet-Router anycast address of a
// /64 (RFC 4291 section 2.6.1).
func nextFree(pool netip.Prefix, allocations []galacticv1alpha1.EdgeAllocation) (netip.Addr, error) {
	if len(allocations) >= maxAllocations {
		return netip.Addr{}, errPoolExhausted
	}
	held := make(map[netip.Addr]bool, len(allocations))
	for _, a := range allocations {
		if addr, err := netip.ParseAddr(a.Address); err == nil {
			held[addr] = true
		}
	}
	for addr := pool.Addr().Next(); addr.IsValid() && pool.Contains(addr); addr = addr.Next() {
		if !held[addr] {
			return addr, nil
		}
	}
	return netip.Addr{}, errPoolExhausted
}

// withAllocation returns allocations plus one for address and the attachment,
// sorted by address so the list is stable across writers.
func withAllocation(allocations []galacticv1alpha1.EdgeAllocation, address, attachment, uid string,
) []galacticv1alpha1.EdgeAllocation {
	out := append(slices.Clone(allocations), galacticv1alpha1.EdgeAllocation{
		Address: address, Attachment: attachment, AttachmentUID: uid,
	})
	slices.SortFunc(out, func(a, b galacticv1alpha1.EdgeAllocation) int {
		x, _ := netip.ParseAddr(a.Address)
		y, _ := netip.ParseAddr(b.Address)
		return x.Compare(y)
	})
	return out
}

// withoutAllocation returns allocations less the one held by uid.
func withoutAllocation(allocations []galacticv1alpha1.EdgeAllocation, uid string,
) []galacticv1alpha1.EdgeAllocation {
	return slices.DeleteFunc(slices.Clone(allocations), func(a galacticv1alpha1.EdgeAllocation) bool {
		return a.AttachmentUID == uid
	})
}
