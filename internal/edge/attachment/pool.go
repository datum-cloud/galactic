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

// nextFree returns the lowest address of pool that allocations do not hold
// and no prefix of routed contains, skipping the pool's first address, the
// Subnet-Router anycast address of a /64 (RFC 4291 section 2.6.1). routed are
// the prefixes routes hold in the pool's VPC: a provider may route a
// delegated prefix inside its own pool, and an address under it would reach
// the route's holder rather than the attachment.
func nextFree(pool netip.Prefix, allocations []galacticv1alpha1.EdgeAllocation, routed []netip.Prefix,
) (netip.Addr, error) {
	if len(allocations) >= maxAllocations {
		return netip.Addr{}, errPoolExhausted
	}
	held := make(map[netip.Addr]bool, len(allocations))
	for _, a := range allocations {
		if addr, err := netip.ParseAddr(a.Address); err == nil {
			held[addr] = true
		}
	}
	addr := pool.Addr().Next()
	for addr.IsValid() && pool.Contains(addr) {
		// Jumps past a routed prefix rather than stepping through it,
		// which in a /64 pool may be 2^64 addresses.
		if p, ok := containing(routed, addr); ok {
			addr = lastAddr(p).Next()
			continue
		}
		if !held[addr] {
			return addr, nil
		}
		addr = addr.Next()
	}
	return netip.Addr{}, errPoolExhausted
}

// containing returns the widest prefix of routed that contains addr.
func containing(routed []netip.Prefix, addr netip.Addr) (netip.Prefix, bool) {
	var out netip.Prefix
	for _, p := range routed {
		if p.Contains(addr) && (!out.IsValid() || p.Bits() < out.Bits()) {
			out = p
		}
	}
	return out, out.IsValid()
}

// lastAddr returns the highest address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As16()
	for i := p.Bits(); i < 128; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	return netip.AddrFrom16(b)
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
