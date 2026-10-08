// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package query

import (
	"net/netip"
)

// specialUse lists the ranges a public probe may never target: the IANA IPv4
// and IPv6 special-purpose registries' ranges that are not globally reachable,
// documentation and benchmarking ranges, multicast, and SRv6 SID space.
// IPv6 destinations must additionally fall inside 2000::/3.
var specialUse = mustPrefixes(
	// IPv4.
	"0.0.0.0/8",          // "this network"
	"10.0.0.0/8",         // private
	"100.64.0.0/10",      // shared address space (CGN)
	"127.0.0.0/8",        // loopback
	"169.254.0.0/16",     // link local
	"172.16.0.0/12",      // private
	"192.0.0.0/24",       // IETF protocol assignments
	"192.0.2.0/24",       // TEST-NET-1
	"192.31.196.0/24",    // AS112-v4
	"192.52.193.0/24",    // AMT
	"192.88.99.0/24",     // deprecated 6to4 relay anycast
	"192.168.0.0/16",     // private
	"192.175.48.0/24",    // direct delegation AS112
	"198.18.0.0/15",      // benchmarking
	"198.51.100.0/24",    // TEST-NET-2
	"203.0.113.0/24",     // TEST-NET-3
	"224.0.0.0/4",        // multicast
	"240.0.0.0/4",        // reserved, including limited broadcast
	"255.255.255.255/32", // limited broadcast
	// IPv6.
	"::/128",         // unspecified
	"::1/128",        // loopback
	"::ffff:0:0/96",  // IPv4-mapped
	"64:ff9b::/96",   // NAT64 well-known prefix
	"64:ff9b:1::/48", // local-use NAT64
	"100::/64",       // discard-only
	"2001::/23",      // IETF protocol assignments (Teredo, ORCHID, ...)
	"2001:db8::/32",  // documentation
	"2002::/16",      // 6to4
	"3fff::/20",      // documentation
	"5f00::/16",      // SRv6 SIDs
	"fc00::/7",       // unique local
	"fe80::/10",      // link local
	"ff00::/8",       // multicast
)

// globalUnicastV6 is the only IPv6 space a public probe may target.
var globalUnicastV6 = netip.MustParsePrefix("2000::/3")

// DestinationPolicy decides whether a resolved, numeric probe destination may
// be probed.
type DestinationPolicy struct {
	// Deny lists additional platform or management ranges no probe may
	// target, on top of the special-use ranges.
	Deny []netip.Prefix
	// Allow lists narrow exceptions that bypass every other rule. Only an
	// operator identity's policy carries any; the public policy has none.
	Allow []netip.Prefix
}

// Check returns nil if a may be probed under p, else a CodeDestinationDeny
// error.
func (p DestinationPolicy) Check(a netip.Addr) error {
	if !a.IsValid() {
		return errorf(CodeDestinationDeny, "destination is not an address")
	}
	if a.Zone() != "" {
		return errorf(CodeDestinationDeny, "destination %s has a zone", a)
	}
	a = a.Unmap()
	for _, pfx := range p.Allow {
		if pfx.Contains(a) {
			return nil
		}
	}
	if a.Is6() && !globalUnicastV6.Contains(a) {
		return errorf(CodeDestinationDeny, "destination %s is not IPv6 global unicast", a)
	}
	for _, pfx := range specialUse {
		if pfx.Contains(a) {
			return errorf(CodeDestinationDeny, "destination %s is in special-use range %s", a, pfx)
		}
	}
	for _, pfx := range p.Deny {
		if pfx.Contains(a) {
			return errorf(CodeDestinationDeny, "destination %s is in excluded range %s", a, pfx)
		}
	}
	return nil
}

// ResolvedProbe returns the numeric destination of a canonical probe query,
// requiring that the target already be an address in the query's family.
// Cells and nodes never resolve a hostname; NSO pins the address first.
func ResolvedProbe(q Query) (netip.Addr, error) {
	a, err := netip.ParseAddr(q.Target)
	if err != nil {
		return netip.Addr{}, errorf(CodeHostnameRequired, "probe destination %q must be a numeric address", q.Target)
	}
	if familyOf(a) != q.AddressFamily {
		return netip.Addr{}, errorf(CodeFamilyConflict, "destination %s is not %s", a, q.AddressFamily)
	}
	return a, nil
}

// ParsePrefixes parses a list of CIDR prefixes, masking host bits.
func ParsePrefixes(ss []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func mustPrefixes(ss ...string) []netip.Prefix {
	out, err := ParsePrefixes(ss)
	if err != nil {
		panic(err)
	}
	return out
}
