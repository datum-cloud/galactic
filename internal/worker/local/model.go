// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"slices"
	"sort"
	"strings"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/worker/module"
)

// maxGuardAddrs is how many source addresses a routed link admits
// (LT_GUARD_ADDRS in local.c).
const maxGuardAddrs = 4

// base62 digits, as intf encodes identifiers.
const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// linkKey is the 3-character key of the links Local creates for the claim on
// attachmentUID, derived from its UID. Two claims in one VPC whose keys
// collide are told apart by the links' alias.
func linkKey(attachmentUID string) string {
	sum := sha256.Sum256([]byte(attachmentUID))
	n := binary.BigEndian.Uint32(sum[:4]) % (62 * 62 * 62)
	out := make([]byte, 3)
	for i := 2; i >= 0; i-- {
		out[i] = base62[n%62]
		n /= 62
	}
	return string(out)
}

// linkName is the name of the Local link of role for the claim on
// attachmentUID in vpc.
func linkName(vpc, attachmentUID, role string) string {
	return intf.GenerateInterfaceNameLocal(vpc, linkKey(attachmentUID), role)
}

// alias is the alias of every link Local creates for the claim k: it marks
// the link as internal (attach.IsInternalLink) and names its claim.
func alias(k module.ClaimKey) string {
	return attach.InternalAliasPrefix + k.VPC + "/" + k.AttachmentUID
}

// parseAlias returns the VPC and attachment UID a Local link's alias names.
func parseAlias(a string) (vpc, attachmentUID string, ok bool) {
	rest, found := strings.CutPrefix(a, attach.InternalAliasPrefix)
	if !found {
		return "", "", false
	}
	vpc, attachmentUID, ok = strings.Cut(rest, "/")
	return vpc, attachmentUID, ok && vpc != "" && attachmentUID != ""
}

// pairWant is the service-internal veth pair of a veth_pair claim.
type pairWant struct {
	key    module.ClaimKey
	nat    string
	tenant string
}

// routedWant is the routed link of a routed_link or socket claim.
type routedWant struct {
	key  module.ClaimKey
	host string
	pod  string
	// podUID is the pod the pod end goes in.
	podUID string
	// addrs are the sources the pod end may use: the claim attachment's
	// IPv6 addresses, at most maxGuardAddrs.
	addrs []netip.Addr
}

// tenantWant is one tenant interface a claim delivers to.
type tenantWant struct {
	name string
	// tap is set when a local.tap claim delivers to it; nh is then the
	// guest address local_rx resolves, or the zero address.
	tap bool
	nh  netip.Addr
	// pair is the tenant end of the VPC's pair a flow from it enters, or "".
	pair string
	// guests are its addresses the pair delivers to.
	guests []netip.Addr
}

// model is the Local state one VPC scope wants.
type model struct {
	vpc     string
	pairs   map[string]pairWant
	routed  map[string]routedWant
	tenants map[string]*tenantWant
	// tap is set when a claim of the scope uses local.tap, which needs
	// local_rx on the node's public receiving devices.
	tap bool
}

// Empty reports whether the scope wants no Local state.
func (m *model) empty() bool {
	return len(m.pairs) == 0 && len(m.routed) == 0 && len(m.tenants) == 0
}

// ipv6 returns addrs' IPv6 addresses, in order.
func ipv6(addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if a.Is6() && !a.Is4In6() {
			out = append(out, a)
		}
	}
	return out
}

// desire computes the Local state the claims of vpc want. A destination
// whose attachment has no host interface yet wants nothing; Read reports it.
func desire(vpc string, claims []module.Claim) *model {
	m := &model{vpc: vpc, pairs: map[string]pairWant{}, routed: map[string]routedWant{},
		tenants: map[string]*tenantWant{}}
	sorted := slices.Clone(claims)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key.String() < sorted[j].Key.String() })
	tenant := func(name string) *tenantWant {
		t := m.tenants[name]
		if t == nil {
			t = &tenantWant{name: name}
			m.tenants[name] = t
		}
		return t
	}
	for _, c := range sorted {
		switch c.Handoff {
		case workerv1alpha1.Handoff_HANDOFF_TAP:
			m.tap = true
			for _, d := range c.Destinations {
				if d.HostInterface == "" {
					continue
				}
				t := tenant(d.HostInterface)
				t.tap = true
				if v6 := ipv6(d.Addresses); len(v6) > 0 && !t.nh.IsValid() {
					t.nh = v6[0]
				}
			}
		case workerv1alpha1.Handoff_HANDOFF_VETH_PAIR:
			p := pairWant{key: c.Key, nat: linkName(vpc, c.Key.AttachmentUID, intf.LocalRolePairNAT),
				tenant: linkName(vpc, c.Key.AttachmentUID, intf.LocalRolePairTenant)}
			m.pairs[p.tenant] = p
			for _, d := range c.Destinations {
				if d.HostInterface == "" {
					continue
				}
				t := tenant(d.HostInterface)
				// One pair steers a tenant's flows: the first claim's,
				// in claim key order.
				if t.pair == "" {
					t.pair = p.tenant
				}
				t.guests = append(t.guests, ipv6(d.Addresses)...)
			}
		case workerv1alpha1.Handoff_HANDOFF_ROUTED_LINK, workerv1alpha1.Handoff_HANDOFF_SOCKET:
			addrs := ipv6(c.Addresses)
			if len(addrs) > maxGuardAddrs {
				addrs = addrs[:maxGuardAddrs]
			}
			r := routedWant{key: c.Key, host: linkName(vpc, c.Key.AttachmentUID, intf.LocalRoleRoutedHost),
				pod: linkName(vpc, c.Key.AttachmentUID, intf.LocalRoleRoutedPod), podUID: c.OwnerPod, addrs: addrs}
			m.routed[r.host] = r
		}
	}
	for _, t := range m.tenants {
		slices.SortFunc(t.guests, func(a, b netip.Addr) int { return a.Compare(b) })
		t.guests = slices.Compact(t.guests)
	}
	return m
}
