// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"testing"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/worker/module"
)

// veth is a veth as a link dump reports it: its peer's ifindex as
// IFLA_LINK, and IFLA_LINK_NETNSID only when the peer is elsewhere.
func veth(name, a string, idx, peer, netnsid int) *netlink.Veth {
	attrs := netlink.NewLinkAttrs()
	attrs.Name, attrs.Alias, attrs.Index, attrs.ParentIndex, attrs.NetNsID = name, a, idx, peer, netnsid
	return &netlink.Veth{LinkAttrs: attrs}
}

// TestReadPairPeers checks that readPair takes a pair as its own only when
// the link dump shows each end as the other's peer in this namespace.
func TestReadPairPeers(t *testing.T) {
	p := pairWant{key: module.ClaimKey{Node: "n", VPC: "0000080", AttachmentUID: "u"}, nat: "nat", tenant: "ten"}
	a := alias(p.key)
	cases := []struct {
		name        string
		tenant, nat *netlink.Veth
		want        bool
	}{
		{"peers", veth("ten", a, 10, 9, -1), veth("nat", a, 9, 10, -1), true},
		{"tenant names another peer", veth("ten", a, 10, 11, -1), veth("nat", a, 9, 10, -1), false},
		{"NAT end names another peer", veth("ten", a, 10, 9, -1), veth("nat", a, 9, 11, -1), false},
		{"no peer reported", veth("ten", a, 10, 0, -1), veth("nat", a, 9, 0, -1), false},
		{"peers in another namespace", veth("ten", a, 10, 9, 3), veth("nat", a, 9, 10, 3), false},
		{"another claim's alias", veth("ten", a+"x", 10, 9, -1), veth("nat", a, 9, 10, -1), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := &host{byName: map[string]netlink.Link{"ten": c.tenant, "nat": c.nat}}
			got, ok := h.readPair(p)
			if ok != c.want {
				t.Fatalf("readPair ok = %t, want %t", ok, c.want)
			}
			if ok && (got.tenant != c.tenant || got.nat != c.nat) {
				t.Fatalf("readPair = %+v, want the tenant and NAT ends", got)
			}
		})
	}
}
