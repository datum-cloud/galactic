// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"net/netip"
	"testing"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/worker/module"
)

func TestLinkNames(t *testing.T) {
	k := linkKey("6c1c3b7e-2a64-4d8a-9a51-1f0c9d1e2b3a")
	if len(k) != 3 || linkKey("6c1c3b7e-2a64-4d8a-9a51-1f0c9d1e2b3a") != k {
		t.Fatalf("linkKey = %q, want 3 stable characters", k)
	}
	for _, role := range []string{intf.LocalRolePairNAT, intf.LocalRolePairTenant, intf.LocalRoleRoutedHost,
		intf.LocalRoleRoutedPod} {
		name := linkName("8KxP2", "6c1c3b7e-2a64-4d8a-9a51-1f0c9d1e2b3a", role)
		if len(name) > 15 || !intf.IsLocalLinkName(name) || !intf.IsGalacticLinkName(name) {
			t.Errorf("linkName(%s) = %q, not a Local link name within 15 characters", role, name)
		}
	}
	for _, cni := range []string{intf.GenerateInterfaceNameHost("8KxP2", "a1"), intf.GenerateInterfaceNameVRF("8KxP2")} {
		if intf.IsLocalLinkName(cni) || !intf.IsGalacticLinkName(cni) {
			t.Errorf("%q: CNI names are Galactic but not Local", cni)
		}
	}
	key := module.ClaimKey{Node: "n", VPC: "8KxP2", AttachmentUID: "uid-1"}
	vpc, uid, ok := parseAlias(alias(key))
	if !ok || vpc != key.VPC || uid != key.AttachmentUID {
		t.Fatalf("parseAlias(alias(%v)) = %q %q %t", key, vpc, uid, ok)
	}
	if _, _, ok := parseAlias(attach.InternalAliasPrefix + "novpc"); ok {
		t.Fatal("an alias without an attachment parsed")
	}
}

func TestDesire(t *testing.T) {
	v6 := netip.MustParseAddr("fd20::1")
	v4 := netip.MustParseAddr("10.0.0.1")
	dest := func(host string, addrs ...netip.Addr) module.Destination {
		return module.Destination{ID: "attachment/" + host, HostInterface: host, Addresses: addrs}
	}
	claims := []module.Claim{
		{Key: module.ClaimKey{VPC: "v", AttachmentUID: "gw"}, Handoff: workerv1alpha1.Handoff_HANDOFF_TAP,
			Destinations: []module.Destination{dest("tapA", v4, v6), dest("")}},
		{Key: module.ClaimKey{VPC: "v", AttachmentUID: "nat-b"}, Handoff: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR,
			Destinations: []module.Destination{dest("tapA", v6)}},
		{Key: module.ClaimKey{VPC: "v", AttachmentUID: "nat-a"}, Handoff: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR,
			Destinations: []module.Destination{dest("tapA", v6, v4)}},
		{Key: module.ClaimKey{VPC: "v", AttachmentUID: "envoy"}, Handoff: workerv1alpha1.Handoff_HANDOFF_SOCKET,
			OwnerPod: "pod", Addresses: []netip.Addr{v4, v6, netip.MustParseAddr("fd20::2"),
				netip.MustParseAddr("fd20::3"), netip.MustParseAddr("fd20::4"), netip.MustParseAddr("fd20::5")}},
	}
	m := desire("v", claims)
	if !m.tap || len(m.pairs) != 2 || len(m.routed) != 1 || len(m.tenants) != 1 {
		t.Fatalf("desire = %+v", m)
	}
	ta := m.tenants["tapA"]
	if !ta.tap || ta.nh != v6 {
		t.Errorf("tapA: tap %t nh %s, want a TAP resolving %s", ta.tap, ta.nh, v6)
	}
	// The first pair in claim key order steers; IPv4 is not delivered.
	if want := linkName("v", "nat-a", intf.LocalRolePairTenant); ta.pair != want {
		t.Errorf("tapA steers into %q, want %q", ta.pair, want)
	}
	if len(ta.guests) != 1 || ta.guests[0] != v6 {
		t.Errorf("tapA guests = %v, want [%s]", ta.guests, v6)
	}
	for _, r := range m.routed {
		if r.podUID != "pod" || len(r.addrs) != maxGuardAddrs || r.addrs[0] != v6 {
			t.Errorf("routed link %+v: want the pod and the first %d IPv6 addresses", r, maxGuardAddrs)
		}
	}
	if !desire("v", nil).empty() {
		t.Error("no claims want state")
	}
}
