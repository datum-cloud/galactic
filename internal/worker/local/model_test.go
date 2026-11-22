// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"net/netip"
	"reflect"
	"strconv"
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

// TestDesireTreatsABackendAsItsAttachment checks that a local.tap claim's
// backend destination wants exactly the state its VPCAttachment's would.
func TestDesireTreatsABackendAsItsAttachment(t *testing.T) {
	v6 := netip.MustParseAddr("fd20::1")
	k := module.ClaimKey{VPC: "v", AttachmentUID: "backend-att"}
	att := module.Destination{ID: "attachment/backend-att", HostInterface: "tapA",
		Addresses: []netip.Addr{v6}}
	backend := att
	backend.ID = "backend/node-a/7"
	backend.Backend = &module.BackendTarget{Slot: 7, Address: v6, Port: 8080, Bindings: []string{"b"}}
	claim := func(d module.Destination) []module.Claim {
		return []module.Claim{{Key: k, Handoff: workerv1alpha1.Handoff_HANDOFF_TAP,
			Destinations: []module.Destination{d}}}
	}
	got, want := desire("v", claim(backend)), desire("v", claim(att))
	if !got.tap || len(got.tenants) != 1 || !reflect.DeepEqual(got.tenants["tapA"], want.tenants["tapA"]) {
		t.Fatalf("backend desire = %+v (tapA %+v), want the attachment's %+v", got, got.tenants["tapA"],
			want.tenants["tapA"])
	}
}

// TestDesireReportsLinkKeyCollisions checks that when two claims of a VPC
// derive the same link names, the first in claim key order gets the links
// and the other is reported, rather than one silently taking the other's.
func TestDesireReportsLinkKeyCollisions(t *testing.T) {
	seen := map[string]string{}
	var a, b string
	for i := 0; a == ""; i++ {
		uid := "uid-" + strconv.Itoa(i)
		k := linkKey(uid)
		if prev, ok := seen[k]; ok {
			a, b = prev, uid
		}
		seen[k] = uid
	}
	if a > b {
		a, b = b, a
	}
	for _, h := range []workerv1alpha1.Handoff{workerv1alpha1.Handoff_HANDOFF_VETH_PAIR,
		workerv1alpha1.Handoff_HANDOFF_ROUTED_LINK} {
		ka := module.ClaimKey{VPC: "v", AttachmentUID: a}
		kb := module.ClaimKey{VPC: "v", AttachmentUID: b}
		m := desire("v", []module.Claim{{Key: kb, Handoff: h}, {Key: ka, Handoff: h}})
		if len(m.pairs)+len(m.routed) != 1 || m.collisions[kb] != ka {
			t.Fatalf("%s: links %d, collisions %v; want %s's links and %s reported", h,
				len(m.pairs)+len(m.routed), m.collisions, a, b)
		}
	}
}

// TestDesireExpandsALocalShard steers every tenant a Local shard serves into
// the claim's pair and authorizes the pair's return to their addresses.
func TestDesireExpandsALocalShard(t *testing.T) {
	key := module.ClaimKey{Node: "n", VPC: "vpc1", AttachmentUID: "uid-shard"}
	sid := netip.MustParseAddr("2001:db8:5:1::")
	a1, a2 := netip.MustParseAddr("2001:db8:a::1"), netip.MustParseAddr("2001:db8:a::2")
	m := desire("vpc1", []module.Claim{{Key: key, Handoff: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR,
		Destinations: []module.Destination{{ID: "shard/s", Shard: &module.ShardTarget{Name: "s", SID: sid,
			Tenants: []module.ShardTenant{
				{UID: "t1", HostInterface: "tap1", Addresses: []netip.Addr{a1}},
				{UID: "t2", HostInterface: "tap2", Addresses: []netip.Addr{a2}},
				{UID: "t3"}, // not attached yet
			}}}}}})
	if m.shard == nil || m.shard.key != key || m.shard.sid != sid {
		t.Fatalf("shard = %+v, want the claim's shard", m.shard)
	}
	if len(m.pairs) != 1 || len(m.tenants) != 2 {
		t.Fatalf("pairs = %v tenants = %v, want one pair and the two attached tenants", m.pairs, m.tenants)
	}
	for name, want := range map[string]netip.Addr{"tap1": a1, "tap2": a2} {
		tw := m.tenants[name]
		if tw == nil || tw.pair != m.shard.pair || len(tw.guests) != 1 || tw.guests[0] != want {
			t.Fatalf("tenant %s = %+v, want steered into %s with guest %s", name, tw, m.shard.pair, want)
		}
	}
}
