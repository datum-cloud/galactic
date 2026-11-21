// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"maps"
	"net/netip"
	"slices"
	"testing"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/module"
)

// fakeEdgeHost is edgeHost over in-memory links, gates, rows and entries.
type fakeEdgeHost struct {
	links []edgeLinkObs
	gates map[uint32]netip.Addr
	rows  map[uint32]netip.Addr
	// pass is each pass-through entry, true when PassThroughEdge owns it.
	pass         map[netip.Prefix]bool
	writes       int
	unregistered []uint32
}

func newFakeEdgeHost(links ...edgeLinkObs) *fakeEdgeHost {
	return &fakeEdgeHost{links: links, gates: map[uint32]netip.Addr{}, rows: map[uint32]netip.Addr{},
		pass: map[netip.Prefix]bool{}}
}

func (h *fakeEdgeHost) Links(string) ([]edgeLinkObs, error) { return slices.Clone(h.links), nil }

func (h *fakeEdgeHost) GateAddr(i uint32) (netip.Addr, bool, error) {
	a, ok := h.gates[i]
	return a, ok, nil
}

func (h *fakeEdgeHost) Registered(_, i uint32, _ string, addr netip.Addr) (bool, error) {
	a, ok := h.rows[i]
	return ok && a == addr, nil
}

func (h *fakeEdgeHost) HasRows(i uint32) (bool, error) {
	_, ok := h.rows[i]
	return ok, nil
}

func (h *fakeEdgeHost) Register(_, i uint32, _ string, addr netip.Addr) error {
	h.writes++
	h.rows[i] = addr
	return nil
}

func (h *fakeEdgeHost) Unregister(i uint32) error {
	h.writes++
	h.unregistered = append(h.unregistered, i)
	delete(h.rows, i)
	return nil
}

func (h *fakeEdgeHost) PassThrough(uint32) (map[netip.Prefix]bool, error) {
	out := map[netip.Prefix]bool{}
	for p, e := range h.pass {
		out[p] = e
	}
	return out, nil
}

func (h *fakeEdgeHost) SyncPassThrough(_ uint32, want []netip.Prefix) error {
	h.writes++
	wanted := map[netip.Prefix]bool{}
	for _, p := range want {
		wanted[p] = true
		if _, ok := h.pass[p]; !ok {
			h.pass[p] = true
		}
	}
	for p, edge := range h.pass {
		if edge && !wanted[p] {
			delete(h.pass, p)
		}
	}
	return nil
}

const (
	link0     = "ge0"
	testVPC   = "vpcA"
	testTable = uint32(100)
)

var (
	addrA = netip.MustParseAddr("2001:db8:100::10")
	addrB = netip.MustParseAddr("2001:db8:100::11")
	pfxA  = netip.MustParsePrefix("2001:db8:200::/48")
)

func edgeClaim(uid, name string, gen uint64, addr netip.Addr, prefixes ...netip.Prefix) module.Claim {
	k := module.ClaimKey{Node: "n", VPC: testVPC, AttachmentUID: uid}
	return module.Claim{Key: k, Generation: gen, Handoff: workerv1alpha1.Handoff_HANDOFF_ROUTED_LINK,
		Destinations: []module.Destination{{ID: "attachment/" + uid}},
		EdgeLink:     &module.EdgeLink{Name: name, Address: addr, Prefixes: prefixes}}
}

// withVRF makes tableID report the test VPC's VRF for the test.
func withVRF(t *testing.T, have bool) {
	t.Helper()
	saved := tableID
	tableID = func(string) (uint32, int, bool, error) { return testTable, 7, have, nil }
	t.Cleanup(func() { tableID = saved })
}

// TestEdgeLinkRegisters registers a claimed, gated link, writes its address
// and prefixes as pass-through entries, and reports it Ready once up.
func TestEdgeLinkRegisters(t *testing.T) {
	withVRF(t, true)
	h := newFakeEdgeHost(edgeLinkObs{Name: link0, Index: 10, UID: "a", Up: false})
	h.gates[10] = addrA
	claims := []module.Claim{edgeClaim("a", link0, 3, addrA, pfxA)}

	p, err := planEdge(h, testVPC, testTable, true, claims)
	if err != nil {
		t.Fatal(err)
	}
	if !p.dirty() {
		t.Fatal("plan of an unregistered link is not dirty")
	}
	if err := applyEdge(h, p); err != nil {
		t.Fatal(err)
	}
	if h.rows[10] != addrA {
		t.Fatalf("rows = %v", h.rows)
	}
	wantPass := map[netip.Prefix]bool{netip.PrefixFrom(addrA, 128): true, pfxA: true}
	if !maps.Equal(h.pass, wantPass) {
		t.Fatalf("pass-through = %v, want %v", h.pass, wantPass)
	}
	if p, _ := planEdge(h, testVPC, testTable, true, claims); p.dirty() {
		t.Fatal("plan after apply is still dirty")
	}

	st := module.State{}
	if err := readEdge(h, "n", testVPC, claims, st); err != nil {
		t.Fatal(err)
	}
	got := st[claims[0].Key]["attachment/a"]
	if !got.Programmed || got.Ready || got.Generation != 3 ||
		got.Reason != workerv1alpha1.ReasonHandoffInterfaceMissing {
		t.Fatalf("state of a down link = %+v, want Programmed and not Ready", got)
	}
	h.links[0].Up = true
	st = module.State{}
	if err := readEdge(h, "n", testVPC, claims, st); err != nil {
		t.Fatal(err)
	}
	if got := st[claims[0].Key]["attachment/a"]; !got.Ready {
		t.Fatalf("state of an up link = %+v, want Ready", got)
	}
}

// TestEdgeLinkReusedIfindexStartsClean clears the rows a deleted link left on
// an ifindex a new link reuses before registering the new link, so it never
// keeps another attachment's policy token.
func TestEdgeLinkReusedIfindexStartsClean(t *testing.T) {
	withVRF(t, true)
	h := newFakeEdgeHost(edgeLinkObs{Name: "ge1", Index: 10, UID: "a", Up: true})
	h.gates[10] = addrA
	// A deleted link of another attachment left its rows on ifindex 10.
	h.rows[10] = addrB
	claims := []module.Claim{edgeClaim("a", "ge1", 1, addrA)}
	p, err := planEdge(h, testVPC, testTable, true, claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyEdge(h, p); err != nil {
		t.Fatal(err)
	}
	if len(h.unregistered) != 1 || h.unregistered[0] != 10 {
		t.Fatalf("unregistered %v, want the reused ifindex 10 cleared first", h.unregistered)
	}
	if h.rows[10] != addrA {
		t.Fatalf("rows of ifindex 10 = %v, want the new link's", h.rows[10])
	}
}

// TestEdgeLinkNotOwned refuses to register a link a claim names that is
// another attachment's, or whose gate names another address, and writes
// nothing for it.
func TestEdgeLinkNotOwned(t *testing.T) {
	withVRF(t, true)
	for _, tc := range []struct {
		name   string
		claim  module.Claim
		gate   netip.Addr
		gated  bool
		reason string
	}{
		{"another attachment's link", edgeClaim("a", link0, 1, addrA), addrA, true,
			workerv1alpha1.ReasonHandoffInterfaceNotOwned},
		{"gate names another address", edgeClaim("b", link0, 1, addrA), addrB, true,
			workerv1alpha1.ReasonHandoffInterfaceNotOwned},
		{"no gate yet", edgeClaim("b", link0, 1, addrA), netip.Addr{}, false,
			workerv1alpha1.ReasonHandoffInterfaceMissing},
		{"no link", edgeClaim("c", "ge9", 1, addrA), addrA, true,
			workerv1alpha1.ReasonHandoffInterfaceMissing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The link is attachment b's.
			h := newFakeEdgeHost(edgeLinkObs{Name: link0, Index: 10, UID: "b", Up: true})
			if tc.gated {
				h.gates[10] = tc.gate
			}
			claims := []module.Claim{tc.claim}
			p, err := planEdge(h, testVPC, testTable, true, claims)
			if err != nil {
				t.Fatal(err)
			}
			if err := applyEdge(h, p); err != nil {
				t.Fatal(err)
			}
			if len(h.rows) != 0 || len(h.pass) != 0 {
				t.Fatalf("wrote rows %v and entries %v", h.rows, h.pass)
			}
			st := module.State{}
			if err := readEdge(h, "n", testVPC, claims, st); err != nil {
				t.Fatal(err)
			}
			got := st[tc.claim.Key]["attachment/"+tc.claim.Key.AttachmentUID]
			if got.Programmed || got.Reason != tc.reason {
				t.Fatalf("state = %+v, want unprogrammed with %s", got, tc.reason)
			}
		})
	}
}

// TestEdgeLinkStaleUnregistered unregisters a stamped link no claim keeps,
// such as a released or revoked one, reports it as a leftover until it is
// gone, and removes its pass-through entries but not another owner's.
func TestEdgeLinkStaleUnregistered(t *testing.T) {
	withVRF(t, true)
	h := newFakeEdgeHost(edgeLinkObs{Name: link0, Index: 10, UID: "a", Up: true},
		edgeLinkObs{Name: "ge1", Index: 11, UID: "b", Up: true})
	h.gates[10], h.gates[11] = addrA, addrB
	h.rows[10], h.rows[11] = addrA, addrB
	cni := netip.MustParsePrefix("2001:db8:300::/48")
	h.pass[netip.PrefixFrom(addrA, 128)] = true
	h.pass[netip.PrefixFrom(addrB, 128)] = true
	h.pass[pfxA] = true
	h.pass[cni] = false
	claims := []module.Claim{edgeClaim("b", "ge1", 1, addrB)}

	st := module.State{}
	if err := readEdge(h, "n", testVPC, claims, st); err != nil {
		t.Fatal(err)
	}
	stale := module.ClaimKey{Node: "n", VPC: testVPC, AttachmentUID: "a"}
	if _, ok := st[stale][leftoverID]; !ok {
		t.Fatalf("no leftover reported for the stale link: %v", st)
	}
	p, err := planEdge(h, testVPC, testTable, true, claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyEdge(h, p); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.rows[10]; ok {
		t.Fatal("stale link still registered")
	}
	if h.rows[11] != addrB {
		t.Fatal("claimed link unregistered")
	}
	want := map[netip.Prefix]bool{netip.PrefixFrom(addrB, 128): true, cni: false}
	if !maps.Equal(h.pass, want) {
		t.Fatalf("pass-through = %v, want %v", h.pass, want)
	}
	st = module.State{}
	if err := readEdge(h, "n", testVPC, claims, st); err != nil {
		t.Fatal(err)
	}
	if _, ok := st[stale]; ok {
		t.Fatalf("leftover still reported after unregistering: %v", st[stale])
	}
}

// TestEdgeLinkOtherOwnerEntryKeepsPlanClean treats a wanted prefix another
// owner's pass-through entry already carries as in place.
func TestEdgeLinkOtherOwnerEntryKeepsPlanClean(t *testing.T) {
	withVRF(t, true)
	h := newFakeEdgeHost(edgeLinkObs{Name: link0, Index: 10, UID: "a", Up: true})
	h.gates[10], h.rows[10] = addrA, addrA
	h.pass[netip.PrefixFrom(addrA, 128)] = true
	h.pass[pfxA] = false
	p, err := planEdge(h, testVPC, testTable, true, []module.Claim{edgeClaim("a", link0, 1, addrA, pfxA)})
	if err != nil {
		t.Fatal(err)
	}
	if p.dirty() {
		t.Fatal("plan is dirty for a prefix another owner already passes through")
	}
}

// TestEdgeLinkWithoutVRF writes nothing while the VPC has no VRF.
func TestEdgeLinkWithoutVRF(t *testing.T) {
	withVRF(t, false)
	h := newFakeEdgeHost(edgeLinkObs{Name: link0, Index: 10, UID: "a"})
	claims := []module.Claim{edgeClaim("a", link0, 1, addrA)}
	p, err := planEdge(h, testVPC, 0, false, claims)
	if err != nil {
		t.Fatal(err)
	}
	if p.dirty() {
		t.Fatal("plan without a VRF is dirty")
	}
	if err := applyEdge(h, p); err != nil || h.writes != 0 {
		t.Fatalf("apply without a VRF wrote %d times: %v", h.writes, err)
	}
	st := module.State{}
	if err := readEdge(h, "n", testVPC, claims, st); err != nil {
		t.Fatal(err)
	}
	if got := st[claims[0].Key]["attachment/a"]; got.Programmed ||
		got.Reason != workerv1alpha1.ReasonHandoffInterfaceMissing {
		t.Fatalf("state = %+v", got)
	}
}
