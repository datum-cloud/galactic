// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabric

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/worker/fabric/fabrictest"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/routes"
)

// Test topology. Addresses are documentation prefixes. VPCs A and B use the
// same guest addresses; only their tables tell them apart.
const (
	vpcA   = "vpcA"
	vpcB   = "vpcB"
	tableA = 100
	tableB = 200
	linkB  = 7
	linkC  = 8
)

var (
	locOwn = netip.MustParsePrefix("2001:db8:0:1::/64")
	locB   = netip.MustParsePrefix("2001:db8:0:2::/64")
	locC   = netip.MustParsePrefix("2001:db8:0:3::/64")

	sidOwnA = netip.MustParseAddr("2001:db8:0:1:e000:1::")
	sidBA   = netip.MustParseAddr("2001:db8:0:2:e000:1::")
	sidBB   = netip.MustParseAddr("2001:db8:0:2:e000:2::")
	sidCA   = netip.MustParseAddr("2001:db8:0:3:e000:1::")

	guest2 = netip.MustParseAddr("2001:db8:a::2")
	guest3 = netip.MustParseAddr("2001:db8:a::3")
	guest4 = netip.MustParseAddr("2001:db8:a::4")

	host2 = netip.PrefixFrom(guest2, 128)
	host3 = netip.PrefixFrom(guest3, 128)
	host4 = netip.PrefixFrom(guest4, 128)

	claimA = module.ClaimKey{Node: "node-a", VPC: vpcA, AttachmentUID: "svc-a"}
)

type fixture struct {
	t  *testing.T
	dp *fabrictest.Datapath
	rt *routes.Table
	m  *Module
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dp := fabrictest.New()
	dp.SetTable(vpcA, tableA)
	dp.SetTable(vpcB, tableB)
	dp.Reach(locB, linkB, "02:00:00:00:00:0b")
	dp.Reach(locC, linkC, "02:00:00:00:00:0c")
	rt := routes.New()
	m, err := New(Config{Routes: rt, Datapath: dp,
		OwnLocator: func(context.Context) (netip.Prefix, error) { return locOwn, nil }})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, dp: dp, rt: rt, m: m}
}

func route(vpc string, table uint32, p netip.Prefix, sid netip.Addr) routes.Route {
	return routes.Route{Key: routes.Key{VPC: vpc, Prefix: p}, TableID: table, SID: sid}
}

func dest(id string, loc netip.Prefix, addrs ...netip.Addr) module.Destination {
	return module.Destination{ID: id, Mode: workerv1alpha1.Mode_MODE_FABRIC, VPC: vpcA, Locator: loc, Addresses: addrs}
}

// claim is claimA with a destination on node B (guest2) and one on node C
// (guest3).
func claim() []module.Claim {
	return []module.Claim{{Key: claimA, Generation: 3, Handoff: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR,
		Destinations: []module.Destination{dest("dB", locB, guest2), dest("dC", locC, guest3)}}}
}

// reconcile runs Plan, Apply and Read for vpc, as Worker does.
func (f *fixture) reconcile(vpc string, desired []module.Claim) (module.Change, module.State) {
	f.t.Helper()
	ctx := context.Background()
	scope := module.Scope{VPC: vpc}
	ch, err := f.m.Plan(ctx, scope, desired)
	if err != nil {
		f.t.Fatalf("Plan(%s): %v", vpc, err)
	}
	if !ch.Empty() {
		if err := f.m.Apply(ctx, scope, ch); err != nil {
			f.t.Fatalf("Apply(%s): %v", vpc, err)
		}
	}
	st, err := f.m.Read(ctx, scope)
	if err != nil {
		f.t.Fatalf("Read(%s): %v", vpc, err)
	}
	return ch, st
}

func (f *fixture) sid(table uint32, p netip.Prefix) netip.Addr {
	f.t.Helper()
	r, ok := f.dp.Entries(table)[p]
	if !ok {
		return netip.Addr{}
	}
	a, _ := netip.AddrFromSlice(r.SID)
	return a
}

func wantState(t *testing.T, st module.State, id string, programmed, forward, ret bool, reason string) {
	t.Helper()
	got, ok := st[claimA][id]
	if !ok {
		t.Fatalf("no state for %s", id)
	}
	if got.Programmed != programmed || got.ForwardReady != forward || got.ReturnReady != ret ||
		got.Ready != (forward && ret) || got.Reason != reason || got.Generation != 3 {
		t.Fatalf("%s = %+v; want programmed=%t forward=%t return=%t reason=%q", id, got, programmed, forward, ret,
			reason)
	}
}

func TestPlanWritesTenantRoutesPerVPCTable(t *testing.T) {
	f := newFixture(t)
	f.rt.Apply([]routes.Route{
		route(vpcA, tableA, host2, sidBA), route(vpcA, tableA, host3, sidCA),
		route(vpcB, tableB, host2, sidBB),
	}, nil)

	ch, st := f.reconcile(vpcA, claim())
	if ch.Empty() {
		t.Fatal("first plan wrote nothing")
	}
	f.reconcile(vpcB, nil)
	if got := f.sid(tableA, host2); got != sidBA {
		t.Errorf("table A %s -> %s, want %s", host2, got, sidBA)
	}
	if got := f.sid(tableB, host2); got != sidBB {
		t.Errorf("table B %s -> %s, want %s", host2, got, sidBB)
	}
	if got := f.sid(tableA, host3); got != sidCA {
		t.Errorf("table A %s -> %s, want %s", host3, got, sidCA)
	}
	wantState(t, st, "dB", true, true, true, "")
	wantState(t, st, "dC", true, true, true, "")

	if ch, _ := f.reconcile(vpcA, claim()); !ch.Empty() {
		t.Errorf("second plan is not empty: %+v", ch)
	}
}

func TestPlanSkipsForeignTableAndOwnLocator(t *testing.T) {
	f := newFixture(t)
	f.rt.Apply([]routes.Route{
		// Recorded for VPC B's table: writing it would cross VPCs.
		route(vpcA, tableB, host2, sidBA),
		// Toward this node: writing it would loop.
		route(vpcA, tableA, host4, sidOwnA),
	}, nil)
	ch, _ := f.reconcile(vpcA, nil)
	if !ch.Empty() {
		t.Fatalf("plan is not empty: %+v", ch)
	}
	if n := len(f.dp.Entries(tableA)) + len(f.dp.Entries(tableB)); n != 0 {
		t.Fatalf("%d entries written, want none", n)
	}
}

func TestWithdrawalRemovesOnlyItsEntry(t *testing.T) {
	f := newFixture(t)
	passThrough := netip.MustParsePrefix("2001:db8:a::10/128")
	def := netip.MustParsePrefix("::/0")
	f.dp.Put(tableA, passThrough, egressroutemap.Row{PassThrough: true})
	f.dp.Put(tableA, def, egressroutemap.Row{Sentinel: true, LinkIndex: -1})
	f.rt.Apply([]routes.Route{route(vpcA, tableA, host2, sidBA), route(vpcA, tableA, host3, sidCA)}, nil)
	f.reconcile(vpcA, nil)

	f.rt.Apply(nil, []routes.Key{
		{VPC: vpcA, Prefix: host2},
		// Never held: removes only an encapsulating entry of its own.
		{VPC: vpcA, Prefix: passThrough},
	})
	f.reconcile(vpcA, nil)
	got := f.dp.Entries(tableA)
	if _, ok := got[host2]; ok {
		t.Error("withdrawn route's entry kept")
	}
	for _, p := range []netip.Prefix{host3, passThrough, def} {
		if _, ok := got[p]; !ok {
			t.Errorf("entry %s removed", p)
		}
	}
	for _, w := range f.rt.Withdrawn(vpcA) {
		if !w.Removed {
			t.Errorf("withdrawal %s not confirmed", w.Prefix)
		}
	}
	if f.rt.HasWork(vpcA) != true {
		t.Error("VPC A has routes but no work")
	}
}

func TestReadinessChangesOnlyForTheAffectedDestination(t *testing.T) {
	f := newFixture(t)
	f.rt.Apply([]routes.Route{route(vpcA, tableA, host2, sidBA), route(vpcA, tableA, host3, sidCA)}, nil)
	_, st := f.reconcile(vpcA, claim())
	wantState(t, st, "dC", true, true, true, "")

	// The underlay route toward node C is lost: its entry is kept, not
	// deleted, and only dC stops being ready.
	f.dp.Unreach(locC, fmt.Errorf("%w: test", egressroutemap.ErrNoUplinkRoute))
	writes, removes := f.dp.Counts()
	_, st = f.reconcile(vpcA, claim())
	if w, r := f.dp.Counts(); w != writes || r != removes {
		t.Errorf("underlay loss wrote %d and removed %d entries, want none", w-writes, r-removes)
	}
	if _, ok := f.dp.Entries(tableA)[host3]; !ok {
		t.Error("entry toward the unreachable node was removed")
	}
	wantState(t, st, "dB", true, true, true, "")
	wantState(t, st, "dC", true, false, true, workerv1alpha1.ReasonUnderlayUnreachable)

	// It comes back through another neighbor: the entry is rewritten and dC
	// recovers.
	f.dp.Reach(locC, linkB, "02:00:00:00:00:0d")
	_, st = f.reconcile(vpcA, claim())
	if r := f.dp.Entries(tableA)[host3]; r.LinkIndex != linkB || r.DMAC.String() != "02:00:00:00:00:0d" {
		t.Errorf("entry toward node C not moved to the new next hop: %+v", r)
	}
	wantState(t, st, "dC", true, true, true, "")

	// The neighbor toward node B is lost.
	f.dp.Unreach(locB, fmt.Errorf("%w: test", egressroutemap.ErrNeighborUnresolved))
	_, st = f.reconcile(vpcA, claim())
	wantState(t, st, "dB", true, false, true, workerv1alpha1.ReasonNeighborUnresolved)
	wantState(t, st, "dC", true, true, true, "")
}

func TestRouteWithdrawnThenRestored(t *testing.T) {
	f := newFixture(t)
	r2 := route(vpcA, tableA, host2, sidBA)
	f.rt.Apply([]routes.Route{r2, route(vpcA, tableA, host3, sidCA)}, nil)
	f.reconcile(vpcA, claim())

	f.rt.Apply(nil, []routes.Key{r2.Key})
	_, st := f.reconcile(vpcA, claim())
	wantState(t, st, "dB", false, false, true, workerv1alpha1.ReasonRouteWithdrawn)
	wantState(t, st, "dC", true, true, true, "")

	f.rt.Apply([]routes.Route{r2}, nil)
	_, st = f.reconcile(vpcA, claim())
	wantState(t, st, "dB", true, true, true, "")
}

func TestRouteToAnotherNodeIsAMismatch(t *testing.T) {
	f := newFixture(t)
	// guest2 is on node B, but the route covering it leads to node C.
	f.rt.Apply([]routes.Route{route(vpcA, tableA, host2, sidCA), route(vpcA, tableA, host3, sidCA)}, nil)
	_, st := f.reconcile(vpcA, claim())
	wantState(t, st, "dB", false, false, true, workerv1alpha1.ReasonRouteMismatch)
	wantState(t, st, "dC", true, true, true, "")
}

func TestMissingRouteAndAddresses(t *testing.T) {
	f := newFixture(t)
	f.rt.Apply([]routes.Route{route(vpcA, tableA, host3, sidCA)}, nil)
	desired := []module.Claim{{Key: claimA, Generation: 3, Destinations: []module.Destination{
		dest("dB", locB, guest2), dest("dNone", locB),
	}}}
	_, st := f.reconcile(vpcA, desired)
	wantState(t, st, "dB", false, false, true, workerv1alpha1.ReasonForwardRouteMissing)
	wantState(t, st, "dNone", false, false, true, workerv1alpha1.ReasonDestinationAddressUnknown)
}

func TestReturnPathIsIndependentOfForward(t *testing.T) {
	f := newFixture(t)
	f.rt.Apply([]routes.Route{route(vpcA, tableA, host2, sidBA), route(vpcA, tableA, host3, sidCA)}, nil)
	f.dp.SetReturn(vpcA, errors.New("no vrf_table row"))
	_, st := f.reconcile(vpcA, claim())
	wantState(t, st, "dB", true, true, false, workerv1alpha1.ReasonReturnPathNotProgrammed)
	f.dp.SetReturn(vpcA, nil)
	_, st = f.reconcile(vpcA, claim())
	wantState(t, st, "dB", true, true, true, "")
}

func TestTableMoveRemovesTheOldEntry(t *testing.T) {
	f := newFixture(t)
	f.rt.Apply([]routes.Route{route(vpcA, tableA, host2, sidBA)}, nil)
	f.reconcile(vpcA, nil)
	const moved = 150
	f.dp.SetTable(vpcA, moved)
	f.rt.Apply([]routes.Route{route(vpcA, moved, host2, sidBA)}, nil)
	f.reconcile(vpcA, nil)
	if _, ok := f.dp.Entries(tableA)[host2]; ok {
		t.Error("entry in the old table kept")
	}
	if got := f.sid(moved, host2); got != sidBA {
		t.Errorf("new table %s -> %s, want %s", host2, got, sidBA)
	}
}

func TestWriteFailureIsIsolated(t *testing.T) {
	f := newFixture(t)
	f.dp.Unreach(locC, fmt.Errorf("%w: test", egressroutemap.ErrNeighborUnresolved))
	f.rt.Apply([]routes.Route{route(vpcA, tableA, host2, sidBA), route(vpcA, tableA, host3, sidCA)}, nil)
	_, st := f.reconcile(vpcA, claim())
	wantState(t, st, "dB", true, true, true, "")
	wantState(t, st, "dC", false, false, true, workerv1alpha1.ReasonNeighborUnresolved)
}

func TestEventsRequeueOnlyTouchedVPCs(t *testing.T) {
	f := newFixture(t)
	f.rt.Apply([]routes.Route{
		route(vpcA, tableA, host2, sidBA), route(vpcA, tableA, host3, sidCA),
		route(vpcB, tableB, host2, sidBB),
	}, nil)
	f.reconcile(vpcA, nil)
	f.reconcile(vpcB, nil)

	ipnet := func(p netip.Prefix) *net.IPNet {
		return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), 128)}
	}
	cases := []struct {
		name string
		got  []string
		want []string
	}{
		{"RouteToC", f.m.routeEvent(netlink.Route{Dst: ipnet(locC)}), []string{vpcA}},
		{"RouteToB", f.m.routeEvent(netlink.Route{Dst: ipnet(locB)}), []string{vpcA, vpcB}},
		{"Default", f.m.routeEvent(netlink.Route{}), []string{vpcA, vpcB}},
		{"OtherTable", f.m.routeEvent(netlink.Route{Dst: ipnet(locC), Table: 1000}), nil},
		{"NeighborC", f.m.neighborEvent(netlink.Neigh{LinkIndex: linkC, IP: net.IP(locC.Addr().AsSlice())}),
			[]string{vpcA}},
		{"NeighborElsewhere", f.m.neighborEvent(netlink.Neigh{LinkIndex: 99, IP: net.IP(locC.Addr().AsSlice())}),
			nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			slices.Sort(c.got)
			if !slices.Equal(c.got, c.want) {
				t.Errorf("got %v, want %v", c.got, c.want)
			}
		})
	}
}

func TestCapabilitiesNeedTheDatapath(t *testing.T) {
	f := newFixture(t)
	for _, c := range f.m.Capabilities() {
		if !c.Available {
			t.Errorf("%s unavailable with the datapath loaded", c.Name)
		}
	}
	f.dp.SetLoaded(errors.New("no pinned maps"))
	got := f.m.Capabilities()
	if len(got) != 2 {
		t.Fatalf("got %d capabilities, want fabric.srv6 and fabric.routes", len(got))
	}
	for _, c := range got {
		if c.Available || c.Reason != workerv1alpha1.ReasonDatapathNotLoaded {
			t.Errorf("%s = %+v, want DatapathNotLoaded", c.Name, c)
		}
	}
}

func TestPlanOfAQuietVPCReadsNothing(t *testing.T) {
	f := newFixture(t)
	m, err := New(Config{Routes: f.rt, Datapath: f.dp,
		OwnLocator: func(context.Context) (netip.Prefix, error) { return netip.Prefix{}, errors.New("API down") }})
	if err != nil {
		t.Fatal(err)
	}
	ch, err := m.Plan(context.Background(), module.Scope{VPC: vpcA}, nil)
	if err != nil || !ch.Empty() {
		t.Fatalf("Plan of a VPC with no routes = %v, %v; want empty and no read", ch, err)
	}
}

func TestRouteUnderACoveringRouteGetsItsOwnEntry(t *testing.T) {
	f := newFixture(t)
	p64 := netip.MustParsePrefix("2001:db8:a::/64")
	f.rt.Apply([]routes.Route{route(vpcA, tableA, p64, sidBA), route(vpcA, tableA, host2, sidBA)}, nil)
	f.reconcile(vpcA, nil)
	if _, ok := f.dp.Entries(tableA)[host2]; !ok {
		t.Fatal("the /128 got no entry of its own under a /64 toward the same SID")
	}
	f.rt.Apply(nil, []routes.Key{{VPC: vpcA, Prefix: p64}})
	f.reconcile(vpcA, nil)
	if got := f.sid(tableA, host2); got != sidBA {
		t.Fatalf("after the /64's withdrawal the /128 leads to %s, want %s", got, sidBA)
	}
}

func TestWithdrawalAfterTheVRFIsGone(t *testing.T) {
	f := newFixture(t)
	f.rt.Apply([]routes.Route{route(vpcA, tableA, host2, sidBA)}, nil)
	f.reconcile(vpcA, nil)
	f.dp.SetTable(vpcA, 0)
	f.rt.Apply(nil, []routes.Key{{VPC: vpcA, Prefix: host2}})
	f.reconcile(vpcA, nil)
	if _, ok := f.dp.Entries(tableA)[host2]; ok {
		t.Fatal("withdrawn entry kept in the old table once the VRF was gone")
	}
	if f.rt.HasWork(vpcA) {
		t.Fatal("the withdrawal is still pending")
	}
}
