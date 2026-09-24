// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srcfilter

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/srcfiltermap"
)

const (
	idxEth0 = iota + 1
	idxEth1
	idxBond0
	idxEth2
	idxEth3
	idxVlan
	idxMgmt
)

var (
	domain     = netip.MustParsePrefix("2001:db8::/32")
	ownLocator = netip.MustParsePrefix("2001:db8:0:1::/64")
	peerA      = netip.MustParsePrefix("2001:db8:0:2::/64")
	peerB      = netip.MustParsePrefix("2001:db8:0:3::/64")
	peerC      = netip.MustParsePrefix("2001:db8:0:4::/64")
	peerD      = netip.MustParsePrefix("2001:db8:0:5::/64")
	shard      = netip.MustParsePrefix("2001:db8:0:6::/64")
	unboundP   = netip.MustParsePrefix("2001:db8:0:7::/64")
	aggregate  = netip.MustParsePrefix("2001:db8:1::/48")
	discard    = netip.MustParsePrefix("2001:db8:0:8::/64")
	outside    = netip.MustParsePrefix("2001:db9:0:1::/64")
	extra      = netip.MustParsePrefix("2001:db8:ffff:1::/64")
)

func testLinks() []netlink.Link {
	dev := func(idx int, name string, master int) netlink.Link {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: idx, Name: name, MasterIndex: master}}
	}
	return []netlink.Link{
		dev(idxEth0, "eth0", 0),
		dev(idxEth1, "eth1", 0),
		&netlink.Bond{LinkAttrs: netlink.LinkAttrs{Index: idxBond0, Name: "bond0"}},
		dev(idxEth2, "eth2", idxBond0),
		dev(idxEth3, "eth3", idxBond0),
		&netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Index: idxVlan, Name: "bond0.100", ParentIndex: idxBond0}},
		dev(idxMgmt, "mgmt", 0),
	}
}

var testUplinks = []string{"eth0", "eth1", "bond0", "eth2", "eth3", "bond0.100"}

func ipnet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), 128)}
}

func route(p netip.Prefix, link int, proto netlink.RouteProtocol) netlink.Route {
	return netlink.Route{
		Dst: ipnet(p), LinkIndex: link, Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, Protocol: proto,
	}
}

func testRoutes() []netlink.Route {
	multipath := route(peerB, 0, unix.RTPROT_BGP)
	multipath.MultiPath = []*netlink.NexthopInfo{{LinkIndex: idxEth0}, {LinkIndex: idxEth1}}
	blackhole := route(discard, 0, unix.RTPROT_BGP)
	blackhole.Type = unix.RTN_BLACKHOLE
	otherTable := route(peerA, idxMgmt, unix.RTPROT_BGP)
	otherTable.Table = 100
	return []netlink.Route{
		route(peerA, idxEth0, unix.RTPROT_BGP),
		multipath,
		route(peerC, idxBond0, unix.RTPROT_BGP),
		route(peerD, idxVlan, unix.RTPROT_BGP),
		route(shard, idxEth1, unix.RTPROT_BOOT),
		route(unboundP, 99, unix.RTPROT_BGP),
		route(aggregate, idxEth0, unix.RTPROT_BGP),
		route(ownLocator, idxEth0, unix.RTPROT_BGP),
		blackhole,
		route(outside, idxEth0, unix.RTPROT_BGP),
		otherTable,
		{Dst: nil, LinkIndex: idxMgmt, Table: unix.RT_TABLE_MAIN},
	}
}

type fixture struct {
	routes    []netlink.Route
	routesErr error
	uplinks   []string
	filter    *srcfiltermap.Filter
	tables    srcfiltermap.Tables
	settings  Settings
}

func newFixture() *fixture {
	f, t := srcfiltermap.NewFake()
	return &fixture{
		routes:  testRoutes(),
		uplinks: testUplinks,
		filter:  f,
		tables:  t,
		settings: Settings{
			Mode:           ModeAudit,
			DomainPrefixes: []netip.Prefix{domain},
			ExtraSources:   []netip.Prefix{extra},
		},
	}
}

func (fx *fixture) reconciler(t *testing.T) *Reconciler {
	t.Helper()
	r, err := New(Options{
		Settings: fx.settings,
		Target:   USIDTarget{Filter: fx.filter},
		Routes:   func() ([]netlink.Route, error) { return fx.routes, fx.routesErr },
		Links:    func() ([]netlink.Link, error) { return testLinks(), nil },
		Uplinks:  func() ([]string, error) { return fx.uplinks, nil },
		OwnLocator: func(context.Context) (netip.Prefix, error) {
			return ownLocator, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func mask(t *testing.T, slots ...uint8) uint32 {
	t.Helper()
	m, err := srcfiltermap.IfaceMask(slots...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Slots follow ifindex order: eth0 0, eth1 1, bond0 2, eth2 3, eth3 4, vlan 5.
func wantEntries(t *testing.T) []srcfiltermap.Entry {
	return []srcfiltermap.Entry{
		{Prefix: peerA, IfaceMask: mask(t, 0)},
		{Prefix: peerB, IfaceMask: mask(t, 0, 1)},
		{Prefix: peerC, IfaceMask: mask(t, 2, 3, 4)},
		{Prefix: peerD, IfaceMask: mask(t, 2, 3, 4, 5)},
		{Prefix: shard, IfaceMask: mask(t, 1)},
		{Prefix: unboundP, AnyIface: true},
		{Prefix: extra, AnyIface: true},
	}
}

func sortEntries(e []srcfiltermap.Entry) []srcfiltermap.Entry {
	slices.SortFunc(e, func(a, b srcfiltermap.Entry) int { return a.Prefix.Compare(b.Prefix) })
	return e
}

func assertAllow(t *testing.T, f *srcfiltermap.Filter, want []srcfiltermap.Entry) {
	t.Helper()
	got, err := f.ListAllow()
	if err != nil {
		t.Fatalf("ListAllow: %v", err)
	}
	if !slices.Equal(got, sortEntries(slices.Clone(want))) {
		t.Errorf("allow-list:\n got  %+v\n want %+v", got, sortEntries(want))
	}
}

func assertConfig(t *testing.T, f *srcfiltermap.Filter, want srcfiltermap.Config) {
	t.Helper()
	got, err := f.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if got != want {
		t.Errorf("config = %+v, want %+v", got, want)
	}
}

func TestReconcileBuildsAllowList(t *testing.T) {
	fx := newFixture()
	res, err := fx.reconciler(t).Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	assertAllow(t, fx.filter, wantEntries(t))
	assertConfig(t, fx.filter, srcfiltermap.Config{Mode: srcfiltermap.ModeAudit, Populated: true, Generation: 2})
	if res.Added != 7 || res.Unbound != 1 || !res.Changed || res.SlotCount != 6 {
		t.Errorf("result = %+v", res)
	}

	slots, err := fx.filter.UplinkSlots()
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint32]uint8{idxEth0: 0, idxEth1: 1, idxBond0: 2, idxEth2: 3, idxEth3: 4, idxVlan: 5}
	if len(slots) != len(want) {
		t.Fatalf("slots = %v, want %v", slots, want)
	}
	for k, v := range want {
		if slots[k] != v {
			t.Errorf("slot[%d] = %d, want %d", k, slots[k], v)
		}
	}
}

func TestReconcileNoOpKeepsGeneration(t *testing.T) {
	fx := newFixture()
	r := fx.reconciler(t)
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed || res.Added+res.Updated+res.Removed != 0 {
		t.Errorf("second pass changed something: %+v", res)
	}
	assertConfig(t, fx.filter, srcfiltermap.Config{Mode: srcfiltermap.ModeAudit, Populated: true, Generation: 2})
}

func TestReconcileRemovesWithdrawnRoute(t *testing.T) {
	fx := newFixture()
	r := fx.reconciler(t)
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.routes = slices.DeleteFunc(testRoutes(), func(rt netlink.Route) bool {
		return rt.Dst != nil && rt.Dst.IP.Equal(peerA.Addr().AsSlice())
	})
	res, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed != 1 || !res.Changed {
		t.Errorf("result = %+v", res)
	}
	assertAllow(t, fx.filter, wantEntries(t)[1:])
	assertConfig(t, fx.filter, srcfiltermap.Config{Mode: srcfiltermap.ModeAudit, Populated: true, Generation: 3})
}

func TestReconcileLooseBinding(t *testing.T) {
	fx := newFixture()
	fx.settings.Binding = BindingLoose
	if _, err := fx.reconciler(t).Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := wantEntries(t)
	for i := range want {
		want[i].AnyIface = true
	}
	assertAllow(t, fx.filter, want)
}

func TestReconcileRouteListFailureKeepsAllowList(t *testing.T) {
	fx := newFixture()
	r := fx.reconciler(t)
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.routesErr = errors.New("netlink dump interrupted")
	if _, err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile succeeded with a failing route list")
	}
	assertAllow(t, fx.filter, wantEntries(t))
	assertConfig(t, fx.filter, srcfiltermap.Config{Mode: srcfiltermap.ModeAudit, Populated: true, Generation: 2})
}

func TestReconcileNoFabricRoutes(t *testing.T) {
	tests := []struct {
		name   string
		routes []netlink.Route
	}{
		{"NoRoutes", nil},
		{"OnlyExcluded", []netlink.Route{
			route(aggregate, idxEth0, unix.RTPROT_BGP),
			route(ownLocator, idxEth0, unix.RTPROT_BGP),
			route(outside, idxEth0, unix.RTPROT_BGP),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newFixture()
			fx.settings.Mode = ModeEnforce
			fx.routes = tt.routes
			_, err := fx.reconciler(t).Reconcile(context.Background())
			if !errors.Is(err, ErrNoFabricRoutes) {
				t.Fatalf("err = %v, want ErrNoFabricRoutes", err)
			}
			assertAllow(t, fx.filter, nil)
			assertConfig(t, fx.filter, srcfiltermap.Config{Mode: srcfiltermap.ModeEnforce, Generation: 1})
		})
	}
}

func TestReconcileEmptyAfterPopulatedKeepsAllowList(t *testing.T) {
	fx := newFixture()
	r := fx.reconciler(t)
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.routes = nil
	if _, err := r.Reconcile(context.Background()); !errors.Is(err, ErrNoFabricRoutes) {
		t.Fatalf("err = %v, want ErrNoFabricRoutes", err)
	}
	assertAllow(t, fx.filter, wantEntries(t))
}

func TestReconcileWriteFailureSkipsDeletesAndPopulate(t *testing.T) {
	fx := newFixture()
	stale := srcfiltermap.Entry{Prefix: netip.MustParsePrefix("2001:db8:0:99::/64"), AnyIface: true}
	if err := fx.filter.PutAllow(stale); err != nil {
		t.Fatal(err)
	}
	fx.tables.Allow.(*srcfiltermap.FakeTable).PutErr = errors.New("map full")

	if _, err := fx.reconciler(t).Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile succeeded with failing writes")
	}
	assertAllow(t, fx.filter, []srcfiltermap.Entry{stale})
	assertConfig(t, fx.filter, srcfiltermap.Config{Mode: srcfiltermap.ModeAudit, Generation: 1})
}

func TestReconcileAppliesModeBeforeFirstSync(t *testing.T) {
	fx := newFixture()
	if err := fx.filter.SetConfig(srcfiltermap.Config{
		Mode: srcfiltermap.ModeEnforce, Populated: true, Generation: 7,
	}); err != nil {
		t.Fatal(err)
	}
	fx.routesErr = errors.New("netlink dump interrupted")
	if _, err := fx.reconciler(t).Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile succeeded with a failing route list")
	}
	assertConfig(t, fx.filter, srcfiltermap.Config{Mode: srcfiltermap.ModeAudit, Populated: true, Generation: 8})
}

func TestReconcileTooManyUplinks(t *testing.T) {
	fx := newFixture()
	links := make([]netlink.Link, 0, MaxSlots+1)
	names := make([]string, 0, MaxSlots+1)
	for i := range MaxSlots + 1 {
		name := "up" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		links = append(links, &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 100 + i, Name: name}})
		names = append(names, name)
	}
	r, err := New(Options{
		Settings: fx.settings,
		Target:   USIDTarget{Filter: fx.filter},
		Routes:   func() ([]netlink.Route, error) { return fx.routes, nil },
		Links:    func() ([]netlink.Link, error) { return links, nil },
		Uplinks:  func() ([]string, error) { return names, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile succeeded with more uplinks than slots")
	}
	assertAllow(t, fx.filter, nil)
}

func TestReconcileNoUplinkExists(t *testing.T) {
	fx := newFixture()
	fx.uplinks = []string{"gone0"}
	if _, err := fx.reconciler(t).Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile succeeded with no resolvable uplink")
	}
}

func TestNewRejectsIncompleteOptions(t *testing.T) {
	f, _ := srcfiltermap.NewFake()
	ok := Options{
		Settings: Settings{Mode: ModeAudit, DomainPrefixes: []netip.Prefix{domain}},
		Target:   USIDTarget{Filter: f},
		Routes:   func() ([]netlink.Route, error) { return nil, nil },
		Links:    func() ([]netlink.Link, error) { return nil, nil },
		Uplinks:  func() ([]string, error) { return nil, nil },
	}
	tests := []struct {
		name      string
		mutate    func(*Options)
		wantError bool
	}{
		{"Valid", func(*Options) {}, false},
		{"NoTarget", func(o *Options) { o.Target = nil }, true},
		{"NoRoutes", func(o *Options) { o.Routes = nil }, true},
		{"ModeOff", func(o *Options) { o.Settings.Mode = ModeOff }, true},
		{"NoDomain", func(o *Options) { o.Settings.DomainPrefixes = nil }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := ok
			tt.mutate(&o)
			if _, err := New(o); (err != nil) != tt.wantError {
				t.Errorf("New() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestDisable(t *testing.T) {
	f, _ := srcfiltermap.NewFake()
	cfg := srcfiltermap.Config{Mode: srcfiltermap.ModeEnforce, Populated: true, Generation: 4}
	if err := f.SetConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := Disable(USIDTarget{Filter: f}); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, f, srcfiltermap.Config{Mode: srcfiltermap.ModeOff, Generation: 5})
	if err := Disable(USIDTarget{Filter: f}); err != nil {
		t.Fatal(err)
	}
	assertConfig(t, f, srcfiltermap.Config{Mode: srcfiltermap.ModeOff, Generation: 5})
}
