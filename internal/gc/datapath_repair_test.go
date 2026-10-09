// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// memTable is an in-memory usidmap.Table keyed by any comparable key, copying
// values in and out by reflection the way *ebpf.Map copies them.
type memTable struct {
	entries map[any]any
	order   []any
}

func newMemTable() *memTable { return &memTable{entries: map[any]any{}} }

func (m *memTable) Put(key, value any) error {
	if _, ok := m.entries[key]; !ok {
		m.order = append(m.order, key)
	}
	m.entries[key] = value
	return nil
}

func (m *memTable) Lookup(key, valueOut any) error {
	v, ok := m.entries[key]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(v))
	return nil
}

func (m *memTable) Delete(key any) error {
	if _, ok := m.entries[key]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.entries, key)
	for i, k := range m.order {
		if k == key {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	return nil
}

func (m *memTable) Iterate() usidmap.Iterator { return &memIterator{table: m, idx: -1} }

type memIterator struct {
	table *memTable
	idx   int
}

func (it *memIterator) Next(keyOut, valueOut any) bool {
	it.idx++
	if it.idx >= len(it.table.order) {
		return false
	}
	k := it.table.order[it.idx]
	reflect.ValueOf(keyOut).Elem().Set(reflect.ValueOf(k))
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(it.table.entries[k]))
	return true
}

func (it *memIterator) Err() error { return nil }

// memMaps is an attachreg.Maps over memTables, with each table kept so a test
// can count its rows.
type memMaps struct {
	maps   *attachreg.Maps
	tables map[string]*memTable
}

func newMemMaps() *memMaps {
	t := map[string]*memTable{}
	for _, name := range []string{"vrf", "locator", "function", "attribution", "ifindex", "kind", "gateway",
		"route", "nodesrc", "uplink"} {
		t[name] = newMemTable()
	}
	m := &memMaps{tables: t}
	m.maps = m.open()
	return m
}

// open returns a new attachreg.Maps over m's tables, as each repair pass
// opens the pinned maps afresh.
func (m *memMaps) open() *attachreg.Maps {
	t := m.tables
	return &attachreg.Maps{
		Registry: &usidmap.Registry{
			VRF:            usidmap.NewVRFTable(t["vrf"]),
			Locator:        usidmap.NewLocatorTable(t["locator"]),
			Function:       usidmap.NewFunctionTable(t["function"]),
			VPCAttribution: usidmap.NewVPCAttributionTable(t["attribution"]),
		},
		IfindexVRF:   ifindexvrfmap.NewIfindexVRFTable(t["ifindex"]),
		EgressKind:   ifindexvrfmap.NewEgressKindTable(t["kind"]),
		Gateway:      ifindexvrfmap.NewGatewayTable(t["gateway"]),
		EgressRoute:  egressroutemap.NewEgressRouteTable(t["route"]),
		NodeSource:   egressroutemap.NewNodeSourceAddress(t["nodesrc"]),
		PublicUplink: egressroutemap.NewPublicUplink(t["uplink"]),
	}
}

// rows returns the number of rows in every table, by name.
func (m *memMaps) rows() map[string]int {
	out := map[string]int{}
	for name, t := range m.tables {
		out[name] = len(t.entries)
	}
	return out
}

const (
	repairNamespace = "galactic-system"
	repairNode      = "worker-a"
	repairRouter    = "router-a"
	repairNodeID    = int32(5)
)

// repairFixture is the kernel and API state one RepairAttachmentDatapath test
// runs against.
type repairFixture struct {
	t       *testing.T
	mem     *memMaps
	links   []netlink.Link
	routes  map[uint32][]netlink.Route
	addrs   map[int][]netlink.Addr
	objects []client.Object
	// gone lists ifindexes linkByIndexFn reports missing, standing in for a
	// CNI DEL that lands mid-pass.
	gone      map[int]bool
	uplinkErr error
	foreign   func(uint32) bool
	egress    attachreg.EgressConfig
	// ctx is the pass's context; nil means context.Background.
	ctx    context.Context
	cancel context.CancelFunc
}

func newRepairFixture(t *testing.T) *repairFixture {
	t.Helper()
	f := &repairFixture{
		t:      t,
		mem:    newMemMaps(),
		routes: map[uint32][]netlink.Route{},
		addrs:  map[int][]netlink.Addr{},
		gone:   map[int]bool{},
	}
	f.objects = append(f.objects, &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: repairRouter, Namespace: repairNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Kind: targetKindNode, Name: repairNode},
			LocalASN:    65000,
			SRv6Locator: testLocator,
			NodeID:      repairNodeID,
		},
	})
	return f
}

func (f *repairFixture) addVRFInstance(name string, vrfID int32) {
	f.objects = append(f.objects, &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: repairNamespace},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: repairRouter}},
			VRFID:              vrfID,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
		},
	})
}

func (f *repairFixture) addVRF(name string, index int, table uint32) *netlink.Vrf {
	v := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}, Table: table}
	f.links = append(f.links, v)
	return v
}

// addHostLink adds an attachment's host-side link enslaved to master (nil for
// none), of type veth or tap.
func (f *repairFixture) addHostLink(ifaceType, name string, index int, master *netlink.Vrf) {
	attrs := netlink.LinkAttrs{Name: name, Index: index}
	if master != nil {
		attrs.MasterIndex = master.Index
	}
	switch ifaceType {
	case attachreg.InterfaceTypeTap:
		f.links = append(f.links, &netlink.Tuntap{LinkAttrs: attrs})
	default:
		f.links = append(f.links, &netlink.Veth{LinkAttrs: attrs})
	}
}

// addPodRoute adds the pod-subnet route the master plugin installs for dst in
// table out ifindex.
func (f *repairFixture) addPodRoute(table uint32, ifindex int, dst string) {
	_, n, err := net.ParseCIDR(dst)
	if err != nil {
		f.t.Fatalf("ParseCIDR(%q): %v", dst, err)
	}
	f.routes[table] = append(f.routes[table], netlink.Route{
		Dst: n, LinkIndex: ifindex, Table: int(table), Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_BOOT,
	})
}

func (f *repairFixture) addAddr(ifindex int, cidr string) {
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		f.t.Fatalf("ParseAddr(%q): %v", cidr, err)
	}
	f.addrs[ifindex] = append(f.addrs[ifindex], *addr)
}

// addAdvertisement adds the BGPAdvertisement galactic-bgp's ADD publishes for
// (vpc, vpcAttachment) on router, carrying prefixes, or the no-addressing
// annotation when noAddressing is set.
func (f *repairFixture) addAdvertisement(router, vpc, vpcAttachment string, noAddressing bool, prefixes ...string) {
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crdnames.BGPAdvertisementName(vpc, vpcAttachment, repairNode),
			Namespace: repairNamespace,
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{RouterRef: bgpv1alpha1.RouterRef{Name: router}},
	}
	if noAddressing {
		adv.Annotations = map[string]string{crdnames.AnnotationNoAddressing: crdnames.AnnotationNoAddressingValue}
	}
	for _, p := range prefixes {
		adv.Spec.Prefixes = append(adv.Spec.Prefixes, bgpv1alpha1.Prefix(p))
	}
	f.objects = append(f.objects, adv)
}

// run installs the fixture's state behind every indirection and runs one
// pass.
func (f *repairFixture) run() (DatapathRepairResult, error) {
	f.t.Helper()
	origOpen, origAll, origRoutes, origAddrs, origByIndex, origUplink :=
		openDatapathMapsFn, listAllLinksFn, listRoutesFn, listAddrsFn, linkByIndexFn, resolvePublicUplinkFn
	f.t.Cleanup(func() {
		openDatapathMapsFn, listAllLinksFn, listRoutesFn, listAddrsFn, linkByIndexFn, resolvePublicUplinkFn =
			origOpen, origAll, origRoutes, origAddrs, origByIndex, origUplink
	})

	openDatapathMapsFn = func(string) (*attachreg.Maps, io.Closer, error) {
		return f.mem.open(), io.NopCloser(nil), nil
	}
	listAllLinksFn = func() ([]netlink.Link, error) { return f.links, nil }
	listRoutesFn = func(table uint32, family int) ([]netlink.Route, error) {
		var out []netlink.Route
		for _, r := range f.routes[table] {
			if (r.Dst.IP.To4() != nil) == (family == netlink.FAMILY_V4) {
				out = append(out, r)
			}
		}
		return out, nil
	}
	listAddrsFn = func(link netlink.Link, family int) ([]netlink.Addr, error) {
		var out []netlink.Addr
		for _, a := range f.addrs[link.Attrs().Index] {
			if (a.IP.To4() != nil) == (family == netlink.FAMILY_V4) {
				out = append(out, a)
			}
		}
		return out, nil
	}
	linkByIndexFn = func(index int) (netlink.Link, error) {
		if f.gone[index] {
			return nil, errors.New("link not found")
		}
		for _, l := range f.links {
			if l.Attrs().Index == index {
				return l, nil
			}
		}
		return nil, errors.New("link not found")
	}
	resolvePublicUplinkFn = func() (int, net.HardwareAddr, net.HardwareAddr, error) {
		if f.uplinkErr != nil {
			return 0, nil, nil, f.uplinkErr
		}
		return 2, net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}, net.HardwareAddr{0xbb, 0, 0, 0, 0, 2}, nil
	}

	k8s := fake.NewClientBuilder().WithScheme(gcTestScheme(f.t)).WithObjects(f.objects...).Build()
	ctx := f.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return RepairAttachmentDatapath(ctx, k8s, DatapathRepairConfig{
		Namespace:      repairNamespace,
		NodeName:       repairNode,
		PinDir:         f.t.TempDir(),
		Egress:         f.egress,
		ForeignTableID: f.foreign,
	})
}

func testBlock(t *testing.T) uint64 {
	t.Helper()
	block, err := blockFromLocator(t)
	if err != nil {
		t.Fatalf("derive block: %v", err)
	}
	return block
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return n
}

// wantPassThrough fails t unless table holds a pass-through entry for every
// one of prefixes.
func wantPassThrough(t *testing.T, mem *memMaps, table uint32, prefixes ...string) {
	t.Helper()
	for _, p := range prefixes {
		sid, ok, err := mem.maps.EgressRoute.Lookup(table, mustCIDR(t, p))
		if err != nil || !ok {
			t.Errorf("egress_route_table[%d, %s]: ok %v err %v, want a pass-through entry", table, p, ok, err)
			continue
		}
		if !sid.Equal(net.IPv6zero) {
			t.Errorf("egress_route_table[%d, %s] sid = %s, want the pass-through sentinel", table, p, sid)
		}
	}
}

func TestRepairAttachmentDatapath_VethAndTap(t *testing.T) {
	f := newRepairFixture(t)
	block := testBlock(t)

	// A veth attachment on VPC "jU", dual-stack with gateways.
	vrfA := f.addVRF("G0000000jUV", 10, 7)
	f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
	f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrfA)
	f.addPodRoute(7, 11, "fd20:30:ff01::/96")
	f.addPodRoute(7, 11, "10.1.0.5/32")
	f.addAddr(11, "fe80::1/64")
	f.addAddr(11, "fd20:30::1/128")
	f.addAddr(11, "172.21.1.1/32")

	// A tap attachment on VPC "kV", IPv6-only.
	vrfB := f.addVRF("G0000000kVV", 20, 8)
	f.addVRFInstance(crdnames.BGPVRFInstanceName("kV", repairNode), 0x22)
	f.addHostLink(attachreg.InterfaceTypeTap, "G0000000kVdefH", 21, vrfB)
	f.addPodRoute(8, 21, "fd20:40:ff01::/96")
	f.addAddr(21, "fd20:40::1/128")

	result, err := f.run()
	if err != nil {
		t.Fatalf("RepairAttachmentDatapath: %v", err)
	}
	if result.Attachments != 2 || result.Skipped != 0 {
		t.Errorf("attachments %d skipped %d, want 2 and 0", result.Attachments, result.Skipped)
	}
	want := attachreg.Counts{
		Locator: 1, Function: 1, NodeSource: 1, PublicUplink: 1,
		VRF: 2, VPCAttribution: 2, IfindexVRF: 2, EgressKind: 2, TenantGateway: 2,
		LocalEgressRoutes: 6,
	}
	if result.Rebuilt != want {
		t.Errorf("rebuilt = %+v, want %+v", result.Rebuilt, want)
	}

	m := f.mem.maps
	for _, w := range []wantAttachmentRows{
		{arg: 0x21, table: 7, kind: usidmap.EgressKindVeth, ifindex: 11, vpc: "jU", att: "abc"},
		{arg: 0x22, table: 8, kind: usidmap.EgressKindTap, ifindex: 21, vpc: "kV", att: "def"},
	} {
		checkAttachmentRows(t, m, block, w)
	}

	gw6, gw4, ok, err := m.Gateway.Get(11)
	if err != nil || !ok || gw6 != netip.MustParseAddr("fd20:30::1") || gw4 != netip.MustParseAddr("172.21.1.1") {
		t.Errorf("tenant_gw_table[11] = %v %v ok %v err %v, want fd20:30::1 and 172.21.1.1", gw6, gw4, ok, err)
	}
	gw6, gw4, ok, err = m.Gateway.Get(21)
	if err != nil || !ok || gw6 != netip.MustParseAddr("fd20:40::1") || gw4.IsValid() {
		t.Errorf("tenant_gw_table[21] = %v %v ok %v err %v, want fd20:40::1 and no IPv4", gw6, gw4, ok, err)
	}

	wantPassThrough(t, f.mem, 7, "fd20:30:ff01::/96", "10.1.0.5/32", "fd20:30::1/128", "172.21.1.1/32")
	wantPassThrough(t, f.mem, 8, "fd20:40:ff01::/96", "fd20:40::1/128")
	if _, ok, _ := m.EgressRoute.Lookup(7, mustCIDR(t, "fe80::/64")); ok {
		t.Error("a link-local address was registered as a local pass-through route")
	}

	checkNodeRows(t, m, block)
}

// wantAttachmentRows is what one attachment's VRF and interface rows must
// hold after a repair.
type wantAttachmentRows struct {
	arg      uint16
	table    uint32
	kind     uint32
	ifindex  uint32
	vpc, att string
}

// checkAttachmentRows fails t unless m holds w's vrf_table,
// vpc_attribution_table, ifindex_vrf_table and ifindex_egress_kind_table rows.
func checkAttachmentRows(t *testing.T, m *attachreg.Maps, block uint64, w wantAttachmentRows) {
	t.Helper()
	entry, ok, err := m.Registry.VRF.Get(block, w.arg)
	if err != nil || !ok || entry.VRFTableID != w.table || entry.EgressKind != w.kind {
		t.Errorf("vrf_table[%#x] = %+v ok %v err %v, want table %d kind %d", w.arg, entry, ok, err, w.table, w.kind)
	}
	wantVPC, wantAtt, _ := attachreg.DecodeVPCIdentifiers(w.vpc, w.att)
	attr, ok, err := m.Registry.VPCAttribution.Get(block, w.arg)
	if err != nil || !ok || attr.VPC != wantVPC || attr.VPCAttachment != wantAtt {
		t.Errorf("vpc_attribution_table[%#x] = %+v ok %v err %v, want VPC %d attachment %d",
			w.arg, attr, ok, err, wantVPC, wantAtt)
	}
	ifEntry, ok, err := m.IfindexVRF.Get(w.ifindex)
	if err != nil || !ok || ifEntry.Block != block || ifEntry.Argument != w.arg {
		t.Errorf("ifindex_vrf_table[%d] = %+v ok %v err %v, want argument %#x", w.ifindex, ifEntry, ok, err, w.arg)
	}
	kind, ok, err := m.EgressKind.Get(w.ifindex)
	if err != nil || !ok || kind != w.kind {
		t.Errorf("ifindex_egress_kind_table[%d] = %d ok %v err %v, want %d", w.ifindex, kind, ok, err, w.kind)
	}
}

// checkNodeRows fails t unless m holds this node's locator_table,
// function_table, node_src_addr_table and public_uplink_table rows.
func checkNodeRows(t *testing.T, m *attachreg.Maps, block uint64) {
	t.Helper()
	if _, ok, err := m.Registry.Locator.Get(block, uint16(repairNodeID)); err != nil || !ok {
		t.Errorf("locator_table entry: ok %v err %v, want present", ok, err)
	}
	if _, ok, err := m.Registry.Function.Get(block, uformat.FunctionEndDT46); err != nil || !ok {
		t.Errorf("function_table entry: ok %v err %v, want present", ok, err)
	}
	wantSrc, err := attachreg.NodeSourceAddress(testLocator, repairNodeID)
	if err != nil {
		t.Fatalf("NodeSourceAddress: %v", err)
	}
	if got, ok, err := m.NodeSource.Get(); err != nil || !ok || !got.Equal(wantSrc) {
		t.Errorf("node_src_addr_table = %v ok %v err %v, want %v", got, ok, err, wantSrc)
	}
	if idx, _, _, ok, err := m.PublicUplink.Get(); err != nil || !ok || idx != 2 {
		t.Errorf("public_uplink_table link %d ok %v err %v, want link 2", idx, ok, err)
	}
}

func TestRepairAttachmentDatapath_LegacyVRF(t *testing.T) {
	f := newRepairFixture(t)
	vrf := f.addVRF("G0000000jUabcV", 10, 9)
	f.addVRFInstance("jU-"+repairNode, 0x30)
	f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)

	if _, err := f.run(); err != nil {
		t.Fatalf("RepairAttachmentDatapath: %v", err)
	}
	entry, ok, err := f.mem.maps.Registry.VRF.Get(testBlock(t), 0x30)
	if err != nil || !ok || entry.VRFTableID != 9 {
		t.Errorf("vrf_table entry = %+v ok %v err %v, want the legacy VRF's table 9", entry, ok, err)
	}
}

func TestRepairAttachmentDatapath_TapWithoutIPAM(t *testing.T) {
	f := newRepairFixture(t)
	vrf := f.addVRF("G0000000jUV", 10, 7)
	f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
	f.addHostLink(attachreg.InterfaceTypeTap, "G0000000jUabcH", 11, vrf)
	f.addAddr(11, "fe80::1/64")

	result, err := f.run()
	if err != nil {
		t.Fatalf("RepairAttachmentDatapath: %v", err)
	}
	if result.Rebuilt.TenantGateway != 0 || result.Rebuilt.LocalEgressRoutes != 0 {
		t.Errorf("rebuilt = %+v, want no tenant_gw_table or local route rows for a tap with no IPAM", result.Rebuilt)
	}
	if result.Rebuilt.VRF != 1 || result.Rebuilt.IfindexVRF != 1 || result.Rebuilt.EgressKind != 1 {
		t.Errorf("rebuilt = %+v, want the VRF and interface rows", result.Rebuilt)
	}
	if kind, _, _ := f.mem.maps.EgressKind.Get(11); kind != usidmap.EgressKindTap {
		t.Errorf("egress kind = %d, want EgressKindTap", kind)
	}
}

// TestRepairAttachmentDatapath_AdvertisedPrefixes covers the guest prefixes
// only the attachment's BGPAdvertisement records: a static address with no
// gateway has no route in the kernel (#806).
func TestRepairAttachmentDatapath_AdvertisedPrefixes(t *testing.T) {
	const (
		guest6 = "fd20:31:ff03::/96"
		guest4 = "10.1.0.7/32"
	)
	tests := []struct {
		name string
		// gateway gives the attachment the kernel state a gateway installs:
		// the pod-subnet route and the host gateway address.
		gateway      bool
		router       string
		noAddressing bool
		advertised   []string
		wantRoutes   []string
		wantCount    int
		// wantGateway is whether a tenant_gw_table row is written at all.
		wantGateway bool
	}{
		{
			name:   "StaticNoGateway",
			router: repairRouter,
			// The IPv6 subnet as ADD records it, with the address's host bits.
			advertised:  []string{"fd20:31:ff03::5/96", guest4},
			wantRoutes:  []string{guest6, guest4},
			wantCount:   2,
			wantGateway: true,
		},
		{
			name:        "AlreadyInKernel",
			gateway:     true,
			router:      repairRouter,
			advertised:  []string{guest6},
			wantRoutes:  []string{guest6, "fd20:31::1/128"},
			wantCount:   2,
			wantGateway: true,
		},
		{
			name:         "NoAddressing",
			router:       repairRouter,
			noAddressing: true,
		},
		{
			name:       "OtherRouter",
			router:     "router-b",
			advertised: []string{guest6},
		},
		{
			name:       "UnparsablePrefix",
			router:     repairRouter,
			advertised: []string{"not-a-prefix", guest4},
			wantRoutes: []string{guest4},
			wantCount:  1,
			// The advertisement still shows an IPAM result.
			wantGateway: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRepairFixture(t)
			vrf := f.addVRF("G0000000jUV", 10, 7)
			f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
			f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)
			if tt.gateway {
				f.addPodRoute(7, 11, guest6)
				f.addAddr(11, "fd20:31::1/128")
			}
			f.addAdvertisement(tt.router, "jU", "abc", tt.noAddressing, tt.advertised...)

			result, err := f.run()
			if err != nil {
				t.Fatalf("RepairAttachmentDatapath: %v", err)
			}
			if result.Rebuilt.LocalEgressRoutes != tt.wantCount {
				t.Errorf("rebuilt %d local pass-through routes, want %d", result.Rebuilt.LocalEgressRoutes, tt.wantCount)
			}
			wantPassThrough(t, f.mem, 7, tt.wantRoutes...)

			_, _, ok, err := f.mem.maps.Gateway.Get(11)
			if err != nil || ok != tt.wantGateway {
				t.Errorf("tenant_gw_table[11] present %v err %v, want present %v", ok, err, tt.wantGateway)
			}
		})
	}
}

// TestRepairAttachmentDatapath_SkipsUnusable covers every interface the pass
// must leave alone, either for good or, with wantPending, until its
// BGPVRFInstance appears. None of them leaves a row in any map.
func TestRepairAttachmentDatapath_SkipsUnusable(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(f *repairFixture)
		wantPending bool
	}{
		{
			name:        "MissingBGPVRFInstance",
			wantPending: true,
			setup: func(f *repairFixture) {
				vrf := f.addVRF("G0000000jUV", 10, 7)
				f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)
			},
		},
		{
			name:        "InstanceOnAnotherNode",
			wantPending: true,
			setup: func(f *repairFixture) {
				vrf := f.addVRF("G0000000jUV", 10, 7)
				f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", "worker-b"), 0x21)
				f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)
			},
		},
		{
			name: "OutOfRangeVRFID",
			setup: func(f *repairFixture) {
				vrf := f.addVRF("G0000000jUV", 10, 7)
				f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), int32(uformat.ArgumentMax)+1)
				f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)
			},
		},
		{
			name: "LinkWithoutMaster",
			setup: func(f *repairFixture) {
				f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
				f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, nil)
			},
		},
		{
			name: "SidecarReturnTableRange",
			setup: func(f *repairFixture) {
				vrf := f.addVRF("G0000000jUV", 10, 0xF021)
				f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
				f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)
				f.foreign = func(id uint32) bool { return id >= 0xF000 && id <= 0xFFFF }
			},
		},
		{
			name: "UnknownLinkType",
			setup: func(f *repairFixture) {
				vrf := f.addVRF("G0000000jUV", 10, 7)
				f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
				f.links = append(f.links, &netlink.Dummy{
					LinkAttrs: netlink.LinkAttrs{Name: "G0000000jUabcH", Index: 11, MasterIndex: vrf.Index},
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRepairFixture(t)
			tt.setup(f)
			result, err := f.run()
			if err != nil {
				t.Fatalf("RepairAttachmentDatapath: %v", err)
			}
			wantSkipped, wantPending := 1, 0
			if tt.wantPending {
				wantSkipped, wantPending = 0, 1
			}
			if result.Attachments != 0 || result.Skipped != wantSkipped || result.Pending != wantPending {
				t.Errorf("attachments %d skipped %d pending %d, want 0, %d and %d",
					result.Attachments, result.Skipped, result.Pending, wantSkipped, wantPending)
			}
			for name, n := range f.mem.rows() {
				if n != 0 {
					t.Errorf("%s holds %d rows, want none", name, n)
				}
			}
		})
	}
}

func TestRepairAttachmentDatapath_IgnoresOtherInterfaces(t *testing.T) {
	f := newRepairFixture(t)
	vrf := f.addVRF("G0000000jUV", 10, 7)
	f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
	f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcG", 11, vrf) // guest-side name
	f.addHostLink(attachreg.InterfaceTypeVeth, "eth0", 12, vrf)

	result, err := f.run()
	if err != nil {
		t.Fatalf("RepairAttachmentDatapath: %v", err)
	}
	if result.Attachments != 0 || result.Skipped != 0 || result.Rebuilt.Total() != 0 {
		t.Errorf("result = %+v, want nothing examined, skipped, or rebuilt", result)
	}
}

// TestRepairAttachmentDatapath_SidecarOwnedTable covers a VRF table the
// ingress sidecar's own vrf_table rows claim.
func TestRepairAttachmentDatapath_SidecarOwnedTable(t *testing.T) {
	f := newRepairFixture(t)
	vrf := f.addVRF("G0000000jUV", 10, 0x10005)
	f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
	f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)
	sidecarVRF := f.mem.maps.Registry.VRF
	if err := sidecarVRF.Register(uformat.BlockIngressSidecar, 0x5, 0x10005, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("seed sidecar row: %v", err)
	}

	result, err := f.run()
	if err != nil {
		t.Fatalf("RepairAttachmentDatapath: %v", err)
	}
	if result.Skipped != 1 || result.Rebuilt.Total() != 0 {
		t.Errorf("result = %+v, want the attachment skipped and nothing rebuilt", result)
	}
}

func TestRepairAttachmentDatapath_TwoAttachmentsOneVRF(t *testing.T) {
	f := newRepairFixture(t)
	vrf := f.addVRF("G0000000jUV", 10, 7)
	f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
	f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)
	f.addPodRoute(7, 11, "fd20:30:ff01::/96")
	f.addAddr(11, "fd20:30::1/128")
	f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUdefH", 12, vrf)
	f.addPodRoute(7, 12, "fd20:30:ff02::/96")
	f.addAddr(12, "fd20:30::1/128")

	result, err := f.run()
	if err != nil {
		t.Fatalf("RepairAttachmentDatapath: %v", err)
	}
	if result.Rebuilt.VRF != 1 || result.Rebuilt.VPCAttribution != 1 {
		t.Errorf("rebuilt = %+v, want one shared vrf_table and vpc_attribution_table row", result.Rebuilt)
	}
	if result.Rebuilt.IfindexVRF != 2 || result.Rebuilt.EgressKind != 2 || result.Rebuilt.TenantGateway != 2 {
		t.Errorf("rebuilt = %+v, want interface rows for both attachments", result.Rebuilt)
	}
	// The shared gateway address is one route, registered once.
	if result.Rebuilt.LocalEgressRoutes != 3 {
		t.Errorf("rebuilt %d local routes, want 3", result.Rebuilt.LocalEgressRoutes)
	}
	wantPassThrough(t, f.mem, 7, "fd20:30:ff01::/96", "fd20:30:ff02::/96", "fd20:30::1/128")
}

// TestRepairAttachmentDatapath_OnlyPodSubnetRoutes covers the other routes a
// VRF table can hold out an attachment's interface, none of which ADD
// registers.
func TestRepairAttachmentDatapath_OnlyPodSubnetRoutes(t *testing.T) {
	f := newRepairFixture(t)
	vrf := f.addVRF("G0000000jUV", 10, 7)
	f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
	f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)
	f.addPodRoute(7, 11, "fd20:30:ff01::/96")
	f.routes[7] = append(f.routes[7],
		netlink.Route{Dst: mustCIDR(t, "fe80::/64"), LinkIndex: 11, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_KERNEL},
		netlink.Route{Dst: mustCIDR(t, "fd99::/64"), LinkIndex: 11, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_BOOT,
			Gw: net.ParseIP("fd20:30:ff01::5")},
		netlink.Route{Dst: mustCIDR(t, "10.9.0.0/24"), LinkIndex: 11, Type: unix.RTN_UNICAST, Protocol: unix.RTPROT_BOOT,
			Scope: netlink.SCOPE_LINK},
		netlink.Route{Dst: mustCIDR(t, "fd20:30:ff09::/96"), LinkIndex: 99, Type: unix.RTN_UNICAST,
			Protocol: unix.RTPROT_BOOT},
	)

	result, err := f.run()
	if err != nil {
		t.Fatalf("RepairAttachmentDatapath: %v", err)
	}
	if result.Rebuilt.LocalEgressRoutes != 1 {
		t.Errorf("rebuilt %d local routes, want only the pod subnet", result.Rebuilt.LocalEgressRoutes)
	}
	wantPassThrough(t, f.mem, 7, "fd20:30:ff01::/96")
}

// TestRepairAttachmentDatapath_ExistingRowsUntouched seeds a row of every
// per-attachment kind with a value the pass would not write, and requires it
// to survive.
func TestRepairAttachmentDatapath_ExistingRowsUntouched(t *testing.T) {
	f := newRepairFixture(t)
	block := testBlock(t)
	vrf := f.addVRF("G0000000jUV", 10, 7)
	f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
	f.addHostLink(attachreg.InterfaceTypeTap, "G0000000jUabcH", 11, vrf)
	f.addPodRoute(7, 11, "fd20:30:ff01::/96")
	f.addAddr(11, "fd20:30::1/128")

	m := f.mem.maps
	// The sidecar return path's row for the same key, pointing at its own
	// table.
	if err := m.Registry.VRF.Register(block, 0x21, 0xF021, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("seed vrf_table: %v", err)
	}
	if err := m.Registry.VPCAttribution.Register(block, 0x21, 1, 2); err != nil {
		t.Fatalf("seed vpc_attribution_table: %v", err)
	}
	if err := m.IfindexVRF.Register(11, block, 0x22); err != nil {
		t.Fatalf("seed ifindex_vrf_table: %v", err)
	}
	if err := m.EgressKind.Register(11, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("seed ifindex_egress_kind_table: %v", err)
	}
	if err := m.Gateway.Register(11, netip.MustParseAddr("fd99::1"), netip.Addr{}); err != nil {
		t.Fatalf("seed tenant_gw_table: %v", err)
	}
	if err := m.NodeSource.Set(net.ParseIP("2001:db8:ffff::1")); err != nil {
		t.Fatalf("seed node_src_addr_table: %v", err)
	}

	result, err := f.run()
	if err != nil {
		t.Fatalf("RepairAttachmentDatapath: %v", err)
	}
	want := attachreg.Counts{Locator: 1, Function: 1, PublicUplink: 1, LocalEgressRoutes: 2}
	if result.Rebuilt != want {
		t.Errorf("rebuilt = %+v, want %+v", result.Rebuilt, want)
	}

	if e, _, _ := m.Registry.VRF.Get(block, 0x21); e.VRFTableID != 0xF021 || e.EgressKind != usidmap.EgressKindVeth {
		t.Errorf("vrf_table row = %+v, want the seeded table 0xF021", e)
	}
	if e, _, _ := m.Registry.VPCAttribution.Get(block, 0x21); e.VPC != 1 || e.VPCAttachment != 2 {
		t.Errorf("vpc_attribution_table row = %+v, want the seeded values", e)
	}
	if e, _, _ := m.IfindexVRF.Get(11); e.Argument != 0x22 {
		t.Errorf("ifindex_vrf_table row = %+v, want the seeded argument", e)
	}
	if kind, _, _ := m.EgressKind.Get(11); kind != usidmap.EgressKindVeth {
		t.Errorf("egress kind = %d, want the seeded veth", kind)
	}
	if gw6, _, _, _ := m.Gateway.Get(11); gw6 != netip.MustParseAddr("fd99::1") {
		t.Errorf("tenant_gw_table IPv6 = %v, want the seeded fd99::1", gw6)
	}
	if src, _, _ := m.NodeSource.Get(); !src.Equal(net.ParseIP("2001:db8:ffff::1")) {
		t.Errorf("node_src_addr_table = %v, want the seeded value", src)
	}
}

func TestRepairAttachmentDatapath_SecondPassIsANoop(t *testing.T) {
	f := newRepairFixture(t)
	vrf := f.addVRF("G0000000jUV", 10, 7)
	f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
	f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)
	f.addPodRoute(7, 11, "fd20:30:ff01::/96")
	f.addAddr(11, "fd20:30::1/128")

	first, err := f.run()
	if err != nil || first.Rebuilt.Total() == 0 {
		t.Fatalf("first pass: rebuilt %+v err %v, want rows rebuilt", first.Rebuilt, err)
	}
	before := f.mem.rows()
	second, err := f.run()
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if second.Rebuilt.Total() != 0 {
		t.Errorf("second pass rebuilt %+v, want nothing", second.Rebuilt)
	}
	if after := f.mem.rows(); !reflect.DeepEqual(before, after) {
		t.Errorf("rows after second pass = %v, want unchanged %v", after, before)
	}
}

// TestRepairAttachmentDatapath_InterfaceGoneMidPass stands in for a CNI DEL
// that removes the interface while the pass writes its rows.
func TestRepairAttachmentDatapath_InterfaceGoneMidPass(t *testing.T) {
	f := newRepairFixture(t)
	vrf := f.addVRF("G0000000jUV", 10, 7)
	f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
	f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)
	f.addPodRoute(7, 11, "fd20:30:ff01::/96")
	f.addAddr(11, "fd20:30::1/128")
	f.gone[11] = true

	result, err := f.run()
	if err != nil {
		t.Fatalf("RepairAttachmentDatapath: %v", err)
	}
	if result.Rebuilt.IfindexVRF != 0 || result.Rebuilt.VRF != 0 || result.Rebuilt.LocalEgressRoutes != 0 {
		t.Errorf("rebuilt = %+v, want none of the vanished attachment's rows counted", result.Rebuilt)
	}
	for _, name := range []string{"ifindex", "kind", "gateway", "vrf", "attribution", "route"} {
		if n := len(f.mem.tables[name].entries); n != 0 {
			t.Errorf("%s holds %d rows, want the rows for the vanished interface removed", name, n)
		}
	}
}

// TestRepairAttachmentDatapath_InterfaceGoneMidPassKeepsSharedRows covers a
// vanished attachment whose VRF another live attachment shares: rows the
// sibling also needs stay, and only the vanished attachment's own go.
func TestRepairAttachmentDatapath_InterfaceGoneMidPassKeepsSharedRows(t *testing.T) {
	f := newRepairFixture(t)
	block := testBlock(t)
	vrf := f.addVRF("G0000000jUV", 10, 7)
	f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
	f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)
	f.addPodRoute(7, 11, "fd20:30:ff01::/96")
	f.addAddr(11, "fd20:30::1/128")
	f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUdefH", 12, vrf)
	f.addPodRoute(7, 12, "fd20:30:ff02::/96")
	f.addAddr(12, "fd20:30::1/128")
	f.gone[11] = true

	if _, err := f.run(); err != nil {
		t.Fatalf("RepairAttachmentDatapath: %v", err)
	}
	m := f.mem.maps
	if _, ok, _ := m.Registry.VRF.Get(block, 0x21); !ok {
		t.Error("vrf_table row removed, want it kept for the attachment still sharing it")
	}
	wantPassThrough(t, f.mem, 7, "fd20:30:ff02::/96", "fd20:30::1/128")
	present, err := m.EgressRoute.Prefixes()
	if err != nil {
		t.Fatalf("Prefixes: %v", err)
	}
	if _, ok := present[7]["fd20:30:ff01::/96"]; ok {
		t.Error("the vanished attachment's own subnet route is still present")
	}
	if _, ok, _ := m.IfindexVRF.Get(11); ok {
		t.Error("ifindex_vrf_table row for the vanished interface is still present")
	}
	if _, ok, _ := m.IfindexVRF.Get(12); !ok {
		t.Error("ifindex_vrf_table row for the live interface is missing")
	}
}

// TestRepairAttachmentDatapath_LowestIfindexOwnsSharedRows covers a VPC with
// a tap and a veth attachment: the shared vrf_table and vpc_attribution_table
// rows come from the lower host ifindex whatever order the kernel lists them
// in, while each interface keeps its own egress kind.
func TestRepairAttachmentDatapath_LowestIfindexOwnsSharedRows(t *testing.T) {
	f := newRepairFixture(t)
	block := testBlock(t)
	vrf := f.addVRF("G0000000jUV", 10, 7)
	f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
	f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUdefH", 12, vrf)
	f.addHostLink(attachreg.InterfaceTypeTap, "G0000000jUabcH", 11, vrf)

	if _, err := f.run(); err != nil {
		t.Fatalf("RepairAttachmentDatapath: %v", err)
	}
	m := f.mem.maps
	if e, _, _ := m.Registry.VRF.Get(block, 0x21); e.EgressKind != usidmap.EgressKindTap {
		t.Errorf("vrf_table egress kind = %d, want the tap's, from ifindex 11", e.EgressKind)
	}
	wantVPC, wantAtt, _ := attachreg.DecodeVPCIdentifiers("jU", "abc")
	if e, _, _ := m.Registry.VPCAttribution.Get(block, 0x21); e.VPC != wantVPC || e.VPCAttachment != wantAtt {
		t.Errorf("vpc_attribution_table = %+v, want attachment abc", e)
	}
	for ifindex, want := range map[uint32]uint32{11: usidmap.EgressKindTap, 12: usidmap.EgressKindVeth} {
		if kind, _, _ := m.EgressKind.Get(ifindex); kind != want {
			t.Errorf("ifindex_egress_kind_table[%d] = %d, want %d", ifindex, kind, want)
		}
	}
}

func TestRepairAttachmentDatapath_CanceledContextStopsBetweenAttachments(t *testing.T) {
	f := newRepairFixture(t)
	vrf := f.addVRF("G0000000jUV", 10, 7)
	f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
	f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)
	f.ctx, f.cancel = context.WithCancel(context.Background())
	f.cancel()

	result, err := f.run()
	if !errors.Is(err, context.Canceled) {
		t.Errorf("RepairAttachmentDatapath = %v, want it to report the cancellation", err)
	}
	if result.Rebuilt.VRF != 0 || result.Rebuilt.IfindexVRF != 0 {
		t.Errorf("rebuilt = %+v, want no attachment repaired after cancellation", result.Rebuilt)
	}
}

func TestRepairAttachmentDatapath_UnresolvedUplinkIsNotAnError(t *testing.T) {
	f := newRepairFixture(t)
	vrf := f.addVRF("G0000000jUV", 10, 7)
	f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
	f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)
	f.uplinkErr = errors.New("no resolved neighbor")

	result, err := f.run()
	if err != nil {
		t.Fatalf("RepairAttachmentDatapath: %v, want no error for an unresolved uplink", err)
	}
	if result.UplinkErr == nil || result.Rebuilt.PublicUplink != 0 {
		t.Errorf("UplinkErr %v, rebuilt uplink %d; want the error reported and no row", result.UplinkErr,
			result.Rebuilt.PublicUplink)
	}
	if result.Rebuilt.VRF != 1 {
		t.Errorf("rebuilt = %+v, want the other rows still rebuilt", result.Rebuilt)
	}
}

func TestRepairAttachmentDatapath_NodeIdentity(t *testing.T) {
	newAttached := func(t *testing.T) *repairFixture {
		f := newRepairFixture(t)
		vrf := f.addVRF("G0000000jUV", 10, 7)
		f.addVRFInstance(crdnames.BGPVRFInstanceName("jU", repairNode), 0x21)
		f.addHostLink(attachreg.InterfaceTypeVeth, "G0000000jUabcH", 11, vrf)
		return f
	}

	t.Run("NoRouterYet", func(t *testing.T) {
		f := newAttached(t)
		f.objects = f.objects[1:]
		result, err := f.run()
		if err != nil || result.Rebuilt.Total() != 0 || result.Pending != 1 {
			t.Errorf("result %+v err %v, want the attachment pending, nothing rebuilt and no error", result, err)
		}
	})
	t.Run("NoRouterNoAttachments", func(t *testing.T) {
		f := newRepairFixture(t)
		f.objects = nil
		f.addVRF("G0000000jUV", 10, 7)
		result, err := f.run()
		if err != nil || result.Pending != 0 || result.Rebuilt.Total() != 0 {
			t.Errorf("result %+v err %v, want a clean, empty pass", result, err)
		}
	})
	t.Run("NoLocator", func(t *testing.T) {
		f := newAttached(t)
		f.objects[0].(*bgpv1alpha1.BGPRouter).Spec.SRv6Locator = ""
		result, err := f.run()
		if err != nil || result.Rebuilt.Total() != 0 {
			t.Errorf("result %+v err %v, want nothing and no error", result, err)
		}
	})
	t.Run("AmbiguousRouters", func(t *testing.T) {
		f := newAttached(t)
		second := f.objects[0].(*bgpv1alpha1.BGPRouter).DeepCopy()
		second.Name = "router-b"
		f.objects = append(f.objects, second)
		if _, err := f.run(); err == nil {
			t.Error("RepairAttachmentDatapath = nil error with two routers for the node, want an error")
		}
	})
	t.Run("MissingPinDir", func(t *testing.T) {
		k8s := fake.NewClientBuilder().WithScheme(gcTestScheme(t)).Build()
		result, err := RepairAttachmentDatapath(context.Background(), k8s, DatapathRepairConfig{
			Namespace: repairNamespace, NodeName: repairNode, PinDir: "/nonexistent/galactic-pin-dir",
		})
		if err != nil || result.Rebuilt.Total() != 0 {
			t.Errorf("result %+v err %v, want nothing and no error", result, err)
		}
	})
}
