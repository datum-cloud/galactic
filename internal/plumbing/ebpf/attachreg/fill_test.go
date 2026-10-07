// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachreg

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/srv6"
)

// memTable is an in-memory usidmap.Table keyed by any comparable key.
type memTable map[any]any

func (m memTable) Put(key, value any) error { m[key] = value; return nil }

func (m memTable) Lookup(key, valueOut any) error {
	v, ok := m[key]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(v))
	return nil
}

func (m memTable) Delete(key any) error {
	if _, ok := m[key]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m, key)
	return nil
}

func (m memTable) Iterate() usidmap.Iterator {
	it := &memIterator{}
	for k, v := range m {
		it.keys = append(it.keys, k)
		it.values = append(it.values, v)
	}
	return it
}

// memIterator walks a snapshot of a memTable's entries.
type memIterator struct {
	keys, values []any
	idx          int
}

func (it *memIterator) Next(keyOut, valueOut any) bool {
	if it.idx >= len(it.keys) {
		return false
	}
	reflect.ValueOf(keyOut).Elem().Set(reflect.ValueOf(it.keys[it.idx]))
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(it.values[it.idx]))
	it.idx++
	return true
}

func (it *memIterator) Err() error { return nil }

// newMemMaps returns Maps over empty memTables, without the optional
// ifindex_egress_kind_table and tenant_gw_table when withOptional is false.
func newMemMaps(withOptional bool) *Maps {
	m := &Maps{
		Registry: &usidmap.Registry{
			VRF:            usidmap.NewVRFTable(memTable{}),
			Locator:        usidmap.NewLocatorTable(memTable{}),
			Function:       usidmap.NewFunctionTable(memTable{}),
			VPCAttribution: usidmap.NewVPCAttributionTable(memTable{}),
		},
		IfindexVRF:   ifindexvrfmap.NewIfindexVRFTable(memTable{}),
		EgressRoute:  egressroutemap.NewEgressRouteTable(memTable{}),
		NodeSource:   egressroutemap.NewNodeSourceAddress(memTable{}),
		PublicUplink: egressroutemap.NewPublicUplink(memTable{}),
	}
	if withOptional {
		m.EgressKind = ifindexvrfmap.NewEgressKindTable(memTable{})
		m.Gateway = ifindexvrfmap.NewGatewayTable(memTable{})
	}
	return m
}

const testBlock = uint64(0x2001_0db8_0001)

func testAttachment() Attachment {
	return Attachment{
		VPC: "jU", VPCAttachment: "abc", HostIfindex: 11, Block: testBlock, Argument: 0x21, VRFTableID: 7,
		InterfaceType: InterfaceTypeVeth,
		LocalPrefixes: []string{"fd20:30:ff01::/96", "fd20:30::1/128"},
		Gateways:      &Gateways{IPv6: net.ParseIP("fd20:30::1")},
	}
}

// TestFillVRF_ShardRoutesFillOnlyMissing checks the VRF's shard routes are
// built from the egress config with the attachment's Argument written into
// the shard SID, and that a route already present is not rewritten.
func TestFillVRF_ShardRoutesFillOnlyMissing(t *testing.T) {
	calls := recordRouteAdds(t, nil)
	m := newMemMaps(true)
	egress := EgressConfig{ShardSIDs: "2001:db8:ff01:9:e001::", NAT64Prefix: testNAT64Prefix}

	// Stand in for a ::/0 route ADD already installed.
	if err := m.EgressRoute.RegisterPassThrough(7, egressroutemap.DefaultPrefix); err != nil {
		t.Fatalf("seed ::/0: %v", err)
	}

	written, err := m.FillVRF(testAttachment(), egress)
	if err != nil {
		t.Fatalf("FillVRF: %v", err)
	}
	if written.ShardEgressRoutes != 1 || len(*calls) != 1 {
		t.Fatalf("shard routes written %d, calls %+v; want only the missing NAT64 route", written.ShardEgressRoutes,
			*calls)
	}
	c := (*calls)[0]
	wantSID := net.ParseIP("2001:db8:ff01:9:e021::")
	if c.table != 7 || c.prefix != testNAT64Prefix || len(c.sids) != 1 || !c.sids[0].Equal(wantSID) {
		t.Errorf("shard route = %+v, want table 7, 64:ff9b::/96 toward %s", c, wantSID)
	}
	if written.VRF != 1 || written.VPCAttribution != 1 || written.LocalEgressRoutes != 2 {
		t.Errorf("written = %+v, want the vrf_table, vpc_attribution_table and both local rows", written)
	}
}

func TestFillVRF_RejectsSidecarBlock(t *testing.T) {
	m := newMemMaps(true)
	a := testAttachment()
	a.Block = uformat.BlockIngressSidecar
	if _, err := m.FillVRF(a, EgressConfig{}); err == nil {
		t.Error("FillVRF under the ingress sidecar's Block = nil error, want a refusal")
	}
	if _, err := m.FillInterface(a); err == nil {
		t.Error("FillInterface under the ingress sidecar's Block = nil error, want a refusal")
	}
}

// TestFillInterface_WithoutOptionalMaps covers a datapath that predates
// ifindex_egress_kind_table and tenant_gw_table.
func TestFillInterface_WithoutOptionalMaps(t *testing.T) {
	m := newMemMaps(false)
	written, err := m.FillInterface(testAttachment())
	if err != nil {
		t.Fatalf("FillInterface: %v", err)
	}
	if want := (Counts{IfindexVRF: 1}); written != want {
		t.Errorf("written = %+v, want %+v", written, want)
	}
	if err := m.RemoveInterfaceRows(11, Counts{IfindexVRF: 1, EgressKind: 1, TenantGateway: 1}); err != nil {
		t.Errorf("RemoveInterfaceRows: %v", err)
	}
	if _, ok, _ := m.IfindexVRF.Get(11); ok {
		t.Error("ifindex_vrf_table row still present after RemoveInterfaceRows")
	}
}

func TestRemoveInterfaceRows_OnlyRemovesWhatWasWritten(t *testing.T) {
	m := newMemMaps(true)
	a := testAttachment()
	if err := m.EgressKind.Register(a.HostIfindex, usidmap.EgressKindTap); err != nil {
		t.Fatalf("seed egress kind: %v", err)
	}
	written, err := m.FillInterface(a)
	if err != nil {
		t.Fatalf("FillInterface: %v", err)
	}
	if err := m.RemoveInterfaceRows(a.HostIfindex, written); err != nil {
		t.Fatalf("RemoveInterfaceRows: %v", err)
	}
	if kind, ok, _ := m.EgressKind.Get(a.HostIfindex); !ok || kind != usidmap.EgressKindTap {
		t.Errorf("egress kind = %d ok %v, want the pre-existing tap row kept", kind, ok)
	}
	if _, _, ok, _ := m.Gateway.Get(a.HostIfindex); ok {
		t.Error("tenant_gw_table row still present, want the written row removed")
	}
}

// TestFillVRF_UnresolvableShardsTriedOncePerPass stands in for a fabric
// outage: every shard attempt waits out its neighbor solicitation and fails.
// Only the first VRF's attempt may pay that wait; later VRFs on the same Maps
// skip their shard routes, so a pass over many VRFs stays bounded, and their
// local rows are still written.
func TestFillVRF_UnresolvableShardsTriedOncePerPass(t *testing.T) {
	const resolveWait = 50 * time.Millisecond
	original := egressPrefixRouteAddFn
	t.Cleanup(func() { egressPrefixRouteAddFn = original })
	var attempts int
	egressPrefixRouteAddFn = func(*egressroutemap.EgressRouteTable, uint32, *net.IPNet, []net.IP) error {
		attempts++
		time.Sleep(resolveWait)
		return fmt.Errorf("%w yet for ::/0", srv6.ErrNoShardResolvable)
	}

	m := newMemMaps(true)
	egress := EgressConfig{ShardSIDs: "2001:db8:ff01:9:e001::,2001:db8:ff02:9:e001::", NAT64Prefix: testNAT64Prefix}
	start := time.Now()
	for i := range 20 {
		a := testAttachment()
		a.Argument = uint16(0x21 + i)
		a.VRFTableID = uint32(7 + i)
		written, err := m.FillVRF(a, egress)
		if i == 0 && !errors.Is(err, srv6.ErrNoShardResolvable) {
			t.Errorf("first FillVRF error = %v, want the unresolvable shard reported", err)
		}
		if i > 0 && err != nil {
			t.Errorf("FillVRF %d error = %v, want shard routes skipped without a further error", i, err)
		}
		if written.VRF != 1 || written.LocalEgressRoutes != 2 {
			t.Errorf("FillVRF %d wrote %+v, want its vrf_table and local rows regardless", i, written.Counts)
		}
	}
	if attempts != 1 {
		t.Errorf("shard route attempts = %d, want 1 for the whole pass", attempts)
	}
	if elapsed := time.Since(start); elapsed > 10*resolveWait {
		t.Errorf("pass over 20 VRFs took %v, want it bounded by about one resolution wait", elapsed)
	}
}

func TestFillNode_NotConfiguredWritesNothing(t *testing.T) {
	m := newMemMaps(true)
	resolve := func() (int, net.HardwareAddr, net.HardwareAddr, error) {
		t.Fatal("resolver called for a node with no SRv6 identity")
		return 0, nil, nil, nil
	}
	written, uplinkErr, err := m.FillNode(Node{}, resolve)
	if written.Total() != 0 || uplinkErr != nil || err != nil {
		t.Errorf("FillNode(zero) = %+v, %v, %v; want nothing", written, uplinkErr, err)
	}
}
