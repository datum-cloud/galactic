// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"go.datum.net/galactic/internal/plumbing/ebpf/vipxlatmap"
	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testSweepOrphanVIP     = "2001:db8:5:5::200"
	testSweepOrphanBackend = "fd20:60::9:9"
	// testSweepUnresolvedArgument is the Argument the unresolvable binding's
	// rows were written under, before its VRF left the node.
	testSweepUnresolvedArgument = uint16(77)
)

// sweepRow is one row a previous galactic-router wrote, before the sweep runs.
type sweepRow struct {
	name     string
	egress   bool
	argument uint16 // 0 means the test binding's resolved Argument
	slot     uint16
	vip      string
	backend  string
}

// writeSweepRows writes rows through a VipXlatTable of their own, as a
// previous process would have, so the sweeper's fresh table over the same map
// reports every one at generation 0.
func writeSweepRows(t *testing.T, mem *memTable, block uint64, argument uint16, rows []sweepRow) {
	t.Helper()
	prev := vipxlatmap.NewVipXlatTable(mem)
	for _, r := range rows {
		arg := argument
		if r.argument != 0 {
			arg = r.argument
		}
		vip, backend := net.ParseIP(r.vip), net.ParseIP(r.backend)
		var err error
		if r.egress {
			err = prev.RegisterEgress(block, arg, ipProtoTCP, backend, 30080, vip, 8080)
		} else {
			err = prev.RegisterIngress(block, arg, r.slot, ipProtoTCP, vip, 8080, backend, 30080)
		}
		if err != nil {
			t.Fatalf("write row %s: %v", r.name, err)
		}
	}
}

// liveSlot is the slot the test binding's ingress row is keyed on.
func liveSlot() uint16 {
	return srv6.BackendSlot(netip.MustParseAddr(testVIPBindingBackendAddr), 30080)
}

func TestVIPXlatSweeper_Sweep(t *testing.T) {
	liveIngress := sweepRow{name: "live ingress", slot: liveSlot(),
		vip: testVIPBindingVIPAddr, backend: testVIPBindingBackendAddr}
	liveEgress := sweepRow{name: "live egress", egress: true,
		vip: testVIPBindingVIPAddr, backend: testVIPBindingBackendAddr}
	legacyIngress := sweepRow{name: "slot-0 ingress", slot: 0,
		vip: testVIPBindingVIPAddr, backend: testVIPBindingBackendAddr}
	orphanIngress := sweepRow{name: "orphan ingress", slot: 0x1234,
		vip: testSweepOrphanVIP, backend: testSweepOrphanBackend}
	orphanEgress := sweepRow{name: "orphan egress", egress: true,
		vip: testSweepOrphanVIP, backend: testSweepOrphanBackend}
	unresolvedIngress := sweepRow{name: "unresolved ingress", argument: testSweepUnresolvedArgument,
		slot: liveSlot(), vip: testVIPBindingVIPAddr, backend: testVIPBindingBackendAddr}
	unresolvedEgress := sweepRow{name: "unresolved egress", egress: true, argument: testSweepUnresolvedArgument,
		vip: testVIPBindingVIPAddr, backend: testVIPBindingBackendAddr}

	tests := []struct {
		name string
		// vpcRef is the test binding's vpcRef; empty means no binding.
		vpcRef    string
		otherNode bool
		rows      []sweepRow
		wantKept  []sweepRow
	}{
		{
			name:     "slot-0 ingress row of a live binding is removed, its live rows kept",
			vpcRef:   testVPCRef,
			rows:     []sweepRow{liveIngress, liveEgress, legacyIngress},
			wantKept: []sweepRow{liveIngress, liveEgress},
		},
		{
			name:     "rows no binding claims are removed",
			vpcRef:   testVPCRef,
			rows:     []sweepRow{liveIngress, liveEgress, orphanIngress, orphanEgress},
			wantKept: []sweepRow{liveIngress, liveEgress},
		},
		{
			name:     "an unresolvable binding keeps rows shaped like its own under any VRF",
			vpcRef:   "vpc-not-on-node",
			rows:     []sweepRow{unresolvedIngress, unresolvedEgress, orphanIngress},
			wantKept: []sweepRow{unresolvedIngress, unresolvedEgress},
		},
		{
			name:   "an unresolvable binding does not keep its slot-0 ingress row",
			vpcRef: "vpc-not-on-node",
			rows: []sweepRow{
				unresolvedIngress, unresolvedEgress,
				{name: "unresolved slot-0 ingress", argument: testSweepUnresolvedArgument, slot: 0,
					vip: testVIPBindingVIPAddr, backend: testVIPBindingBackendAddr},
			},
			wantKept: []sweepRow{unresolvedIngress, unresolvedEgress},
		},
		{
			name:      "a binding on another node keeps nothing here",
			vpcRef:    testVPCRef,
			otherNode: true,
			rows:      []sweepRow{liveIngress, liveEgress},
		},
		{
			name: "no bindings removes every row",
			rows: []sweepRow{liveIngress, orphanEgress},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, _, vrf := newBackendFixtures(testVPCRef)
			objs := []client.Object{router, vrf}
			if tt.vpcRef != "" {
				node := testComputeNodeName
				if tt.otherNode {
					node = "some-other-node"
				}
				b := newTestServiceVIPBinding(bgpv1alpha1.ServiceVIPBindingEgressKindTap, node)
				b.Spec.VPCRef = tt.vpcRef
				objs = append(objs, b)
			}
			c := fake.NewClientBuilder().WithScheme(newRuleTestScheme(t)).WithObjects(objs...).Build()

			block, argument, err := resolveVIPBindingContext(context.Background(), c, testNamespace,
				testComputeNodeName, testVPCRef)
			if err != nil {
				t.Fatalf("resolveVIPBindingContext: %v", err)
			}
			mem := newMemTable()
			writeSweepRows(t, mem, block, argument, tt.rows)

			table := vipxlatmap.NewVipXlatTable(mem)
			s := &VIPXlatSweeper{Client: c, NodeName: testComputeNodeName, Table: table}
			result := s.Sweep(context.Background())
			if result.Errors != 0 {
				t.Fatalf("Sweep: %d errors", result.Errors)
			}

			want := map[vipxlatmap.Key]string{}
			for _, r := range tt.wantKept {
				want[sweepRowKey(block, argument, r)] = r.name
			}
			entries, err := table.List()
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			for _, e := range entries {
				if _, ok := want[e.Key]; !ok {
					t.Errorf("row %+v survived the sweep", e.Key)
				}
				delete(want, e.Key)
			}
			for _, name := range want {
				t.Errorf("row %q was removed, want kept", name)
			}
			if got, wantRemoved := result.EBPFVIPXlatEntriesRemoved, len(tt.rows)-len(tt.wantKept); got != wantRemoved {
				t.Errorf("EBPFVIPXlatEntriesRemoved = %d, want %d", got, wantRemoved)
			}
		})
	}
}

// sweepRowKey is the key writeSweepRows wrote r under.
func sweepRowKey(block uint64, argument uint16, r sweepRow) vipxlatmap.Key {
	if r.argument != 0 {
		argument = r.argument
	}
	if r.egress {
		return vipxlatmap.Key{Block: block, Argument: argument, Proto: ipProtoTCP,
			Addr: netip.MustParseAddr(r.backend), Port: 30080}
	}
	return vipxlatmap.Key{Block: block, Argument: argument, Slot: r.slot, Proto: ipProtoTCP,
		Addr: netip.MustParseAddr(r.vip), Port: 8080}
}

// TestVIPXlatSweeper_ListErrorSkipsPass checks that a failure to list the
// node's bindings removes nothing rather than sweeping against an empty set.
func TestVIPXlatSweeper_ListErrorSkipsPass(t *testing.T) {
	router, _, vrf := newBackendFixtures(testVPCRef)
	c := fake.NewClientBuilder().WithScheme(newRuleTestScheme(t)).WithObjects(router, vrf).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*bgpv1alpha1.ServiceVIPBindingList); ok {
					return errors.New("injected list failure")
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()

	mem := newMemTable()
	writeSweepRows(t, mem, 0x20010db8ff01, 70, []sweepRow{{name: "orphan", slot: 0x1234,
		vip: testSweepOrphanVIP, backend: testSweepOrphanBackend}})
	table := vipxlatmap.NewVipXlatTable(mem)

	result := (&VIPXlatSweeper{Client: c, NodeName: testComputeNodeName, Table: table}).Sweep(context.Background())
	if result.Errors != 1 || result.EBPFVIPXlatEntriesRemoved != 0 {
		t.Errorf("Sweep = %+v, want 1 error and nothing removed", result)
	}
	entries, err := table.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("table holds %d rows, want the 1 row untouched", len(entries))
	}
}
