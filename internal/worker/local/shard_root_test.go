// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/worker/module"
)

// memShards is an in-memory egress_local_shard.
type memShards struct {
	mu   sync.Mutex
	rows map[uint32]LocalShardRow
}

func (m *memShards) Put(t uint32, r LocalShardRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[t] = r
	return nil
}

func (m *memShards) Delete(t uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, t)
	return nil
}

func (m *memShards) Get(t uint32) (LocalShardRow, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[t]
	return r, ok, nil
}

func (m *memShards) All() (map[uint32]LocalShardRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[uint32]LocalShardRow{}
	for k, v := range m.rows {
		out[k] = v
	}
	return out, nil
}

var (
	testShardSID = netip.MustParseAddr("2001:db8:4135:9::")
	testNodeSID  = netip.MustParseAddr("2001:db8:4135:1::")
)

// shardClaim is NAT's claim on v: a veth pair toward a Local shard serving
// v's TAP guest.
func shardClaim(v *vpcRig) module.Claim {
	return module.Claim{Key: module.ClaimKey{Node: testNode, VPC: v.vpc, AttachmentUID: v.natUID},
		Owner: "galactic-system/nat", Generation: 1, Handoff: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR,
		Destinations: []module.Destination{{ID: "shard/s", Mode: workerv1alpha1.Mode_MODE_LOCAL, VPC: v.vpc,
			Node: testNode, Shard: &module.ShardTarget{Name: "s", SID: testShardSID,
				Tenants: []module.ShardTenant{{UID: v.attUID, HostInterface: v.tap,
					Addresses: []netip.Addr{guestAddr}}}}}}}
}

// TestLocalShardRowRoot writes a VPC's egress_local_shard row only while
// its pair can carry the VPC's flows to the shard, withdraws only that VPC's
// row when NAT's program leaves the pair, and reports the VPC's tenant SID
// on the NAT end.
func TestLocalShardRowRoot(t *testing.T) {
	r := newRig(t, "shard", xdpmode.Native)
	shards := &memShards{rows: map[uint32]LocalShardRow{}}
	r.kernel.Shards = shards
	if err := r.usid.NodeSrcAddrTable.Put(uint32(0), testNodeSID.As16()); err != nil {
		t.Fatal(err)
	}

	natEnd := func(v *vpcRig) (nat, tenant netlink.Link) {
		r.in(r.node, func() error {
			var err error
			if nat, err = netlink.LinkByName(linkName(v.vpc, v.natUID, intf.LocalRolePairNAT)); err != nil {
				return err
			}
			tenant, err = netlink.LinkByName(linkName(v.vpc, v.natUID, intf.LocalRolePairTenant))
			return err
		})
		return nat, tenant
	}
	attachNAT := func(v *vpcRig) {
		nat, _ := natEnd(v)
		r.in(r.node, func() error { return netlink.LinkSetXdpFdWithFlags(nat, r.fix.LtfPass.FD(), xdpDrvMode) })
	}
	shardState := func(st module.State, v *vpcRig) module.DestinationState {
		return st[shardClaim(v).Key]["shard/s"]
	}

	for _, v := range r.vpcs {
		st := r.reconcile(v.vpc, []module.Claim{shardClaim(v)})
		if got := shardState(st, v); got.Ready || got.Reason != workerv1alpha1.ReasonHandoffHookMissing {
			t.Fatalf("%s before NAT attaches: %+v, want HandoffHookMissing", v.vpc, got)
		}
		if _, have, _ := shards.Get(v.table); have {
			t.Fatalf("%s has a row before NAT's program is on the pair", v.vpc)
		}
	}

	for _, v := range r.vpcs {
		attachNAT(v)
		r.reconcile(v.vpc, []module.Claim{shardClaim(v)}) // writes the row
		st := r.reconcile(v.vpc, []module.Claim{shardClaim(v)})
		if got := shardState(st, v); !got.Ready {
			t.Fatalf("%s after NAT attaches: %+v, want Ready", v.vpc, got)
		}
		_, tenant := natEnd(v)
		row, have, _ := shards.Get(v.table)
		if !have || row.ShardSID != testShardSID || row.PairIfindex != uint32(tenant.Attrs().Index) {
			t.Fatalf("%s row = %+v (%t), want the shard toward pair %d", v.vpc, row, have, tenant.Attrs().Index)
		}
		var nat module.HandoffInterface
		for _, h := range r.mod.HandoffInterfaces(module.Scope{VPC: v.vpc})[shardClaim(v).Key] {
			if h.Role == workerv1alpha1.HandoffRoleNAT {
				nat = h
			}
		}
		base := testNodeSID.As16()
		if want := spliceArgument(base, v.argument).String(); nat.TenantSID != want {
			t.Fatalf("%s NAT end tenant SID = %q, want %q", v.vpc, nat.TenantSID, want)
		}
	}
	if a, b := r.vpcs[0], r.vpcs[1]; spliceArgument(testNodeSID.As16(), a.argument) ==
		spliceArgument(testNodeSID.As16(), b.argument) {
		t.Fatal("two VPCs share a tenant SID")
	}

	// NAT's program leaves the first VPC's pair: only that VPC's row goes.
	v0, v1 := r.vpcs[0], r.vpcs[1]
	nat0, _ := natEnd(v0)
	r.in(r.node, func() error { return netlink.LinkSetXdpFdWithFlags(nat0, -1, xdpDrvMode) })
	st := r.reconcile(v0.vpc, []module.Claim{shardClaim(v0)})
	if got := shardState(st, v0); got.Ready || got.Reason != workerv1alpha1.ReasonHandoffHookMissing {
		t.Fatalf("%s after NAT detaches: %+v, want HandoffHookMissing", v0.vpc, got)
	}
	if _, have, _ := shards.Get(v0.table); have {
		t.Fatalf("%s keeps its row after NAT's program left its pair", v0.vpc)
	}
	if _, have, _ := shards.Get(v1.table); !have {
		t.Fatalf("%s lost its row when another VPC's pair failed", v1.vpc)
	}

	// Releasing the claim removes the pair and its row.
	r.reconcile(v1.vpc, nil)
	if _, have, _ := shards.Get(v1.table); have {
		t.Fatalf("%s keeps its row after its claim was released", v1.vpc)
	}
}
