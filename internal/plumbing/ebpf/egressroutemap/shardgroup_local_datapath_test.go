// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package egressroutemap

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// tcActUnspec is TC_ACT_UNSPEC (-1) as BPF_PROG_RUN reports it.
const tcActUnspec = 0xFFFFFFFF

// cbLocalShard mirrors USID_CB_LOCAL_SHARD in usid.c.
const cbLocalShard = 0x4c534844

// skbCtx is struct __sk_buff up to and including cb, the part BPF_PROG_RUN
// copies back out.
type skbCtx struct {
	Len, PktType, Mark, QueueMapping, Protocol, VlanPresent, VlanTCI, VlanProto uint32
	Priority, IngressIfindex, Ifindex, TCIndex                                  uint32
	CB                                                                          [5]uint32
}

// withLocalView attaches egress_shard_local_groups to dp's table.
func (dp *datapath) withLocalView() {
	dp.groups.WithLocalView(NewKernelGroupStore(dp.objs.EgressShardLocalGroups))
}

// run runs pkt through usid_egress and returns the verdict, the packet out
// and the skb's cb words.
func (dp *datapath) run(t *testing.T, pkt []byte) (uint32, []byte, [5]uint32) {
	t.Helper()
	// The kernel copies the whole struct __sk_buff back and refuses a
	// shorter buffer, so the context comes out into a generous one.
	var (
		in  skbCtx
		out [64]uint32
	)
	opts := ebpf.RunOptions{Data: pkt, DataOut: make([]byte, len(pkt)+256), Context: &in, ContextOut: &out}
	ret, err := dp.objs.UsidEgress.Run(&opts)
	if err != nil {
		t.Fatalf("program test-run: %v", err)
	}
	var cb [5]uint32
	copy(cb[:], out[12:17]) // cb starts at byte 48 of struct __sk_buff
	return ret, opts.DataOut, cb
}

func (dp *datapath) putLocalRow(t *testing.T, table uint32, shard netip.Addr) {
	t.Helper()
	row := LocalShard{ShardSID: shard, PairIfindex: 9}
	if err := NewLocalShardTable(dp.objs.EgressLocalShard).Put(table, row); err != nil {
		t.Fatal(err)
	}
}

type pinSummary struct {
	shard      uint8
	generation uint32
}

func pinsOf(t *testing.T, m *ebpf.Map) map[string]pinSummary {
	t.Helper()
	out := map[string]pinSummary{}
	var (
		key   prog.UsidEgressShardPinKey
		value prog.UsidEgressShardPinValue
	)
	it := m.Iterate()
	for it.Next(&key, &value) {
		out[pinKeyString(key)] = pinSummary{shard: value.Shard, generation: value.Generation}
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func pinKeyString(k prog.UsidEgressShardPinKey) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%d/%d/%d/%d:%d/", k.TableId, k.Group, k.Protocol, k.Sport, k.Dport)
	b.WriteString(netip.AddrFrom16(k.Saddr).String())
	b.WriteByte('/')
	b.WriteString(netip.AddrFrom16(k.Daddr).String())
	return b.String()
}

func countersOf(t *testing.T, m *ebpf.Map) map[uint32]uint64 {
	t.Helper()
	out := map[uint32]uint64{}
	for i := range uint32(MaxShardGroups * MaxShardsPerGroup) {
		var perCPU []prog.UsidEgressShardCounter
		if err := m.Lookup(i, &perCPU); err != nil {
			t.Fatal(err)
		}
		for _, c := range perCPU {
			out[i] += c.Packets
		}
	}
	return out
}

// TestLocalDatapath_NoRowMatchesToday is the coordinator's guard on the
// datapath: with a local view published and a row for another VRF, a VRF
// with no egress_local_shard row gets exactly the verdicts, packets, cb,
// pins, per-shard counters and stats a datapath with no local view gives it.
func TestLocalDatapath_NoRowMatchesToday(t *testing.T) {
	local, a, b := shardSID(0x10), shardSID(0x11), shardSID(0x12)
	reachable(t, a, b)
	policy := GroupPolicy{PinIdle: time.Hour}
	in := []ShardCandidate{{SID: local.AsSlice(), Local: true}, {SID: a.AsSlice()}, {SID: b.AsSlice()}}

	today, withView := loadDatapath(t), loadDatapath(t)
	withView.withLocalView()
	withView.putLocalRow(t, dpTableID+1, local)
	today.apply(t, policy, in)
	if r := withView.apply(t, policy, in); !r.LocalView {
		t.Fatalf("Apply = %+v, want a local view published", r)
	}

	for i := range 400 {
		pkt := udp6(tenant(i), internet, uint16(i), 53) //nolint:gosec // test index
		r1, out1, cb1 := today.run(t, pkt)
		r2, out2, cb2 := withView.run(t, pkt)
		if r1 != r2 || !bytes.Equal(out1, out2) || cb1 != cb2 {
			t.Fatalf("tenant %d: today %d %x cb %v; with a local view %d %x cb %v", i, r1, out1, cb1, r2, out2, cb2)
		}
		if r1 == tcActUnspec {
			t.Fatalf("tenant %d was handed on without a row", i)
		}
	}
	if p1, p2 := pinsOf(t, today.objs.EgressShardPin), pinsOf(t, withView.objs.EgressShardPin); len(p1) != len(p2) {
		t.Errorf("pins: today %d, with a local view %d", len(p1), len(p2))
	} else {
		for k, v := range p1 {
			if p2[k] != v {
				t.Errorf("pin %s: today %+v, with a local view %+v", k, v, p2[k])
			}
		}
	}
	c1, c2 := countersOf(t, today.objs.EgressShardCounters), countersOf(t, withView.objs.EgressShardCounters)
	for k, v := range c1 {
		if c2[k] != v {
			t.Errorf("counter %d: today %d, with a local view %d", k, v, c2[k])
		}
	}
	for i := range prog.EgressShardStatCount {
		if s1, s2 := stat(t, today.objs.EgressShardStats, i), stat(t, withView.objs.EgressShardStats, i); s1 != s2 {
			t.Errorf("egress_shard_stats[%s]: today %d, with a local view %d", prog.EgressShardStatNames[i], s1, s2)
		}
	}
}

// TestLocalDatapath_RowPlacesTenantsOnTheLocalShard checks the local branch:
// with a row, the tenants Maglev gives the local shard are handed on
// unencapsulated with the marker and the VRF table in cb, and the rest are
// encapsulated toward the remote shard as before. Removing the row sends the
// local shard's tenants to the remote one, their pins stale.
func TestLocalDatapath_RowPlacesTenantsOnTheLocalShard(t *testing.T) {
	local, remote := shardSID(0x10), shardSID(0x11)
	reachable(t, remote)
	dp := loadDatapath(t)
	dp.withLocalView()
	dp.apply(t, GroupPolicy{PinIdle: time.Hour},
		[]ShardCandidate{{SID: local.AsSlice(), Local: true}, {SID: remote.AsSlice()}})
	dp.putLocalRow(t, dpTableID, local)

	var onLocal, onRemote []netip.Addr
	for i := range 200 {
		pkt := udp6(tenant(i), internet, 1, 53)
		want := predict(t, ShardPinKey{TableID: dpTableID, Src: tenant(i)}, HashSource, local, remote)
		ret, out, cb := dp.run(t, pkt)
		switch want {
		case local:
			if ret != tcActUnspec || cb[0] != cbLocalShard || cb[1] != dpTableID || !bytes.Equal(out[:len(pkt)], pkt) {
				t.Fatalf("tenant %d: verdict %#x cb %v; want handed on unchanged with the marker", i, ret, cb)
			}
			onLocal = append(onLocal, tenant(i))
		default:
			if ret != tcActRedirect || cb[0] == cbLocalShard {
				t.Fatalf("tenant %d: verdict %#x cb %v; want encapsulated toward the remote shard", i, ret, cb)
			}
			onRemote = append(onRemote, tenant(i))
		}
	}
	if len(onLocal) == 0 || len(onRemote) == 0 {
		t.Fatalf("local %d, remote %d: want both shards used", len(onLocal), len(onRemote))
	}
	if got := stat(t, dp.objs.EgressShardStats, prog.EgressShardStatLocal); got != uint64(len(onLocal)) {
		t.Errorf("egress_shard_stats[local] = %d, want %d", got, len(onLocal))
	}

	// Pinned to the local shard: still there on the next packet.
	if ret, _, _ := dp.run(t, udp6(onLocal[0], internet, 2, 53)); ret != tcActUnspec {
		t.Errorf("pinned local tenant verdict %#x on its second packet", ret)
	}

	if err := NewLocalShardTable(dp.objs.EgressLocalShard).Delete(dpTableID); err != nil {
		t.Fatal(err)
	}
	stale := stat(t, dp.objs.EgressShardStats, prog.EgressShardStatPinStale)
	for _, a := range onLocal {
		ret, _, cb := dp.run(t, udp6(a, internet, 3, 53))
		if ret != tcActRedirect || cb[0] == cbLocalShard {
			t.Fatalf("tenant %s after the row went: verdict %#x cb %v; want the remote shard", a, ret, cb)
		}
	}
	if got := stat(t, dp.objs.EgressShardStats, prog.EgressShardStatPinStale) - stale; got != uint64(len(onLocal)) {
		t.Errorf("pin_stale rose by %d, want %d: every local pin is stale without the row", got, len(onLocal))
	}
	for _, a := range onLocal[:1] {
		if _, got, _ := dp.send(t, udp6(a, internet, 4, 53)); got != remote {
			t.Errorf("tenant %s went to %s, want %s", a, got, remote)
		}
	}
}

// TestLocalDatapath_NoLocalViewUsesTheBaseView checks that a row with no local
// view published reads the base view: the local shard is never chosen.
func TestLocalDatapath_NoLocalViewUsesTheBaseView(t *testing.T) {
	local, remote := shardSID(0x10), shardSID(0x11)
	reachable(t, remote)
	dp := loadDatapath(t)
	dp.apply(t, GroupPolicy{}, []ShardCandidate{{SID: local.AsSlice(), Local: true}, {SID: remote.AsSlice()}})
	dp.putLocalRow(t, dpTableID, local)
	for i := range 100 {
		if ret, _, cb := dp.run(t, udp6(tenant(i), internet, 1, 53)); ret != tcActRedirect || cb[0] == cbLocalShard {
			t.Fatalf("tenant %d: verdict %#x cb %v; want the remote shard", i, ret, cb)
		}
	}
}
