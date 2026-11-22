// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeprog

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
)

// dispatchRig is a real XDP dispatcher root with edge_lb in the gateway's
// public slot and a stand-in for the egress shard in the NAT slot, as on a
// gateway node whose public uplink both share.
type dispatchRig struct {
	t    *testing.T
	root *xdpdispatch.DispatchObjects
	edge *EdgedsrObjects
	nat  *ebpf.Program
}

func newDispatchRig(t *testing.T) *dispatchRig {
	t.Helper()
	requireRoot(t)
	var root xdpdispatch.DispatchObjects
	if err := xdpdispatch.LoadDispatchObjects(&root, nil); err != nil {
		t.Fatalf("load the dispatcher: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })

	// edge_lb reads and tail-calls through the dispatcher's own maps, as
	// edgeattach.Load arranges in dispatch mode.
	var edge EdgedsrObjects
	if err := LoadEdgedsrObjects(&edge, &ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{
		EdgedsrMapDispatchProgs: root.DispatchProgs,
		EdgedsrMapIfaceRoles:    root.IfaceRoles,
		EdgedsrMapSlotLease:     root.SlotLease,
	}}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load edgedsr: %+v", ve)
		}
		t.Fatalf("load edgedsr: %v", err)
	}
	t.Cleanup(func() { _ = edge.Close() })

	nat, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.XDP,
		AttachType:   ebpf.AttachXDP,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, chainStubVerdict), asm.Return()},
		License:      "GPL",
	})
	if err != nil {
		t.Fatalf("load the NAT stand-in: %v", err)
	}
	t.Cleanup(func() { _ = nat.Close() })

	r := &dispatchRig{t: t, root: &root, edge: &edge, nat: nat}
	if err := root.IfaceRoles.Put(testRunIfindex,
		uint32(xdpdispatch.RolePublicLB|xdpdispatch.RoleEgress)); err != nil {
		t.Fatalf("set roles: %v", err)
	}
	r.fill(xdpdispatch.SlotGatewayLB, edge.EdgeLb)
	r.fill(xdpdispatch.SlotNAT, nat)
	return r
}

// fill and release do what xdpdispatch's Locked.Fill and Locked.Clear do to
// the maps: a program and a live lease, then neither.
func (r *dispatchRig) fill(slot xdpdispatch.Slot, p *ebpf.Program) {
	r.t.Helper()
	if err := r.root.DispatchProgs.Put(uint32(slot), p); err != nil {
		r.t.Fatalf("fill slot %d: %v", slot, err)
	}
	if err := r.root.SlotLease.Put(uint32(slot), monotonicNow()+uint64(time.Minute)); err != nil {
		r.t.Fatalf("lease slot %d: %v", slot, err)
	}
}

func (r *dispatchRig) release(slot xdpdispatch.Slot) {
	r.t.Helper()
	if err := r.root.DispatchProgs.Delete(uint32(slot)); err != nil {
		r.t.Fatalf("clear slot %d: %v", slot, err)
	}
	if err := r.root.SlotLease.Put(uint32(slot), uint64(0)); err != nil {
		r.t.Fatalf("expire slot %d: %v", slot, err)
	}
}

// run runs the dispatcher root on pkt and returns the verdict and the
// metadata in front of the packet.
func (r *dispatchRig) run(pkt []byte) (uint32, []byte) {
	r.t.Helper()
	out := make([]byte, len(pkt)+256)
	var ctxOut xdpMd
	ret, err := r.root.XdpDispatch.Run(&ebpf.RunOptions{
		Data: pkt, DataOut: out,
		Context:    xdpMd{DataEnd: uint32(len(pkt))}, //nolint:gosec // a test frame
		ContextOut: &ctxOut,
	})
	if err != nil {
		r.t.Fatalf("dispatcher test-run: %v", err)
	}
	return ret, out[:ctxOut.Data]
}

func (r *dispatchRig) wantHandoff(pkt []byte, tap uint32) {
	r.t.Helper()
	ret, meta := r.run(pkt)
	if ret != xdpPass {
		r.t.Fatalf("verdict = %d, want XDP_PASS (%d); %d is the NAT slot's", ret, xdpPass, chainStubVerdict)
	}
	if len(meta) != localMetaLen || binary.NativeEndian.Uint32(meta[0:4]) != localMetaMagicV2 ||
		binary.NativeEndian.Uint32(meta[4:8]) != tap {
		r.t.Fatalf("metadata = % x, want GLM2 for TAP %d", meta, tap)
	}
}

// TestDispatch_LocalHandoffNeverRunsTheNATSlot proves that edge_lb's XDP_PASS
// for a Local backend is final in the shared dispatcher: the NAT slot after it
// never sees the packet, while an unclaimed packet still reaches it. It also
// proves that releasing either slot leaves the other serving.
func TestDispatch_LocalHandoffNeverRunsTheNATSlot(t *testing.T) {
	r := newDispatchRig(t)
	vip := netip.MustParseAddr("2001:db8::100")
	notReadyVIP := netip.MustParseAddr("2001:db8::101")
	notReadySID := netip.MustParseAddr("fc00:1:2:3:e1a5:8::")
	putIPv4VIP(t, r.edge, ipprotoUDP, 443, vip, testLocalSID)
	putIPv4VIP(t, r.edge, ipprotoUDP, 443, notReadyVIP, notReadySID)
	putLocal(t, r.edge, testLocalSID, 42)
	putLocal(t, r.edge, notReadySID, 0)

	client := netip.MustParseAddr("2001:db8:ffff::1")
	local := buildL4Packet(t, ipprotoUDP, vip, client, 41000, 443, []byte("hello"))
	notReady := buildL4Packet(t, ipprotoUDP, notReadyVIP, client, 41000, 443, []byte("hello"))
	unclaimed := buildL4Packet(t, ipprotoUDP, netip.MustParseAddr("2001:db8::200"), client, 41000, 443, nil)

	r.wantHandoff(local, 42)
	if ret, _ := r.run(unclaimed); ret != chainStubVerdict {
		t.Fatalf("unclaimed verdict = %d, want the NAT slot's %d", ret, chainStubVerdict)
	}
	if got := localHandoffs(t, r.edge); got != 1 {
		t.Errorf("local_handoffs = %d, want 1", got)
	}

	// The gateway's slot released: the NAT slot still serves, and now sees
	// what the gateway would have claimed.
	r.release(xdpdispatch.SlotGatewayLB)
	if ret, meta := r.run(local); ret != chainStubVerdict || len(meta) != 0 {
		t.Fatalf("with the gateway released, verdict = %d with %d bytes of metadata, want the NAT slot's %d",
			ret, len(meta), chainStubVerdict)
	}

	// The NAT slot released instead: the gateway still serves, handing off
	// and dropping as before, and what it does not claim passes.
	r.fill(xdpdispatch.SlotGatewayLB, r.edge.EdgeLb)
	r.release(xdpdispatch.SlotNAT)
	r.wantHandoff(local, 42)
	if ret, _ := r.run(notReady); ret != xdpDrop {
		t.Fatalf("not-ready verdict = %d, want XDP_DROP (%d)", ret, xdpDrop)
	}
	if got := sumPerCPU(t, r.edge.DropReasons, DropReasonLocalUnavailable); got != 1 {
		t.Errorf("drop_reasons[local_unavailable] = %d, want 1", got)
	}
	if ret, meta := r.run(unclaimed); ret != xdpPass || len(meta) != 0 {
		t.Fatalf("unclaimed verdict = %d with %d bytes of metadata, want XDP_PASS and none", ret, len(meta))
	}
	if got := localHandoffs(t, r.edge); got != 2 {
		t.Errorf("local_handoffs = %d, want 2", got)
	}
}
