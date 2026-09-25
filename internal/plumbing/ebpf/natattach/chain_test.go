// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natattach

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

// pinEdgeChain loads the real edge gateway objects and pins their xdp_chain
// under a per-test bpffs directory, standing in for a running galactic-gateway.
// The real objects rather than a hand-made program array matter: the kernel
// ties an array to its first user's program type and expected attach type, and
// that owner is what AttachChain's program has to be compatible with.
func pinEdgeChain(t *testing.T) (*edgeprog.EdgedsrObjects, string) {
	t.Helper()
	requireRoot(t)

	var edge edgeprog.EdgedsrObjects
	if err := edgeprog.LoadEdgedsrObjects(&edge, nil); err != nil {
		t.Fatalf("load edge objects: %v", err)
	}
	t.Cleanup(func() { _ = edge.Close() })

	dir := filepath.Join("/sys/fs/bpf", "natattach-chain-test-"+filepath.Base(t.Name()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("bpffs not writable at /sys/fs/bpf: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "xdp_chain")
	if err := edge.XdpChain.Pin(path); err != nil {
		t.Fatalf("pin xdp_chain: %v", err)
	}
	t.Cleanup(func() { _ = edge.XdpChain.Unpin() })
	return &edge, path
}

func loadNatObjects(t *testing.T) *natprog.NatObjects {
	t.Helper()
	var objs natprog.NatObjects
	if err := natprog.LoadNatObjects(&objs, nil); err != nil {
		t.Fatalf("load nat objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	return &objs
}

// TestAttachChain_InstallsTheShardInTheGatewaysSlot is the property the edge
// placement rests on: the shard's real dispatcher is accepted into the real
// gateway's array, and ChainHolds reads that back.
func TestAttachChain_InstallsTheShardInTheGatewaysSlot(t *testing.T) {
	_, path := pinEdgeChain(t)
	nat := loadNatObjects(t)

	if held, err := ChainHolds(nat.NatIngress, path); err != nil || held {
		t.Fatalf("ChainHolds before AttachChain = %v, %v; want false, nil", held, err)
	}
	if err := AttachChain(nat.NatIngress, path); err != nil {
		t.Fatalf("AttachChain: %v", err)
	}
	if held, err := ChainHolds(nat.NatIngress, path); err != nil || !held {
		t.Fatalf("ChainHolds after AttachChain = %v, %v; want true, nil", held, err)
	}
	// Idempotent, since the re-assert loop calls it again on every miss.
	if err := AttachChain(nat.NatIngress, path); err != nil {
		t.Fatalf("second AttachChain: %v", err)
	}
}

// TestChainHolds_ReportsASlotSomethingElseTook covers what a re-assert has to
// notice: the slot now holding a different program, as after a gateway
// restart that recreated its map.
func TestChainHolds_ReportsASlotSomethingElseTook(t *testing.T) {
	edge, path := pinEdgeChain(t)
	nat := loadNatObjects(t)
	if err := AttachChain(nat.NatIngress, path); err != nil {
		t.Fatalf("AttachChain: %v", err)
	}

	other, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.XDP,
		AttachType:   ebpf.AttachXDP,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()},
		License:      "GPL",
	})
	if err != nil {
		t.Fatalf("load other program: %v", err)
	}
	t.Cleanup(func() { _ = other.Close() })
	if err := edge.XdpChain.Put(chainSlot, other); err != nil {
		t.Fatalf("replace slot: %v", err)
	}

	if held, err := ChainHolds(nat.NatIngress, path); err != nil || held {
		t.Fatalf("ChainHolds with another program in the slot = %v, %v; want false, nil", held, err)
	}
	if err := AttachChain(nat.NatIngress, path); err != nil {
		t.Fatalf("re-assert AttachChain: %v", err)
	}
	if held, err := ChainHolds(nat.NatIngress, path); err != nil || !held {
		t.Fatalf("ChainHolds after re-assert = %v, %v; want true, nil", held, err)
	}
}

// TestAttachChain_MissingMapIsNotExist lets the caller tell "the gateway has
// not loaded yet", which it retries, from a real failure.
func TestAttachChain_MissingMapIsNotExist(t *testing.T) {
	requireRoot(t)
	nat := loadNatObjects(t)

	err := AttachChain(nat.NatIngress, "/sys/fs/bpf/natattach-chain-test-absent/xdp_chain")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("AttachChain on a missing map = %v, want an error wrapping os.ErrNotExist", err)
	}
}

func TestAttachChain_NilProgramIsError(t *testing.T) {
	if err := AttachChain(nil, EdgeChainMapPath); err == nil {
		t.Fatal("AttachChain(nil, _) error = nil, want an error")
	}
}
