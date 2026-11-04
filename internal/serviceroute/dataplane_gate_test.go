//go:build linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/serviceroutemap"
)

// pinnedGate is a policy-state map holding the gate a previous router
// process left pinned.
type pinnedGate struct {
	recordingTable
	enabled uint8
}

func (g *pinnedGate) Lookup(_ any, value any) error {
	reflect.ValueOf(value).Elem().Field(0).SetUint(uint64(g.enabled))
	return nil
}

func (g *pinnedGate) Put(key any, value any) error {
	g.enabled = uint8(reflect.ValueOf(value).Field(0).Uint())
	return g.recordingTable.Put(key, value)
}

// restartedProgrammer is a fresh router process over pinned maps whose
// policy gate is gate.
func restartedProgrammer(gate *pinnedGate) *EBPFRouteProgrammer {
	ids := mapSetIDs{1, 2, 3, 4, 5, 6, 7, 8}
	return &EBPFRouteProgrammer{
		openMapSetFn: func(string) (*serviceroutemap.Tables, []*ebpf.Map, mapSetIDs, error) {
			return serviceroutemap.New(&recordingTable{}, &recordingTable{}, &recordingTable{}, &recordingTable{},
				&recordingTable{identityTokens: map[uint32]uint64{}}, gate, &recordingTable{}), nil, ids, nil
		},
		readMapIDsFn: func(string) (mapSetIDs, error) { return ids, nil },
	}
}

// A router restart must not drop every private-service packet on the node
// until the API answers: the previous process's finalized generation keeps
// serving until this process's startup sync replaces it.
func TestRestartKeepsInheritedOpenGate(t *testing.T) {
	gate := &pinnedGate{enabled: 1}
	programmer := restartedProgrammer(gate)
	for range 2 {
		if err := programmer.Initialize(); err != nil {
			t.Fatalf("Initialize: %v", err)
		}
		if gate.enabled != 1 {
			t.Fatal("Initialize closed the gate a finalized generation left open")
		}
	}
	if err := programmer.Finalize(); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if gate.enabled != 1 || !programmer.policyFinalized || programmer.inheritedGate {
		t.Fatalf("after Finalize gate=%d finalized=%t inherited=%t, want open, finalized, not inherited",
			gate.enabled, programmer.policyFinalized, programmer.inheritedGate)
	}
}

// A gate pinned closed, as a crash mid-rebuild leaves it, stays closed.
func TestRestartKeepsClosedGateClosed(t *testing.T) {
	gate := &pinnedGate{}
	programmer := restartedProgrammer(gate)
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if gate.enabled != 0 || programmer.inheritedGate {
		t.Fatalf("gate=%d inherited=%t, want closed and not inherited", gate.enabled, programmer.inheritedGate)
	}
}

// The inherited generation is trusted only while this process rebuilds
// cleanly; a failed mutation fails closed as before.
func TestInheritedGateClosesOnSyncFailure(t *testing.T) {
	gate := &pinnedGate{enabled: 1}
	programmer := restartedProgrammer(gate)
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	programmer.markSyncFailure("policy")
	if gate.enabled != 0 || programmer.inheritedGate {
		t.Fatalf("gate=%d inherited=%t after a sync failure, want closed", gate.enabled, programmer.inheritedGate)
	}
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if gate.enabled != 0 {
		t.Fatal("Initialize reopened a gate closed by a sync failure")
	}
}

func TestInheritedGateClosesWhenFinalizeFails(t *testing.T) {
	gate := &pinnedGate{enabled: 1}
	programmer := restartedProgrammer(gate)
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	programmer.pendingRollbacks["policy"] = []appliedEntry{{}}
	if err := programmer.Finalize(); err == nil {
		t.Fatal("Finalize succeeded with a pending rollback")
	}
	if gate.enabled != 0 || programmer.inheritedGate {
		t.Fatalf("gate=%d inherited=%t after a failed Finalize, want closed", gate.enabled, programmer.inheritedGate)
	}
}
