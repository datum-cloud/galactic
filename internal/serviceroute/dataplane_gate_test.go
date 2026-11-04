//go:build linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/serviceroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
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
	if err := g.recordingTable.Put(key, value); err != nil {
		return err
	}
	g.enabled = uint8(reflect.ValueOf(value).Field(0).Uint())
	return nil
}

// restartedProgrammer is a fresh router process over pinned maps whose
// policy gate is gate.
func restartedProgrammer(gate *pinnedGate) *EBPFRouteProgrammer {
	ids := mapSetIDs{1, 2, 3, 4, 5, 6, 7, 8, 9}
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

// A failed close must not be forgotten when the next Initialize resets the
// failure state.
func TestInheritedGateRetriesFailedClose(t *testing.T) {
	gate := &pinnedGate{enabled: 1}
	programmer := restartedProgrammer(gate)
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	gate.putErr = errors.New("map update failed")
	programmer.markSyncFailure("policy")
	if gate.enabled != 1 {
		t.Fatal("test setup: the failed close changed the gate")
	}
	if err := programmer.Initialize(); err == nil {
		t.Fatal("Initialize reset the failure state while the gate could not close")
	}
	gate.putErr = nil
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if gate.enabled != 0 || programmer.inheritedGate {
		t.Fatalf("gate=%d inherited=%t after the retried close, want closed", gate.enabled, programmer.inheritedGate)
	}
}

// A compatible datapath reload keeps the pinned gate, so the router keeps
// the inherited generation across it. This is the roll order where the
// router restarts first and the CNI then pins a new map.
func TestInheritedGateSurvivesCompatibleMapReload(t *testing.T) {
	gate := &pinnedGate{enabled: 1}
	ids := mapSetIDs{1, 2, 3, 4, 5, 6, 7, 0, 9}
	programmer := &EBPFRouteProgrammer{
		openMapSetFn: func(string) (*serviceroutemap.Tables, []*ebpf.Map, mapSetIDs, error) {
			return serviceroutemap.New(&recordingTable{}, &recordingTable{}, &recordingTable{}, &recordingTable{},
				&recordingTable{identityTokens: map[uint32]uint64{}}, gate, &recordingTable{}), nil, ids, nil
		},
	}
	programmer.readMapIDsFn = func(string) (mapSetIDs, error) { return ids, nil }
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	ids[7] = 8 // the CNI pinned the next-hop map
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("Initialize after reload: %v", err)
	}
	if gate.enabled != 1 || !programmer.inheritedGate {
		t.Fatalf("gate=%d inherited=%t after a compatible reload, want open and inherited",
			gate.enabled, programmer.inheritedGate)
	}

	// A reload that drains authorization closes the pinned gate, and the
	// router reads it closed.
	gate.enabled = 0
	ids[0] = 10
	if err := programmer.Initialize(); err != nil {
		t.Fatalf("Initialize after draining reload: %v", err)
	}
	if programmer.inheritedGate {
		t.Fatal("router kept inheriting a gate the datapath closed")
	}
}

// An absent optional map has no handle, so later handles must keep their
// own slots or every check reads as a map set change.
func TestMapSetSlotsSkipAbsentOptionalMaps(t *testing.T) {
	// New takes the remote grant, identity, policy state, deny and next-hop
	// tables after the first three; four omit the next-hop map.
	required := func() []usidmap.Table {
		return []usidmap.Table{&recordingTable{}, &recordingTable{}, &recordingTable{}, &recordingTable{},
			&recordingTable{}}
	}
	base := []int{0, 1, 2, 3, 4, 5, 6}
	tests := []struct {
		name   string
		tables *serviceroutemap.Tables
		want   []int
	}{
		{"no optional maps", serviceroutemap.New(&recordingTable{}, &recordingTable{}, &recordingTable{},
			required()[:4]...), base},
		{"producer sets without next hops", serviceroutemap.New(&recordingTable{}, &recordingTable{},
			&recordingTable{}, required()[:4]...).WithProducerSets(&recordingTable{}), append(base[:7:7], 8)},
		{"next hops without producer sets", serviceroutemap.New(&recordingTable{}, &recordingTable{},
			&recordingTable{}, required()...), append(base[:7:7], 7)},
		{"both", serviceroutemap.New(&recordingTable{}, &recordingTable{}, &recordingTable{},
			required()...).WithProducerSets(&recordingTable{}), append(base[:7:7], 7, 8)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapSetSlots(tt.tables); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("mapSetSlots = %v, want %v", got, tt.want)
			}
		})
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
