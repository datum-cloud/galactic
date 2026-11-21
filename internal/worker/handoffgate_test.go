// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"testing"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/module/fake"
)

// The destination IDs of the status tests.
const (
	localDest  = "local/a"
	fabricDest = "fabric/b"
)

// gateModule is a Local module whose handoff reports fixed blocks.
type gateModule struct {
	*fake.Module
	blocked map[workerv1alpha1.Mode]map[module.ClaimKey]module.Blocked
}

func (m *gateModule) HandoffBlocked(_ module.Scope, mode workerv1alpha1.Mode) map[module.ClaimKey]module.Blocked {
	return m.blocked[mode]
}

// TestHandoffBlocks checks that a module's blocks are collected for the other
// modes only, and a module without a gate contributes none.
func TestHandoffBlocks(t *testing.T) {
	key := module.ClaimKey{Node: "node-a", VPC: "0000080", AttachmentUID: "envoy-1"}
	egress := module.Blocked{Reason: workerv1alpha1.ReasonRoutedLinkEgressUnavailable, Message: "not first"}
	host := fake.NewHost()
	local := &gateModule{Module: fake.New("local", workerv1alpha1.Mode_MODE_LOCAL, host),
		blocked: map[workerv1alpha1.Mode]map[module.ClaimKey]module.Blocked{
			workerv1alpha1.Mode_MODE_FABRIC: {key: egress},
			// A module's own mode is its own to report.
			workerv1alpha1.Mode_MODE_LOCAL: {key: {Reason: "Own"}},
		}}
	fab := fake.New("fabric", workerv1alpha1.Mode_MODE_FABRIC, host)
	got := handoffBlocks([]module.Module{local, fab}, module.Scope{VPC: key.VPC})
	if b, ok := got[workerv1alpha1.Mode_MODE_FABRIC][key]; !ok || b != egress {
		t.Fatalf("Fabric blocks = %v, want %+v", got[workerv1alpha1.Mode_MODE_FABRIC], egress)
	}
	if b, ok := got[workerv1alpha1.Mode_MODE_LOCAL][key]; ok {
		t.Fatalf("the module's own mode was blocked: %+v", b)
	}
}

// TestApplyStatusHandoffBlocked checks how a blocked handoff changes a
// claim's status: a ready destination of the blocked mode is not
// forward-ready and reports the block, one already not ready keeps its own
// reason, and a destination of another mode is untouched, so a claim with
// only those stays Ready.
func TestApplyStatusHandoffBlocked(t *testing.T) {
	key := module.ClaimKey{Node: "node-a", VPC: "0000080", AttachmentUID: "envoy-1"}
	egress := module.Blocked{Reason: workerv1alpha1.ReasonRoutedLinkEgressUnavailable, Message: "not first"}
	ready := module.DestinationState{Generation: 1, Programmed: true, Ready: true, ForwardReady: true,
		ReturnReady: true}
	notReady := module.DestinationState{Generation: 1, Programmed: true, ReturnReady: true,
		Reason: workerv1alpha1.ReasonRouteWithdrawn, Message: "withdrawn"}
	dest := func(id string, mode workerv1alpha1.Mode) destEval {
		return destEval{ref: &workerv1alpha1.Destination{}, id: id, mode: mode, resolved: true}
	}
	tests := []struct {
		name       string
		dests      []destEval
		state      map[workerv1alpha1.Mode]module.State
		blocked    bool
		wantReady  bool
		wantReason string
		// destReasons are each destination's reason, in order.
		destReasons []string
		destForward []bool
	}{
		{"LocalOnlyStaysReady", []destEval{dest(localDest, workerv1alpha1.Mode_MODE_LOCAL)},
			map[workerv1alpha1.Mode]module.State{workerv1alpha1.Mode_MODE_LOCAL: {key: {localDest: ready}}},
			true, true, workerv1alpha1.ReasonAsExpected, []string{""}, []bool{true}},
		{"FabricBlocked",
			[]destEval{dest(localDest, workerv1alpha1.Mode_MODE_LOCAL), dest(fabricDest, workerv1alpha1.Mode_MODE_FABRIC)},
			map[workerv1alpha1.Mode]module.State{workerv1alpha1.Mode_MODE_LOCAL: {key: {localDest: ready}},
				workerv1alpha1.Mode_MODE_FABRIC: {key: {fabricDest: ready}}},
			true, false, workerv1alpha1.ReasonRoutedLinkEgressUnavailable, []string{"", egress.Reason},
			[]bool{true, false}},
		{"FabricNotReadyKeepsItsReason", []destEval{dest(fabricDest, workerv1alpha1.Mode_MODE_FABRIC)},
			map[workerv1alpha1.Mode]module.State{workerv1alpha1.Mode_MODE_FABRIC: {key: {fabricDest: notReady}}},
			true, false, workerv1alpha1.ReasonRouteWithdrawn, []string{workerv1alpha1.ReasonRouteWithdrawn},
			[]bool{false}},
		{"FabricUnblocked", []destEval{dest(fabricDest, workerv1alpha1.Mode_MODE_FABRIC)},
			map[workerv1alpha1.Mode]module.State{workerv1alpha1.Mode_MODE_FABRIC: {key: {fabricDest: ready}}},
			false, true, workerv1alpha1.ReasonAsExpected, []string{""}, []bool{true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked := map[workerv1alpha1.Mode]map[module.ClaimKey]module.Blocked{}
			if tt.blocked {
				blocked[workerv1alpha1.Mode_MODE_FABRIC] = map[module.ClaimKey]module.Blocked{key: egress}
			}
			c := &claim{status: &workerv1alpha1.ClaimStatus{}}
			(&Worker{}).applyStatus(c, &claimEval{key: key, gen: 1, dests: tt.dests}, tt.state, blocked)
			rc := readyCondition(c.status)
			if rc == nil {
				t.Fatal("no Ready condition")
			}
			if got := rc.GetStatus() == condTrue; got != tt.wantReady || rc.GetReason() != tt.wantReason {
				t.Fatalf("Ready = %s %s, want ready %t reason %s", rc.GetStatus(), rc.GetReason(), tt.wantReady,
					tt.wantReason)
			}
			for i, ds := range c.status.GetDestinations() {
				if ds.GetReason() != tt.destReasons[i] || ds.GetForwardReady() != tt.destForward[i] {
					t.Errorf("destination %d = reason %q forward %t, want %q %t", i, ds.GetReason(),
						ds.GetForwardReady(), tt.destReasons[i], tt.destForward[i])
				}
			}
		})
	}
}
