// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/model"
)

// These tests guard issue #614: applyVRFs logged and skipped a VRF whose kernel
// table failed to resolve, returned nil, and reported nothing, so the VRF
// looked healthy in status and was never retried once the controller's config
// hash settled.

const testVRFName = "35-edge-node"

var testVRFRuntimeKey = types.NamespacedName{Namespace: "vrf-status", Name: "r1"}

// stubVRFKernel replaces the kernel-facing VRF steps for the duration of t.
// resolve and probe are consulted in order, one entry per call, the last entry
// repeating.
func stubVRFKernel(t *testing.T, resolve []error, probe []error) {
	t.Helper()
	origResolve, origProbe := resolveVRFTable, probeVRFDatapath
	t.Cleanup(func() { resolveVRFTable, probeVRFDatapath = origResolve, origProbe })

	next := func(errs []error, i *int) error {
		if len(errs) == 0 {
			return nil
		}
		err := errs[min(*i, len(errs)-1)]
		*i++
		return err
	}
	var ri, pi int
	resolveVRFTable = func(string) (uint32, error) {
		if err := next(resolve, &ri); err != nil {
			return 0, err
		}
		return 7, nil
	}
	probeVRFDatapath = func(uint32) error { return next(probe, &pi) }
}

func newTestVRFRuntime(t *testing.T) *GoBGPRuntime {
	t.Helper()
	rt, err := NewRuntimeFactory(-1, false, "", nil)(testVRFRuntimeKey)
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}
	return rt.(*GoBGPRuntime)
}

func testVRFs() []model.DesiredVRFInstance {
	return []model.DesiredVRFInstance{{
		Name:               testVRFName,
		VRFID:              7,
		ImportRouteTargets: []string{testRT100},
		ExportRouteTargets: []string{testRT100},
	}}
}

// TestApplyVRFsRetriesUntilResolved verifies a VRF whose first attempts fail is
// reported as not applied, stays out of appliedVRFs so the next apply retries
// it, and moves to Applied once the kernel side resolves.
func TestApplyVRFsRetriesUntilResolved(t *testing.T) {
	notInNetns := fmt.Errorf("VRF %q: %w", testVRFName, errVRFNotInThisNetns)
	stubVRFKernel(t, []error{errors.New("netlink: permission denied"), notInNetns, nil}, nil)

	r := newTestVRFRuntime(t)
	b := newTestBgpServer(t)
	ctx := context.Background()

	steps := []struct {
		wantState  model.VRFState
		wantReason string
	}{
		{model.VRFStateFailed, model.VRFReasonKernelVRFUnresolved},
		{model.VRFStateNotInNetns, model.VRFReasonNotInRouterNetns},
		{model.VRFStateApplied, ""},
	}
	for i, step := range steps {
		if err := r.applyVRFs(ctx, b, testVRFs(), testRouterID1); err != nil {
			t.Fatalf("apply %d: applyVRFs() error = %v, want nil so other VRFs still converge", i, err)
		}
		got := r.vrfStatus[testVRFName]
		if got.State != step.wantState || got.Reason != step.wantReason {
			t.Errorf("apply %d: VRF status = %s/%q, want %s/%q", i, got.State, got.Reason, step.wantState, step.wantReason)
		}
		_, applied := r.appliedVRFs[testVRFName]
		if wantApplied := step.wantState == model.VRFStateApplied; applied != wantApplied {
			t.Errorf("apply %d: VRF in appliedVRFs = %v, want %v", i, applied, wantApplied)
		}
	}
}

// TestApplyVRFsReportsProbeFailure verifies a VRF whose datapath write probe
// fails is reported Failed with its own reason, and retried.
func TestApplyVRFsReportsProbeFailure(t *testing.T) {
	stubVRFKernel(t, nil, []error{errors.New("open pinned egress_route_table: no such file"), nil})

	r := newTestVRFRuntime(t)
	b := newTestBgpServer(t)
	ctx := context.Background()

	if err := r.applyVRFs(ctx, b, testVRFs(), testRouterID1); err != nil {
		t.Fatalf("applyVRFs() error = %v", err)
	}
	got := r.vrfStatus[testVRFName]
	if got.State != model.VRFStateFailed || got.Reason != model.VRFReasonDatapathProbeFailed {
		t.Errorf("VRF status = %s/%q, want %s/%s",
			got.State, got.Reason, model.VRFStateFailed, model.VRFReasonDatapathProbeFailed)
	}

	if err := r.applyVRFs(ctx, b, testVRFs(), testRouterID1); err != nil {
		t.Fatalf("retry applyVRFs() error = %v", err)
	}
	if got := r.vrfStatus[testVRFName]; got.State != model.VRFStateApplied {
		t.Errorf("VRF status after retry = %s, want %s", got.State, model.VRFStateApplied)
	}
}

// TestApplyVRFsDropsStatusOfRemovedVRF verifies a VRF leaving desired state
// stops being reported.
func TestApplyVRFsDropsStatusOfRemovedVRF(t *testing.T) {
	stubVRFKernel(t, []error{errors.New("boom")}, nil)

	r := newTestVRFRuntime(t)
	b := newTestBgpServer(t)
	ctx := context.Background()

	if err := r.applyVRFs(ctx, b, testVRFs(), testRouterID1); err != nil {
		t.Fatalf("applyVRFs() error = %v", err)
	}
	if err := r.applyVRFs(ctx, b, nil, testRouterID1); err != nil {
		t.Fatalf("applyVRFs(nil) error = %v", err)
	}
	if _, ok := r.vrfStatus[testVRFName]; ok {
		t.Errorf("status for removed VRF %s still reported", testVRFName)
	}
}
