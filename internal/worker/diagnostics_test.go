// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/diag"
	"go.datum.net/galactic/internal/worker/module"
)

// lookupClaim returns the claim k in s.
func lookupClaim(s diag.Snapshot, k module.ClaimKey) (diag.Scope, diag.Claim, bool) {
	for _, sc := range s.Scopes {
		for _, c := range sc.Claims {
			if c.Key == k.String() {
				return sc, c, true
			}
		}
	}
	return diag.Scope{}, diag.Claim{}, false
}

// findClaim returns the claim k in s, failing the test without it.
func findClaim(t *testing.T, s diag.Snapshot, k module.ClaimKey) (diag.Scope, diag.Claim) {
	t.Helper()
	sc, c, ok := lookupClaim(s, k)
	if !ok {
		t.Fatalf("claim %s not in the snapshot %+v", k, s)
	}
	return sc, c
}

// TestDiagnosticsNameEachFailure checks that the snapshot and gauges report a
// destination's locality, the scope's owner and generation, and the reason
// a destination is not ready, and that the reason clears on recovery.
func TestDiagnosticsNameEachFailure(t *testing.T) {
	e := newEnv(t)
	e.cfg.StatusFile = filepath.Join(t.TempDir(), "status.json")
	e.cfg.StatusInterval = 10 * time.Millisecond
	e.start()
	e.local.SetReady(func(module.ClaimKey, string) (bool, string) {
		return false, workerv1alpha1.ReasonHandoffHookMissing
	})
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1", "guest-a2")))
	e.waitObserved(k)

	s := e.w.Diagnostics()
	sc, c := findClaim(t, s, k)
	if sc.Fence.Owner != e.w.Owner() || sc.Fence.Generation == 0 {
		t.Fatalf("scope fence %+v, want this Worker as owner with a generation", sc.Fence)
	}
	if c.Owner != natSA || c.Generation != 1 || c.ObservedGeneration != 1 || c.Handoff != "veth_pair" {
		t.Fatalf("claim %+v", c)
	}
	got := map[string]diag.Destination{}
	for _, d := range c.Destinations {
		got[d.ID] = d
	}
	local, fabric := got["attachment/guest-a1"], got["attachment/guest-a2"]
	if local.Locality != localityLocal || local.Capability != workerv1alpha1.CapabilityLocalVethPair ||
		!local.Programmed || local.Ready || local.Reason != workerv1alpha1.ReasonHandoffHookMissing {
		t.Fatalf("Local destination %+v, want programmed, not ready, HandoffHookMissing", local)
	}
	if fabric.Locality != localityFabric || fabric.Capability != workerv1alpha1.CapabilityFabricSRv6 || !fabric.Ready {
		t.Fatalf("Fabric destination %+v, want ready over fabric.srv6", fabric)
	}
	if len(s.Capabilities) == 0 {
		t.Fatal("no capabilities in the snapshot")
	}

	updateDiagnosticGauges(s)
	if v := testutil.ToFloat64(localHooksGauge.WithLabelValues(hookMissing)); v != 1 {
		t.Fatalf("missing hooks = %v, want 1", v)
	}
	if v := testutil.ToFloat64(destinationsGauge.WithLabelValues(workerv1alpha1.CapabilityLocalVethPair, localityLocal,
		workerv1alpha1.ReasonHandoffHookMissing)); v != 1 {
		t.Fatalf("Local destinations with HandoffHookMissing = %v, want 1", v)
	}
	if v := testutil.ToFloat64(destinationsGauge.WithLabelValues(workerv1alpha1.CapabilityFabricSRv6, localityFabric,
		workerv1alpha1.ReasonAsExpected)); v != 1 {
		t.Fatalf("ready Fabric destinations = %v, want 1", v)
	}
	if v := testutil.ToFloat64(scopesGauge.WithLabelValues(scopeOwned)); v < 1 {
		t.Fatalf("owned scopes = %v", v)
	}

	// The snapshot file inspect reads carries the same reason.
	e.eventually("status snapshot written", func() bool {
		f, err := diag.Read(e.cfg.StatusFile)
		if err != nil {
			return false
		}
		_, fc, ok := lookupClaim(f, k)
		if !ok {
			return false
		}
		for _, d := range fc.Destinations {
			if d.Reason == workerv1alpha1.ReasonHandoffHookMissing {
				return true
			}
		}
		return false
	})
	var out bytes.Buffer
	if err := diag.Print(&out, s, s.Time); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"attachment/guest-a1", localityLocal, workerv1alpha1.ReasonHandoffHookMissing,
		e.w.Owner() + " (this Worker)"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("inspect output lacks %q:\n%s", want, out.String())
		}
	}

	e.local.SetReady(nil)
	e.w.Changed(vpcA)
	e.waitReady(k, 1)
	updateDiagnosticGauges(e.w.Diagnostics())
	if v := testutil.ToFloat64(localHooksGauge.WithLabelValues(hookMissing)); v != 0 {
		t.Fatalf("missing hooks after recovery = %v, want 0", v)
	}
	if v := testutil.ToFloat64(localHooksGauge.WithLabelValues(hookCovered)); v != 1 {
		t.Fatalf("covered hooks after recovery = %v, want 1", v)
	}
}

// TestDriftRepairIsReported checks that host state removed under Worker,
// such as a hook another process detached, is repaired and reported with
// the module and what differed, and that a claim change is not drift.
func TestDriftRepairIsReported(t *testing.T) {
	e := newEnv(t)
	e.start()
	k := mkey(vpcA, "svc-a")
	e.mustOK(e.request(natSA, key(vpcA, "svc-a"), 1, veth("guest-a1")))
	e.waitReady(k, 1)
	before := testutil.ToFloat64(driftRepairsTotal.WithLabelValues(localityLocal))

	// A new generation changes desired state: not drift.
	e.mustOK(e.update(natSA, key(vpcA, "svc-a"), 2, veth("guest-a1", "guest-a3")))
	e.waitReady(k, 2)
	if got := testutil.ToFloat64(driftRepairsTotal.WithLabelValues(localityLocal)); got != before {
		t.Fatalf("a claim update counted as drift: %v → %v", before, got)
	}

	e.host.Drop(localityLocal, vpcA, k, "attachment/guest-a3")
	e.w.Changed(vpcA)
	e.eventually("dropped row repaired", func() bool {
		return slices.Contains(rowIDs(e.host.Rows(vpcA)), "svc-a→attachment/guest-a3")
	})
	if got := testutil.ToFloat64(driftRepairsTotal.WithLabelValues(localityLocal)); got != before+1 {
		t.Fatalf("drift repairs %v, want %v", got, before+1)
	}
	var drift *diag.Drift
	for _, sc := range e.w.Diagnostics().Scopes {
		if sc.VPC == vpcA {
			drift = sc.LastDrift
		}
	}
	if drift == nil || drift.Module != localityLocal || drift.Detail != "rows differ" {
		t.Fatalf("last drift %+v", drift)
	}
}
