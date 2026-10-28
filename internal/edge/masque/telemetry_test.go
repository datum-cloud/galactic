// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package masque

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/connectip"
	edgeroute "go.datum.net/galactic/internal/edge/route"
)

func admissions(outcome string) float64 {
	return testutil.ToFloat64(admissionsTotal.WithLabelValues(outcome))
}

func ends(reason string) float64 { return testutil.ToFloat64(requestEnds.WithLabelValues(reason)) }

func claims(outcome string) float64 { return testutil.ToFloat64(routeClaims.WithLabelValues(outcome)) }

// scrape returns the collector's request counts by state and its lease
// gauge.
func scrape(t *testing.T) (map[string]float64, float64) {
	t.Helper()
	ch := make(chan prometheus.Metric, 8)
	go func() { collector{}.Collect(ch); close(ch) }()
	states, held := map[string]float64{}, -1.0
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatal(err)
		}
		if len(pb.GetLabel()) == 0 {
			held = pb.GetGauge().GetValue()
			continue
		}
		states[pb.GetLabel()[0].GetValue()] = pb.GetGauge().GetValue()
	}
	return states, held
}

// TestTelemetryAdmissionOutcomes counts each refusal under its own outcome:
// a client denial, a provider denial and a route core refuses stay apart.
func TestTelemetryAdmissionOutcomes(t *testing.T) {
	refuseRoute := func(rt *galacticv1alpha1.EdgeRoute) {
		meta.SetStatusCondition(&rt.Status.Conditions, metav1.Condition{Type: galacticv1alpha1.EdgeRouteClaimed,
			Status: metav1.ConditionFalse, Reason: edgeroute.ReasonPrefixConflict, Message: "held by another grant"})
	}
	for _, tc := range []struct {
		name, credential, vpc, outcome string
		setup                          func(h *harness)
		wantErr                        error
		claimOutcome                   string
	}{
		{name: "admitted", credential: credA1, outcome: admitAdmitted, claimOutcome: claimAccepted},
		{name: "unauthenticated", credential: "nope", outcome: admitUnauthenticated,
			wantErr: connectip.ErrUnauthenticated},
		{name: "forbidden", credential: credA1, vpc: "other-vpc", outcome: admitForbidden,
			wantErr: connectip.ErrForbidden},
		{name: "authorizer failed", credential: credA1, outcome: admitAuthorizerFailed, setup: func(h *harness) {
			h.authorize = func(context.Context) error { return errors.New("authority unreachable") }
		}},
		{name: "no instance lease", credential: credA1, outcome: admitNoLease, wantErr: ErrUnavailable,
			setup: func(h *harness) { h.a.setLease(nil) }},
		{name: "attachment refused", credential: credA1, outcome: admitAttachmentFailed, wantErr: ErrUnavailable,
			setup: func(h *harness) {
				h.setCore(func(att *galacticv1alpha1.EdgeAttachment) {
					meta.SetStatusCondition(&att.Status.Conditions, metav1.Condition{
						Type: galacticv1alpha1.EdgeAttachmentAdmitted, Status: metav1.ConditionFalse,
						Reason: "ServiceNotGranted", Message: "refused by core"})
				}, h.accepted)
			}},
		{name: "route refused", credential: credA1, outcome: admitRouteRefused, wantErr: ErrUnavailable,
			claimOutcome: claimRefused, setup: func(h *harness) { h.setCore(h.programmed, refuseRoute) }},
		{name: "route not accepted", credential: credA1, outcome: admitRouteFailed, wantErr: ErrUnavailable,
			claimOutcome: claimFailed, setup: func(h *harness) { h.setCore(h.programmed, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.start()
			h.a.cfg.Prepare = 200 * time.Millisecond
			if tc.setup != nil {
				tc.setup(h)
			}
			vpc := tc.vpc
			if vpc == "" {
				vpc = testVPCName
			}
			before := admissions(tc.outcome)
			var claimBefore float64
			if tc.claimOutcome != "" {
				claimBefore = claims(tc.claimOutcome)
			}
			l, err := h.a.Admit(context.Background(), tc.credential, vpc)
			if l != nil {
				defer func() { _ = l.Close() }()
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Admit error = %v, want %v", err, tc.wantErr)
			}
			if got := admissions(tc.outcome) - before; got != 1 {
				t.Fatalf("%s admissions rose by %v, want 1 (err %v)", tc.outcome, got, err)
			}
			if tc.claimOutcome != "" {
				if got := claims(tc.claimOutcome) - claimBefore; got != 1 {
					t.Fatalf("%s route claims rose by %v, want 1", tc.claimOutcome, got)
				}
			}
		})
	}
}

// TestTelemetryRequestStates follows a request from admitted through
// forwarding, and checks that a grant past its deadline is programmed but
// not forwarding.
func TestTelemetryRequestStates(t *testing.T) {
	h := newHarness(t)
	h.start()
	if _, held := scrape(t); held != 1 {
		t.Fatalf("lease_held = %v, want 1", held)
	}
	base, _ := scrape(t)
	l := h.admit(credA1)
	defer func() { _ = l.Close() }()
	states, _ := scrape(t)
	if got := states[stateProgrammed] - base[stateProgrammed]; got != 1 {
		t.Fatalf("programmed requests rose by %v before the packet path opened, want 1", got)
	}
	s, err := h.a.Open(context.Background(), l.Info())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	states, _ = scrape(t)
	if got := states[stateForwarding] - base[stateForwarding]; got != 1 {
		t.Fatalf("forwarding requests rose by %v, want 1", got)
	}

	// Past the grant's deadline the request no longer forwards, even before
	// its timer ends it.
	h.mu.Lock()
	h.now = h.now.Add(2 * time.Hour)
	h.mu.Unlock()
	states, _ = scrape(t)
	if got := states[stateForwarding] - base[stateForwarding]; got != 0 {
		t.Fatalf("forwarding requests rose by %v after the grant expired, want 0", got)
	}
	if got := states[stateProgrammed] - base[stateProgrammed]; got != 1 {
		t.Fatalf("programmed requests rose by %v after the grant expired, want 1", got)
	}
}

// TestTelemetryRequestEnds counts each way an admitted request stops under
// its own reason.
func TestTelemetryRequestEnds(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		// setup runs before admission, stop after it.
		setup func(h *harness)
		stop  func(h *harness)
	}{
		{name: endGrantExpired, reason: endGrantExpired, setup: func(h *harness) {
			// The first refresh shortens the deadline; later ones fail
			// without changing it, so it passes.
			h.a.cfg.Refresh = 10 * time.Millisecond
			var refreshed atomic.Bool
			h.refresh = func(g Grant) (Grant, error) {
				if refreshed.Swap(true) {
					return Grant{}, errors.New("authority unreachable")
				}
				g.NotAfter = h.wall().Add(100 * time.Millisecond)
				return g, nil
			}
		}},
		{name: endGrantRevoked, reason: endGrantRevoked, setup: func(h *harness) {
			h.a.cfg.Refresh = 10 * time.Millisecond
			h.refresh = func(Grant) (Grant, error) { return Grant{}, connectip.ErrForbidden }
		}},
		{name: endRevoked, reason: endRevoked, stop: func(h *harness) { h.a.Revoke("a1") }},
		{name: endLeaseLost, reason: endLeaseLost, stop: func(h *harness) {
			before := testutil.ToFloat64(leaseLosses)
			h.a.loseLease(errors.New("test"))
			if got := testutil.ToFloat64(leaseLosses) - before; got != 1 {
				h.t.Fatalf("lease losses rose by %v, want 1", got)
			}
			if _, held := scrape(h.t); held != 0 {
				h.t.Fatalf("lease_held = %v after the lease was lost, want 0", held)
			}
		}},
		{name: endRouteRevoked, reason: endRouteRevoked, stop: func(h *harness) {
			before := claims(claimRevoked)
			h.setCore(nil, nil)
			rt := h.route(credA1)
			meta.SetStatusCondition(&rt.Status.Conditions, metav1.Condition{Type: galacticv1alpha1.EdgeRouteAccepted,
				Status: metav1.ConditionFalse, Reason: "Revoked"})
			if err := h.c.Status().Update(context.Background(), rt); err != nil {
				h.t.Fatal(err)
			}
			h.a.check(context.Background())
			if got := claims(claimRevoked) - before; got != 1 {
				h.t.Fatalf("revoked route claims rose by %v, want 1", got)
			}
		}},
		{name: endAttachmentDraining, reason: endAttachmentDraining, stop: func(h *harness) {
			h.setCore(nil, nil)
			att := h.attachment(svcA)
			meta.SetStatusCondition(&att.Status.Conditions, metav1.Condition{
				Type: galacticv1alpha1.EdgeAttachmentDraining, Status: metav1.ConditionTrue, Reason: "Maintenance"})
			if err := h.c.Status().Update(context.Background(), att); err != nil {
				h.t.Fatal(err)
			}
			h.a.check(context.Background())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.start()
			if tc.setup != nil {
				tc.setup(h)
			}
			before := ends(tc.reason)
			l := h.admit(credA1)
			defer func() { _ = l.Close() }()
			if tc.stop != nil {
				tc.stop(h)
			}
			expectDone(t, l, tc.name)
			if got := ends(tc.reason) - before; got != 1 {
				t.Fatalf("%s request ends rose by %v, want 1", tc.reason, got)
			}
		})
	}
}

// TestEndReasonsAreConstants fails when the adapter ends a request with a
// string literal, which endReasons cannot map and would count as other.
func TestEndReasonsAreConstants(t *testing.T) {
	literal := regexp.MustCompile(`(?:\.end\(|deactivate\([a-z]+, |closeAttachment\([a-z]+, |reason = )"([^"]+)"`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range literal.FindAllSubmatch(src, -1) {
			t.Errorf("%s ends requests with the literal %q; add a reason constant to endReasons", f, m[1])
		}
	}
	for reason, label := range endReasons {
		if label == endOther || label == "" {
			t.Errorf("reason %q maps to %q", reason, label)
		}
	}
}

// TestTelemetryLabelsAreBounded fails when an adapter metric gains a label
// that could carry a connector, principal, VPC, prefix, service or
// attachment.
func TestTelemetryLabelsAreBounded(t *testing.T) {
	allowed := []string{"outcome", "reason", labelState}
	admissionsTotal.WithLabelValues(admitAdmitted)
	requestEnds.WithLabelValues(endClosed)
	routeClaims.WithLabelValues(claimAccepted)
	for name, c := range map[string]prometheus.Collector{
		"admissions": admissionsTotal, "ends": requestEnds, "claims": routeClaims, "drops": deviceDrops,
		"losses": leaseLosses, "collector": collector{},
	} {
		ch := make(chan prometheus.Metric, 64)
		go func() { c.Collect(ch); close(ch) }()
		n := 0
		for m := range ch {
			n++
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Fatal(err)
			}
			for _, l := range pb.GetLabel() {
				if !slices.Contains(allowed, l.GetName()) {
					t.Errorf("%s has label %q, want only %v", name, l.GetName(), allowed)
				}
			}
		}
		if n == 0 {
			t.Errorf("%s exported no series", name)
		}
	}
}
