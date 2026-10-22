// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/healthprobe"
)

// fakeProber returns decision from every Ensure and records the calls.
type fakeProber struct {
	decision healthprobe.Decision
	owners   map[string]string // owner -> id
	targets  map[string]healthprobe.Target
	seeds    map[string]*healthprobe.Decision
}

func newFakeProber(d healthprobe.Decision) *fakeProber {
	return &fakeProber{
		decision: d,
		owners:   map[string]string{},
		targets:  map[string]healthprobe.Target{},
		seeds:    map[string]*healthprobe.Decision{},
	}
}

func (f *fakeProber) Ensure(owner, id string, t healthprobe.Target, seed *healthprobe.Decision) healthprobe.Decision {
	f.owners[owner] = id
	f.targets[owner] = t
	f.seeds[owner] = seed
	return f.decision
}

func (f *fakeProber) Release(owner string) { delete(f.owners, owner) }

const testHealthUID = types.UID("attachment-uid-1")

// newHealthFixture returns a rule with a health check, its backend attachment
// on testComputeNodeName, and the binding the node writes for it.
func newHealthFixture(t *testing.T) (*bgpv1alpha1.NetworkService, client.Object, *bgpv1alpha1.ServiceVIPBinding) {
	t.Helper()
	rule := newBindingTestRule()
	rule.Spec.HealthCheck = &bgpv1alpha1.NetworkServiceHealthCheck{
		IntervalSeconds: 5, TimeoutSeconds: 2, UnhealthyThreshold: 3, HealthyThreshold: 3,
	}
	attachment := newBackendAttachment(testVPCRef)
	attachment.UID = testHealthUID
	attachment.Status.HostInterface = "G0000000100aH"

	writer, c := newBindingWriter(t, rule, attachment)
	reconcileBindings(t, writer)
	bindings := listBindings(t, c)
	if len(bindings) != 1 {
		t.Fatalf("bindings = %d, want 1", len(bindings))
	}
	return rule, attachment, &bindings[0]
}

func newHealthReconciler(
	t *testing.T, prober BackendProber, objs ...client.Object,
) (*BackendHealthReconciler, client.Client) {
	t.Helper()
	_, c := newBindingWriter(t, objs...)
	return &BackendHealthReconciler{Client: c, NodeName: testComputeNodeName, Prober: prober}, c
}

func reconcileHealth(t *testing.T, r *BackendHealthReconciler, binding *bgpv1alpha1.ServiceVIPBinding) {
	t.Helper()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(binding)}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

func getHealth(
	t *testing.T, c client.Client, binding *bgpv1alpha1.ServiceVIPBinding,
) *bgpv1alpha1.ServiceVIPBindingHealth {
	t.Helper()
	got := &bgpv1alpha1.ServiceVIPBinding{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(binding), got); err != nil {
		t.Fatalf("get binding: %v", err)
	}
	return got.Status.Health
}

// TestBackendHealthReconciler_PublishesDecision: the backend is probed over its
// host-side interface on backendPort, and the decision lands in status.health
// with the attachment and port it describes.
func TestBackendHealthReconciler_PublishesDecision(t *testing.T) {
	rule, attachment, binding := newHealthFixture(t)
	since := time.Unix(1_700_000_000, 0)
	prober := newFakeProber(healthprobe.Decision{
		State: healthprobe.StateUnhealthy, Reason: healthprobe.ReasonProbeFailed, Message: "connection refused",
		Since: since,
	})
	r, c := newHealthReconciler(t, prober, rule, attachment, binding)

	reconcileHealth(t, r, binding)

	target := prober.targets[client.ObjectKeyFromObject(binding).String()]
	if target.Interface != "G0000000100aH" || target.Addr.String() != testBackendAddr || target.Port != testBackendPort {
		t.Errorf("target = %+v, want %s port %d over G0000000100aH", target, testBackendAddr, testBackendPort)
	}
	if target.Config != (healthprobe.Config{
		Interval: 5 * time.Second, Timeout: 2 * time.Second, UnhealthyThreshold: 3, HealthyThreshold: 3,
	}) {
		t.Errorf("config = %+v", target.Config)
	}
	want := &bgpv1alpha1.ServiceVIPBindingHealth{
		State: bgpv1alpha1.BackendHealthUnhealthy, Reason: healthprobe.ReasonProbeFailed,
		Message: "connection refused", AttachmentUID: testHealthUID, Port: testBackendPort,
		LastTransitionTime: metav1.NewTime(since),
	}
	if got := getHealth(t, c, binding); !healthEqual(got, want) {
		t.Errorf("status.health = %+v, want %+v", got, want)
	}
}

// TestBackendHealthReconciler_HealthCheckPort: healthCheck.port replaces
// backendPort as the probed port.
func TestBackendHealthReconciler_HealthCheckPort(t *testing.T) {
	rule, attachment, binding := newHealthFixture(t)
	rule.Spec.HealthCheck.Port = 9000
	prober := newFakeProber(healthprobe.Decision{State: healthprobe.StateUnknown, Reason: healthprobe.ReasonPending})
	r, c := newHealthReconciler(t, prober, rule, attachment, binding)

	reconcileHealth(t, r, binding)

	if got := prober.targets[client.ObjectKeyFromObject(binding).String()].Port; got != 9000 {
		t.Errorf("probed port = %d, want 9000", got)
	}
	if got := getHealth(t, c, binding); got == nil || got.Port != 9000 {
		t.Errorf("status.health = %+v, want port 9000", got)
	}
}

// TestBackendHealthReconciler_SeedsFromPublishedDecision: a restarted router
// carries on from the published decision for the same attachment and port,
// and starts over for another attachment holding the address.
func TestBackendHealthReconciler_SeedsFromPublishedDecision(t *testing.T) {
	rule, attachment, binding := newHealthFixture(t)
	published := &bgpv1alpha1.ServiceVIPBindingHealth{
		State: bgpv1alpha1.BackendHealthUnhealthy, Reason: healthprobe.ReasonProbeFailed,
		AttachmentUID: testHealthUID, Port: testBackendPort, LastTransitionTime: metav1.NewTime(time.Unix(100, 0)),
	}
	binding.Status.Health = published
	owner := client.ObjectKeyFromObject(binding).String()

	prober := newFakeProber(healthprobe.Decision{State: healthprobe.StateUnhealthy, Reason: healthprobe.ReasonProbeFailed})
	r, _ := newHealthReconciler(t, prober, rule, attachment, binding)
	reconcileHealth(t, r, binding)
	if seed := prober.seeds[owner]; seed == nil || seed.State != healthprobe.StateUnhealthy {
		t.Errorf("seed = %+v, want the published Unhealthy decision", seed)
	}

	published.AttachmentUID = "an-earlier-attachment"
	prober = newFakeProber(healthprobe.Decision{State: healthprobe.StateUnknown, Reason: healthprobe.ReasonPending})
	r, c := newHealthReconciler(t, prober, rule, attachment, binding)
	reconcileHealth(t, r, binding)
	if seed := prober.seeds[owner]; seed != nil {
		t.Errorf("seed = %+v, want none for a decision about another attachment", seed)
	}
	if got := getHealth(t, c, binding); got == nil || got.AttachmentUID != testHealthUID ||
		got.State != bgpv1alpha1.BackendHealthUnknown {
		t.Errorf("status.health = %+v, want Unknown for %s", got, testHealthUID)
	}
}

// TestBackendHealthReconciler_NoHealthCheckClears: a rule without a
// healthCheck releases the probe and clears status.health.
func TestBackendHealthReconciler_NoHealthCheckClears(t *testing.T) {
	rule, attachment, binding := newHealthFixture(t)
	rule.Spec.HealthCheck = nil
	binding.Status.Health = &bgpv1alpha1.ServiceVIPBindingHealth{
		State: bgpv1alpha1.BackendHealthHealthy, Reason: healthprobe.ReasonProbeSucceeded,
		AttachmentUID: testHealthUID, Port: testBackendPort,
	}
	prober := newFakeProber(healthprobe.Decision{})
	owner := client.ObjectKeyFromObject(binding).String()
	prober.owners[owner] = "old"
	r, c := newHealthReconciler(t, prober, rule, attachment, binding)

	reconcileHealth(t, r, binding)

	if _, ok := prober.owners[owner]; ok {
		t.Error("probe still held for a rule without a healthCheck")
	}
	if got := getHealth(t, c, binding); got != nil {
		t.Errorf("status.health = %+v, want cleared", got)
	}
}

// TestBackendHealthReconciler_IgnoresOtherNodesBindings: a binding written for
// another node is never probed from this one.
func TestBackendHealthReconciler_IgnoresOtherNodesBindings(t *testing.T) {
	rule, attachment, binding := newHealthFixture(t)
	prober := newFakeProber(healthprobe.Decision{State: healthprobe.StateHealthy})
	r, c := newHealthReconciler(t, prober, rule, attachment, binding)
	r.NodeName = "another-node"

	reconcileHealth(t, r, binding)

	if len(prober.owners) != 0 {
		t.Errorf("probes = %v, want none", prober.owners)
	}
	if got := getHealth(t, c, binding); got != nil {
		t.Errorf("status.health = %+v, want unset", got)
	}
}

// TestBackendHealthReconciler_PreservesBound: publishing health leaves the Bound
// condition ServiceVIPBindingReconciler wrote untouched.
func TestBackendHealthReconciler_PreservesBound(t *testing.T) {
	rule, attachment, binding := newHealthFixture(t)
	prober := newFakeProber(healthprobe.Decision{
		State: healthprobe.StateHealthy, Reason: healthprobe.ReasonProbeSucceeded,
	})
	r, c := newHealthReconciler(t, prober, rule, attachment, binding)
	markBindingBound(t, c, *binding)

	reconcileHealth(t, r, binding)

	got := &bgpv1alpha1.ServiceVIPBinding{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(binding), got); err != nil {
		t.Fatalf("get binding: %v", err)
	}
	if bindingUnboundReason(got) != "" {
		t.Errorf("Bound lost after publishing health: %+v", got.Status.Conditions)
	}
	if got.Status.Health == nil || got.Status.Health.State != bgpv1alpha1.BackendHealthHealthy {
		t.Errorf("status.health = %+v, want Healthy", got.Status.Health)
	}
}
