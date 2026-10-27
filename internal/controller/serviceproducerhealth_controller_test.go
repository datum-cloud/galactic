// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/healthprobe"
)

const (
	producerHealthEndpoint  = "resolver"
	producerHealthLabel     = "role"
	producerHealthAddress   = "fd53::53"
	producerHealthRefused   = "connection refused"
	producerHealthNamespace = "dns"
	producerHealthNode      = "node-a"
	producerHealthOtherNode = "node-b"
	producerHealthClass     = "dns"
)

// ownerProber returns a decision per probe owner, Unknown/Pending for any
// owner without one, and records the calls.
type ownerProber struct {
	decisions map[string]healthprobe.Decision
	owners    map[string]string
	targets   map[string]healthprobe.Target
	seeds     map[string]*healthprobe.Decision
}

func newOwnerProber() *ownerProber {
	return &ownerProber{
		decisions: map[string]healthprobe.Decision{}, owners: map[string]string{},
		targets: map[string]healthprobe.Target{}, seeds: map[string]*healthprobe.Decision{},
	}
}

func (p *ownerProber) Ensure(owner, id string, t healthprobe.Target, seed *healthprobe.Decision) healthprobe.Decision {
	p.owners[owner], p.targets[owner], p.seeds[owner] = id, t, seed
	if d, ok := p.decisions[owner]; ok {
		return d
	}
	return healthprobe.Decision{State: healthprobe.StateUnknown, Reason: healthprobe.ReasonPending,
		Since: time.Unix(1_700_000_000, 0)}
}

func (p *ownerProber) Release(owner string) { delete(p.owners, owner) }

func startProducerHealthAPI(t *testing.T) client.Client {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("KUBEBUILDER_ASSETS not set in CI")
		}
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	environment := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = environment.Stop() })
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	_ = cloudv1alpha1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: producerHealthNamespace},
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

func createProducer(t *testing.T, c client.Client, name, node, address string) *cloudv1alpha1.VPCAttachment {
	t.Helper()
	ctx := context.Background()
	attachment := &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: producerHealthNamespace,
			Labels: map[string]string{producerHealthLabel: producerHealthEndpoint}},
		Spec: cloudv1alpha1.VPCAttachmentSpec{
			VPC: cloudv1alpha1.VPCRef{Name: "vpc"},
			Interface: cloudv1alpha1.VPCAttachmentInterface{
				Name: "net1", Addresses: []cloudv1alpha1.IPAddress{cloudv1alpha1.IPAddress(address)},
			},
		},
	}
	if err := c.Create(ctx, attachment); err != nil {
		t.Fatal(err)
	}
	attachment.Status = cloudv1alpha1.VPCAttachmentStatus{
		ObservedGeneration: attachment.Generation, Node: node, VPC: "vpc1", VPCAttachment: "att" + name,
		HostInterface: "host-" + name,
		Conditions: []metav1.Condition{
			{Type: cloudv1alpha1.ConditionTypeReady, Status: metav1.ConditionTrue, Reason: "Fixture",
				LastTransitionTime: metav1.Now()},
			{Type: cloudv1alpha1.ConditionTypeProgrammed, Status: metav1.ConditionTrue, Reason: "Fixture",
				LastTransitionTime: metav1.Now()},
		},
	}
	if err := c.Status().Update(ctx, attachment); err != nil {
		t.Fatal(err)
	}
	return attachment
}

func producerEntries(t *testing.T, c client.Client) map[string]networkv1alpha1.ServiceEndpointProducerStatus {
	t.Helper()
	endpoint := &networkv1alpha1.ServiceEndpoint{}
	key := types.NamespacedName{Namespace: producerHealthNamespace, Name: producerHealthEndpoint}
	if err := c.Get(context.Background(), key,
		endpoint); err != nil {
		t.Fatal(err)
	}
	out := map[string]networkv1alpha1.ServiceEndpointProducerStatus{}
	for _, entry := range endpoint.Status.Producers {
		out[entry.Name] = entry
	}
	return out
}

func TestServiceProducerHealthReconcilerPublishesThisNodesProducers(t *testing.T) {
	c := startProducerHealthAPI(t)
	ctx := context.Background()
	endpoint := &networkv1alpha1.ServiceEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: producerHealthEndpoint, Namespace: producerHealthNamespace},
		Spec: networkv1alpha1.ServiceEndpointSpec{
			ServiceClass: producerHealthClass, Address: producerHealthAddress, Port: 53,
			Protocol:     networkv1alpha1.NetworkServiceProtocolUDP,
			DeliveryMode: networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal,
			AttachmentSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{producerHealthLabel: producerHealthEndpoint},
			},
			Distribution: networkv1alpha1.ServiceEndpointDistributionSpread,
			HealthCheck: &networkv1alpha1.ServiceEndpointHealthCheck{
				Port: 8053, IntervalSeconds: 2, TimeoutSeconds: 1, UnhealthyThreshold: 2, HealthyThreshold: 1,
			},
		},
	}
	if err := c.Create(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	first := createProducer(t, c, "resolver-a", producerHealthNode, "fd00:1::a/64")
	second := createProducer(t, c, "resolver-b", producerHealthNode, "fd00:1::b/64")
	other := createProducer(t, c, "resolver-c", producerHealthOtherNode, "fd00:1::c/64")

	key := types.NamespacedName{Namespace: producerHealthNamespace, Name: producerHealthEndpoint}
	firstOwner := producerProbeOwner(key, client.ObjectKeyFromObject(first))
	secondOwner := producerProbeOwner(key, client.ObjectKeyFromObject(second))
	since := time.Unix(1_700_000_100, 0)
	prober := newOwnerProber()
	prober.decisions[firstOwner] = healthprobe.Decision{State: healthprobe.StateHealthy,
		Reason: healthprobe.ReasonProbeSucceeded, Since: since}
	prober.decisions[secondOwner] = healthprobe.Decision{State: healthprobe.StateUnhealthy,
		Reason: healthprobe.ReasonProbeFailed, Message: producerHealthRefused, Since: since}
	reconcilerA := &ServiceProducerHealthReconciler{Client: c, NodeName: producerHealthNode, Prober: prober}
	reconcilerB := &ServiceProducerHealthReconciler{Client: c, NodeName: producerHealthOtherNode,
		Prober: newOwnerProber()}
	reconcile := func(r *ServiceProducerHealthReconciler) {
		t.Helper()
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("Reconcile on %s: %v", r.NodeName, err)
		}
	}

	reconcile(reconcilerB)
	reconcile(reconcilerA)
	entries := producerEntries(t, c)
	if len(entries) != 3 {
		t.Fatalf("status.producers = %v, want resolver-a, resolver-b and resolver-c", entries)
	}
	if got := entries["resolver-a"]; got.State != networkv1alpha1.BackendHealthHealthy ||
		got.Node != producerHealthNode || got.AttachmentUID != first.UID || got.Port != 8053 ||
		!got.LastTransitionTime.Time.Equal(since) {
		t.Errorf("resolver-a = %+v, want Healthy on %s for its UID and port 8053", got, producerHealthNode)
	}
	if got := entries["resolver-b"]; got.State != networkv1alpha1.BackendHealthUnhealthy ||
		got.Message != producerHealthRefused {
		t.Errorf("resolver-b = %+v, want Unhealthy with the probe error", got)
	}
	if got := entries["resolver-c"]; got.Node != producerHealthOtherNode ||
		got.State != networkv1alpha1.BackendHealthUnknown {
		t.Errorf("resolver-c = %+v, want Unknown from %s", got, producerHealthOtherNode)
	}
	target := prober.targets[firstOwner]
	if target.Interface != "host-resolver-a" || target.Addr.String() != "fd00:1::a" || target.Port != 8053 ||
		target.Config != (healthprobe.Config{Interval: 2 * time.Second, Timeout: time.Second,
			UnhealthyThreshold: 2, HealthyThreshold: 1}) {
		t.Errorf("resolver-a target = %+v", target)
	}
	if _, probed := prober.owners[producerProbeOwner(key, client.ObjectKeyFromObject(other))]; probed {
		t.Error("node-a probes a producer on node-b")
	}

	// A restarted router starts each probe from its published decision.
	restarted := newOwnerProber()
	reconcile(&ServiceProducerHealthReconciler{Client: c, NodeName: producerHealthNode, Prober: restarted})
	if seed := restarted.seeds[secondOwner]; seed == nil || seed.State != healthprobe.StateUnhealthy {
		t.Errorf("seed for resolver-b = %+v, want its published Unhealthy decision", seed)
	}

	// A producer that stops being selected loses its probe and its entry;
	// the other node's entry stays.
	second.Labels = map[string]string{producerHealthLabel: "retired"}
	if err := c.Update(ctx, second); err != nil {
		t.Fatal(err)
	}
	reconcile(reconcilerA)
	entries = producerEntries(t, c)
	if _, ok := entries["resolver-b"]; ok || len(entries) != 2 {
		t.Errorf("status.producers after deselecting resolver-b = %v, want resolver-a and resolver-c", entries)
	}
	if _, probed := prober.owners[secondOwner]; probed {
		t.Error("deselected producer is still probed")
	}

	// Turning Spread off removes this node's entries and stops its probes.
	if err := c.Get(ctx, key, endpoint); err != nil {
		t.Fatal(err)
	}
	endpoint.Spec.Distribution, endpoint.Spec.HealthCheck = networkv1alpha1.ServiceEndpointDistributionSingle, nil
	if err := c.Update(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	reconcile(reconcilerA)
	entries = producerEntries(t, c)
	if _, ok := entries["resolver-a"]; ok || len(entries) != 1 {
		t.Errorf("status.producers after Single = %v, want only node-b's resolver-c", entries)
	}
	if len(prober.owners) != 0 {
		t.Errorf("probes after Single = %v, want none", prober.owners)
	}
}

func TestServiceProducerHealthReconcilerRenewsReports(t *testing.T) {
	c := startProducerHealthAPI(t)
	ctx := context.Background()
	endpoint := &networkv1alpha1.ServiceEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: producerHealthEndpoint, Namespace: producerHealthNamespace},
		Spec: networkv1alpha1.ServiceEndpointSpec{
			ServiceClass: producerHealthClass, Address: producerHealthAddress, Port: 53,
			Protocol:     networkv1alpha1.NetworkServiceProtocolUDP,
			DeliveryMode: networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal,
			AttachmentSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{producerHealthLabel: producerHealthEndpoint},
			},
			Distribution: networkv1alpha1.ServiceEndpointDistributionSpread,
			HealthCheck:  &networkv1alpha1.ServiceEndpointHealthCheck{Port: 8053},
		},
	}
	if err := c.Create(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	createProducer(t, c, "resolver-a", producerHealthNode, "fd00:1::a/64")
	key := client.ObjectKeyFromObject(endpoint)
	r := &ServiceProducerHealthReconciler{Client: c, NodeName: producerHealthNode, Prober: newOwnerProber()}
	interval := networkv1alpha1.ServiceEndpointProducerReportRenewInterval

	result, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatal(err)
	}
	first := producerEntries(t, c)["resolver-a"]
	if first.RenewTime == nil || time.Since(first.RenewTime.Time) > time.Minute {
		t.Fatalf("resolver-a renewTime = %v, want now", first.RenewTime)
	}
	if result.RequeueAfter != interval {
		t.Fatalf("RequeueAfter after publishing = %v, want %v", result.RequeueAfter, interval)
	}

	// An unchanged decision within the renew interval is not rewritten.
	if err := c.Get(ctx, key, endpoint); err != nil {
		t.Fatal(err)
	}
	version := endpoint.ResourceVersion
	result, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, key, endpoint); err != nil {
		t.Fatal(err)
	}
	if endpoint.ResourceVersion != version {
		t.Fatal("an unchanged decision was rewritten within the renew interval")
	}
	if result.RequeueAfter <= 0 || result.RequeueAfter > interval {
		t.Fatalf("RequeueAfter before renewal is due = %v, want within %v", result.RequeueAfter, interval)
	}

	// Once the interval passes, the same decision is renewed.
	later := first.RenewTime.Add(interval)
	entries := []networkv1alpha1.ServiceEndpointProducerStatus{first}
	entries[0].RenewTime = nil
	if _, err := r.publish(ctx, endpoint, entries, later); err != nil {
		t.Fatal(err)
	}
	if got := producerEntries(t, c)["resolver-a"]; got.RenewTime == nil || !got.RenewTime.Time.Equal(later) ||
		got.State != first.State || !got.LastTransitionTime.Equal(&first.LastTransitionTime) {
		t.Fatalf("resolver-a after renewal = %+v, want the same decision renewed at %v", got, later)
	}
}
