// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// TestNetworkServiceHealthCheckAdmission covers healthCheck against a real API
// server: an empty one takes every default, a udp service must name a port,
// and the timeout may not exceed the interval.
func TestNetworkServiceHealthCheckAdmission(t *testing.T) {
	c, _ := startProtocolAPI(t)
	ctx := context.Background()

	svc := protocolService("hc-defaults", networkv1alpha1.NetworkServiceProtocolTCP, 443, 8443)
	svc.Spec.HealthCheck = &networkv1alpha1.NetworkServiceHealthCheck{}
	if err := c.Create(ctx, svc); err != nil {
		t.Fatalf("create tcp service with an empty healthCheck: %v", err)
	}
	got := &networkv1alpha1.NetworkService{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(svc), got); err != nil {
		t.Fatal(err)
	}
	want := networkv1alpha1.NetworkServiceHealthCheck{
		IntervalSeconds: 5, TimeoutSeconds: 2, UnhealthyThreshold: 3, HealthyThreshold: 3,
	}
	if got.Spec.HealthCheck == nil || *got.Spec.HealthCheck != want {
		t.Errorf("healthCheck = %+v, want the defaults %+v", got.Spec.HealthCheck, want)
	}

	udp := protocolService("hc-udp-no-port", networkv1alpha1.NetworkServiceProtocolUDP, 53, 53)
	udp.Spec.HealthCheck = &networkv1alpha1.NetworkServiceHealthCheck{}
	requireRefusal(t, c.Create(ctx, udp), []string{"healthCheck.port is required for udp"}, nil)

	udp = protocolService("hc-udp-port", networkv1alpha1.NetworkServiceProtocolUDP, 53, 53)
	udp.Spec.HealthCheck = &networkv1alpha1.NetworkServiceHealthCheck{Port: 8080}
	if err := c.Create(ctx, udp); err != nil {
		t.Fatalf("create udp service with a health check port: %v", err)
	}

	slow := protocolService("hc-timeout", networkv1alpha1.NetworkServiceProtocolTCP, 443, 8443)
	slow.Spec.HealthCheck = &networkv1alpha1.NetworkServiceHealthCheck{IntervalSeconds: 2, TimeoutSeconds: 3}
	requireRefusal(t, c.Create(ctx, slow), []string{"timeoutSeconds must not exceed intervalSeconds"}, nil)
}

// TestServiceVIPBindingHealthStatus: status.health round-trips through the
// status subresource, a state outside the enum is refused, and clearing it
// leaves the rest of the status alone.
func TestServiceVIPBindingHealthStatus(t *testing.T) {
	c, _ := startProtocolAPI(t)
	ctx := context.Background()

	binding := &networkv1alpha1.ServiceVIPBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "health", Namespace: protocolNamespace},
		Spec: networkv1alpha1.ServiceVIPBindingSpec{
			TargetRef:      networkv1alpha1.TargetRef{Kind: "Node", Name: "node-1"},
			VPCRef:         "vpc-a",
			VIPAddress:     "2001:db8:1::10",
			Port:           443,
			Protocol:       networkv1alpha1.NetworkServiceProtocolTCP,
			BackendAddress: "fd20::100",
			BackendPort:    8443,
			EgressKind:     networkv1alpha1.ServiceVIPBindingEgressKindVeth,
		},
	}
	if err := c.Create(ctx, binding); err != nil {
		t.Fatal(err)
	}

	health := &networkv1alpha1.ServiceVIPBindingHealth{
		State: networkv1alpha1.BackendHealthUnhealthy, Reason: "ProbeFailed", Message: "connection refused",
		AttachmentUID: "uid-1", Port: 8443, LastTransitionTime: metav1.NewTime(time.Unix(1_700_000_000, 0)),
	}
	binding.Status.Conditions = []metav1.Condition{{
		Type: networkv1alpha1.ConditionTypeBound, Status: metav1.ConditionTrue, Reason: "Bound",
		LastTransitionTime: metav1.Now(),
	}}
	binding.Status.Health = health
	if err := c.Status().Update(ctx, binding); err != nil {
		t.Fatalf("update status with health: %v", err)
	}
	got := &networkv1alpha1.ServiceVIPBinding{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(binding), got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Health == nil || got.Status.Health.State != health.State ||
		got.Status.Health.AttachmentUID != health.AttachmentUID || !got.Status.Health.LastTransitionTime.Equal(&health.LastTransitionTime) {
		t.Errorf("status.health = %+v, want %+v", got.Status.Health, health)
	}

	bad := got.DeepCopy()
	bad.Status.Health.State = "Degraded"
	requireRefusal(t, c.Status().Update(ctx, bad), []string{"status.health.state"}, nil)

	base := got.DeepCopy()
	got.Status.Health = nil
	if err := c.Status().Patch(ctx, got, client.MergeFrom(base)); err != nil {
		t.Fatalf("clear status.health: %v", err)
	}
	cleared := &networkv1alpha1.ServiceVIPBinding{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(binding), cleared); err != nil {
		t.Fatal(err)
	}
	if cleared.Status.Health != nil || len(cleared.Status.Conditions) != 1 {
		t.Errorf("status = %+v, want health cleared and Bound kept", cleared.Status)
	}
}
