// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/serviceroute"
)

// orderedRouteProgrammer logs every Apply and Remove as "apply <device>" or
// "remove <device>", naming an intent by its first producer's device.
type orderedRouteProgrammer struct {
	retryRouteProgrammer
	log      []string
	applyErr error
}

func (p *orderedRouteProgrammer) Apply(intent serviceroute.RouteIntent) error {
	p.log = append(p.log, "apply "+intent.Producers[0].Device)
	return p.applyErr
}

func (p *orderedRouteProgrammer) Remove(intent serviceroute.RouteIntent) error {
	p.log = append(p.log, "remove "+intent.Producers[0].Device)
	return nil
}

const applyNew = "apply new"

func localSetTestIntent(device string, draining bool) serviceroute.RouteIntent {
	return serviceroute.RouteIntent{
		Attachment: types.NamespacedName{Namespace: testServiceRouteTenantNamespace, Name: testServiceRouteConsumerName},
		Kind:       serviceroute.RouteIntentLocalSet,
		Producers:  []serviceroute.ProducerTarget{{Device: device, Draining: draining}},
	}
}

// A LocalSet intent whose producer set changes is applied before the old one
// is removed, so the consumer's route never disappears.
func TestServiceRouteReplacePolicyAppliesChangedProducerSetFirst(t *testing.T) {
	programmer := &orderedRouteProgrammer{}
	reconciler := &ServiceRoutePolicyReconciler{Programmer: programmer}
	policy := types.NamespacedName{Namespace: testServiceRoutePolicyNamespace, Name: testServiceRouteName}

	if err := reconciler.replacePolicy(policy, []serviceroute.RouteIntent{localSetTestIntent("old", false)}); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.replacePolicy(policy, []serviceroute.RouteIntent{localSetTestIntent("new", true)}); err != nil {
		t.Fatal(err)
	}
	want := []string{"apply old", applyNew, "remove old"}
	if len(programmer.log) != len(want) {
		t.Fatalf("operations = %v, want %v", programmer.log, want)
	}
	for i := range want {
		if programmer.log[i] != want[i] {
			t.Fatalf("operations = %v, want %v", programmer.log, want)
		}
	}
	consumer := types.NamespacedName{Namespace: testServiceRouteTenantNamespace, Name: testServiceRouteConsumerName}
	if got := reconciler.Applied[policy][consumer].Producers[0].Device; got != "new" {
		t.Fatalf("applied intent producer = %s, want new", got)
	}
}

// When the new intent cannot coexist with the old one, the replacement falls
// back to removing the old intent first.
func TestServiceRouteReplacePolicyFallsBackWhenProducerSetsCannotCoexist(t *testing.T) {
	programmer := &orderedRouteProgrammer{}
	reconciler := &ServiceRoutePolicyReconciler{Programmer: programmer}
	policy := types.NamespacedName{Namespace: testServiceRoutePolicyNamespace, Name: testServiceRouteName}
	if err := reconciler.replacePolicy(policy, []serviceroute.RouteIntent{localSetTestIntent("old", false)}); err != nil {
		t.Fatal(err)
	}
	programmer.log = nil
	programmer.applyErr = errors.New("conflicting redirect targets")
	if err := reconciler.replacePolicy(policy, []serviceroute.RouteIntent{localSetTestIntent("new", false)}); err == nil {
		t.Fatal("replacePolicy succeeded with a failing Apply")
	}
	want := []string{applyNew, "remove old", applyNew}
	if len(programmer.log) != len(want) {
		t.Fatalf("operations = %v, want %v", programmer.log, want)
	}
	for i := range want {
		if programmer.log[i] != want[i] {
			t.Fatalf("operations = %v, want %v", programmer.log, want)
		}
	}
}

func TestProducerReportsOnlyRenewed(t *testing.T) {
	now := time.Now()
	renewedAt := func(ago time.Duration) *metav1.Time {
		at := metav1.NewTime(now.Add(-ago))
		return &at
	}
	endpoint := func(state networkv1alpha1.BackendHealthState, renewed *metav1.Time) *networkv1alpha1.ServiceEndpoint {
		return &networkv1alpha1.ServiceEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: producerHealthEndpoint, Namespace: producerHealthNamespace,
				ResourceVersion: "1"},
			Status: networkv1alpha1.ServiceEndpointStatus{Producers: []networkv1alpha1.ServiceEndpointProducerStatus{{
				Namespace: producerHealthNamespace, Name: "resolver-a", AttachmentUID: "uid-a",
				Node: producerHealthNode, Port: 8053,
				State: state, Reason: "ProbeSucceeded", RenewTime: renewed,
			}}},
		}
	}
	lifetime := networkv1alpha1.ServiceEndpointProducerReportLifetime
	for _, tc := range []struct {
		name     string
		old, new *networkv1alpha1.ServiceEndpoint
		want     bool
	}{
		{"current report renewed", endpoint(networkv1alpha1.BackendHealthHealthy, renewedAt(20*time.Second)),
			endpoint(networkv1alpha1.BackendHealthHealthy, renewedAt(0)), true},
		{"expired report renewed", endpoint(networkv1alpha1.BackendHealthHealthy, renewedAt(lifetime+time.Second)),
			endpoint(networkv1alpha1.BackendHealthHealthy, renewedAt(0)), false},
		{"renewTime dropped", endpoint(networkv1alpha1.BackendHealthHealthy, renewedAt(20*time.Second)),
			endpoint(networkv1alpha1.BackendHealthHealthy, nil), false},
		{"decision changed", endpoint(networkv1alpha1.BackendHealthHealthy, renewedAt(20*time.Second)),
			endpoint(networkv1alpha1.BackendHealthUnhealthy, renewedAt(0)), false},
	} {
		if got := producerReportsOnlyRenewed(tc.old, tc.new, now); got != tc.want {
			t.Errorf("%s: producerReportsOnlyRenewed = %v, want %v", tc.name, got, tc.want)
		}
	}
	added := endpoint(networkv1alpha1.BackendHealthHealthy, renewedAt(0))
	added.Status.Producers = append(added.Status.Producers, added.Status.Producers[0])
	added.Status.Producers[1].Name = "resolver-b"
	if producerReportsOnlyRenewed(endpoint(networkv1alpha1.BackendHealthHealthy, renewedAt(time.Second)), added, now) {
		t.Error("producerReportsOnlyRenewed accepted an added producer")
	}
}
