// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"errors"
	"testing"

	"k8s.io/apimachinery/pkg/types"

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
