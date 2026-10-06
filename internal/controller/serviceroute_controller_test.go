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

type retryRouteProgrammer struct {
	applyCalls  int
	removeCalls int
	failApply   int
	failRemove  int
}

func (p *retryRouteProgrammer) Apply(serviceroute.RouteIntent) error {
	p.applyCalls++
	if p.applyCalls == p.failApply {
		return errors.New("apply failed")
	}
	return nil
}

func (p *retryRouteProgrammer) Remove(serviceroute.RouteIntent) error {
	p.removeCalls++
	if p.removeCalls == p.failRemove {
		return errors.New("remove failed")
	}
	return nil
}

func TestServiceRouteReplacePolicyResumesPartialApply(t *testing.T) {
	programmer := &retryRouteProgrammer{failApply: 2}
	reconciler := &ServiceRoutePolicyReconciler{Programmer: programmer}
	policy := types.NamespacedName{Namespace: "platform", Name: "dns"}
	intents := []serviceroute.RouteIntent{
		{Attachment: types.NamespacedName{Namespace: "tenant", Name: "a"}},
		{Attachment: types.NamespacedName{Namespace: "tenant", Name: "b"}},
	}

	if err := reconciler.replacePolicy(policy, intents); err == nil {
		t.Fatal("first replacePolicy succeeded, want injected failure")
	}
	if got := len(reconciler.Applied[policy]); got != 1 {
		t.Fatalf("tracked intents after partial apply = %d, want 1", got)
	}
	programmer.failApply = 0
	if err := reconciler.replacePolicy(policy, intents); err != nil {
		t.Fatalf("retry replacePolicy: %v", err)
	}
	if programmer.applyCalls != 3 {
		t.Fatalf("Apply calls = %d, want 3 (successful intent was not replayed)", programmer.applyCalls)
	}
	if got := len(reconciler.Applied[policy]); got != 2 {
		t.Fatalf("tracked intents after retry = %d, want 2", got)
	}
}

func TestServiceRouteRemovePolicyResumesPartialRemove(t *testing.T) {
	programmer := &retryRouteProgrammer{failRemove: 2}
	policy := types.NamespacedName{Namespace: "platform", Name: "dns"}
	reconciler := &ServiceRoutePolicyReconciler{
		Programmer: programmer,
		Applied: map[types.NamespacedName]map[types.NamespacedName]serviceroute.RouteIntent{
			policy: {
				{Namespace: "tenant", Name: "a"}: {Attachment: types.NamespacedName{Namespace: "tenant", Name: "a"}},
				{Namespace: "tenant", Name: "b"}: {Attachment: types.NamespacedName{Namespace: "tenant", Name: "b"}},
			},
		},
	}

	if err := reconciler.removePolicy(policy); err == nil {
		t.Fatal("first removePolicy succeeded, want injected failure")
	}
	if got := len(reconciler.Applied[policy]); got != 1 {
		t.Fatalf("tracked intents after partial remove = %d, want 1", got)
	}
	programmer.failRemove = 0
	if err := reconciler.removePolicy(policy); err != nil {
		t.Fatalf("retry removePolicy: %v", err)
	}
	if programmer.removeCalls != 3 {
		t.Fatalf("Remove calls = %d, want 3 (successful removal was not replayed)", programmer.removeCalls)
	}
	if _, ok := reconciler.Applied[policy]; ok {
		t.Fatal("policy remains tracked after successful retry")
	}
}
