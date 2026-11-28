// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

const (
	exactlyOneBackendSourceMsg = "exactly one of backendSelector and edgeListenerRef is required"
	emptySelectorMsg           = "backendSelector must not be empty"
)

// TestNetworkServiceBackendSource covers the rule that a service takes its
// backends from exactly one of backendSelector and edgeListenerRef, and that a
// backendSelector that is set must still not be empty.
func TestNetworkServiceBackendSource(t *testing.T) {
	c, _ := startProtocolAPI(t)
	ctx := context.Background()
	listener := &networkv1alpha1.NetworkServiceEdgeListenerReference{Name: "masque-public"}

	for _, tc := range []struct {
		name   string
		mutate func(*networkv1alpha1.NetworkService)
		want   string // empty when the service is admitted
	}{
		{"Selector", func(*networkv1alpha1.NetworkService) {}, ""},
		{"EdgeListener", func(s *networkv1alpha1.NetworkService) {
			s.Spec.BackendSelector = metav1.LabelSelector{}
			s.Spec.EdgeListenerRef = listener
		}, ""},
		{"Both", func(s *networkv1alpha1.NetworkService) { s.Spec.EdgeListenerRef = listener }, exactlyOneBackendSourceMsg},
		{"Neither", func(s *networkv1alpha1.NetworkService) {
			s.Spec.BackendSelector = metav1.LabelSelector{}
		}, exactlyOneBackendSourceMsg},
		{"EmptyListenerName", func(s *networkv1alpha1.NetworkService) {
			s.Spec.BackendSelector = metav1.LabelSelector{}
			s.Spec.EdgeListenerRef = &networkv1alpha1.NetworkServiceEdgeListenerReference{}
		}, "spec.edgeListenerRef.name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := protocolService("source-"+strings.ToLower(tc.name), networkv1alpha1.NetworkServiceProtocolTCP, 443, 8443)
			tc.mutate(svc)
			err := c.Create(ctx, svc)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Create: %v", err)
				}
				return
			}
			requireRefusal(t, err, []string{tc.want}, nil)
		})
	}

	// A selector written as {} is present but empty, and keeps its own
	// refusal rather than counting as absent.
	t.Run("ExplicitEmptySelector", func(t *testing.T) {
		svc := protocolService("source-explicit-empty", networkv1alpha1.NetworkServiceProtocolTCP, 443, 8443)
		obj := unstructuredService(t, svc)
		if err := unstructured.SetNestedMap(obj.Object, map[string]any{}, "spec", "backendSelector"); err != nil {
			t.Fatal(err)
		}
		requireRefusal(t, c.Create(ctx, obj), []string{emptySelectorMsg}, nil)
	})
}

// TestNetworkServiceOmitsEmptySelector checks that a service written from Go
// without a selector encodes no backendSelector, which the exactly-one rule
// depends on.
func TestNetworkServiceOmitsEmptySelector(t *testing.T) {
	svc := protocolService("encode", networkv1alpha1.NetworkServiceProtocolTCP, 443, 8443)
	svc.Spec.BackendSelector = metav1.LabelSelector{}
	svc.Spec.EdgeListenerRef = &networkv1alpha1.NetworkServiceEdgeListenerReference{Name: "masque-public"}
	data, err := json.Marshal(svc.Spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "backendSelector") {
		t.Errorf("spec = %s, want no backendSelector", data)
	}
}
