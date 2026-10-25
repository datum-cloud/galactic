// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

func TestServiceEndpointSpreadAdmission(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for isolated API admission tests")
	}
	apiRoot := os.Getenv("GALACTIC_TEST_NETWORK_API")
	if apiRoot == "" {
		apiRoot = "../../.."
	}
	data, err := os.ReadFile(filepath.Join(apiRoot, "config", "crd", "galactic.datumapis.com_serviceendpoints.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	crd := &apiextensionsv1.CustomResourceDefinition{}
	if err := yaml.Unmarshal(data, crd); err != nil {
		t.Fatal(err)
	}
	environment := &envtest.Environment{CRDs: []*apiextensionsv1.CustomResourceDefinition{crd}}
	cfg, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Errorf("stop API: %v", err)
		}
	})
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networkv1alpha1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const namespace = "spread-admission"
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
		t.Fatal(err)
	}
	endpoint := func(name string) *networkv1alpha1.ServiceEndpoint {
		return &networkv1alpha1.ServiceEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: networkv1alpha1.ServiceEndpointSpec{
				ServiceClass: "dns", Address: "fd53::53", Port: 53,
				Protocol:           networkv1alpha1.NetworkServiceProtocolUDP,
				DeliveryMode:       networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal,
				AttachmentSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "dns"}},
				Distribution:       networkv1alpha1.ServiceEndpointDistributionSpread,
				HealthCheck:        &networkv1alpha1.ServiceEndpointHealthCheck{Port: 8053},
			},
		}
	}
	for _, tt := range []struct {
		name      string
		mutate    func(*networkv1alpha1.ServiceEndpoint)
		wantError bool
	}{
		{"spread", func(*networkv1alpha1.ServiceEndpoint) {}, false},
		{"single-default", func(e *networkv1alpha1.ServiceEndpoint) {
			e.Spec.Distribution, e.Spec.HealthCheck = "", nil
		}, false},
		{"single", func(e *networkv1alpha1.ServiceEndpoint) {
			e.Spec.Distribution, e.Spec.HealthCheck = networkv1alpha1.ServiceEndpointDistributionSingle, nil
		}, false},
		{"spread-without-health-check", func(e *networkv1alpha1.ServiceEndpoint) { e.Spec.HealthCheck = nil }, true},
		{"single-with-health-check", func(e *networkv1alpha1.ServiceEndpoint) {
			e.Spec.Distribution = networkv1alpha1.ServiceEndpointDistributionSingle
		}, true},
		{"udp-without-health-check-port", func(e *networkv1alpha1.ServiceEndpoint) {
			e.Spec.HealthCheck.Port = 0
		}, true},
		{"tcp-without-health-check-port", func(e *networkv1alpha1.ServiceEndpoint) {
			e.Spec.Protocol = networkv1alpha1.NetworkServiceProtocolTCP
			e.Spec.HealthCheck.Port = 0
		}, false},
		{"unknown-distribution", func(e *networkv1alpha1.ServiceEndpoint) { e.Spec.Distribution = "RoundRobin" }, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := endpoint(tt.name)
			tt.mutate(e)
			err := c.Create(ctx, e)
			if (err != nil) != tt.wantError {
				t.Fatalf("create error=%v", err)
			}
			if tt.wantError && !apierrors.IsInvalid(err) {
				t.Fatalf("expected schema rejection, got %v", err)
			}
		})
	}

	// Each node applies only its own producers' entries; one node's apply
	// neither replaces nor removes another node's.
	shared := endpoint("shared")
	if err := c.Create(ctx, shared); err != nil {
		t.Fatal(err)
	}
	entry := func(name, node string) networkv1alpha1.ServiceEndpointProducerStatus {
		return networkv1alpha1.ServiceEndpointProducerStatus{
			Namespace: namespace, Name: name, AttachmentUID: types.UID(name + "-uid"), Node: node, Port: 8053,
			State: networkv1alpha1.BackendHealthHealthy, Reason: "ProbeSucceeded",
			LastTransitionTime: metav1.Now(),
		}
	}
	apply := func(node string, entries ...networkv1alpha1.ServiceEndpointProducerStatus) {
		t.Helper()
		if entries == nil {
			entries = []networkv1alpha1.ServiceEndpointProducerStatus{}
		}
		body, err := json.Marshal(map[string]any{
			"apiVersion": networkv1alpha1.GroupVersion.String(), "kind": "ServiceEndpoint",
			"metadata": map[string]string{"name": shared.Name, "namespace": namespace},
			"status":   map[string]any{"producers": entries},
		})
		if err != nil {
			t.Fatal(err)
		}
		obj := &networkv1alpha1.ServiceEndpoint{}
		obj.Name, obj.Namespace = shared.Name, namespace
		if err := c.Status().Patch(ctx, obj, client.RawPatch(types.ApplyPatchType, body),
			client.FieldOwner("galactic-router/"+node), client.ForceOwnership); err != nil {
			t.Fatal(err)
		}
	}
	names := func() []string {
		t.Helper()
		got := &networkv1alpha1.ServiceEndpoint{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(shared), got); err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(got.Status.Producers))
		for _, p := range got.Status.Producers {
			out = append(out, p.Name+"@"+p.Node)
		}
		return out
	}
	apply("node-a", entry("a1", "node-a"), entry("a2", "node-a"))
	apply("node-b", entry("b1", "node-b"))
	if got := names(); len(got) != 3 {
		t.Fatalf("producers after both nodes applied = %v, want a1, a2 and b1", got)
	}
	apply("node-a", entry("a2", "node-a"))
	if got := names(); len(got) != 2 || got[0] != "a2@node-a" || got[1] != "b1@node-b" {
		t.Fatalf("producers after node-a dropped a1 = %v, want a2@node-a and b1@node-b", got)
	}
	apply("node-b")
	if got := names(); len(got) != 1 || got[0] != "a2@node-a" {
		t.Fatalf("producers after node-b dropped its entries = %v, want a2@node-a", got)
	}
}
