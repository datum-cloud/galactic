// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

func TestTranslatedAPIAdmission(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for isolated API admission tests")
	}
	apiRoot := os.Getenv("GALACTIC_TEST_NETWORK_API")
	if apiRoot == "" {
		apiRoot = "../.."
	}
	crds := make([]*apiextensionsv1.CustomResourceDefinition, 0, 2)
	for _, name := range []string{
		"galactic.datumapis.com_serviceendpoints.yaml",
		"galactic.datumapis.com_serviceroutepolicies.yaml",
	} {
		data, err := os.ReadFile(filepath.Join(apiRoot, "config", "crd", name))
		if err != nil {
			t.Fatal(err)
		}
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.Unmarshal(data, crd); err != nil {
			t.Fatal(err)
		}
		crds = append(crds, crd)
	}
	environment := &envtest.Environment{CRDs: crds}
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
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "psc-admission"}}); err != nil {
		t.Fatal(err)
	}
	policy := func(name string) *networkv1alpha1.ServiceRoutePolicy {
		return &networkv1alpha1.ServiceRoutePolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "psc-admission"},
			Spec: networkv1alpha1.ServiceRoutePolicySpec{
				ServiceRef:         networkv1alpha1.ServiceEndpointReference{Name: "dns"},
				AttachmentSelector: metav1.LabelSelector{MatchLabels: map[string]string{"access": "dns"}},
				Frontend:           &networkv1alpha1.ServiceRouteFrontend{Address: "fd53::53"},
				ConsumerVPCRef:     &networkv1alpha1.ServiceRouteVPCReference{Name: "vpc", UID: "vpc-uid"},
				Authorization: &networkv1alpha1.ServiceRouteAuthorization{
					ValidUntil: metav1.NewTime(time.Now().Add(time.Minute)),
				},
			},
		}
	}
	for _, tt := range []struct {
		name      string
		mutate    func(*networkv1alpha1.ServiceRoutePolicy)
		wantError bool
	}{
		{"missing-pin", func(p *networkv1alpha1.ServiceRoutePolicy) { p.Spec.ConsumerVPCRef = nil }, true},
		{"empty-uid", func(p *networkv1alpha1.ServiceRoutePolicy) { p.Spec.ConsumerVPCRef.UID = "" }, true},
		{"missing-authorization", func(p *networkv1alpha1.ServiceRoutePolicy) { p.Spec.Authorization = nil }, true},
		{"legacy-direct", func(p *networkv1alpha1.ServiceRoutePolicy) {
			p.Spec.Frontend = nil
			p.Spec.ConsumerVPCRef = nil
			p.Spec.Authorization = nil
		}, false},
		{"translated", func(*networkv1alpha1.ServiceRoutePolicy) {}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := policy(tt.name)
			tt.mutate(p)
			err := c.Create(ctx, p)
			if (err != nil) != tt.wantError {
				t.Fatalf("create error=%v", err)
			}
			if tt.wantError && !apierrors.IsInvalid(err) {
				t.Fatalf("expected schema rejection, got %v", err)
			}
		})
	}
	// A real API preserves competing node reports and prevents stale resource-
	// version writes from replacing a newer authorization generation.
	p := policy("fenced")
	if err := c.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	old := p.DeepCopy()
	p.Spec.Authorization.ValidUntil = metav1.NewTime(time.Now().Add(90 * time.Second))
	if err := c.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	old.Status.Nodes = []networkv1alpha1.ServiceRouteNodeStatus{{
		NodeName: "node-a", PolicyUID: string(old.UID), ObservedGeneration: old.Generation,
		InputDigest: "old", Ready: true, ValidUntil: metav1.NewTime(time.Now().Add(time.Minute)),
	}}
	if err := c.Status().Update(ctx, old); !apierrors.IsConflict(err) {
		t.Fatalf("stale status write error=%v", err)
	}
}
