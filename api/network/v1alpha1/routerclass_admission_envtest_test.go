// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// startRouterClassAPI starts an API server holding the generated BGPRouter
// and BGPRouterClass CRDs and returns a client and a namespace for routers.
func startRouterClassAPI(t *testing.T) (client.Client, string) {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS for isolated API admission tests")
	}
	crds := make([]*apiextensionsv1.CustomResourceDefinition, 0, 2)
	for _, name := range []string{"bgprouters", "bgprouterclasses"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "crd", "galactic.datumapis.com_"+name+".yaml"))
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
	const ns = "routers"
	if err := c.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil {
		t.Fatal(err)
	}
	return c, ns
}

func admissionRouter(name, ns string, class *string, plane *networkv1alpha1.BGPRoutingPlane) *networkv1alpha1.BGPRouter {
	return &networkv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: networkv1alpha1.BGPRouterSpec{
			RouterClassName: class,
			Plane:           plane,
			TargetRef:       networkv1alpha1.TargetRef{Kind: "Node", Name: "node-a"},
			LocalASN:        65000,
			RouterID:        "10.0.0.1",
			AddressFamilies: []networkv1alpha1.AddressFamily{
				{AFI: networkv1alpha1.AFIIPv6, SAFI: networkv1alpha1.SAFIUnicast},
			},
		},
	}
}

// TestBGPRouterClassAdmission checks the ownership fields on a real API
// server: an Underlay router must name a class, and neither the class nor
// the plane can be added, changed or removed once the router exists.
func TestBGPRouterClassAdmission(t *testing.T) {
	c, ns := startRouterClassAPI(t)
	ctx := context.Background()
	underlay := ptr.To(networkv1alpha1.BGPRoutingPlaneUnderlay)
	overlay := ptr.To(networkv1alpha1.BGPRoutingPlaneOverlay)

	t.Run("create", func(t *testing.T) {
		for i, tc := range []struct {
			name  string
			class *string
			plane *networkv1alpha1.BGPRoutingPlane
			admit bool
		}{
			{"legacy router", nil, nil, true},
			{"overlay without class", nil, overlay, true},
			{"underlay with class", ptr.To("fabric-frr"), underlay, true},
			{"class without plane", ptr.To("fabric-frr"), nil, true},
			{"overlay with class", ptr.To("fabric-frr"), overlay, true},
			{"underlay without class", nil, underlay, false},
			{"empty class", ptr.To(""), nil, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				err := c.Create(ctx, admissionRouter(fmt.Sprintf("create-%d", i), ns, tc.class, tc.plane))
				if tc.admit && err != nil {
					t.Fatalf("refused: %v", err)
				}
				if !tc.admit && err == nil {
					t.Fatal("admitted an invalid router")
				}
			})
		}
	})

	t.Run("update", func(t *testing.T) {
		for i, tc := range []struct {
			name         string
			class, next  *string
			plane, nextP *networkv1alpha1.BGPRoutingPlane
			admit        bool
		}{
			{"unchanged ownership", ptr.To("fabric-frr"), ptr.To("fabric-frr"), underlay, underlay, true},
			{"unchanged legacy router", nil, nil, nil, nil, true},
			{"unchanged overlay plane", nil, nil, overlay, overlay, true},
			{"add class", nil, ptr.To("fabric-frr"), nil, nil, false},
			{"change class", ptr.To("fabric-frr"), ptr.To("other"), underlay, underlay, false},
			{"remove class", ptr.To("fabric-frr"), nil, nil, nil, false},
			{"add plane", nil, nil, nil, overlay, false},
			{"change plane", ptr.To("fabric-frr"), ptr.To("fabric-frr"), underlay, overlay, false},
			{"remove plane", ptr.To("fabric-frr"), ptr.To("fabric-frr"), underlay, nil, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				router := admissionRouter(fmt.Sprintf("update-%d", i), ns, tc.class, tc.plane)
				if err := c.Create(ctx, router); err != nil {
					t.Fatal(err)
				}
				router.Spec.RouterClassName = tc.next
				router.Spec.Plane = tc.nextP
				router.Spec.LocalASN = 65001
				err := c.Update(ctx, router)
				if tc.admit && err != nil {
					t.Fatalf("refused: %v", err)
				}
				if !tc.admit && err == nil {
					t.Fatal("admitted an ownership change")
				}
			})
		}
	})

	t.Run("class", func(t *testing.T) {
		class := &networkv1alpha1.BGPRouterClass{
			ObjectMeta: metav1.ObjectMeta{Name: "fabric-frr"},
			Spec:       networkv1alpha1.BGPRouterClassSpec{ControllerName: networkv1alpha1.FabricRouterControllerName},
		}
		if err := c.Create(ctx, class); err != nil {
			t.Fatalf("refused the fabric router class: %v", err)
		}
		class.Spec.ControllerName = "example.com/other"
		if err := c.Update(ctx, class); err == nil {
			t.Error("admitted a controllerName change")
		}
		for i, name := range []string{"fabric-router", "Example.com/x", "example.com/", "/fabric-router"} {
			bad := &networkv1alpha1.BGPRouterClass{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("invalid-%d", i)},
				Spec:       networkv1alpha1.BGPRouterClassSpec{ControllerName: name},
			}
			if err := c.Create(ctx, bad); err == nil {
				t.Errorf("admitted controllerName %q", name)
			}
		}

		withParams := &networkv1alpha1.BGPRouterClass{
			ObjectMeta: metav1.ObjectMeta{Name: "with-params"},
			Spec: networkv1alpha1.BGPRouterClassSpec{
				ControllerName: networkv1alpha1.FabricRouterControllerName,
				ParametersRef: &networkv1alpha1.BGPRouterClassParametersRef{
					Group: "galactic.datumapis.com", Kind: "FRRRouterParameters", Name: "v1",
				},
			},
		}
		if err := c.Create(ctx, withParams); err != nil {
			t.Fatalf("refused a class with parameters: %v", err)
		}
		withParams.Spec.ParametersRef.Name = "v2"
		if err := c.Update(ctx, withParams); err == nil {
			t.Error("admitted a parametersRef change")
		}
	})
}
