// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

const ownershipNamespace = "galactic-system"

func overlayRouter(name, node string) *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ownershipNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Kind: testTargetRefKind, Name: node},
			SRv6Locator: "2001:db8:ff01::/48",
			NodeID:      7,
		},
	}
}

func underlayRouter(name, node string) *bgpv1alpha1.BGPRouter {
	r := overlayRouter(name, node)
	r.Spec.RouterClassName = ptr("fabric-frr")
	r.Spec.Plane = ptr(bgpv1alpha1.BGPRoutingPlaneUnderlay)
	// A different locator, so picking the wrong router is visible.
	r.Spec.SRv6Locator = "2001:db8:ee01::/48"
	return r
}

func ownershipScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

// routerOrders returns the overlay and underlay routers for node in both
// list orders, with names that sort either way.
func routerOrders(node string) map[string][]client.Object {
	return map[string][]client.Object{
		"underlay sorts and lists first": {underlayRouter("aa-fabric", node), overlayRouter("zz-galactic", node)},
		"overlay sorts and lists first":  {overlayRouter("aa-galactic", node), underlayRouter("zz-fabric", node)},
	}
}

// TestRouterNameForNodeIgnoresFabricRouters: with a fabric router and a
// Galactic router on the same node, in either name or list order, gateway and
// NAT advertisements attach to the Galactic router.
func TestRouterNameForNodeIgnoresFabricRouters(t *testing.T) {
	for name, objs := range routerOrders("node-a") {
		t.Run(name, func(t *testing.T) {
			c := newIndexedClientBuilder(ownershipScheme(t)).WithObjects(objs...).Build()
			got, err := routerNameForNode(context.Background(), c, ownershipNamespace, "node-a")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(got, "-galactic") {
				t.Errorf("routerNameForNode = %q, want the Galactic router", got)
			}
		})
	}
}

// TestRouterNameForNodeOnlyFabric: a node with only a fabric router has no
// Galactic router yet.
func TestRouterNameForNodeOnlyFabric(t *testing.T) {
	c := newIndexedClientBuilder(ownershipScheme(t)).WithObjects(underlayRouter("fabric", "node-a")).Build()
	got, err := routerNameForNode(context.Background(), c, ownershipNamespace, "node-a")
	if err != nil || got != "" {
		t.Errorf("routerNameForNode = %q, %v; want no router", got, err)
	}
}

// TestRouterNameForNodeAmbiguous: two Galactic routers on one node are an
// error, not an arbitrary pick.
func TestRouterNameForNodeAmbiguous(t *testing.T) {
	c := newIndexedClientBuilder(ownershipScheme(t)).
		WithObjects(overlayRouter("one", "node-a"), overlayRouter("two", "node-a")).Build()
	got, err := routerNameForNode(context.Background(), c, ownershipNamespace, "node-a")
	if !errors.Is(err, errAmbiguousRouter) {
		t.Errorf("routerNameForNode = %q, %v; want an ambiguity error", got, err)
	}
}

// TestBackendSIDIndexExcludesFabricRouters: the gateway's backend index never
// holds a fabric router, so no backend or VIP binding resolves through one.
func TestBackendSIDIndexExcludesFabricRouters(t *testing.T) {
	for name, objs := range routerOrders("node-a") {
		t.Run(name, func(t *testing.T) {
			c := newIndexedClientBuilder(ownershipScheme(t)).WithObjects(objs...).Build()
			idx, err := buildBackendSIDIndex(context.Background(), c, ownershipNamespace)
			if err != nil {
				t.Fatal(err)
			}
			if len(idx.routers) != 1 {
				t.Fatalf("index holds %d routers, want only the Galactic one", len(idx.routers))
			}
			for routerName := range idx.routers {
				if !strings.HasSuffix(routerName, "-galactic") {
					t.Errorf("index holds %q, want only the Galactic router", routerName)
				}
			}
		})
	}
}

// TestResolveVIPBindingVRFAmbiguous: two Galactic routers on a node no longer
// resolve to whichever the map iteration happened to return.
func TestResolveVIPBindingVRFAmbiguous(t *testing.T) {
	c := newIndexedClientBuilder(ownershipScheme(t)).
		WithObjects(overlayRouter("one", "node-a"), overlayRouter("two", "node-a")).Build()
	idx, err := buildBackendSIDIndex(context.Background(), c, ownershipNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolveVIPBindingVRF(idx, "node-a", "vpc1"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("resolveVIPBindingVRF error = %v, want an ambiguity error", err)
	}
}
