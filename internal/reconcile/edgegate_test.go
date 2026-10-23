// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
)

// gateSet opens the advertisements it names.
type gateSet map[string]bool

func (g gateSet) Open(adv *bgpv1alpha1.BGPAdvertisement) bool { return g[adv.Name] }

// TestBuildDesiredRouter_EdgeGate: a Galactic Edge route's advertisement is
// in the desired router only while its gate is open on the node, and never
// without a gate to check; every other advertisement is unaffected.
func TestBuildDesiredRouter_EdgeGate(t *testing.T) {
	const node = "node-a"
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: testNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{TargetRef: bgpv1alpha1.TargetRef{Name: node}, NodeID: 1,
			SRv6Locator: testLocator},
	}
	adv := func(name string, edge bool) *bgpv1alpha1.BGPAdvertisement {
		a := &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec: bgpv1alpha1.BGPAdvertisementSpec{
				RouterRef:     bgpv1alpha1.RouterRef{Name: router.Name},
				AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
				Prefixes:      []bgpv1alpha1.Prefix{"fd00:10::/64"},
				VRFID:         ptrInt32(5),
				Function:      ptrFunction(bgpv1alpha1.SRv6FunctionEndDT46),
			},
		}
		if edge {
			a.Labels = map[string]string{crdnames.LabelEdgeRoute: "uid-" + name}
		}
		return a
	}
	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).
		WithObjects(adv("workload", false), adv("open", true), adv("closed", true)).
		WithIndex(&bgpv1alpha1.BGPAdvertisement{}, routerRefIndexer, func(obj client.Object) []string {
			return []string{obj.(*bgpv1alpha1.BGPAdvertisement).Spec.RouterRef.Name}
		}).
		WithIndex(&bgpv1alpha1.BGPVRFInstance{}, routerRefIndexer, func(client.Object) []string { return nil }).
		Build()

	for _, tc := range []struct {
		name string
		gate EdgeGate
		want []string
	}{
		{"no gate", nil, []string{"workload"}},
		{"gate", gateSet{"open": true}, []string{"open", "workload"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New(c, node, "2001:db8::1")
			if tc.gate != nil {
				r.SetEdgeGate(tc.gate)
			}
			got, err := r.BuildDesiredRouter(context.Background(), router)
			if err != nil {
				t.Fatal(err)
			}
			names := make([]string, 0, len(got.Advertisements))
			for _, a := range got.Advertisements {
				names = append(names, a.Name)
			}
			slices.Sort(names)
			if !slices.Equal(names, tc.want) {
				t.Fatalf("advertised %v, want %v", names, tc.want)
			}
		})
	}
}
