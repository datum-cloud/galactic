// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

func indexedFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(objs...).
		WithIndex(&bgpv1alpha1.BGPAdvertisement{}, routerRefIndexer, func(obj client.Object) []string {
			return []string{obj.(*bgpv1alpha1.BGPAdvertisement).Spec.RouterRef.Name}
		}).
		WithIndex(&bgpv1alpha1.BGPVRFInstance{}, routerRefIndexer, func(obj client.Object) []string {
			if ref := obj.(*bgpv1alpha1.BGPVRFInstance).Spec.RouterRef; ref != nil {
				return []string{ref.Name}
			}
			return nil
		}).
		Build()
}

// TestBuildDesiredRouterRejectsFabricOnlyFields: the GoBGP path refuses the
// settings only the fabric router implements instead of running a session
// or advertisement without them.
func TestBuildDesiredRouterRejectsFabricOnlyFields(t *testing.T) {
	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: testNamespace, Labels: map[string]string{"site": "dfw"}},
		Spec:       bgpv1alpha1.BGPRouterSpec{TargetRef: bgpv1alpha1.TargetRef{Name: "node-a"}},
	}
	evpn := []bgpv1alpha1.AddressFamily{{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}}
	peer := func(mutate func(*bgpv1alpha1.BGPPeerSpec)) client.Object {
		p := &bgpv1alpha1.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: testNamespace},
			Spec: bgpv1alpha1.BGPPeerSpec{
				RouterTarget:    bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: "r1"}},
				Address:         "2001:db8:ff01::1",
				PeerASN:         65000,
				AddressFamilies: evpn,
			},
		}
		mutate(&p.Spec)
		return p
	}
	ttl := int32(2)
	for _, tc := range []struct {
		name  string
		obj   client.Object
		field string
	}{
		{"peer profile", peer(func(s *bgpv1alpha1.BGPPeerSpec) {
			s.PeerProfileRef = &bgpv1alpha1.LocalObjectRef{Name: "edge"}
		}), "peerProfileRef"},
		{"selector-bound peer profile", peer(func(s *bgpv1alpha1.BGPPeerSpec) {
			s.RouterRef = nil
			s.RouterSelector = &bgpv1alpha1.RouterSelector{MatchLabels: map[string]string{"site": "dfw"}}
			s.PeerProfileRef = &bgpv1alpha1.LocalObjectRef{Name: "edge"}
		}), "peerProfileRef"},
		{"peer transport", peer(func(s *bgpv1alpha1.BGPPeerSpec) {
			s.Transport = &bgpv1alpha1.BGPPeerTransport{EBGPMultihopTTL: &ttl}
		}), "transport"},
		{"peer family settings", peer(func(s *bgpv1alpha1.BGPPeerSpec) {
			s.FamilySettings = []bgpv1alpha1.BGPPeerFamilySettings{{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN}}
		}), "familySettings"},
		{"peer without families", peer(func(s *bgpv1alpha1.BGPPeerSpec) {
			s.AddressFamilies = nil
		}), "addressFamilies"},
		{"aggregate advertisement", &bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{Name: "agg", Namespace: testNamespace},
			Spec: bgpv1alpha1.BGPAdvertisementSpec{
				RouterRef:     bgpv1alpha1.RouterRef{Name: "r1"},
				AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIIPv6, SAFI: bgpv1alpha1.SAFIUnicast},
				Aggregation:   &bgpv1alpha1.BGPAggregation{Prefix: "2001:db8::/32"},
			},
		}, "aggregation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New(indexedFakeClient(t, tc.obj), "node-a", "2001:db8::1")
			_, err := r.BuildDesiredRouter(context.Background(), router)
			if err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Errorf("BuildDesiredRouter error = %v, want a refusal naming %s", err, tc.field)
			}
		})
	}
}
