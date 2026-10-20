// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package topology

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// TestReleased: a generated peer the topology no longer holds is released
// only on evidence that an end is out of service, never because something
// merely stopped matching.
func TestReleased(t *testing.T) {
	base := func() *snapshot {
		topo := reflectionTopology("cell-a", "l")
		topo.Spec.External = []networkv1alpha1.FabricExternalRelationship{{Name: extRel,
			Peers: []networkv1alpha1.FabricExternalPeer{{Address: extPeer, ASN: 64999}}}}
		remote := endpoint(remoteRec, "cell-b", "r", transportP, "", "2001:db8:b::1", 0, nil)
		return &snapshot{
			topology: topo,
			routers:  routerMap(router("l", nil), router("same-cell", nil)),
			endpoints: map[string]*EndpointState{
				remoteRec: {Endpoint: &remote},
			},
			deployments: map[string]*networkv1alpha1.FabricRouterDeployment{},
		}
	}
	peer := func(relationship, cell, remoteRouter, remoteEP, uid, address string) *networkv1alpha1.BGPPeer {
		return &networkv1alpha1.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: "p",
				Labels: map[string]string{networkv1alpha1.LabelPeerCell: cell},
				Annotations: map[string]string{
					networkv1alpha1.AnnotationRelationship:      relationship,
					networkv1alpha1.AnnotationLocalEndpoint:     "local-ep",
					networkv1alpha1.AnnotationRemoteEndpoint:    remoteEP,
					networkv1alpha1.AnnotationRemoteEndpointUID: uid,
					networkv1alpha1.AnnotationRemoteRouter:      remoteRouter,
				}},
			Spec: networkv1alpha1.BGPPeerSpec{
				RouterTarget: networkv1alpha1.RouterTarget{RouterRef: &networkv1alpha1.RouterRef{Name: "l"}},
				Address:      address,
			},
		}
	}
	toRemote := func() *networkv1alpha1.BGPPeer {
		return peer("reflection/public", "cell-b", "r", remoteRec, "uid-remote", "2001:db8:b::1")
	}
	toSameCell := func() *networkv1alpha1.BGPPeer {
		return peer("mesh/m", "cell-a", "same-cell", "same-cell-ep", "uid-same", "2001:db8:a::9")
	}
	external := func() *networkv1alpha1.BGPPeer { return peer("external/transit", "", "", "", "", extPeer) }
	retire := func(s *snapshot, name string, applied int64) {
		s.deployments[name] = &networkv1alpha1.FabricRouterDeployment{
			Spec: networkv1alpha1.FabricRouterDeploymentSpec{
				RouterRef:       networkv1alpha1.FabricObjectIdentity{Name: name, UID: "uid-" + name},
				ActivationEpoch: 3, Recovery: &networkv1alpha1.FabricRecovery{Retired: true}},
			Status: networkv1alpha1.FabricRouterDeploymentStatus{AppliedEpoch: applied},
		}
	}
	for _, tc := range []struct {
		name    string
		peer    func() *networkv1alpha1.BGPPeer
		mutate  func(*snapshot)
		release bool
	}{
		{"RemoteRecordPresent", toRemote, nil, false},
		{"RemoteRecordDeleted", toRemote, func(s *snapshot) { delete(s.endpoints, remoteRec) }, true},
		{"RemoteRecordRecreated", toRemote, func(s *snapshot) {
			s.endpoints[remoteRec].Endpoint.UID = types.UID("new")
		}, true},
		{"RemoteRecordDrained", toRemote, func(s *snapshot) {
			drainEndpoint(s, remoteRec)
		}, true},
		{"LocalEndpointDrained", toRemote, func(s *snapshot) {
			drainEndpoint(s, "local-ep")
		}, true},
		{"LocalRouterDeleted", toRemote, func(s *snapshot) { delete(s.routers, "l") }, true},
		{"LocalRouterDrained", toRemote, func(s *snapshot) {
			drainRouter(s, "l")
		}, true},
		{"LocalRouterRetiring", toRemote, func(s *snapshot) { retire(s, "l", 2) }, false},
		{"LocalRouterRetired", toRemote, func(s *snapshot) { retire(s, "l", 3) }, true},
		{"RetiredDeploymentOfEarlierRouter", toRemote, func(s *snapshot) {
			retire(s, "l", 3)
			s.deployments["l"].Spec.RouterRef.UID = "uid-older"
		}, false},
		{"SameCellRouterRunning", toSameCell, nil, false},
		{"SameCellEndpointDeletedRouterRunning", toSameCell, nil, false},
		{"SameCellRouterDeleted", toSameCell, func(s *snapshot) { delete(s.routers, "same-cell") }, true},
		{"SameCellRouterRetired", toSameCell, func(s *snapshot) { retire(s, "same-cell", 3) }, true},
		{"SameCellRouterDrained", toSameCell, func(s *snapshot) {
			drainRouter(s, "same-cell")
		}, true},
		{"ExternalListed", external, nil, false},
		{"ExternalRemoved", external, func(s *snapshot) {
			s.topology.Spec.External[0].Peers[0].Address = "2001:db8:ffff::2"
		}, true},
		{"ExternalRelationshipRemoved", external, func(s *snapshot) { s.topology.Spec.External = nil }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			if tc.mutate != nil {
				tc.mutate(s)
			}
			why, _, err := s.released(context.Background(), tc.peer())
			if err != nil {
				t.Fatal(err)
			}
			if (why != "") != tc.release {
				t.Errorf("released %q, want release %t", why, tc.release)
			}
		})
	}
}

func drainEndpoint(s *snapshot, name string) {
	s.topology.Spec.Drain = &networkv1alpha1.FabricTopologyDrain{Endpoints: []networkv1alpha1.LocalObjectRef{{Name: name}}}
}

func drainRouter(s *snapshot, name string) {
	s.topology.Spec.Drain = &networkv1alpha1.FabricTopologyDrain{Routers: []networkv1alpha1.LocalObjectRef{{Name: name}}}
}

// TestReleasedConfirmsAbsence: a router or record missing from the cache is
// released only once the API server confirms it is gone, and a release on
// absence says so, for the release guard. A peer without a router is kept.
func TestReleasedConfirmsAbsence(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = networkv1alpha1.AddToScheme(scheme)
	topo := reflectionTopology(cellA, "l")
	remote := endpoint(remoteRec, cellB, "r", transportP, "", "2001:db8:b::1", 0, nil)
	local := router("l", nil)
	toRemote := &networkv1alpha1.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Labels: map[string]string{networkv1alpha1.LabelPeerCell: cellB},
			Annotations: map[string]string{
				networkv1alpha1.AnnotationRelationship:      "reflection/public",
				networkv1alpha1.AnnotationRemoteEndpoint:    remoteRec,
				networkv1alpha1.AnnotationRemoteEndpointUID: "uid-remote",
			}},
		Spec: networkv1alpha1.BGPPeerSpec{
			RouterTarget: networkv1alpha1.RouterTarget{RouterRef: &networkv1alpha1.RouterRef{Name: "l"}},
			Address:      "2001:db8:b::1"},
	}
	stored := func(objs ...*networkv1alpha1.FabricEndpoint) []*networkv1alpha1.FabricEndpoint { return objs }
	for _, tc := range []struct {
		name         string
		inCache      bool
		apiRouter    bool
		apiEndpoints []*networkv1alpha1.FabricEndpoint
		release      bool
		absent       bool
	}{
		{"RouterOnlyInAPI", false, true, stored(&remote), false, false},
		{"RouterGone", false, false, stored(&remote), true, true},
		{"RecordOnlyInAPI", true, true, stored(&remote), false, false},
		{"RecordGone", true, true, nil, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := fake.NewClientBuilder().WithScheme(scheme)
			if tc.apiRouter {
				r := local.DeepCopy()
				r.Namespace, r.UID = topo.Namespace, ""
				b = b.WithObjects(r)
			}
			for _, ep := range tc.apiEndpoints {
				e := ep.DeepCopy()
				e.Namespace, e.UID = topo.Namespace, ""
				b = b.WithObjects(e)
			}
			reader := b.Build()
			// The fake API server assigns UIDs; the peer was generated from
			// the stored record.
			if len(tc.apiEndpoints) > 0 {
				e := &networkv1alpha1.FabricEndpoint{}
				key := types.NamespacedName{Namespace: topo.Namespace, Name: remoteRec}
				if err := reader.Get(context.Background(), key, e); err != nil {
					t.Fatal(err)
				}
				toRemote.Annotations[networkv1alpha1.AnnotationRemoteEndpointUID] = string(e.UID)
			}
			s := &snapshot{topology: topo, reader: reader, endpoints: map[string]*EndpointState{},
				routers: map[string]*networkv1alpha1.BGPRouter{}, deployments: map[string]*networkv1alpha1.FabricRouterDeployment{}}
			if tc.inCache {
				s.routers["l"] = local
			}
			why, absent, err := s.released(context.Background(), toRemote)
			if err != nil {
				t.Fatal(err)
			}
			if (why != "") != tc.release || absent != tc.absent {
				t.Errorf("released %q absent %t, want release %t absent %t", why, absent, tc.release, tc.absent)
			}
		})
	}

	s := &snapshot{topology: topo}
	noRouter := toRemote.DeepCopy()
	noRouter.Spec.RouterRef = nil
	if why, _, _ := s.released(context.Background(), noRouter); why != "" {
		t.Errorf("a peer without a router released: %s", why)
	}
}

// TestReconcileIgnoresOtherNamespaces: the reconcilers act on nothing
// outside the served namespace, whatever RBAC would allow.
func TestReconcileIgnoresOtherNamespaces(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = networkv1alpha1.AddToScheme(scheme)
	topo := reflectionTopology(cellA, "a1")
	topo.Namespace = otherNS
	ep := endpoint("ep", cellA, "a1", transportP, "", a1v6, 0, nil)
	ep.Namespace, ep.UID = otherNS, ""
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(topo, &ep).
		WithStatusSubresource(&networkv1alpha1.FabricEndpoint{}, &networkv1alpha1.FabricTopology{}).Build()
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: otherNS, Name: topo.Name}}
	if _, err := (&Reconciler{Client: c, APIReader: c, Namespace: unitNS}).Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := (&EndpointReconciler{Client: c, Namespace: unitNS}).Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	got := &networkv1alpha1.FabricTopology{}
	if err := c.Get(ctx, req.NamespacedName, got); err != nil {
		t.Fatal(err)
	}
	gotEP := &networkv1alpha1.FabricEndpoint{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: otherNS, Name: "ep"}, gotEP); err != nil {
		t.Fatal(err)
	}
	if len(got.Finalizers) != 0 || len(got.Status.Conditions) != 0 || len(gotEP.Status.Conditions) != 0 {
		t.Errorf("acted outside the served namespace: finalizers %v, conditions %d and %d", got.Finalizers,
			len(got.Status.Conditions), len(gotEP.Status.Conditions))
	}
}
