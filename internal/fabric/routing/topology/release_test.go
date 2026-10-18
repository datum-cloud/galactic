// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package topology

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// TestReleased: a generated peer the topology no longer holds is released
// only on evidence that an end is out of service, never because something
// merely stopped matching.
func TestReleased(t *testing.T) {
	base := func() *snapshot {
		topo := reflectionTopology("cell-a", "l")
		topo.Spec.External = []networkv1alpha1.FabricExternalRelationship{{Name: "transit",
			Peers: []networkv1alpha1.FabricExternalPeer{{Address: "2001:db8:ffff::1", ASN: 64999}}}}
		remote := endpoint("remote", "cell-b", "r", transportP, "", "2001:db8:b::1", 0, nil)
		return &snapshot{
			topology: topo,
			routers:  routerMap(router("l", nil), router("same-cell", nil)),
			endpoints: map[string]*EndpointState{
				"remote": {Endpoint: &remote},
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
		return peer("reflection/public", "cell-b", "r", "remote", "uid-remote", "2001:db8:b::1")
	}
	toSameCell := func() *networkv1alpha1.BGPPeer {
		return peer("mesh/m", "cell-a", "same-cell", "same-cell-ep", "uid-same", "2001:db8:a::9")
	}
	external := func() *networkv1alpha1.BGPPeer { return peer("external/transit", "", "", "", "", "2001:db8:ffff::1") }
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
		{"RemoteRecordDeleted", toRemote, func(s *snapshot) { delete(s.endpoints, "remote") }, true},
		{"RemoteRecordRecreated", toRemote, func(s *snapshot) {
			s.endpoints["remote"].Endpoint.UID = types.UID("new")
		}, true},
		{"RemoteRecordDrained", toRemote, func(s *snapshot) {
			drainEndpoint(s, "remote")
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
			if why := s.released(tc.peer()); (why != "") != tc.release {
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
