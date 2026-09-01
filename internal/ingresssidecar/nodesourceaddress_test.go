// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"net"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const nodeSrcTestNode = "worker-1"

func newTestBGPPeer(name, routerRefName string, updateSource *string) *bgpv1alpha1.BGPPeer {
	peer := &bgpv1alpha1.BGPPeer{
		ObjectMeta: metav1.ObjectMeta{Namespace: gatewayTestNamespace, Name: name},
		Spec: bgpv1alpha1.BGPPeerSpec{
			PeerASN: 65000,
			Address: "2607:f740:100::f77",
			AddressFamilies: []bgpv1alpha1.AddressFamily{
				{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			},
			UpdateSource: updateSource,
		},
	}
	if routerRefName != "" {
		peer.Spec.RouterTarget = bgpv1alpha1.RouterTarget{
			RouterRef: &bgpv1alpha1.RouterRef{Name: routerRefName},
		}
	}
	return peer
}

func strPtr(s string) *string { return &s }

func TestResolveNodeSourceAddress_ReturnsUpdateSource(t *testing.T) {
	scheme := gatewayTestScheme(t)
	peer := newTestBGPPeer("worker-1-to-rr", nodeSrcTestNode, strPtr("2607:f740:100::635"))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(peer).Build()

	r := NewK8sNodeSourceAddressResolver(fakeClient, nodeSrcTestNode, gatewayTestNamespace)
	addr, err := r.ResolveNodeSourceAddress()
	if err != nil {
		t.Fatalf("ResolveNodeSourceAddress: %v", err)
	}
	want := net.ParseIP("2607:f740:100::635")
	if !addr.Equal(want) {
		t.Errorf("ResolveNodeSourceAddress() = %v, want %v", addr, want)
	}
}

func TestResolveNodeSourceAddress_IgnoresOtherNodesPeers(t *testing.T) {
	scheme := gatewayTestScheme(t)
	other := newTestBGPPeer("psi-puborr-to-rr", "psi-puborr", strPtr("2600:9c02::2"))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(other).Build()

	r := NewK8sNodeSourceAddressResolver(fakeClient, nodeSrcTestNode, gatewayTestNamespace)
	if _, err := r.ResolveNodeSourceAddress(); err == nil {
		t.Fatal("expected an error when no BGPPeer targets this node, got nil")
	}
}

func TestResolveNodeSourceAddress_SkipsPeerWithNoUpdateSource(t *testing.T) {
	scheme := gatewayTestScheme(t)
	noSource := newTestBGPPeer("worker-1-to-fabric", nodeSrcTestNode, nil)
	withSource := newTestBGPPeer("worker-1-to-rr", nodeSrcTestNode, strPtr("2607:f740:100::635"))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(noSource, withSource).Build()

	r := NewK8sNodeSourceAddressResolver(fakeClient, nodeSrcTestNode, gatewayTestNamespace)
	addr, err := r.ResolveNodeSourceAddress()
	if err != nil {
		t.Fatalf("ResolveNodeSourceAddress: %v", err)
	}
	want := net.ParseIP("2607:f740:100::635")
	if !addr.Equal(want) {
		t.Errorf("ResolveNodeSourceAddress() = %v, want %v (the peer with a usable updateSource)", addr, want)
	}
}

func TestResolveNodeSourceAddress_SkipsUnparseableUpdateSource(t *testing.T) {
	scheme := gatewayTestScheme(t)
	bad := newTestBGPPeer("worker-1-to-fabric", nodeSrcTestNode, strPtr("not-an-ip"))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bad).Build()

	r := NewK8sNodeSourceAddressResolver(fakeClient, nodeSrcTestNode, gatewayTestNamespace)
	if _, err := r.ResolveNodeSourceAddress(); err == nil {
		t.Fatal("expected an error when the only matching peer's updateSource doesn't parse, got nil")
	}
}

func TestResolveNodeSourceAddress_NoPeersAtAll(t *testing.T) {
	scheme := gatewayTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := NewK8sNodeSourceAddressResolver(fakeClient, nodeSrcTestNode, gatewayTestNamespace)
	if _, err := r.ResolveNodeSourceAddress(); err == nil {
		t.Fatal("expected an error with no BGPPeers at all, got nil")
	}
}

func TestNodeSourceAddressResolver_DefaultDisabled(t *testing.T) {
	if r := getNodeSourceAddressResolver(); r != nil {
		t.Errorf("getNodeSourceAddressResolver() = %v, want nil by default", r)
	}
}

func TestSetNodeSourceAddressResolver_RoundTrips(t *testing.T) {
	t.Cleanup(func() { SetNodeSourceAddressResolver(nil) })

	scheme := gatewayTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := NewK8sNodeSourceAddressResolver(fakeClient, nodeSrcTestNode, gatewayTestNamespace)

	SetNodeSourceAddressResolver(r)
	if got := getNodeSourceAddressResolver(); got != r {
		t.Errorf("getNodeSourceAddressResolver() = %v, want %v", got, r)
	}

	SetNodeSourceAddressResolver(nil)
	if got := getNodeSourceAddressResolver(); got != nil {
		t.Errorf("getNodeSourceAddressResolver() after reset = %v, want nil", got)
	}
}
