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

const (
	nodeSrcTestNode    = "worker-1"
	nodeSrcTestLocator = "2001:db8:ff01::/48"
	nodeSrcTestNodeID  = 9

	// nodeSrcTestSID is srv6.NodeSIDBase(nodeSrcTestLocator,
	// nodeSrcTestNodeID) written out by hand: the Block, then the Node-ID in
	// bits 49-64, then the End.DT46 Function nibble with a zero Argument
	// beside it. Spelled literally rather than computed, so a change to the
	// encoding has to be restated here to pass rather than tracked silently.
	nodeSrcTestSID = "2001:db8:ff01:9:e000::"
)

// newNodeSrcTestRouter returns a BGPRouter targeting node, carrying locator
// and nodeID. An empty locator or a zero nodeID is a router with no SRv6
// identity, which the resolver must skip rather than derive a SID from.
func newNodeSrcTestRouter(name, node, locator string, nodeID int32) *bgpv1alpha1.BGPRouter {
	return &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Namespace: gatewayTestNamespace, Name: name},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Kind: "Node", Name: node},
			LocalASN:    65000,
			RouterID:    "10.0.0.1",
			SRv6Locator: locator,
			NodeID:      nodeID,
		},
	}
}

func TestResolveNodeSourceAddress_ReturnsNodeSIDBase(t *testing.T) {
	scheme := gatewayTestScheme(t)
	router := newNodeSrcTestRouter(nodeSrcTestNode, nodeSrcTestNode, nodeSrcTestLocator, nodeSrcTestNodeID)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router).Build()

	r := NewK8sNodeSourceAddressResolver(fakeClient, nodeSrcTestNode, gatewayTestNamespace)
	addr, err := r.ResolveNodeSourceAddress()
	if err != nil {
		t.Fatalf("ResolveNodeSourceAddress: %v", err)
	}
	want := net.ParseIP(nodeSrcTestSID)
	if !addr.Equal(want) {
		t.Errorf("ResolveNodeSourceAddress() = %v, want %v", addr, want)
	}
}

// TestResolveNodeSourceAddress_IsNotAnInterfaceAddress is the regression guard
// for #550. The uplink address this used to return is routable nowhere in the
// fabric and matches no node's locator_table, so an egress shard's reply to it
// is dropped. Assert the answer sits inside the locator this node advertises.
func TestResolveNodeSourceAddress_IsNotAnInterfaceAddress(t *testing.T) {
	scheme := gatewayTestScheme(t)
	router := newNodeSrcTestRouter(nodeSrcTestNode, nodeSrcTestNode, nodeSrcTestLocator, nodeSrcTestNodeID)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(router).Build()

	r := NewK8sNodeSourceAddressResolver(fakeClient, nodeSrcTestNode, gatewayTestNamespace)
	addr, err := r.ResolveNodeSourceAddress()
	if err != nil {
		t.Fatalf("ResolveNodeSourceAddress: %v", err)
	}
	_, locator, err := net.ParseCIDR(nodeSrcTestLocator)
	if err != nil {
		t.Fatalf("parse locator: %v", err)
	}
	if !locator.Contains(addr) {
		t.Errorf("ResolveNodeSourceAddress() = %v, want an address inside %s", addr, locator)
	}
}

func TestResolveNodeSourceAddress_IgnoresOtherNodesRouters(t *testing.T) {
	scheme := gatewayTestScheme(t)
	other := newNodeSrcTestRouter("psi-puborr", "psi-puborr", "2001:db8:ff02::/48", 3)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(other).Build()

	r := NewK8sNodeSourceAddressResolver(fakeClient, nodeSrcTestNode, gatewayTestNamespace)
	if _, err := r.ResolveNodeSourceAddress(); err == nil {
		t.Fatal("expected an error when no BGPRouter targets this node, got nil")
	}
}

func TestResolveNodeSourceAddress_SkipsRouterWithNoSRv6Identity(t *testing.T) {
	scheme := gatewayTestScheme(t)
	noIdentity := newNodeSrcTestRouter("worker-1-underlay", nodeSrcTestNode, "", 0)
	withIdentity := newNodeSrcTestRouter(nodeSrcTestNode, nodeSrcTestNode, nodeSrcTestLocator, nodeSrcTestNodeID)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(noIdentity, withIdentity).Build()

	r := NewK8sNodeSourceAddressResolver(fakeClient, nodeSrcTestNode, gatewayTestNamespace)
	addr, err := r.ResolveNodeSourceAddress()
	if err != nil {
		t.Fatalf("ResolveNodeSourceAddress: %v", err)
	}
	want := net.ParseIP(nodeSrcTestSID)
	if !addr.Equal(want) {
		t.Errorf("ResolveNodeSourceAddress() = %v, want %v (the router with an SRv6 identity)", addr, want)
	}
}

// TestResolveNodeSourceAddress_UnusableLocatorFailsLoudly covers a router
// carrying a locator that is not a /48 uSID Block. Returning nothing rather
// than an error would let node_src_addr_table's "all-zero means not
// configured" convention read a garbage answer as a legitimate one.
func TestResolveNodeSourceAddress_UnusableLocatorFailsLoudly(t *testing.T) {
	scheme := gatewayTestScheme(t)
	bad := newNodeSrcTestRouter(nodeSrcTestNode, nodeSrcTestNode, "2001:db8:ff01::/64", nodeSrcTestNodeID)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bad).Build()

	r := NewK8sNodeSourceAddressResolver(fakeClient, nodeSrcTestNode, gatewayTestNamespace)
	if _, err := r.ResolveNodeSourceAddress(); err == nil {
		t.Fatal("expected an error when the matching router's locator is not a /48, got nil")
	}
}

func TestResolveNodeSourceAddress_NoRoutersAtAll(t *testing.T) {
	scheme := gatewayTestScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := NewK8sNodeSourceAddressResolver(fakeClient, nodeSrcTestNode, gatewayTestNamespace)
	if _, err := r.ResolveNodeSourceAddress(); err == nil {
		t.Fatal("expected an error with no BGPRouters at all, got nil")
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
