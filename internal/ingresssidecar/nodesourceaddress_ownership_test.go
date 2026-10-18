// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"net"
	"strings"
	"testing"

	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestResolveNodeSourceAddress_SkipsFabricRouter: a fabric-class router on
// the node with its own locator neither replaces the Galactic router's SID
// nor makes the node ambiguous.
func TestResolveNodeSourceAddress_SkipsFabricRouter(t *testing.T) {
	fabric := newNodeSrcTestRouter("aa-fabric", nodeSrcTestNode, "2001:db8:ee01::/48", 4)
	fabric.Spec.RouterClassName = ptr.To("fabric-frr")
	galactic := newNodeSrcTestRouter("zz-galactic", nodeSrcTestNode, nodeSrcTestLocator, nodeSrcTestNodeID)
	c := fake.NewClientBuilder().WithScheme(gatewayTestScheme(t)).WithObjects(fabric, galactic).Build()

	addr, err := NewK8sNodeSourceAddressResolver(c, nodeSrcTestNode, gatewayTestNamespace).ResolveNodeSourceAddress()
	if err != nil {
		t.Fatal(err)
	}
	if want := net.ParseIP(nodeSrcTestSID); !addr.Equal(want) {
		t.Errorf("ResolveNodeSourceAddress() = %v, want %v", addr, want)
	}
}

// TestResolveNodeSourceAddress_AmbiguousGalacticRouters: two Galactic
// routers with locators on one node are an error, not a list-order pick.
func TestResolveNodeSourceAddress_AmbiguousGalacticRouters(t *testing.T) {
	one := newNodeSrcTestRouter("one", nodeSrcTestNode, nodeSrcTestLocator, nodeSrcTestNodeID)
	two := newNodeSrcTestRouter("two", nodeSrcTestNode, "2001:db8:ee01::/48", 4)
	c := fake.NewClientBuilder().WithScheme(gatewayTestScheme(t)).WithObjects(one, two).Build()

	_, err := NewK8sNodeSourceAddressResolver(c, nodeSrcTestNode, gatewayTestNamespace).ResolveNodeSourceAddress()
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("ResolveNodeSourceAddress error = %v, want an ambiguity error", err)
	}
}
