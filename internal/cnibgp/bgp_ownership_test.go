// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// TestLookupBGPRouterSkipsFabricRouter: a fabric-class router on the node
// neither makes the lookup ambiguous nor supplies the tenant's locator.
func TestLookupBGPRouterSkipsFabricRouter(t *testing.T) {
	class := "fabric-frr"
	fabric := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: "aa-fabric", Namespace: "galactic-system"},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Name: "node-a"}, RouterClassName: &class,
			LocalASN: 64999, SRv6Locator: "2001:db8:ee01::/48", NodeID: 9,
		},
	}
	galactic := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: "zz-galactic", Namespace: "galactic-system"},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Name: "node-a"},
			LocalASN:  65000, SRv6Locator: "2001:db8:ff01::/48", NodeID: 7,
		},
	}
	cfg, err := lookupBGPRouter(context.Background(), fakeClient(fabric, galactic), "node-a", "galactic-system")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.asNumber != 65000 {
		t.Errorf("asNumber = %d, want the Galactic router's 65000", cfg.asNumber)
	}

	if _, err := lookupBGPRouter(context.Background(), fakeClient(fabric), "node-a", "galactic-system"); err == nil {
		t.Error("a node with only a fabric router resolved a Galactic BGP config")
	}
}
