// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"testing"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

func fabricRouter(name, target string) *bgpv1alpha1.BGPRouter {
	class := "fabric-frr"
	r := router(target, "2001:db8:ee01::/48", 9)
	r.Name = name
	r.Spec.RouterClassName = &class
	return r
}

// TestNodeLocatorPrefixSkipsFabricRouter: the locator route is carved from
// the Galactic router's locator even when a fabric router targets the node.
func TestNodeLocatorPrefixSkipsFabricRouter(t *testing.T) {
	galactic := router("node-a", testLocator, 0x0102)
	galactic.Name = "zz-galactic"
	c := newRouterClient(t, fabricRouter("aa-fabric", "node-a"), galactic)
	got, err := nodeLocatorPrefix(context.Background(), c, testNamespace, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if want := "2001:db8:8002:102::/64"; got.String() != want {
		t.Errorf("nodeLocatorPrefix = %s, want %s", got, want)
	}
}

// TestNodeLocatorPrefixAmbiguous: two Galactic routers on one node are an
// error rather than whichever the list returned first.
func TestNodeLocatorPrefixAmbiguous(t *testing.T) {
	one := router("node-a", testLocator, 1)
	one.Name = "one"
	two := router("node-a", testLocator, 2)
	two.Name = "two"
	c := newRouterClient(t, one, two)
	if got, err := nodeLocatorPrefix(context.Background(), c, testNamespace, "node-a"); err == nil {
		t.Errorf("nodeLocatorPrefix = %s, want an ambiguity error", got)
	}
}

// TestGalacticRouterNamesForNode: membership follows the router's target,
// not its name, and leaves fabric routers out.
func TestGalacticRouterNamesForNode(t *testing.T) {
	galactic := router("node-a", testLocator, 1)
	galactic.Name = "edge-router-1"
	other := router("node-b", testLocator, 2)
	other.Name = "node-a"
	c := newRouterClient(t, galactic, other, fabricRouter("fabric-node-a", "node-a"))
	names, err := galacticRouterNamesForNode(context.Background(), c, testNamespace, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := names["edge-router-1"]; !ok || len(names) != 1 {
		t.Errorf("galacticRouterNamesForNode = %v, want only edge-router-1", names)
	}
}
