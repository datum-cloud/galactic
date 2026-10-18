// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"testing"

	"k8s.io/utils/ptr"
)

// TestEncapSourceSkipsFabricRouter: a fabric-class router on the gateway
// node, with a different locator, neither conflicts with nor replaces the
// Galactic router's encapsulation source.
func TestEncapSourceSkipsFabricRouter(t *testing.T) {
	fabric := testEncapRouter("galactic-system", "aa-fabric", testEncapNode, "2001:db8:ee01::/48", 0x2001)
	fabric.Spec.RouterClassName = ptr.To("fabric-frr")
	galactic := testEncapRouter("galactic-system", "zz-galactic", testEncapNode, testEncapLocator, 0x1002)

	got, err := resolveEncapSource(context.Background(), testEncapReader(t, fabric, galactic), testEncapNode, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != testEncapDerived {
		t.Errorf("encap source = %s, want %s", got, testEncapDerived)
	}
}
