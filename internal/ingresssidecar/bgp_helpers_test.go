// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// bgpTestNamespace holds the test node's BGPRouter.
const bgpTestNamespace = "galactic-system"

// bgpTestScheme returns a scheme with the BGP types.
func bgpTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return scheme
}
