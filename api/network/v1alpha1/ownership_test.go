// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIsLegacyOwned(t *testing.T) {
	class := "fabric-frr"
	for _, tc := range []struct {
		name   string
		router *BGPRouter
		want   bool
	}{
		{"nil router", nil, false},
		{"no class", &BGPRouter{}, true},
		{"named class", &BGPRouter{Spec: BGPRouterSpec{RouterClassName: &class}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLegacyOwned(tc.router); got != tc.want {
				t.Errorf("IsLegacyOwned = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLegacyOwnedRoutersKeepsOrder(t *testing.T) {
	class := "fabric-frr"
	in := []BGPRouter{
		{ObjectMeta: metav1.ObjectMeta{Name: "a"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "b"}, Spec: BGPRouterSpec{RouterClassName: &class}},
		{ObjectMeta: metav1.ObjectMeta{Name: "c"}},
	}
	got := LegacyOwnedRouters(in)
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "c" {
		t.Errorf("LegacyOwnedRouters = %v, want a and c", got)
	}
}
