// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.datum.net/galactic/internal/model"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testLocator   = "2001:db8:ff01::/48"
	testLegacySID = "2001:db8::1234:5678"
)

func ptrInt32(v int32) *int32 { return &v }

func ptrFunction(fn bgpv1alpha1.SRv6Function) *bgpv1alpha1.SRv6Function { return &fn }

func TestBuildVRFInstance(t *testing.T) {
	v := bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "vpc-a"},
		Spec: bgpv1alpha1.BGPVRFInstanceSpec{
			VRFID: 42,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{
				{Value: "65000:100"},
			},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{
				{Value: "65000:200"},
			},
		},
	}

	got := buildVRFInstance(v)

	want := model.DesiredVRFInstance{
		Name:               "vpc-a",
		VRFID:              42,
		ImportRouteTargets: []string{"65000:100"},
		ExportRouteTargets: []string{"65000:200"},
	}

	if got.Name != want.Name {
		t.Errorf("buildVRFInstance().Name = %q, want %q", got.Name, want.Name)
	}
	if got.VRFID != want.VRFID {
		t.Errorf("buildVRFInstance().VRFID = %d, want %d", got.VRFID, want.VRFID)
	}
	if len(got.ImportRouteTargets) != 1 || got.ImportRouteTargets[0] != want.ImportRouteTargets[0] {
		t.Errorf("buildVRFInstance().ImportRouteTargets = %v, want %v", got.ImportRouteTargets, want.ImportRouteTargets)
	}
	if len(got.ExportRouteTargets) != 1 || got.ExportRouteTargets[0] != want.ExportRouteTargets[0] {
		t.Errorf("buildVRFInstance().ExportRouteTargets = %v, want %v", got.ExportRouteTargets, want.ExportRouteTargets)
	}
}

func TestResolveSRv6SID(t *testing.T) {
	tests := []struct {
		name      string
		router    *bgpv1alpha1.BGPRouter
		adv       *bgpv1alpha1.BGPAdvertisement
		want      string
		wantError bool
	}{
		{
			name: "computes uSID when VRFID/Function and SRv6Locator/NodeID all set",
			router: &bgpv1alpha1.BGPRouter{
				Spec: bgpv1alpha1.BGPRouterSpec{
					SRv6Locator: testLocator,
					NodeID:      7,
				},
			},
			adv: &bgpv1alpha1.BGPAdvertisement{
				Spec: bgpv1alpha1.BGPAdvertisementSpec{
					VRFID:    ptrInt32(42),
					Function: ptrFunction(bgpv1alpha1.SRv6FunctionEndDT46),
				},
			},
			// locator 2001:db8:ff01::/48 (6 bytes) + NodeID 0x07 + VRFID 0x002a + Function 0x00
			want: "2001:db8:ff01:700:2a00::",
		},
		{
			name: "falls back to legacy annotation when adv VRFID/Function unset",
			router: &bgpv1alpha1.BGPRouter{
				Spec: bgpv1alpha1.BGPRouterSpec{
					SRv6Locator: testLocator,
					NodeID:      7,
				},
			},
			adv: &bgpv1alpha1.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{legacySRv6SIDAnnotation: testLegacySID},
				},
			},
			want: testLegacySID,
		},
		{
			name:   "falls back to legacy annotation when router lacks SRv6Locator/NodeID",
			router: &bgpv1alpha1.BGPRouter{},
			adv: &bgpv1alpha1.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{legacySRv6SIDAnnotation: testLegacySID},
				},
				Spec: bgpv1alpha1.BGPAdvertisementSpec{
					VRFID:    ptrInt32(42),
					Function: ptrFunction(bgpv1alpha1.SRv6FunctionEndDT46),
				},
			},
			want: testLegacySID,
		},
		{
			name: "falls back to empty string when neither adv fields nor annotation set",
			router: &bgpv1alpha1.BGPRouter{
				Spec: bgpv1alpha1.BGPRouterSpec{
					SRv6Locator: testLocator,
					NodeID:      7,
				},
			},
			adv:  &bgpv1alpha1.BGPAdvertisement{},
			want: "",
		},
		{
			name: "propagates ComputeSID error (e.g. nodeID out of range)",
			router: &bgpv1alpha1.BGPRouter{
				Spec: bgpv1alpha1.BGPRouterSpec{
					SRv6Locator: testLocator,
					NodeID:      255, // out of ComputeSID's [1,254] range
				},
			},
			adv: &bgpv1alpha1.BGPAdvertisement{
				Spec: bgpv1alpha1.BGPAdvertisementSpec{
					VRFID:    ptrInt32(42),
					Function: ptrFunction(bgpv1alpha1.SRv6FunctionEndDT46),
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveSRv6SID(tt.router, tt.adv)
			if (err != nil) != tt.wantError {
				t.Fatalf("resolveSRv6SID() error = %v, wantError = %v", err, tt.wantError)
			}
			if tt.wantError {
				return
			}
			if got != tt.want {
				t.Errorf("resolveSRv6SID() = %q, want %q", got, tt.want)
			}
		})
	}
}
