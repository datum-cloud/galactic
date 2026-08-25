// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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

// newTestScheme returns a runtime.Scheme with the BGP API types registered,
// for constructing a fake.Client in tests.
func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add bgpv1alpha1 to scheme: %v", err)
	}
	return scheme
}

// routerRefIndexer indexes BGPAdvertisement/BGPVRFInstance by
// .spec.routerRef.name, mirroring internal/controller/indexer.go's
// BGPAdvByRouterName/BGPVRFInstanceByRouterName registration on the real
// manager cache — BuildDesiredRouter's client.MatchingFields lookups require
// it, and the fake client has no cache to register it on implicitly.
const routerRefIndexer = ".spec.routerRef.name"

func TestBuildDesiredRouter_NodeFilter(t *testing.T) {
	const thisNode = "node-a"

	tests := []struct {
		name       string
		targetNode string
		wantSkip   bool
	}{
		{
			name:       "skips a router targeting a different node",
			targetNode: "node-b",
			wantSkip:   true,
		},
		{
			name:       "proceeds for a router targeting this node",
			targetNode: thisNode,
			wantSkip:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			router := &bgpv1alpha1.BGPRouter{
				ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "default"},
				Spec: bgpv1alpha1.BGPRouterSpec{
					TargetRef: bgpv1alpha1.TargetRef{Name: tc.targetNode},
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(newTestScheme(t)).
				WithIndex(&bgpv1alpha1.BGPAdvertisement{}, routerRefIndexer, func(obj client.Object) []string {
					adv := obj.(*bgpv1alpha1.BGPAdvertisement)
					return []string{adv.Spec.RouterRef.Name}
				}).
				WithIndex(&bgpv1alpha1.BGPVRFInstance{}, routerRefIndexer, func(obj client.Object) []string {
					vrf := obj.(*bgpv1alpha1.BGPVRFInstance)
					if vrf.Spec.RouterRef == nil {
						return nil
					}
					return []string{vrf.Spec.RouterRef.Name}
				}).
				Build()

			// localAddress set so the "proceeds" case doesn't also need a
			// fake Node object just to resolve an EVPN next-hop.
			r := New(fakeClient, thisNode, "2001:db8::1")

			got, err := r.BuildDesiredRouter(context.Background(), router)
			if err != nil {
				t.Fatalf("BuildDesiredRouter() error = %v, want nil", err)
			}
			if tc.wantSkip {
				if got != nil {
					t.Errorf("BuildDesiredRouter() = %+v, want nil (skip)", got)
				}
				return
			}
			if got == nil {
				t.Error("BuildDesiredRouter() = nil, want a non-nil DesiredRouter")
			}
		})
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
			// locator 2001:db8:ff01::/48 (uSID Block) + Node-ID 0x0007 (bits
			// 49-64) + Function 0xE (uformat.FunctionEndDT46, bits 65-68) +
			// Argument 0x02a (bits 69-80) -- uFMT 48+16 layout, not the
			// legacy NodeID(8)/VRFID(16)/Function(8) suffix ComputeSID used
			// before #283's rewrite onto uformat.
			want: "2001:db8:ff01:7:e02a::",
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
					NodeID:      0xE000, // one past uformat.NodeIDMax (0xDFFF) -- PR #740's reserved Node-ID range
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
