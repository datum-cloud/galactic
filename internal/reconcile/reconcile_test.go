// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.datum.net/galactic/internal/model"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
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
					NodeID:      uformat.NodeIDMax + 1, // one past uformat.NodeIDMax -- PR #740's reserved Node-ID range
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

// buildDesiredRouterTestScheme builds a fake client scheme plus the field
// indexes BuildDesiredRouter's client.MatchingFields lookups require
// (mirroring internal/controller.RegisterIndexes, without importing that
// package -- a controller/reconcile layering inversion just for a test).
func buildDesiredRouterTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme (client-go): %v", err)
	}
	if err := bgpv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme (bgpv1alpha1): %v", err)
	}
	return s
}

func routerRefIndexer(obj client.Object) []string {
	switch o := obj.(type) {
	case *bgpv1alpha1.BGPAdvertisement:
		return []string{o.Spec.RouterRef.Name}
	case *bgpv1alpha1.BGPVRFInstance:
		if o.Spec.RouterRef == nil {
			return nil
		}
		return []string{o.Spec.RouterRef.Name}
	default:
		return nil
	}
}

// TestBuildDesiredRouter_SkipsAdvertisementWithOutOfRangeVRFID guards
// against a regression of the fix where one BGPAdvertisement whose VRFID
// the eBPF datapath's 12-bit Argument can't represent (e.g. a pre-cutover
// object allocated under the old, wider legacy VRFID scheme, still valid
// per the CRD's own wider field maximum) used to abort resolveSRv6SID's
// caller entirely -- discarding peers, VRFs, and every other advertisement
// for the whole router, not just the one bad object. It must instead be
// skipped on its own, leaving every valid advertisement intact.
func TestBuildDesiredRouter_SkipsAdvertisementWithOutOfRangeVRFID(t *testing.T) {
	const (
		namespace  = "default"
		nodeName   = "node-a"
		routerName = "router-a"
	)

	router := &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: routerName, Namespace: namespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef:   bgpv1alpha1.TargetRef{Kind: "Node", Name: nodeName},
			Roles:       []bgpv1alpha1.RouterRole{bgpv1alpha1.RouterRoleTenant},
			LocalASN:    65000,
			SRv6Locator: testLocator,
			NodeID:      7,
		},
	}
	validAdv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: "valid-adv", Namespace: namespace},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: routerName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{"2001:db8:1::/64"},
			VRFID:         ptrInt32(42),
			Function:      ptrFunction(bgpv1alpha1.SRv6FunctionEndDT46),
		},
	}
	badAdv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-adv", Namespace: namespace},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: routerName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{"2001:db8:2::/64"},
			VRFID:         ptrInt32(int32(uformat.ArgumentMax) + 1),
			Function:      ptrFunction(bgpv1alpha1.SRv6FunctionEndDT46),
		},
	}

	k8s := fake.NewClientBuilder().
		WithScheme(buildDesiredRouterTestScheme(t)).
		WithObjects(router, validAdv, badAdv).
		WithIndex(&bgpv1alpha1.BGPAdvertisement{}, ".spec.routerRef.name", routerRefIndexer).
		WithIndex(&bgpv1alpha1.BGPVRFInstance{}, ".spec.routerRef.name", routerRefIndexer).
		Build()

	r := New(k8s, nodeName, string(bgpv1alpha1.RouterRoleTenant), "2001:db8:ffff::1")

	got, err := r.BuildDesiredRouter(context.Background(), router)
	if err != nil {
		t.Fatalf("BuildDesiredRouter: unexpected error: %v (bad-adv should be skipped, not fail the whole build)", err)
	}
	if len(got.Advertisements) != 1 {
		t.Fatalf("Advertisements = %+v, want exactly 1 (bad-adv skipped, valid-adv kept)", got.Advertisements)
	}
	if got.Advertisements[0].Name != "valid-adv" {
		t.Errorf("Advertisements[0].Name = %q, want %q", got.Advertisements[0].Name, "valid-adv")
	}
}
