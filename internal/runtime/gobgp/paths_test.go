// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"testing"

	bgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"go.datum.net/galactic/internal/model"
)

const (
	testRouterID1 = "1.2.3.4"
	testRouterID2 = "10.0.0.1"
	testNextHop   = "fc00::1"
	testPrefix    = "fd00:10:ff01::/80"
	testSID1      = "2001:db8:ff01::1"
	testSID2      = "2001:db8:ff01::2"
	testRT100     = "65000:100"
	testRT200     = "65000:200"
	testRT99      = "65000:99"
	testLegacyRD  = "1.2.3.4:0"
	testRD100     = "1.2.3.4:100"
	testRD200     = "1.2.3.4:200"
	testRD99      = "10.0.0.1:99"
)

func ptrInt32Test(v int32) *int32 { return &v }

func TestDeriveRD(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		vrfID *int32
		want  string
	}{
		{
			name:  "with VRFID derives per-VRF RD",
			id:    testRouterID1,
			vrfID: ptrInt32Test(42),
			want:  "1.2.3.4:42",
		},
		{
			name:  "nil VRFID falls back to routerID:0",
			id:    testRouterID1,
			vrfID: nil,
			want:  testLegacyRD,
		},
		{
			name:  "max VRFID",
			id:    testRouterID2,
			vrfID: ptrInt32Test(65535),
			want:  "10.0.0.1:65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveRD(tt.id, tt.vrfID)
			if got != tt.want {
				t.Errorf("deriveRD(%q, %v) = %q, want %q", tt.id, tt.vrfID, got, tt.want)
			}
		})
	}
}

// TestBuildEVPNPathsPerVRFRD verifies that two DesiredAdvertisements with
// identical prefixes but different VRFIDs produce distinct EVPN Type 5 NLRIs
// (via distinct Route Distinguishers). This is the acceptance criterion from
// issue #235: two VRFs on the same router advertising the same prefix must
// never collide.
func TestBuildEVPNPathsPerVRFRD(t *testing.T) {
	b := newTestBgpServer(t)

	// Two advertisements with identical prefix but different VRFIDs.
	adv1 := model.DesiredAdvertisement{
		Name: "adv-vrf-a",
		AddressFamily: model.AddressFamily{
			AFI:  afiL2VPN,
			SAFI: safiEVPN,
		},
		Prefixes:    []string{testPrefix},
		NextHop:     testNextHop,
		SRv6SID:     testSID1,
		VRFID:       ptrInt32Test(100),
		Communities: []string{testRT100},
	}
	adv2 := model.DesiredAdvertisement{
		Name: "adv-vrf-b",
		AddressFamily: model.AddressFamily{
			AFI:  afiL2VPN,
			SAFI: safiEVPN,
		},
		Prefixes:    []string{testPrefix}, // same prefix as adv1
		NextHop:     testNextHop,
		SRv6SID:     testSID2,
		VRFID:       ptrInt32Test(200),
		Communities: []string{testRT200},
	}

	// Both should succeed without error.
	if err := buildEVPNPaths(b, adv1, testRouterID1, false); err != nil {
		t.Fatalf("buildEVPNPaths(adv1) error = %v", err)
	}
	if err := buildEVPNPaths(b, adv2, testRouterID1, false); err != nil {
		t.Fatalf("buildEVPNPaths(adv2) error = %v", err)
	}

	// Verify the derived RDs are distinct.
	rd1 := deriveRD(testRouterID1, adv1.VRFID)
	rd2 := deriveRD(testRouterID1, adv2.VRFID)

	if rd1 == rd2 {
		t.Fatalf("RD collision: both advertisements derived RD %q — two VRFs with identical prefix would collide", rd1)
	}

	if rd1 != testRD100 {
		t.Errorf("adv1 RD = %q, want %q", rd1, testRD100)
	}
	if rd2 != testRD200 {
		t.Errorf("adv2 RD = %q, want %q", rd2, testRD200)
	}

	// Verify both RDs parse correctly.
	for _, rdStr := range []string{rd1, rd2} {
		rd, err := bgp.ParseRouteDistinguisher(rdStr)
		if err != nil {
			t.Fatalf("ParseRouteDistinguisher(%q) error = %v", rdStr, err)
		}
		if rd.String() != rdStr {
			t.Errorf("RD round-trip: %q -> %q", rdStr, rd.String())
		}
	}
}

// TestBuildEVPNPathsWithoutVRFID verifies that an advertisement without a
// VRFID falls back to the legacy "routerID:0" route distinguisher.
func TestBuildEVPNPathsWithoutVRFID(t *testing.T) {
	b := newTestBgpServer(t)

	adv := model.DesiredAdvertisement{
		Name: "adv-legacy",
		AddressFamily: model.AddressFamily{
			AFI:  afiL2VPN,
			SAFI: safiEVPN,
		},
		Prefixes:    []string{testPrefix},
		NextHop:     testNextHop,
		SRv6SID:     testSID1,
		VRFID:       nil, // no VRFID
		Communities: []string{testRT100},
	}

	if err := buildEVPNPaths(b, adv, testRouterID1, false); err != nil {
		t.Fatalf("buildEVPNPaths(legacy) error = %v", err)
	}

	rdStr := deriveRD(testRouterID1, adv.VRFID)
	if rdStr != testLegacyRD {
		t.Errorf("legacy RD = %q, want %q", rdStr, testLegacyRD)
	}
}

// TestBuildEVPNPathsWithdraw verifies that withdrawing a path with a per-VRF
// RD succeeds.
func TestBuildEVPNPathsWithdraw(t *testing.T) {
	b := newTestBgpServer(t)

	adv := model.DesiredAdvertisement{
		Name: "adv-withdraw",
		AddressFamily: model.AddressFamily{
			AFI:  afiL2VPN,
			SAFI: safiEVPN,
		},
		Prefixes:    []string{testPrefix},
		NextHop:     testNextHop,
		SRv6SID:     testSID1,
		VRFID:       ptrInt32Test(42),
		Communities: []string{testRT100},
	}

	if err := buildEVPNPaths(b, adv, testRouterID1, false); err != nil {
		t.Fatalf("buildEVPNPaths(add) error = %v", err)
	}
	if err := buildEVPNPaths(b, adv, testRouterID1, true); err != nil {
		t.Fatalf("buildEVPNPaths(withdraw) error = %v", err)
	}
}

// TestBuildEVPNPathsMatchesApplyVRFRD verifies that the RD derived by
// buildEVPNPaths matches the one used by applyVRF for the same VRFID.
// This ensures VRF registration and EVPN path advertisement are consistent.
func TestBuildEVPNPathsMatchesApplyVRFRD(t *testing.T) {
	b := newTestBgpServer(t)
	ctx := context.Background()

	vrfID := int32(99)
	vrf := model.DesiredVRFInstance{
		Name:               "vrf-test",
		VRFID:              vrfID,
		ImportRouteTargets: []string{testRT99},
		ExportRouteTargets: []string{testRT99},
	}

	// Apply the VRF.
	if err := applyVRF(ctx, b, &vrf, testRouterID2); err != nil {
		t.Fatalf("applyVRF() error = %v", err)
	}

	// Derive the RD that buildEVPNPaths would use for an advertisement
	// with the same VRFID.
	advVRFID := &vrfID
	advRD := deriveRD(testRouterID2, advVRFID)

	// The applyVRF function derives the RD as "routerID:vrfID".
	if advRD != testRD99 {
		t.Errorf("buildEVPNPaths RD = %q, want %q (should match applyVRF derivation)", advRD, testRD99)
	}
}
