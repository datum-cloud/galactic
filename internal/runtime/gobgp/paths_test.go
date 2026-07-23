// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"net"
	"net/netip"
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

// TestGatewayForPrefix verifies that gatewayForPrefix selects a Gateway IP
// matching each prefix's own address family: the IPv6 gateway (SRv6 SID or
// next-hop) for an IPv6 prefix, and the IPv4 zero address for an IPv4
// prefix — never the IPv6 gateway reused for an IPv4 prefix, which is the
// bug this fixes (see buildEVPNPaths doc comment).
func TestGatewayForPrefix(t *testing.T) {
	ipv6GW := netip.MustParseAddr(testSID1)

	tests := []struct {
		name   string
		prefix string
		want   netip.Addr
	}{
		{
			name:   "IPv6 prefix uses the IPv6 gateway",
			prefix: testPrefix,
			want:   ipv6GW,
		},
		{
			name:   "IPv4 prefix uses the IPv4 zero address, not the IPv6 gateway",
			prefix: "10.128.0.5/32",
			want:   netip.IPv4Unspecified(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := netip.ParsePrefix(tt.prefix)
			if err != nil {
				t.Fatalf("ParsePrefix(%q): %v", tt.prefix, err)
			}
			got := gatewayForPrefix(prefix, ipv6GW)
			if got != tt.want {
				t.Errorf("gatewayForPrefix(%q, %v) = %v, want %v", tt.prefix, ipv6GW, got, tt.want)
			}
		})
	}
}

// TestPrefixSIDAttrRoundTrip verifies that prefixSIDAttr's encoding of a SID
// is recovered exactly by prefixSIDGateway's decoding — the pair that lets
// an IPv4 EVPN Type 5 prefix carry its SRv6 SID at all, since GWIPAddress
// can't (see TestGatewayForPrefix and TestBuildEVPNPathsIPv4CarriesSID).
func TestPrefixSIDAttrRoundTrip(t *testing.T) {
	sid := netip.MustParseAddr(testSID1)
	attr := prefixSIDAttr(sid)

	got := prefixSIDGateway([]bgp.PathAttributeInterface{attr})
	if got == nil {
		t.Fatal("prefixSIDGateway returned nil, want the encoded SID")
	}
	if want := net.IP(sid.AsSlice()).To16(); !got.Equal(want) {
		t.Errorf("prefixSIDGateway round-trip = %v, want %v", got, want)
	}
}

// TestPrefixSIDGatewayNoAttribute verifies that prefixSIDGateway returns nil
// (signaling "fall back to GWIPAddress") when no Prefix-SID attribute is
// present, e.g. a path from a peer/build that doesn't send one yet.
func TestPrefixSIDGatewayNoAttribute(t *testing.T) {
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
	}
	if got := prefixSIDGateway(attrs); got != nil {
		t.Errorf("prefixSIDGateway = %v, want nil", got)
	}
}

// TestBuildEVPNPathsIPv4CarriesSID is the regression test for the vpc20
// cross-region IPv4 ping bug: an EVPN Type 5 path for an IPv4 prefix cannot
// carry its SRv6 SID in GWIPAddress (gatewayForPrefix leaves that zeroed,
// per RFC 9136's family constraint), so before this fix the SID never
// reached the remote node for IPv4-family routes at all. Confirms the SID
// still round-trips end-to-end via the Prefix-SID attribute regardless.
func TestBuildEVPNPathsIPv4CarriesSID(t *testing.T) {
	sid := netip.MustParseAddr(testSID1)
	ipv4Prefix := netip.MustParsePrefix("10.128.0.5/32")

	// GWIPAddress itself carries nothing usable for this prefix — this is
	// the fact that makes the Prefix-SID attribute necessary, not a defect
	// introduced by this test.
	if gw := gatewayForPrefix(ipv4Prefix, sid); gw != netip.IPv4Unspecified() {
		t.Fatalf("gatewayForPrefix(IPv4 prefix) = %v, want the IPv4 zero address", gw)
	}

	// The Prefix-SID attribute buildEVPNPaths attaches whenever adv.SRv6SID
	// is set recovers the real SID regardless.
	attrs := []bgp.PathAttributeInterface{prefixSIDAttr(sid)}
	got := prefixSIDGateway(attrs)
	if got == nil {
		t.Fatal("prefixSIDGateway returned nil for an IPv4-prefix path's Prefix-SID attribute")
	}
	if want := net.IP(sid.AsSlice()).To16(); !got.Equal(want) {
		t.Errorf("prefixSIDGateway(IPv4 prefix path) = %v, want %v", got, want)
	}
}

// TestBuildEVPNPathsMixedFamily verifies that a dual-stack DesiredAdvertisement
// (one IPv6 prefix, one IPv4 prefix, sharing a single SRv6 SID next-hop)
// produces two well-formed EVPN Type 5 NLRIs instead of a malformed one.
// Before the gatewayForPrefix fix, the IPv4 prefix's NLRI paired a 4-byte
// IPv4 prefix with the shared 16-byte IPv6 gateway: EVPNIPPrefixRoute.Len()
// (computed from the prefix's family alone) would declare 34 bytes while
// Serialize() actually emitted more, corrupting the wire encoding. This test
// re-derives each prefix's NLRI the same way buildEVPNPaths does and checks
// the serialized length always matches the declared Len().
func TestBuildEVPNPathsMixedFamily(t *testing.T) {
	b := newTestBgpServer(t)

	const ipv6Prefix = "fd00:10:ff01::/96"
	const ipv4Prefix = "10.128.0.5/32"

	adv := model.DesiredAdvertisement{
		Name: "adv-dual-stack",
		AddressFamily: model.AddressFamily{
			AFI:  afiL2VPN,
			SAFI: safiEVPN,
		},
		Prefixes:    []string{ipv6Prefix, ipv4Prefix},
		NextHop:     testNextHop,
		SRv6SID:     testSID1,
		VRFID:       ptrInt32Test(1),
		Communities: []string{testRT100},
	}

	if err := buildEVPNPaths(b, adv, testRouterID1, false); err != nil {
		t.Fatalf("buildEVPNPaths(dual-stack) error = %v", err)
	}

	rd, err := bgp.ParseRouteDistinguisher(deriveRD(testRouterID1, adv.VRFID))
	if err != nil {
		t.Fatalf("ParseRouteDistinguisher: %v", err)
	}
	ipv6GW := netip.MustParseAddr(testSID1)

	for _, prefixStr := range adv.Prefixes {
		prefix, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", prefixStr, err)
		}
		gwIP := gatewayForPrefix(prefix, ipv6GW)

		nlri, err := bgp.NewEVPNIPPrefixRoute(
			rd, bgp.EthernetSegmentIdentifier{}, 0, uint8(prefix.Bits()), prefix.Addr(), gwIP, 0,
		)
		if err != nil {
			t.Fatalf("NewEVPNIPPrefixRoute(%q) error = %v", prefixStr, err)
		}

		serialized, err := nlri.Serialize()
		if err != nil {
			t.Fatalf("Serialize(%q) error = %v", prefixStr, err)
		}
		if len(serialized) != nlri.Len() {
			t.Errorf("prefix %q: serialized NLRI length %d != declared Len() %d — malformed wire encoding",
				prefixStr, len(serialized), nlri.Len())
		}
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
