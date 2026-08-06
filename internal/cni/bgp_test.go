// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/srv6"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// ---- ipv4GatewayAddrParams ------------------------------------------------

func TestIPv4GatewayAddrParams(t *testing.T) {
	tests := []struct {
		name      string
		hostLink  netlink.Link
		wantMask  net.IPMask
		wantFlags int
	}{
		{
			name:      "tap gets /25 with NOPREFIXROUTE",
			hostLink:  &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: "tap0"}},
			wantMask:  net.CIDRMask(25, 32),
			wantFlags: unix.IFA_F_NOPREFIXROUTE,
		},
		{
			name:      "veth gets /32 with no flags",
			hostLink:  &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "veth0"}},
			wantMask:  net.CIDRMask(32, 32),
			wantFlags: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMask, gotFlags := ipv4GatewayAddrParams(tt.hostLink)
			if gotMask.String() != tt.wantMask.String() {
				t.Errorf("mask = %v, want %v", gotMask, tt.wantMask)
			}
			if gotFlags != tt.wantFlags {
				t.Errorf("flags = %v, want %v", gotFlags, tt.wantFlags)
			}
		})
	}
}

// ---- routeConflicts ------------------------------------------------------

func TestRouteConflicts(t *testing.T) {
	dst := mustParseCIDR(t, "fd00:10:ff01::1234/80")
	gw1 := net.ParseIP("fd00:10:ff01::1")
	gw2 := net.ParseIP("fd00:10:ff01::2")
	otherDst := mustParseCIDR(t, "fd00:10:ff02::1234/80")

	tests := []struct {
		name     string
		existing *netlink.Route
		desired  *netlink.Route
		want     bool
	}{
		{
			name:     "nil existing destination — no conflict",
			existing: &netlink.Route{Dst: nil},
			desired:  &netlink.Route{Dst: dst},
			want:     false,
		},
		{
			name:     "nil desired destination — no conflict",
			existing: &netlink.Route{Dst: dst},
			desired:  &netlink.Route{Dst: nil},
			want:     false,
		},
		{
			name:     "different destinations — no conflict",
			existing: &netlink.Route{Dst: otherDst},
			desired:  &netlink.Route{Dst: dst},
			want:     false,
		},
		{
			name:     "same destination, no gateway on either — no conflict",
			existing: &netlink.Route{Dst: dst, LinkIndex: 5},
			desired:  &netlink.Route{Dst: dst, LinkIndex: 5},
			want:     false,
		},
		{
			name:     "same destination, same gateway — no conflict",
			existing: &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 5},
			desired:  &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 5},
			want:     false,
		},
		{
			name:     "same destination, different gateway — conflict",
			existing: &netlink.Route{Dst: dst, Gw: gw1},
			desired:  &netlink.Route{Dst: dst, Gw: gw2},
			want:     true,
		},
		{
			name:     "existing has gateway, desired does not — conflict",
			existing: &netlink.Route{Dst: dst, Gw: gw1},
			desired:  &netlink.Route{Dst: dst},
			want:     true,
		},
		{
			name:     "desired has gateway, existing does not — conflict",
			existing: &netlink.Route{Dst: dst},
			desired:  &netlink.Route{Dst: dst, Gw: gw1},
			want:     true,
		},
		{
			name:     "same destination, same gateway, different link index — conflict",
			existing: &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 5},
			desired:  &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 7},
			want:     true,
		},
		{
			name:     "same destination, gateway set, link index zero on existing — no conflict",
			existing: &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 0},
			desired:  &netlink.Route{Dst: dst, Gw: gw1, LinkIndex: 5},
			want:     false,
		},
		{
			name:     "same destination, no gateway, different link index — conflict",
			existing: &netlink.Route{Dst: dst, LinkIndex: 5},
			desired:  &netlink.Route{Dst: dst, LinkIndex: 7},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := routeConflicts(tt.existing, tt.desired)
			if got != tt.want {
				t.Errorf("routeConflicts() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---- vrfIDFromAttachment --------------------------------------------------

func TestVRFIDFromAttachment(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int32
		wantErr string
	}{
		{
			name:  "valid base62 decodes to VRFID",
			input: "jU", // 1234 decimal; see internal/plumbing/intf fixtures
			want:  1234,
		},
		{
			name:    "invalid base62 fails to decode",
			input:   testInvalidBase62,
			wantErr: "decode VPCAttachment",
		},
		{
			name:    "value exceeding 16 bits is rejected",
			input:   mustHexToBase62(t, "10000"), // 65536, out of range for VRFID
			wantErr: "parse VPCAttachment hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vrfIDFromAttachment(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("vrfIDFromAttachment(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func mustHexToBase62(t *testing.T, hex string) string {
	t.Helper()
	b62, err := intf.HexToBase62(hex)
	if err != nil {
		t.Fatalf("HexToBase62(%q): %v", hex, err)
	}
	return b62
}

// ---- resolveSRv6SID --------------------------------------------------------

func TestResolveSRv6SID(t *testing.T) {
	const locator = "fd00:10::/48"
	const nodeID, vrfID = int32(7), int32(1234)

	computed, err := srv6.ComputeSID(locator, nodeID, vrfID, bgpv1alpha1.SRv6FunctionEndDT46)
	if err != nil {
		t.Fatalf("srv6.ComputeSID setup: %v", err)
	}

	tests := []struct {
		name    string
		bgp     bgpConfig
		vrfID   int32
		want    string
		wantErr string
	}{
		{
			name:  "computed from router locator+nodeID when explicit is empty",
			bgp:   bgpConfig{srv6Locator: locator, nodeID: nodeID},
			vrfID: vrfID,
			want:  computed.String(),
		},
		{
			name:  "no locator configured on router — SID skipped",
			bgp:   bgpConfig{nodeID: nodeID},
			vrfID: vrfID,
			want:  "",
		},
		{
			name:  "no nodeID configured on router — SID skipped",
			bgp:   bgpConfig{srv6Locator: locator},
			vrfID: vrfID,
			want:  "",
		},
		{
			name:    "ComputeSID error propagates",
			bgp:     bgpConfig{srv6Locator: "fd00:10::/33", nodeID: nodeID}, // not byte-aligned
			vrfID:   vrfID,
			wantErr: "compute SRv6 SID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveSRv6SID(tt.bgp, tt.vrfID)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("resolveSRv6SID() = %q, want %q", got, tt.want)
			}
		})
	}

}

// ---- buildVRFInstanceSpec ---------------------------------------------------

func TestBuildVRFInstanceSpec(t *testing.T) {
	spec := buildVRFInstanceSpec(testRouterName, testRD65000_1, 1234)

	if spec.RouterRef == nil || spec.RouterRef.Name != testRouterName {
		t.Errorf("RouterRef = %+v, want Name %q", spec.RouterRef, testRouterName)
	}
	if spec.RouterSelector != nil {
		t.Errorf("RouterSelector = %+v, want nil", spec.RouterSelector)
	}
	if spec.VRFID != 1234 {
		t.Errorf("VRFID = %d, want 1234", spec.VRFID)
	}
	if len(spec.ImportRouteTargets) != 1 || spec.ImportRouteTargets[0].Value != testRD65000_1 {
		t.Errorf("ImportRouteTargets = %+v, want [{%q}]", spec.ImportRouteTargets, testRD65000_1)
	}
	if len(spec.ExportRouteTargets) != 1 || spec.ExportRouteTargets[0].Value != testRD65000_1 {
		t.Errorf("ExportRouteTargets = %+v, want [{%q}]", spec.ExportRouteTargets, testRD65000_1)
	}
}

// ---- ipamAdvertisementPrefixes ----------------------------------------------

func TestIPAMAdvertisementPrefixesNil(t *testing.T) {
	prefixes, ipv6Subnet, ipv4Addr := ipamAdvertisementPrefixes(nil)
	if prefixes != nil {
		t.Errorf("prefixes = %v, want nil", prefixes)
	}
	if ipv6Subnet != "" || ipv4Addr != "" {
		t.Errorf("ipv6Subnet, ipv4Addr = %q, %q, want empty strings", ipv6Subnet, ipv4Addr)
	}
}

func TestIPAMAdvertisementPrefixesIPv4Only(t *testing.T) {
	res := &ipamResult{ipv4Address: net.ParseIP("10.128.0.5")}

	prefixes, ipv6Subnet, ipv4Addr := ipamAdvertisementPrefixes(res)

	if ipv6Subnet != "" {
		t.Errorf("ipv6Subnet = %q, want empty", ipv6Subnet)
	}
	if ipv4Addr != "10.128.0.5" {
		t.Errorf("ipv4Addr = %q, want 10.128.0.5", ipv4Addr)
	}
	if len(prefixes) != 1 || prefixes[0] != "10.128.0.5/32" {
		t.Errorf("prefixes = %v, want exactly [\"10.128.0.5/32\"] (no panic, no empty-prefixes case)", prefixes)
	}
}

func TestIPAMAdvertisementPrefixesDualStack(t *testing.T) {
	ipv6Subnet := mustParseCIDR(t, "fd00:10:ff01::1234/96")
	res := &ipamResult{ipv6Subnet: ipv6Subnet, ipv4Address: net.ParseIP("10.128.0.5")}

	prefixes, gotIPv6Subnet, gotIPv4Addr := ipamAdvertisementPrefixes(res)

	if gotIPv6Subnet != ipv6Subnet.String() {
		t.Errorf("ipv6Subnet = %q, want %q", gotIPv6Subnet, ipv6Subnet.String())
	}
	if gotIPv4Addr != "10.128.0.5" {
		t.Errorf("ipv4Addr = %q, want 10.128.0.5", gotIPv4Addr)
	}
	if len(prefixes) != 2 || prefixes[0] != ipv6Subnet.String() || prefixes[1] != "10.128.0.5/32" {
		t.Errorf("prefixes = %v, want [%q, \"10.128.0.5/32\"]", prefixes, ipv6Subnet.String())
	}
}

// ---- allAdvertisedPrefixes ---------------------------------------------------

func TestAllAdvertisedPrefixesEmpty(t *testing.T) {
	if got := allAdvertisedPrefixes(nil); got != nil {
		t.Errorf("prefixes = %v, want nil", got)
	}
	if got := allAdvertisedPrefixes(map[string]string{}); got != nil {
		t.Errorf("prefixes = %v, want nil", got)
	}
}

func TestAllAdvertisedPrefixesSingleContainer(t *testing.T) {
	const v6, v4 = "fd00:20:ff01::1234/96", "172.20.1.5"
	annotations := map[string]string{
		netnsAnnotationKey("cid-a"):      testNetns,
		subnetAnnotationKeyIPv6("cid-a"): v6,
		subnetAnnotationKeyIPv4("cid-a"): v4,
	}

	got := allAdvertisedPrefixes(annotations)

	want := []string{v4 + "/32", v6}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prefixes = %v, want %v", got, want)
	}
}

// TestAllAdvertisedPrefixesMultipleContainers is the regression test for the
// bug this function fixes: a second container attaching under the same
// (vpc, vpcAttachment) — and thus sharing this BGPAdvertisement CRD — must
// not cause the first, still-live container's prefix to disappear from
// Spec.Prefixes. See allAdvertisedPrefixes's doc comment.
func TestAllAdvertisedPrefixesMultipleContainers(t *testing.T) {
	const aV4, bV6, bV4 = "172.20.1.5", "fd00:20:ff01::1234/96", "172.21.1.2"
	annotations := map[string]string{
		netnsAnnotationKey("cid-a"):        testNetns,
		subnetAnnotationKeyIPv4("cid-a"):   aV4,
		netnsAnnotationKey("cid-b"):        testNetns,
		subnetAnnotationKeyIPv6("cid-b"):   bV6,
		subnetAnnotationKeyIPv4(("cid-b")): bV4,
	}

	got := allAdvertisedPrefixes(annotations)

	want := []string{aV4 + "/32", bV4 + "/32", bV6}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prefixes = %v, want %v (a second container's annotations must not drop the first's prefix)", got, want)
	}
}

func TestAllAdvertisedPrefixesIgnoresOtherAnnotations(t *testing.T) {
	const v4 = "172.20.1.5"
	annotations := map[string]string{
		netnsAnnotationKey("cid-a"):      testNetns,
		subnetAnnotationKeyIPv4("cid-a"): v4,
		"some.other/annotation":          "should be ignored",
	}

	got := allAdvertisedPrefixes(annotations)

	want := []string{v4 + "/32"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prefixes = %v, want %v", got, want)
	}
}

// ---- buildAdvertisementSpec -------------------------------------------------

func TestBuildAdvertisementSpec(t *testing.T) {
	const podSubnet = "fd00:10:ff01::1234/80"
	spec := buildAdvertisementSpec(testRouterName, testRD65000_1, []string{podSubnet}, 1234)

	if spec.RouterRef.Name != testRouterName {
		t.Errorf("RouterRef.Name = %q, want %q", spec.RouterRef.Name, testRouterName)
	}
	if spec.AddressFamily.AFI != bgpv1alpha1.AFIL2VPN || spec.AddressFamily.SAFI != bgpv1alpha1.SAFIEVPN {
		t.Errorf("AddressFamily = %+v, want L2VPN/EVPN", spec.AddressFamily)
	}
	if len(spec.Prefixes) != 1 || string(spec.Prefixes[0]) != podSubnet {
		t.Errorf("Prefixes = %+v, want [%q]", spec.Prefixes, podSubnet)
	}
	if len(spec.Communities) != 1 || string(spec.Communities[0]) != testRD65000_1 {
		t.Errorf("Communities = %+v, want [%q]", spec.Communities, testRD65000_1)
	}
	if spec.VRFID == nil || *spec.VRFID != 1234 {
		t.Errorf("VRFID = %v, want pointer to 1234", spec.VRFID)
	}
	if spec.Function == nil || *spec.Function != bgpv1alpha1.SRv6FunctionEndDT46 {
		t.Errorf("Function = %v, want pointer to %q", spec.Function, bgpv1alpha1.SRv6FunctionEndDT46)
	}
}

func TestBuildAdvertisementSpecDualStack(t *testing.T) {
	const ipv6Prefix = "fd00:10:ff01::1234/96"
	const ipv4Prefix = "10.128.0.5/32"
	spec := buildAdvertisementSpec(testRouterName, testRD65000_1, []string{ipv6Prefix, ipv4Prefix}, 1234)

	if len(spec.Prefixes) != 2 {
		t.Fatalf("Prefixes = %+v, want 2 entries", spec.Prefixes)
	}
	if string(spec.Prefixes[0]) != ipv6Prefix {
		t.Errorf("Prefixes[0] = %q, want %q", spec.Prefixes[0], ipv6Prefix)
	}
	if string(spec.Prefixes[1]) != ipv4Prefix {
		t.Errorf("Prefixes[1] = %q, want %q", spec.Prefixes[1], ipv4Prefix)
	}
}
