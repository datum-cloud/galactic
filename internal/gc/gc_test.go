// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/intf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testVRFName       = "G0000000jUV"
	testVRFNameLegacy = "G0000000jU00GV"
	testVRFNameHost   = "G0000000jU00GH"
	testVRFNameGuest  = "G0000000jU00GG"
	testEth0          = "eth0"
)

func TestCollectNetNSPaths(t *testing.T) {
	tests := []struct {
		name string
		adv  *bgpv1alpha1.BGPAdvertisement
		want map[string]string
	}{
		{
			name: "nil annotations",
			adv:  &bgpv1alpha1.BGPAdvertisement{},
			want: map[string]string{},
		},
		{
			name: "empty annotations",
			adv: &bgpv1alpha1.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
			want: map[string]string{},
		},
		{
			name: "no netns annotation",
			adv: &bgpv1alpha1.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"galactic.datum.net/srv6-sid": "2001:db8::1234:5678",
					},
				},
			},
			want: map[string]string{},
		},
		{
			name: "single netns annotation",
			adv: &bgpv1alpha1.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"galactic.datum.net/netns.abc123def456": "/var/run/netns/cni-1234",
					},
				},
			},
			want: map[string]string{"abc123def456": "/var/run/netns/cni-1234"},
		},
		{
			name: "multiple annotations returns all",
			adv: &bgpv1alpha1.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"galactic.datum.net/netns.aaa111bbb222": "/var/run/netns/cni-aaa",
						"galactic.datum.net/netns.ccc333ddd444": "/var/run/netns/cni-ccc",
						"galactic.datum.net/srv6-sid":           "2001:db8::1234:5678",
					},
				},
			},
			want: map[string]string{
				"aaa111bbb222": "/var/run/netns/cni-aaa",
				"ccc333ddd444": "/var/run/netns/cni-ccc",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collectNetNSPaths(tt.adv)
			if len(got) != len(tt.want) {
				t.Fatalf("collectNetNSPaths() = %v, want %v", got, tt.want)
			}
			for id, path := range tt.want {
				if got[id] != path {
					t.Errorf("collectNetNSPaths()[%q] = %q, want %q", id, got[id], path)
				}
			}
		})
	}
}

func TestParseVRFName(t *testing.T) {
	tests := []struct {
		name    string
		vrfName string
		wantVPC string
		wantOk  bool
	}{
		{
			name:    "valid VRF name",
			vrfName: testVRFName,
			wantVPC: "jU",
			wantOk:  true,
		},
		{
			name:    "valid VRF name with digits",
			vrfName: "G000000123V",
			wantVPC: "123",
			wantOk:  true,
		},
		{
			name:    "small numeric VPC (regression — GC naming mismatch)",
			vrfName: "G000000010V",
			wantVPC: "10",
			wantOk:  true,
		},
		{
			// parseVRFName must keep rejecting the legacy shape: it feeds
			// vrf.Delete, which rebuilds the current name from the VPC and
			// would no-op against a legacy interface. RemoveOrphanedVRFs
			// relies on this to route legacy names into its by-name fallback.
			name:    "legacy VRF name is not resolvable to a deletable VPC",
			vrfName: testVRFNameLegacy,
			wantOk:  false,
		},
		{
			name:    "not a VRF name (host interface)",
			vrfName: testVRFNameHost,
			wantOk:  false,
		},
		{
			name:    "not a VRF name (guest interface)",
			vrfName: testVRFNameGuest,
			wantOk:  false,
		},
		{
			name:    "random name",
			vrfName: testEth0,
			wantOk:  false,
		},
		{
			name:    "empty name",
			vrfName: "",
			wantOk:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVPC, gotOk := parseVRFName(tt.vrfName)
			if gotOk != tt.wantOk {
				t.Errorf("parseVRFName(%q) ok = %v, want %v", tt.vrfName, gotOk, tt.wantOk)
				return
			}
			if gotVPC != tt.wantVPC {
				t.Errorf("parseVRFName(%q) vpc = %q, want %q", tt.vrfName, gotVPC, tt.wantVPC)
			}
		})
	}
}

// TestVPCFromVRFName covers the collection-side name resolution, which must
// accept both the current per-VPC VRF name and the legacy pre-rename name that
// still carried a VPCAttachment segment. Both resolve to the same VPC, so a
// VRF created before the rename is judged against the same BGPAdvertisements
// as one created after it, instead of being skipped as "not a Galactic VRF"
// and stranding its routing table ID forever.
func TestVPCFromVRFName(t *testing.T) {
	tests := []struct {
		name    string
		vrfName string
		wantVPC string
		wantOk  bool
	}{
		{
			name:    "legacy VRF name resolves to the same VPC",
			vrfName: testVRFNameLegacy,
			wantVPC: "jU",
			wantOk:  true,
		},
		{
			name:    "legacy VRF name with a numeric VPC",
			vrfName: "G000000010001V",
			wantVPC: "10",
			wantOk:  true,
		},
		{
			name:    "current VRF name still resolves",
			vrfName: testVRFName,
			wantVPC: "jU",
			wantOk:  true,
		},
		{
			name:    "current VRF name with a numeric VPC still resolves",
			vrfName: "G000000010V",
			wantVPC: "10",
			wantOk:  true,
		},
		{
			name:    "host veth is still not a VRF",
			vrfName: testVRFNameHost,
			wantOk:  false,
		},
		{
			name:    "guest veth is still not a VRF",
			vrfName: testVRFNameGuest,
			wantOk:  false,
		},
		{
			name:    "random name is still not a VRF",
			vrfName: testEth0,
			wantOk:  false,
		},
		{
			name:    "empty name is still not a VRF",
			vrfName: "",
			wantOk:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVPC, gotOk := vpcFromVRFName(tt.vrfName)
			if gotOk != tt.wantOk {
				t.Errorf("vpcFromVRFName(%q) ok = %v, want %v", tt.vrfName, gotOk, tt.wantOk)
				return
			}
			if gotVPC != tt.wantVPC {
				t.Errorf("vpcFromVRFName(%q) vpc = %q, want %q", tt.vrfName, gotVPC, tt.wantVPC)
			}
		})
	}
}

func TestVRFNameRegex(t *testing.T) {
	// Verify the regex matches the expected VRF naming pattern. The template
	// is "G%09sV" where %09s is the base62-padded VPC — no VPCAttachment
	// segment, since the VRF is shared by every attachment on this VPC on
	// this node.
	testCases := []struct {
		name   string
		input  string
		expect bool
	}{
		{testVRFName, testVRFName, true},
		{"G000000000V", "G000000000V", true},
		{"G123456789V", "G123456789V", true},
		// The legacy shape is matched by legacyVRFNameRegex during
		// collection only — never by this one.
		{testVRFNameLegacy, testVRFNameLegacy, false},
		// Non-VRF names should not match.
		{testVRFNameHost, testVRFNameHost, false},
		{testVRFNameGuest, testVRFNameGuest, false},
		{testEth0, testEth0, false},
		{"vrf0", "vrf0", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := vrfNameRegex.MatchString(tc.input)
			if matches != tc.expect {
				t.Errorf("vrfNameRegex.MatchString(%q) = %v, want %v", tc.input, matches, tc.expect)
			}
		})
	}
}

// TestVPCFromName covers the shared vpc-suffix name parsing used by both
// CollectOrphanedCRDs (BGPAdvertisement's vpc-vpcAttachment,
// BGPVRFInstance's vpc-node) and CollectOrphanedVRFs.
func TestVPCFromName(t *testing.T) {
	const vpc = "abc"
	tests := []struct {
		name    string
		input   string
		wantVPC string
	}{
		{"BGPAdvertisement-shaped name", vpc + "-def", vpc},
		{"BGPVRFInstance name with a hyphenated node name", vpc + "-dfw-worker-control", vpc},
		{"no separator at all", vpc, vpc},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := vpcFromName(tt.input); got != tt.wantVPC {
				t.Errorf("vpcFromName(%q) = %q, want %q", tt.input, got, tt.wantVPC)
			}
		})
	}
}

// TestVRFNameJoinsCRDNames pins the join CollectOrphanedVRFs makes: the base62
// VPC recovered from a kernel VRF interface name has to encode to the same
// segment the BGP CRD names for that VPC start with, whether or not the
// interface name carried the template's zero padding.
func TestVRFNameJoinsCRDNames(t *testing.T) {
	for _, vpc := range []string{"1dLaEmCAp", "0000000jU"} {
		parsed, ok := vpcFromVRFName(intf.GenerateInterfaceNameVRF(vpc))
		if !ok {
			t.Fatalf("vpcFromVRFName(%q) did not match", intf.GenerateInterfaceNameVRF(vpc))
		}
		advVPC := vpcFromName(crdnames.BGPAdvertisementName(vpc, "2Bc"))
		if got := crdnames.VPCSegment(parsed); got != advVPC {
			t.Errorf("kernel VRF for VPC %q resolves to %q, but its BGPAdvertisements are named after %q", vpc, got, advVPC)
		}
	}
}

// TestVPCKeysJoinLegacyAndCurrentNames covers the upgrade window in which one
// VPC has CRDs named both before and after the name encoding changed: neither
// side may look orphaned to the other.
func TestVPCKeysJoinLegacyAndCurrentNames(t *testing.T) {
	const vpc = "10" // base62, as a pre-rename CRD name and a kernel VRF name carry it
	encoded := crdnames.VPCSegment(vpc)

	legacy := map[string]struct{}{}
	addVPC(legacy, vpc)
	if !vpcInSet(legacy, encoded) {
		t.Errorf("a current-named CRD (%q) does not join a pre-rename one (%q)", encoded, vpc)
	}

	current := map[string]struct{}{}
	addVPC(current, encoded)
	if !vpcInSet(current, vpc) {
		t.Errorf("a pre-rename CRD (%q) does not join a current-named one (%q)", vpc, encoded)
	}

	if vpcInSet(current, "zz") {
		t.Errorf("unrelated VPC %q matched the set for %q", "zz", vpc)
	}
}
