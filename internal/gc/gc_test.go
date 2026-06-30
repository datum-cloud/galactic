// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"testing"

	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testVRFName      = "G0000000jU00GV"
	testVRFNameHost  = "G0000000jU00GH"
	testVRFNameGuest = "G0000000jU00GG"
	testEth0         = "eth0"
)

func TestFindContainerID(t *testing.T) {
	tests := []struct {
		name   string
		adv    *bgpv1alpha1.BGPAdvertisement
		wantID string
	}{
		{
			name:   "nil annotations",
			adv:    &bgpv1alpha1.BGPAdvertisement{},
			wantID: "",
		},
		{
			name: "empty annotations",
			adv: &bgpv1alpha1.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
			},
			wantID: "",
		},
		{
			name: "no allocated-subnet annotation",
			adv: &bgpv1alpha1.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"galactic.datum.net/srv6-sid": "2001:db8::1234:5678",
					},
				},
			},
			wantID: "",
		},
		{
			name: "single allocated-subnet annotation",
			adv: &bgpv1alpha1.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"galactic.datum.net/allocated-subnet.abc123def456": "fd00:10:ff01::1234/80",
					},
				},
			},
			wantID: "abc123def456",
		},
		{
			name: "multiple annotations returns first",
			adv: &bgpv1alpha1.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"galactic.datum.net/allocated-subnet.aaa111bbb222": "fd00:10:ff01::1234/80",
						"galactic.datum.net/allocated-subnet.ccc333ddd444": "fd00:10:ff01::5678/80",
						"galactic.datum.net/srv6-sid":                      "2001:db8::1234:5678",
					},
				},
			},
			wantID: "aaa111bbb222",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findContainerID(tt.adv)
			if got != tt.wantID {
				t.Errorf("findContainerID() = %q, want %q", got, tt.wantID)
			}
		})
	}
}

func TestParseVRFName(t *testing.T) {
	tests := []struct {
		name       string
		vrfName    string
		wantVPC    string
		wantVPCAtt string
		wantOk     bool
	}{
		{
			name:       "valid VRF name",
			vrfName:    testVRFName,
			wantVPC:    "0000000jU",
			wantVPCAtt: "00G",
			wantOk:     true,
		},
		{
			name:       "valid VRF name with digits",
			vrfName:    "G000000123001V",
			wantVPC:    "000000123",
			wantVPCAtt: "001",
			wantOk:     true,
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
			gotVPC, gotVPCAtt, gotOk := parseVRFName(tt.vrfName)
			if gotOk != tt.wantOk {
				t.Errorf("parseVRFName(%q) ok = %v, want %v", tt.vrfName, gotOk, tt.wantOk)
				return
			}
			if gotVPC != tt.wantVPC {
				t.Errorf("parseVRFName(%q) vpc = %q, want %q", tt.vrfName, gotVPC, tt.wantVPC)
			}
			if gotVPCAtt != tt.wantVPCAtt {
				t.Errorf("parseVRFName(%q) vpcAttachment = %q, want %q", tt.vrfName, gotVPCAtt, tt.wantVPCAtt)
			}
		})
	}
}

func TestVRFNameRegex(t *testing.T) {
	// Verify the regex matches the expected VRF naming pattern.
	// The template is "G%09s%03sV" where %09s is base62-padded VPC
	// and %03s is base62-padded VPCAttachment.
	testCases := []struct {
		name   string
		input  string
		expect bool
	}{
		{testVRFName, testVRFName, true},
		{"G000000000000V", "G000000000000V", true},
		{"G123456789001V", "G123456789001V", true},
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
