// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package crdnames

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

func TestServiceVIPBindingName(t *testing.T) {
	tests := []struct {
		name                 string
		nodeName, vip, proto string
		port                 int32
		want                 string
	}{
		{"IPv6", "iad-worker", "2001:db8::1", "tcp", 443, "iad-worker-2001-db8--1-tcp-443"},
		{"IPv4", "iad-worker", "203.0.113.5", "udp", 53, "iad-worker-203-0-113-5-udp-53"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ServiceVIPBindingName(tt.nodeName, tt.vip, tt.port, tt.proto)
			if got != tt.want {
				t.Errorf("ServiceVIPBindingName(%q, %q, %d, %q) = %q, want %q",
					tt.nodeName, tt.vip, tt.port, tt.proto, got, tt.want)
			}
			if strings.HasPrefix(got, "-") {
				t.Errorf("ServiceVIPBindingName(%q, %q, %d, %q) = %q starts with '-' (invalid k8s name)",
					tt.nodeName, tt.vip, tt.port, tt.proto, got)
			}
		})
	}
}

// testVPC, testVPCBase62, and testAttachment are shared across this file's
// table-driven tests — the same (vpc, attachment)-shaped fixtures recur
// across BGPVRFInstanceName/BGPAdvertisementName/TenantIdentifier. Only the
// first two go through nameSegment's hex encoding (they end up in a
// Kubernetes object name, which must be a lowercase RFC 1123 subdomain);
// TenantIdentifier deliberately doesn't — see its own doc comment.
const (
	testVPC        = "abc"
	testVPCBase62  = "0000000jU"
	testAttachment = "def"
)

func TestBGPVRFInstanceName(t *testing.T) {
	tests := []struct{ vpc, nodeName, want string }{
		{testVPC, "worker-1", "98de-worker-1"},
		{testVPCBase62, "dfw-worker", "4d2-dfw-worker"},
	}
	for _, tt := range tests {
		got := BGPVRFInstanceName(tt.vpc, tt.nodeName)
		if got != tt.want {
			t.Errorf("BGPVRFInstanceName(%q, %q) = %q, want %q", tt.vpc, tt.nodeName, got, tt.want)
		}
	}
}

// TestBGPVRFInstanceNameSharedAcrossAttachments verifies that two different
// attachments (vpcAttachment values) on the same VPC and node converge on
// the identical BGPVRFInstance name — the whole point of keying this by
// (vpc, node) instead of (vpc, vpcAttachment).
func TestBGPVRFInstanceNameSharedAcrossAttachments(t *testing.T) {
	const vpc, nodeName = testVPC, "dfw-worker"
	first := BGPVRFInstanceName(vpc, nodeName)
	second := BGPVRFInstanceName(vpc, nodeName)
	if first != second {
		t.Errorf("BGPVRFInstanceName(%q, %q) should be stable regardless of caller/attachment, got %q and %q",
			vpc, nodeName, first, second)
	}
}

func TestBGPAdvertisementName(t *testing.T) {
	tests := []struct{ vpc, attachment, want string }{
		{testVPC, testAttachment, "98de-c6a7"},
		{testVPCBase62, "00G", "4d2-2a"},
	}
	for _, tt := range tests {
		got := BGPAdvertisementName(tt.vpc, tt.attachment)
		if got != tt.want {
			t.Errorf("BGPAdvertisementName(%q, %q) = %q, want %q", tt.vpc, tt.attachment, got, tt.want)
		}
	}
}

func TestTenantIdentifier(t *testing.T) {
	tests := []struct{ vpc, attachment, want string }{
		{testVPC, testAttachment, "abc-def"},
		{testVPCBase62, "00G", "0000000jU-00G"},
	}
	for _, tt := range tests {
		got := TenantIdentifier(tt.vpc, tt.attachment)
		if got != tt.want {
			t.Errorf("TenantIdentifier(%q, %q) = %q, want %q", tt.vpc, tt.attachment, got, tt.want)
		}
	}
}

// TestTenantIdentifierDoesNotMatchBGPAdvertisementName documents a
// deliberate divergence: the two used to format a (vpc, attachment) pair
// identically, back when neither went through nameSegment's hex encoding.
// That's no longer true for BGPAdvertisementName (a Kubernetes object name,
// which must be a lowercase RFC 1123 subdomain), but TenantIdentifier (a
// label/annotation *value*, which permits uppercase) deliberately stays
// unencoded — see its own doc comment for why a plain string split
// recovering the original vpc depends on that.
func TestTenantIdentifierDoesNotMatchBGPAdvertisementName(t *testing.T) {
	const vpc, attachment = testVPC, testAttachment
	if got, other := TenantIdentifier(vpc, attachment), BGPAdvertisementName(vpc, attachment); got == other {
		t.Errorf("TenantIdentifier(%q, %q) = %q unexpectedly matches BGPAdvertisementName() -- "+
			"if nameSegment's encoding changed to make these equal again, TenantIdentifier's "+
			"raw-value recoverability guarantee needs re-verifying, not just this test updating",
			vpc, attachment, got)
	}
}

func TestEndpointSliceName(t *testing.T) {
	tests := []string{"my-pod", "web-0", "vm-workload-abc123"}
	for _, podName := range tests {
		if got := EndpointSliceName(podName); got != podName {
			t.Errorf("EndpointSliceName(%q) = %q, want %q", podName, got, podName)
		}
	}
}

// TestAnnotationKeyNameLength verifies that every annotation key builder
// stays within Kubernetes' 63-byte limit on the "name" part of an
// annotation key (the segment after the last "/"), using a realistic
// 64-character container ID (containerd/Docker use full SHA256 hex
// digests). This guards against a real production incident:
// containerIDLen was sized for the old "allocated-subnet." prefix (17
// bytes) and wasn't updated when the prefix grew by 5 bytes to
// "allocated-subnet-ipv6."/"-ipv4." — every BGPAdvertisement apply failed
// with "name part must be no more than 63 bytes" until fixed.
func TestAnnotationKeyNameLength(t *testing.T) {
	const maxAnnotationNameLen = 63
	// A realistic full-length container ID (64 hex chars, as containerd/Docker use).
	fullContainerID := strings.Repeat("a", 64)

	tests := []struct {
		name string
		key  string
	}{
		{"SubnetKeyIPv6", SubnetKeyIPv6(fullContainerID)},
		{"SubnetKeyIPv4", SubnetKeyIPv4(fullContainerID)},
		{"NetNSKey", NetNSKey(fullContainerID)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slash := strings.LastIndex(tt.key, "/")
			namePart := tt.key
			if slash != -1 {
				namePart = tt.key[slash+1:]
			}
			if len(namePart) > maxAnnotationNameLen {
				t.Errorf("%s(%d-char containerID) name part %q is %d bytes, want <= %d",
					tt.name, len(fullContainerID), namePart, len(namePart), maxAnnotationNameLen)
			}
		})
	}
}

// TestCRDNamesAreValidObjectNames covers the reason nameSegment exists: base62
// (baseconv Digits62) encodes the value 36 as "A", so a realistic randomly
// generated 48-bit VPC identifier almost always carries uppercase, and
// metadata.name must be a lowercase RFC 1123 subdomain.
func TestCRDNamesAreValidObjectNames(t *testing.T) {
	// Real base62 renderings of 48-bit VPC identifiers, plus the smallest
	// values that produce an uppercase character at all.
	vpcs := []string{"1dLaEmCAp", testVPCBase62, "A", "zZ", "ZZZZZZZZZ", "10"}
	attachments := []string{"A", "00G", "ZZZ", "20"}
	nodes := []string{"dfw-worker", "iad-worker-control-plane"}

	for _, vpc := range vpcs {
		for _, node := range nodes {
			assertValidObjectName(t, "BGPVRFInstanceName", BGPVRFInstanceName(vpc, node))
		}
		for _, att := range attachments {
			assertValidObjectName(t, "BGPAdvertisementName", BGPAdvertisementName(vpc, att))
		}
	}
}

// TestNameSegmentFallbackIsValid covers identifiers that are not valid base62
// at all (nothing in production should produce one, but a name must never be
// rejected by the API server because of it).
func TestNameSegmentFallbackIsValid(t *testing.T) {
	for _, id := range []string{"vpc-other", "", "attach-a", "Not/Base62"} {
		got := nameSegment(id)
		assertValidObjectName(t, "nameSegment", got+"-node")
		if got != nameSegment(id) {
			t.Errorf("nameSegment(%q) is not deterministic", id)
		}
		if !strings.HasPrefix(got, "x") {
			t.Errorf("nameSegment(%q) = %q, want the non-base62 fallback prefix %q", id, got, "x")
		}
	}
}

// TestNameSegmentDistinguishesCase guards the property a plain strings.ToLower
// would lose: base62 "A" is 36 and "a" is 10, two different identifiers.
func TestNameSegmentDistinguishesCase(t *testing.T) {
	if nameSegment("A") == nameSegment("a") {
		t.Errorf("nameSegment collapsed distinct base62 identifiers %q and %q onto %q", "A", "a", nameSegment("A"))
	}
}

// TestVPCSegmentSharedByBothNames is what internal/gc's orphan rule depends on:
// it matches a BGPVRFInstance against the BGPAdvertisements of the same VPC by
// cutting each name at the first '-', so both helpers must encode the VPC
// identically — including when the node name itself contains '-'.
func TestVPCSegmentSharedByBothNames(t *testing.T) {
	const vpc, att, node = "1dLaEmCAp", "2Bc", "dfw-worker-control"
	advVPC, _, _ := strings.Cut(BGPAdvertisementName(vpc, att), "-")
	vrfVPC, _, _ := strings.Cut(BGPVRFInstanceName(vpc, node), "-")
	if advVPC != vrfVPC || advVPC != VPCSegment(vpc) {
		t.Errorf("VPC segments disagree: advertisement %q, VRF instance %q, VPCSegment %q", advVPC, vrfVPC, VPCSegment(vpc))
	}
}

func assertValidObjectName(t *testing.T, who, name string) {
	t.Helper()
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		t.Errorf("%s produced %q, which is not a valid Kubernetes object name: %v", who, name, errs)
	}
	if name != strings.ToLower(name) {
		t.Errorf("%s produced %q, which contains uppercase characters", who, name)
	}
}
