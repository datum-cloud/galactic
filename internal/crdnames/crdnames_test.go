// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package crdnames

import (
	"strings"
	"testing"
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

func TestBGPVRFInstanceName(t *testing.T) {
	tests := []struct{ vpc, nodeName, want string }{
		{"abc", "worker-1", "abc-worker-1"},
		{"0000000jU", "dfw-worker", "0000000jU-dfw-worker"},
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
	const vpc, nodeName = "abc", "dfw-worker"
	first := BGPVRFInstanceName(vpc, nodeName)
	second := BGPVRFInstanceName(vpc, nodeName)
	if first != second {
		t.Errorf("BGPVRFInstanceName(%q, %q) should be stable regardless of caller/attachment, got %q and %q",
			vpc, nodeName, first, second)
	}
}

func TestBGPAdvertisementName(t *testing.T) {
	tests := []struct{ vpc, attachment, want string }{
		{"abc", "def", "abc-def"},
		{"0000000jU", "00G", "0000000jU-00G"},
	}
	for _, tt := range tests {
		got := BGPAdvertisementName(tt.vpc, tt.attachment)
		if got != tt.want {
			t.Errorf("BGPAdvertisementName(%q, %q) = %q, want %q", tt.vpc, tt.attachment, got, tt.want)
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
