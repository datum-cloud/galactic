// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package crdnames is the shared vocabulary for naming and annotating the
// BGPVRFInstance/BGPAdvertisement CRDs a VPC attachment's chain of plugins
// cooperate on: galactic-bgp writes them, galactic-ipam's deallocation path
// (until its own local marker-file persistence lands) reads the subnet
// annotations back, and galactic-router's GC controller reads the netns
// annotation to decide liveness. Kept as one small leaf package — imported
// by internal/cni, internal/cnitap, internal/cniipam, and internal/cnibgp —
// so none of those need to import each other just to agree on a name.
package crdnames

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"go.datum.net/galactic/internal/plumbing/intf"
)

// AnnotationAllocatedSubnetIPv6 is the BGPAdvertisement annotation key prefix
// holding the allocated IPv6 pod subnet CIDR (the /96) for a container ID.
// The full key appends a truncated container ID; see SubnetKeyIPv6.
const AnnotationAllocatedSubnetIPv6 = "galactic.datum.net/allocated-subnet-ipv6"

// AnnotationAllocatedSubnetIPv4 is the BGPAdvertisement annotation key prefix
// holding the allocated IPv4 pod address (the /32) for a container ID, when
// the attachment is dual-stack. The full key appends a truncated container
// ID; see SubnetKeyIPv4.
const AnnotationAllocatedSubnetIPv4 = "galactic.datum.net/allocated-subnet-ipv4"

// AnnotationNetNS is the BGPAdvertisement annotation key prefix holding the
// CNI-provided network namespace path for a container ID. The GC controller
// checks whether this exact path still exists to decide if the container is
// still live — it cannot reconstruct the path from the container ID alone,
// since netns bind-mounts are named by the runtime's own convention (e.g.
// containerd's "cni-<uuid>"), which is unrelated to the container ID. The
// full key appends a truncated container ID; see NetNSKey.
const AnnotationNetNS = "galactic.datum.net/netns"

// AnnotationNoAddressing marks a BGPAdvertisement whose spec.prefixes is
// empty by design — the attachment's config carries no "ipam" block, so no
// address was ever requested for it (a VM managing its own addressing is a
// supported case; see internal/cnitap). Unlike the annotations above, this
// one is not keyed per container ID: every container attaching under the
// same VPCAttachment shares the same master-plugin config, so they always
// agree on whether addressing was requested, and the value only needs to
// reflect the most recent ADD.
//
// Without this, an empty spec.prefixes cannot be told apart from one whose
// addressing silently failed to arrive (#342) — the same failure #327 closed
// for the case where a stale config caused it. Set to
// AnnotationNoAddressingValue whenever publishBGPState runs with a nil
// *cniipam.IPAMResult, cleared otherwise.
const AnnotationNoAddressing = "galactic.datum.net/no-addressing"

// AnnotationNoAddressingValue is the only value AnnotationNoAddressing is
// ever set to — a named constant instead of a literal "true" purely so
// callers and tests share one spelling.
const AnnotationNoAddressingValue = "true"

// containerIDLen is the number of characters used from a container ID in
// annotation keys. Kubernetes limits the name part of an annotation key to
// 63 bytes. The longest prefix sharing this constant is
// "allocated-subnet-ipv6." (or "-ipv4."), both 22 bytes, leaving 41 bytes for
// the container ID suffix — shorter prefixes ("netns.") just leave more room
// than they need.
const containerIDLen = 41

// truncate returns id, shortened to containerIDLen characters if longer.
func truncate(id string) string {
	if len(id) > containerIDLen {
		return id[:containerIDLen]
	}
	return id
}

// SubnetKeyIPv6 returns the annotation key for storing the allocated IPv6
// subnet for the given container ID.
func SubnetKeyIPv6(containerID string) string {
	return fmt.Sprintf("%s.%s", AnnotationAllocatedSubnetIPv6, truncate(containerID))
}

// SubnetKeyIPv4 returns the annotation key for storing the allocated IPv4
// address for the given container ID.
func SubnetKeyIPv4(containerID string) string {
	return fmt.Sprintf("%s.%s", AnnotationAllocatedSubnetIPv4, truncate(containerID))
}

// NetNSKey returns the annotation key for storing the network namespace path
// used by the given container ID.
func NetNSKey(containerID string) string {
	return fmt.Sprintf("%s.%s", AnnotationNetNS, truncate(containerID))
}

// nameSegmentHashLen is the number of hex characters kept from the SHA-256 fallback.
const nameSegmentHashLen = 12

// nameSegment renders a base62 identifier as the lowercase hex value it encodes, since
// metadata.name must be a lowercase RFC 1123 subdomain and base62 turns uppercase at 36.
// Input that is not valid base62 is hashed under an "x" prefix no hex encoding can produce.
func nameSegment(id string) string {
	if encoded, err := intf.Base62ToHex(id); err == nil && encoded != "" {
		return encoded
	}
	sum := sha256.Sum256([]byte(id))
	return "x" + hex.EncodeToString(sum[:])[:nameSegmentHashLen]
}

// VPCSegment returns the leading segment every BGP CRD name starts with for a base62 VPC.
func VPCSegment(vpc string) string {
	return nameSegment(vpc)
}

// BGPVRFInstanceName returns the deterministic name for a BGPVRFInstance.
// Unlike BGPAdvertisementName, this is keyed by (vpc, node) rather than
// (vpc, vpcAttachment): the underlying kernel VRF is shared by every
// attachment (pod or VM) on this VPC on this node (see internal/plumbing/vrf
// and internal/plumbing/intf's GenerateInterfaceNameVRF), so every attachment
// on the same VPC/node must resolve to the same BGPVRFInstance rather than
// creating its own. This is the one CRD name that needs node identity at
// all — the kernel side never does, since interface names only need to be
// unique within one host's own namespace.
func BGPVRFInstanceName(vpc, nodeName string) string {
	return fmt.Sprintf("%s-%s", VPCSegment(vpc), nodeName)
}

// BGPAdvertisementName returns the deterministic name for a
// BGPAdvertisement. Each VPCAttachment is unique per interface across the
// cluster, so the (vpc, vpcAttachment) pair is a reliable 1:1 key. Both segments
// are encoded by nameSegment, the VPC one identically to BGPVRFInstanceName.
func BGPAdvertisementName(vpc, vpcAttachment string) string {
	return fmt.Sprintf("%s-%s", VPCSegment(vpc), nameSegment(vpcAttachment))
}

// vipNameReplacer sanitizes an IP address for use inside a Kubernetes
// object name (RFC 1123 DNS subdomain: lowercase alphanumeric, '-', '.'
// only) -- ':' (every IPv6 address) and '.' (every IPv4 address, and the
// zone-id separator on a link-local IPv6 address) are not valid there.
var vipNameReplacer = strings.NewReplacer(":", "-", ".", "-")

// ServiceVIPBindingName returns the deterministic name for a
// ServiceVIPBinding: one binding per (node, VIP, protocol, port) tuple.
// Prefixed by nodeName (always alphanumeric) rather than the sanitized
// address directly, so an IPv6 address's leading "::" never produces a
// name starting with '-' (invalid for a Kubernetes object name).
func ServiceVIPBindingName(nodeName, vip string, port int32, proto string) string {
	return fmt.Sprintf("%s-%s-%s-%d", nodeName, vipNameReplacer.Replace(vip), proto, port)
}
