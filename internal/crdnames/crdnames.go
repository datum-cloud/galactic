// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package crdnames is the shared vocabulary for naming and annotating the
// BGPVRFInstance and BGPAdvertisement CRDs a VPC attachment's chain of plugins
// cooperate on: galactic-bgp writes them, galactic-ipam's deallocation path
// reads the subnet annotations back, and galactic-router's GC reads the netns
// annotation to decide liveness. It is a leaf package so none of those need to
// import each other just to agree on a name.
package crdnames

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"go.datum.net/galactic/internal/plumbing/intf"
)

// AnnotationAllocatedSubnetIPv6 is the BGPAdvertisement annotation key prefix
// holding a container's allocated IPv6 pod subnet CIDR. The full key appends a
// truncated container ID; see SubnetKeyIPv6.
const AnnotationAllocatedSubnetIPv6 = "galactic.datum.net/allocated-subnet-ipv6"

// AnnotationAllocatedSubnetIPv4 is the BGPAdvertisement annotation key prefix
// holding a container's allocated IPv4 pod address, when the attachment is
// dual-stack. The full key appends a truncated container ID; see
// SubnetKeyIPv4.
const AnnotationAllocatedSubnetIPv4 = "galactic.datum.net/allocated-subnet-ipv4"

// AnnotationNetNS is the BGPAdvertisement annotation key prefix holding a
// container's CNI-provided network namespace path. GC checks whether that exact
// path still exists to decide whether the container is live, and cannot
// reconstruct it from the container ID, since netns bind mounts are named by
// the runtime's own convention. The full key appends a truncated container ID;
// see NetNSKey.
const AnnotationNetNS = "galactic.datum.net/netns"

// AnnotationIngressHostIfindex and AnnotationIngressHostMAC carry the two facts
// about an ingress sidecar's own pod that the host side of its return path
// needs, and that only the sidecar can read.
//
// A reply for a sidecar gateway address must be redirected into the pod holding
// it, so the host needs the ifindex of the host-side end of that pod's veth and
// the pod-side MAC to address the frame to. Both are trivial to read from
// inside the pod and unreadable from outside without entering the namespace,
// which needs CAP_SYS_ADMIN, a privilege the node agent deliberately does not
// carry.
//
// The side that can see them publishes them, on the advertisement the sidecar
// already creates for this address, so one object describes one return path.
const (
	AnnotationIngressHostIfindex = "galactic.datum.net/ingress-host-ifindex"
	AnnotationIngressHostMAC     = "galactic.datum.net/ingress-host-mac"
)

// AnnotationNoAddressing marks a BGPAdvertisement whose spec.prefixes is empty
// by design, because the attachment's config carries no "ipam" block and no
// address was ever requested. A VM managing its own addressing is a supported
// case.
//
// Without it, an empty spec.prefixes is indistinguishable from addressing that
// failed to arrive. Set to AnnotationNoAddressingValue whenever the publish
// path runs with no IPAM result, cleared otherwise.
//
// Not keyed per container ID, unlike the annotations above: every container
// under one VPCAttachment shares the master plugin's config, so they always
// agree on whether addressing was requested.
const AnnotationNoAddressing = "galactic.datum.net/no-addressing"

// AnnotationNoAddressingValue is the only value AnnotationNoAddressing is set
// to. Named so callers and tests share one spelling.
const AnnotationNoAddressingValue = "true"

// AnnotationSID is the per-pod EndpointSlice annotation holding the computed
// SRv6 uSID that routes traffic to this pod's VRF. Human-readable detail, and
// absent when this node's BGPRouter has no SRv6 locator or node ID
// configured.
const AnnotationSID = "galactic.datum.net/srv6-sid"

// LabelTenantID is the per-pod EndpointSlice label carrying the
// TenantIdentifier value, which is how the HTTP ingress extension server finds
// the EndpointSlices for a VPC attachment. A label rather than only an
// annotation, because annotations are not selectable in a List or Watch.
const LabelTenantID = "galactic.datum.net/tenant-id"

// AnnotationTenantID is the per-pod EndpointSlice annotation carrying the same
// TenantIdentifier value as LabelTenantID, as human-readable detail alongside
// the label that drives discovery.
const AnnotationTenantID = LabelTenantID

// containerIDLen is how many characters of a container ID appear in an
// annotation key. Kubernetes limits the name part of an annotation key to 63
// bytes, and the longest prefix here is 22 bytes, leaving 41 for the suffix.
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

// nameSegment renders a base62 identifier as the lowercase hex it encodes,
// since metadata.name must be a lowercase RFC 1123 subdomain and base62 turns
// uppercase at 36. Input that is not valid base62 is hashed under an "x" prefix
// no hex encoding can produce.
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

// IngressAttachment is the synthetic vpcAttachment segment the ingress sidecar
// publishes its per-VPC gateway address under. A sidecar has no real
// VPCAttachment, since no CNI ADD ever runs for it, but BGPAdvertisementName
// needs a middle segment, and one fixed value keeps the name deterministic and
// one per (VPC, node).
//
// It lives here, in the package that owns every CRD name, rather than in the
// sidecar that writes these advertisements, because the host side has to
// recognise them, and two copies of the same literal is how that recognition
// silently stops matching.
const IngressAttachment = "ingress"

// IngressAdvertisementSegment returns the middle name segment of every
// BGPAdvertisement the ingress sidecar publishes, that is, what
// BGPAdvertisementName renders IngressAttachment as. Exported so a reader can
// identify a sidecar's gateway advertisement without re-deriving the
// encoding.
func IngressAdvertisementSegment() string {
	return nameSegment(IngressAttachment)
}

// BGPVRFInstanceName returns the deterministic name for a BGPVRFInstance,
// keyed by (vpc, node). The kernel VRF is shared by every attachment, pod or
// VM, on this VPC on this node, so they must all resolve to the same
// BGPVRFInstance rather than each creating one.
func BGPVRFInstanceName(vpc, nodeName string) string {
	return fmt.Sprintf("%s-%s", VPCSegment(vpc), nodeName)
}

// BGPAdvertisementName returns the deterministic name for a BGPAdvertisement,
// keyed by (vpc, vpcAttachment, node).
//
// The node segment is required. A VPCAttachment identifies one logical
// attachment but is not unique per node: a multi-replica Deployment spread
// across nodes is ordinary, and every replica's CNI ADD carries the same
// VPCAttachment identity. Without node in the key, every node with a live
// attachment races to write one shared object, each write replacing the
// previous node's router reference and prefixes, so only the last writer is
// advertised. Traffic for the first node's local pod is then redirected to the
// second node's SID instead of delivered locally, and the second node's egress
// route registration collides with itself for the same reason.
//
// This is also why VRF-level address overlap across nodes is tolerated rather
// than prevented: two nodes may each carry local traffic for the same VPC, and
// neither advertisement may displace the other.
//
// All three segments pass through nameSegment except node, which is included
// raw, matching BGPVRFInstanceName.
func BGPAdvertisementName(vpc, vpcAttachment, nodeName string) string {
	return fmt.Sprintf("%s-%s-%s", VPCSegment(vpc), nameSegment(vpcAttachment), nodeName)
}

// vipNameReplacer sanitizes an IP address for use inside a Kubernetes object
// name, which must be an RFC 1123 DNS subdomain. Neither ':' nor '.' is valid
// there.
var vipNameReplacer = strings.NewReplacer(":", "-", ".", "-")

// ServiceVIPBindingName returns the deterministic name for a ServiceVIPBinding,
// one per (node, VIP, protocol, port). It leads with nodeName, which is always
// alphanumeric, so an IPv6 address's leading "::" never produces a name
// starting with '-'.
func ServiceVIPBindingName(nodeName, vip string, port int32, proto string) string {
	return fmt.Sprintf("%s-%s-%s-%d", nodeName, vipNameReplacer.Replace(vip), proto, port)
}

// TenantIdentifier returns the value identifying a VPC attachment across the
// EndpointSlice discovery surface: a plain (vpc, vpcAttachment) join, not run
// through nameSegment.
//
// Those that are encoded build an object name, which must be a lowercase RFC
// 1123 subdomain; this builds a label and annotation value, which permits
// uppercase. Staying unencoded also keeps it reversible: a consumer recovers
// the original vpc by splitting on the first "-", which works because both
// halves are base62 and so never contain the separator. Hex encoding would make
// that split unrecoverable.
func TenantIdentifier(vpc, vpcAttachment string) string {
	return fmt.Sprintf("%s-%s", vpc, vpcAttachment)
}

// EndpointSliceName returns the deterministic name for the per-pod
// EndpointSlice galactic-bgp publishes, a passthrough of the pod's own name
// since slices are one per pod. Centralized here like every other name in this
// package, so callers never spell the convention out themselves.
func EndpointSliceName(podName string) string {
	return podName
}

// ParseTenantIdentifier splits a TenantIdentifier value back into its vpc and
// vpcAttachment components. It is the ingress sidecar's only way to recover
// vpc, the value the kernel-side VRF primitives are keyed by, since neither the
// label nor the annotation carries vpc on its own.
//
// The split is unambiguous: both components are non-empty base62 strings, and
// base62 never contains "-", so vpc can never contain the separator the two
// halves are joined with. Nothing is lossy here, unlike recovering vpc from a
// zero-padded kernel interface name.
//
// ok is false when id contains no "-" or either half is empty.
func ParseTenantIdentifier(id string) (vpc, vpcAttachment string, ok bool) {
	vpc, vpcAttachment, found := strings.Cut(id, "-")
	if !found || vpc == "" || vpcAttachment == "" {
		return "", "", false
	}
	return vpc, vpcAttachment, true
}
