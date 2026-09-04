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

// AnnotationIngressHostIfindex and AnnotationIngressHostMAC are the
// BGPAdvertisement annotations the ingress sidecar records the two facts
// about its own pod that the host side of its return path needs, and that
// only the sidecar can read.
//
// A reply for a sidecar gateway address has to be redirected into the pod
// that holds it, which means the host needs the ifindex of the host-side
// end of that pod's netns-crossing veth, and the pod-side MAC to address
// the frame to. Both are trivially readable from inside the pod (the
// primary interface's peer index and its own hardware address) and not
// readable from outside it without entering the namespace, which needs
// CAP_SYS_ADMIN -- a privilege the node agent deliberately does not carry
// (its container drops ALL and adds only BPF, NET_ADMIN and NET_RAW).
//
// So the side that can see them publishes them, rather than the side that
// cannot being given the privilege to go and look. Recorded on the
// advertisement the sidecar already creates for this address, keyed the
// same way, so there is one object describing one return path.
const (
	AnnotationIngressHostIfindex = "galactic.datum.net/ingress-host-ifindex"
	AnnotationIngressHostMAC     = "galactic.datum.net/ingress-host-mac"
)

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

// AnnotationSID is the per-pod EndpointSlice annotation key holding the
// computed SRv6 uSID (see internal/plumbing/srv6.ComputeSID) that routes
// traffic to this pod's VRF — human-readable detail, matching the
// annotation-based pattern used elsewhere in this package. Not present when
// this node's BGPRouter has no SRv6Locator/nodeID configured (see
// registerEBPFDatapath's own skip case in internal/cnibgp/bgp.go).
const AnnotationSID = "galactic.datum.net/srv6-sid"

// LabelTenantID is the per-pod EndpointSlice label carrying the same value
// as TenantIdentifier(vpc, vpcAttachment) — the discovery mechanism the HTTP
// ingress extension server watches/indexes on to find the EndpointSlices for
// a given VPC attachment. A label, not only an annotation, because
// annotations aren't selectable in a k8s List/Watch call.
const LabelTenantID = "galactic.datum.net/tenant-id"

// AnnotationTenantID is the per-pod EndpointSlice annotation carrying the
// same TenantIdentifier(vpc, vpcAttachment) value as LabelTenantID —
// human-readable detail alongside the label that actually drives discovery.
const AnnotationTenantID = LabelTenantID

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

// IngressAttachment is the synthetic vpcAttachment segment the ingress
// sidecar publishes its own per-VPC gateway address under. A sidecar has no
// real VPCAttachment -- it is not a tenant workload and no CNI ADD ever runs
// for it -- but BGPAdvertisementName needs a middle segment, and one fixed
// value keeps the name deterministic and one-per-(VPC, node).
//
// Defined here, in the package that owns every CRD name, rather than in
// internal/ingresssidecar which writes these advertisements: the host side
// (internal/installer's sidecar return path) has to *recognize* them, and
// two independently-maintained copies of the same literal is exactly how
// that recognition silently stops matching.
const IngressAttachment = "ingress"

// IngressAdvertisementSegment is the middle name segment of every
// BGPAdvertisement the ingress sidecar publishes, i.e. what
// BGPAdvertisementName renders IngressAttachment as. Exported so a reader
// can identify a sidecar's own gateway advertisement among the ones this
// node originates, without re-deriving the encoding.
func IngressAdvertisementSegment() string {
	return nameSegment(IngressAttachment)
}

// BGPVRFInstanceName returns the deterministic name for a BGPVRFInstance.
// This is keyed by (vpc, node): the underlying kernel VRF is shared by every
// attachment (pod or VM) on this VPC on this node (see internal/plumbing/vrf
// and internal/plumbing/intf's GenerateInterfaceNameVRF), so every attachment
// on the same VPC/node must resolve to the same BGPVRFInstance rather than
// creating its own.
func BGPVRFInstanceName(vpc, nodeName string) string {
	return fmt.Sprintf("%s-%s", VPCSegment(vpc), nodeName)
}

// BGPAdvertisementName returns the deterministic name for a
// BGPAdvertisement. Keyed by (vpc, vpcAttachment, node) -- node included for
// the same reason BGPVRFInstanceName needs it (see that function's own
// doc comment): a VPCAttachment identifies one logical attachment, but
// nothing about that guarantees it is unique per *node* -- a multi-replica
// Deployment scheduled across several nodes is the ordinary case, not an
// edge case, and every replica's CNI ADD shares the very same VPCAttachment
// identity from the CNI config on its own node.
//
// Before node was part of this key, every node with a live attachment to
// the same VPCAttachment raced to CreateOrUpdate the *same* BGPAdvertisement
// object: each write clobbered the previous node's RouterRef/prefixes
// wholesale, so only the last writer's node was ever actually advertised —
// every other node's own attachment silently vanished from BGP the moment
// a second node's ADD ran: a second node's attachment to a VPC that already
// had one elsewhere would overwrite the first's BGPAdvertisement, and from
// that point on BGP would advertise only the second node's SID for both —
// traffic destined for the first node's own local pod would get redirected
// to the second node's own uSID SID instead of ever being delivered
// locally, and the second node's own egress_route_table registration for
// its "own" prefix would then collide with itself for the same underlying
// reason (two attachments, one shared key, one winner). This is also why
// VRF-level address overlap across nodes must be tolerated, not prevented:
// two nodes are allowed to each
// have their own local traffic to/from the same VPC, and neither one's
// BGPAdvertisement is allowed to silently displace the other's.
//
// All three segments are encoded by nameSegment (the VPC one identically to
// BGPVRFInstanceName); node is included raw, unencoded, matching
// BGPVRFInstanceName's own convention.
func BGPAdvertisementName(vpc, vpcAttachment, nodeName string) string {
	return fmt.Sprintf("%s-%s-%s", VPCSegment(vpc), nameSegment(vpcAttachment), nodeName)
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

// TenantIdentifier returns the deterministic value used to identify a VPC
// attachment across the EndpointSlice discovery surface (LabelTenantID/
// AnnotationTenantID) — a plain (vpc, vpcAttachment) join, deliberately
// *not* run through nameSegment like BGPVRFInstanceName/BGPAdvertisementName
// are. Those two build a Kubernetes object *name*, which must be a
// lowercase RFC 1123 subdomain and so needs nameSegment's hex-safe encoding;
// this builds a label/annotation *value*, which permits uppercase and has
// no such constraint. Staying unencoded matters for a second reason: a
// consumer recovering the original vpc from this value only has to split on
// the first "-", which works because vpc/vpcAttachment are both base62
// ([0-9a-zA-Z]) and therefore never contain that separator themselves —
// nameSegment's hex encoding would make that split unrecoverable back to
// the original vpc.
func TenantIdentifier(vpc, vpcAttachment string) string {
	return fmt.Sprintf("%s-%s", vpc, vpcAttachment)
}

// EndpointSliceName returns the deterministic name for the per-pod
// discoveryv1.EndpointSlice published by galactic-bgp — a trivial
// passthrough of the pod's own name (EndpointSlices are 1:1 with a pod, one
// per namespace), centralized here like every other name in this package so
// callers never spell the convention out themselves.
func EndpointSliceName(podName string) string {
	return podName
}

// ParseTenantIdentifier splits a TenantIdentifier(vpc, vpcAttachment) value
// back into its vpc and vpcAttachment components. This is the ingress
// sidecar's (#855) only way to recover vpc — the value the kernel-side VRF
// primitives are actually keyed by, per docs/plans/855-ingress-sidecar-vpc-
// backend-connectivity.md §1/§2 — since neither LabelTenantID nor
// AnnotationTenantID carries vpc on its own, only the combined identifier.
//
// The split is unambiguous: both components are non-empty base62 strings
// ([0-9a-zA-Z], see internal/cnimaster.IsValidBase62) and base62 never
// contains "-", so vpc can never itself contain the separator
// TenantIdentifier joins the two halves with. This is a stronger guarantee
// than internal/gc's vpcFromVRFName has to work with — that one recovers vpc
// from a zero-padded, lossy kernel interface name and has to tolerate
// stripping leading zeros; this recovers it from the same unpadded string
// TenantIdentifier itself produced, so there is nothing lossy to correct
// for.
//
// Returns ok=false if id contains no "-" or either resulting half is empty.
func ParseTenantIdentifier(id string) (vpc, vpcAttachment string, ok bool) {
	vpc, vpcAttachment, found := strings.Cut(id, "-")
	if !found || vpc == "" || vpcAttachment == "" {
		return "", "", false
	}
	return vpc, vpcAttachment, true
}
