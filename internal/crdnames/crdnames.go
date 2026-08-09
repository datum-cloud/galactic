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

import "fmt"

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

// BGPVRFInstanceName returns the deterministic name for a BGPVRFInstance.
// Each VPCAttachment is unique per interface across the cluster, so the
// (vpc, vpcAttachment) pair is a reliable 1:1 key.
func BGPVRFInstanceName(vpc, vpcAttachment string) string {
	return fmt.Sprintf("%s-%s", vpc, vpcAttachment)
}

// BGPAdvertisementName returns the deterministic name for a
// BGPAdvertisement. Each VPCAttachment is unique per interface across the
// cluster, so the (vpc, vpcAttachment) pair is a reliable 1:1 key.
func BGPAdvertisementName(vpc, vpcAttachment string) string {
	return fmt.Sprintf("%s-%s", vpc, vpcAttachment)
}
