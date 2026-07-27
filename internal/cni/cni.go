// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"

	"go.datum.net/galactic/internal/metadata"
)

const cniTimeout = 10 * time.Second

// ipamTypeStatic is the ipam type for a single pre-assigned static address.
// Any other (or empty) IPAM.Type value takes the pool-based dual-stack path
// — see wantsIPAM/allocateIPAM in ipam_ops.go.
const ipamTypeStatic = "static"

// localIPAMDefaultPool is the IPv6 CIDR pool used when local IPAM is enabled
// but IPv6Subnet is unset in the CNI config. Allocations from it use
// ipam.DefaultSubnetLen (/96).
const localIPAMDefaultPool = "fd00:10:ff01::/64"

const (
	// annotationAllocatedSubnetIPv6 is the BGPAdvertisement annotation key
	// prefix holding the allocated IPv6 pod subnet CIDR (the /96) for a
	// container ID. The full key appends a truncated container ID; see
	// subnetAnnotationKeyIPv6.
	annotationAllocatedSubnetIPv6 = "galactic.datum.net/allocated-subnet-ipv6"

	// annotationAllocatedSubnetIPv4 is the BGPAdvertisement annotation key
	// prefix holding the allocated IPv4 pod address (the /32) for a
	// container ID, when the attachment is dual-stack. The full key appends
	// a truncated container ID; see subnetAnnotationKeyIPv4.
	annotationAllocatedSubnetIPv4 = "galactic.datum.net/allocated-subnet-ipv4"

	// annotationNetNS is the BGPAdvertisement annotation key prefix holding
	// the CNI-provided network namespace path for a container ID. The GC
	// controller checks whether this exact path still exists to decide if
	// the container is still live — it cannot reconstruct the path from the
	// container ID alone, since netns bind-mounts are named by the
	// runtime's own convention (e.g. containerd's "cni-<uuid>"), which is
	// unrelated to the container ID. The full key appends a truncated
	// container ID; see netnsAnnotationKey.
	annotationNetNS = "galactic.datum.net/netns"

	// annotationContainerIDLen is the number of characters used from a
	// container ID in annotation keys. Kubernetes limits the name part of an
	// annotation key to 63 bytes; "allocated-subnet." is 17 bytes, leaving 46
	// bytes for the container ID prefix.
	annotationContainerIDLen = 46
)

const (
	// interfaceTypeVeth is the default interface type: veth pair for containers.
	interfaceTypeVeth = "veth"
	// interfaceTypeTap is the tap interface type: L2 fd for VMs (Kata, Firecracker).
	interfaceTypeTap = "tap"
)

// RunPlugin starts the CNI plugin, handling ADD, DEL, CHECK, and STATUS operations.
func RunPlugin() {
	skel.PluginMainFuncs(
		skel.CNIFuncs{
			Add:    cmdAdd,
			Check:  cmdCheck,
			Del:    cmdDel,
			Status: cmdStatus,
		},
		version.All,
		"CNI galactic plugin "+metadata.Version,
	)
}
