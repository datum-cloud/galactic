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

// ipamTypePool is the ipam type for the built-in local IPAM pool allocator.
const ipamTypePool = "pool"

const (
	// localIPAMDefaultPool is the IPv6 CIDR pool used when local IPAM is
	// enabled but no explicit ipam block is present in the CNI config.
	localIPAMDefaultPool = "fd00:10:ff01::/48"

	// localIPAMDefaultSubnetLen is the default prefix length for local IPAM
	// allocations (default /80, giving 2^48 addresses per pod subnet).
	localIPAMDefaultSubnetLen = 80
)

const (
	// annotationAllocatedSubnet is the BGPAdvertisement annotation key prefix
	// holding the allocated pod subnet CIDR for a container ID. The full key
	// appends a truncated container ID; see subnetAnnotationKey.
	annotationAllocatedSubnet = "galactic.datum.net/allocated-subnet"

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

	// cniVersion100 is the CNI spec version this plugin reports.
	cniVersion100 = "1.0.0"
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
