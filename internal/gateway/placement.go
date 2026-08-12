// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"errors"
	"hash/fnv"
	"sort"
)

// ErrNoGatewayNodes is returned by AssignPrimaryNode when given an empty
// gateway node set.
var ErrNoGatewayNodes = errors.New("gateway: no gateway nodes available for placement")

// AssignPrimaryNode deterministically selects one of gatewayNodes as the
// primary_node for vpcRef, implementing the design plan's Active-Active BGP
// model:
//
//	primary_node = hash(vpc_id) % <gateway node count>
//
// gatewayNodes is sorted internally before indexing so the result does not
// depend on the caller's (e.g. a Kubernetes List's) iteration order — only
// on the *set* of gateway node names and vpcRef. This must be called
// exactly once per NetworkRule, at creation (the NetworkRule controller
// enforces the immutability guard on status.primaryNode); calling it again
// with a different gatewayNodes set (e.g. after a node is added or
// removed) will generally produce a different assignment for the same
// vpcRef, which is why the caller must never invoke this a second time for
// an already-assigned rule.
func AssignPrimaryNode(vpcRef string, gatewayNodes []string) (string, error) {
	if len(gatewayNodes) == 0 {
		return "", ErrNoGatewayNodes
	}

	sorted := make([]string, len(gatewayNodes))
	copy(sorted, gatewayNodes)
	sort.Strings(sorted)

	h := fnv.New32a()
	_, _ = h.Write([]byte(vpcRef)) // hash.Hash32.Write never returns an error
	idx := int(h.Sum32() % uint32(len(sorted)))
	return sorted[idx], nil
}
