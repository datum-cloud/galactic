// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import "net"

// DesiredRoute is the desired SRv6 egress-route state for one pod, derived from
// a single EndpointSlice. The store keys each by that slice's namespace and
// name; VPC is the coarser key its VRF device lifecycle rolls up to.
type DesiredRoute struct {
	// VPC is the base62 VPC identifier this pod is attached to, recovered from
	// the tenant identifier. Never the combined identifier itself, which no
	// kernel-side primitive here accepts.
	VPC string
	// Prefix is the pod's own address as a host route, these backends being
	// IPv6-only. Never a subnet aggregate, since none exists: SIDs vary per
	// hosting node, so pods of one tenant on different nodes need independent
	// routes even though they share a VPC.
	Prefix *net.IPNet
	// SID is the pod's own computed SRv6 uSID — the seg6 encap gateway
	// address for Prefix's route.
	SID net.IP
}
