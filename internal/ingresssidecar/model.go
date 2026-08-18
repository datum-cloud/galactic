// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import "net"

// DesiredRoute is the desired SRv6 egress-route state for one pod, derived
// from a single EndpointSlice — see BuildDesiredRoute. Store.SetDesired
// keys each DesiredRoute by that EndpointSlice's own namespace/name; VPC is
// the separate, coarser key its VRF device lifecycle rolls up to (see
// Store's doc comment and §1 of the plan).
type DesiredRoute struct {
	// VPC is the base62 VPC identifier this pod is attached to, recovered
	// via crdnames.ParseTenantIdentifier — never the combined tenant
	// identifier (vpc-vpcAttachment) itself, which is not a value any
	// kernel-side primitive in this codebase accepts.
	VPC string
	// Prefix is the pod's own address as a host route (/128 for the
	// IPv6-only backends this sidecar handles per §3 of the plan) — never a
	// tenant/subnet aggregate, since none exists: SIDs vary per hosting
	// node, so pods of the same tenant on different nodes need independent
	// routes even though they share a VPC.
	Prefix *net.IPNet
	// SID is the pod's own computed SRv6 uSID — the seg6 encap gateway
	// address for Prefix's route.
	SID net.IP
}
