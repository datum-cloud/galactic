// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cni implements galactic-veth, the veth master plugin wiring container
// workloads into SRv6-backed VPC networks. Tap-based workloads are a separate
// master plugin: interface kind is which binary the runtime invokes, not a
// config field either branches on.
//
// On ADD it creates a VRF, a veth pair, and patches the pod's attachment
// definition with the host interface name. On DEL it cleans up best-effort in
// reverse order. CHECK and STATUS validate that the managed kernel resources
// are intact.
//
// Address allocation, termination routes, and BGP publishing are each their own
// chain-invoked binary, not this package's concern.
//
// Subpackages isolate kernel primitives: veth creates the pair for container
// workloads. The sibling ipam, route, and tap packages are the same kind of
// package but are used by their own binaries rather than by this one.
//
// Usage:
//
//	import "go.datum.net/galactic/internal/cni"
//	cni.RunPlugin()
package cni
