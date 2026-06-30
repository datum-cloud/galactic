// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cni implements the Galactic CNI plugin for wiring containers into
// SRv6-backed VPC networks.
//
// On ADD the plugin creates a VRF, a veth or tap interface, installs
// termination routes in the VRF table, allocates a pod subnet via IPAM,
// and publishes BGPAdvertisement/BGPVRFInstance CRDs for route distribution.
// On DEL it performs best-effort cleanup in reverse order. CHECK and STATUS
// validate that managed kernel resources are intact.
//
// Subpackages isolate kernel primitives:
//
//   - ipam: IPv6 subnet allocation from a CIDR pool or static address
//   - route: VRF route add/delete for termination gateways
//   - veth: veth pair creation for container workloads
//   - tap: TAP device creation for VM workloads (Kata, Firecracker)
//
// Usage:
//
//	import "go.datum.net/galactic/internal/cni"
//	cni.RunPlugin()
package cni
