// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cni implements galactic-veth, the veth master plugin for wiring
// container workloads into SRv6-backed VPC networks. Tap-based workloads
// (Kata, Firecracker, kraftlet/Unikraft) are galactic-tap's own master
// plugin (internal/cnitap) — interface kind is which binary is invoked now,
// not a config field either binary branches on.
//
// On ADD the plugin creates a VRF, a veth pair, and patches the pod's NAD
// with the host interface name. On DEL it performs best-effort cleanup in
// reverse order. CHECK and STATUS validate that managed kernel resources are
// intact. IPAM allocation, termination-route installation, and
// BGPAdvertisement/BGPVRFInstance publish are no longer this package's
// concern — they're galactic-ipam's, galactic-route's, and galactic-bgp's
// own, chained after this plugin per the conflist (see
// internal/cniipam, internal/cniroute, internal/cnibgp).
//
// Subpackages isolate kernel primitives:
//
//   - veth: veth pair creation for container workloads
//
// internal/cni/ipam, internal/cni/route, and internal/cni/tap are the same
// kind of kernel-primitive package, but are no longer used by this package
// itself — they're used exclusively by internal/cniipam, internal/cniroute,
// and internal/cnitap respectively, now that IPAM, termination routes, and
// tap are each their own chain-invoked binary.
//
// Usage:
//
//	import "go.datum.net/galactic/internal/cni"
//	cni.RunPlugin()
package cni
