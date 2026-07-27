// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vmtap implements a chained CNI plugin that gives a Unikraft
// microVM (managed by kraftlet) access to the pod's real Cilium-assigned
// identity via a tap device, using the tc-redirect pattern Kata Containers
// uses for its "tcfilter" endpoint type.
//
// vmtap-cni is unrelated to the VPC/SRv6 dataplane implemented by
// internal/cni — it never touches a VRF, never creates a BGPAdvertisement,
// and these pods have no vpc/vpcattachment. It must be chained after
// Cilium's own CNI plugin in the pod's primary conflist and requires a
// prevResult describing the interface Cilium already configured (typically
// eth0). On ADD it creates a tap device in the same network namespace, adds
// mirred redirect tc filters between the two links in both directions, and
// reports the tap as a synthetic VM-facing interface in the CNI result —
// eth0 itself is never modified. DEL removes the filters and the tap
// device; both DEL and CHECK are idempotent per the CNI spec.
//
// See .local/kraftlet-cilium-tap-plan.md for the design this package
// implements, including caveats around route-MTU, Cilium's socketLB, and
// tc/bpf hook ordering that still require empirical validation on a real
// cluster.
package vmtap
