// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ingresssidecar implements #855's ingress sidecar: the second
// container in the shared Envoy Gateway fleet's pod, responsible only for
// VPC backend connectivity — Linux VRF device + SRv6 seg6 encap route
// lifecycle — never for xDS/EDS, health checking, or anything Envoy-facing.
// See docs/plans/855-ingress-sidecar-vpc-backend-connectivity.md for the
// full design; this doc comment only orients the code.
//
// Desired state comes from a single source: a cluster-scoped watch on
// discoveryv1.EndpointSlice objects published per pod by galactic-cni
// (#854), selected by the crdnames.LabelTenantID label. That label's value
// — TenantIdentifier(vpc, vpcAttachment) — is used only to decide *which*
// slices this sidecar cares about; it is never the reconcile key for either
// kernel resource this package manages, because the two are keyed at two
// different granularities than the tenant label:
//
//   - VRF device: one per VPC (crdnames.ParseTenantIdentifier's vpc half),
//     shared by every attachment of that VPC present on this node —
//     matching the kernel VRF's identity everywhere else in this codebase
//     (internal/plumbing/vrf).
//   - SRv6 egress route: one per pod (per EndpointSlice) — pods of the same
//     tenant on different nodes carry different SIDs, so there is no
//     tenant-aggregate route to install.
//
// Package layout:
//
//   - model.go — DesiredRoute, the one value this package's desired-state
//     translation produces.
//   - desired.go — BuildDesiredRoute: EndpointSlice → DesiredRoute.
//   - backend.go — Backend, the kernel-facing interface Store converges
//     against, and kernelBackend, its production implementation wired to
//     internal/plumbing/vrf and internal/plumbing/srv6 directly.
//   - store.go — Store: the mutex-protected, two-granularity, grace-period-
//     aware reconciler at this package's core. Mirrors internal/gateway's
//     Engine and internal/runtime/gobgp's GoBGPRuntime in shape.
//   - metrics.go — Prometheus metrics (§6 of the plan).
//   - controller.go — Reconciler: the thin controller-runtime glue that
//     turns EndpointSlice watch events into Store.SetDesired calls, plus
//     the startup-inventory and periodic-sweep wiring cmd/galactic-vrf's
//     root.go drives.
package ingresssidecar
