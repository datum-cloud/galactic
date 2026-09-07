// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ingresssidecar implements the ingress sidecar: the second container
// in the shared Envoy fleet's pod, responsible only for VPC backend
// connectivity, meaning the Linux VRF device and SRv6 egress route lifecycle,
// and never for xDS, health checking, or anything Envoy-facing.
//
// Desired state comes from one source: a cluster-scoped watch on EndpointSlice
// objects published per pod by the CNI, selected by the tenant label. That
// label's value decides only which slices this sidecar cares about; it is never
// the reconcile key for either kernel resource, because the two are keyed at
// different granularities than the label:
//
//   - VRF device: one per VPC, shared by every attachment of that VPC on this
//     node, matching the kernel VRF's identity everywhere else in this
//     codebase.
//   - SRv6 egress route: one per pod, since pods of the same tenant on
//     different nodes carry different SIDs and there is no tenant-aggregate
//     route to install.
//
// Package layout:
//
//   - model.go: DesiredRoute, the one value the desired-state translation
//     produces.
//   - desired.go: turning an EndpointSlice into a DesiredRoute.
//   - backend.go: the kernel-facing interface Store converges against, and its
//     production implementation.
//   - store.go: the mutex-protected, two-granularity, grace-period-aware
//     reconciler at this package's core.
//   - metrics.go: Prometheus metrics.
//   - controller.go: the controller-runtime glue turning watch events into
//     desired-state updates, plus the startup inventory and periodic sweep
//     wiring the binary drives.
package ingresssidecar
