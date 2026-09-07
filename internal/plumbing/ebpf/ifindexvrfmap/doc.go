// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ifindexvrfmap implements the read/write API for the eBPF uSID
// datapath's ifindex_vrf_table map: one row per attachment, veth or tap, keyed
// by that attachment's host-side interface ifindex and mapping it to the
// (Block, Argument) its VRF resolves to.
//
// usid_egress consults it to resolve which VRF a plain, not-yet-encapsulated
// outbound packet belongs to, having no outer uSID destination to decode that
// from the way usid_ingress does.
//
// # Reusing usidmap's map interfaces
//
// As in nptv6map: this is a map of the same datapath program as vrf_table, so
// the map-operation seam, kernel adapter, and iterator usidmap defines are
// imported rather than re-declared.
//
// # Lifecycle: CNI DEL, not a periodic sweep
//
// vrf_table's key is shared by every attachment on one VPC and node, so it needs
// the GC-driven list-live-CRDs-then-reconcile pattern. This table's key is a
// single attachment's own ifindex, private to that attachment exactly as its
// veth pair or tap device is, with no sibling that could still depend on it.
//
// Register happens at the same call site that registers this attachment's
// vrf_table entry, keyed additionally by the host-side ifindex resolved there.
// Unregister happens at CNI DEL, immediately before the interface is destroyed
// and using the same already-resolved ifindex.
//
// A sweep is not an option anyway: no CRD records an ifindex, so there is no
// live set to reconcile against without inventing a liveness mechanism this
// codebase has no analogue for. CNI DEL already knows exactly when the interface
// goes away and is best-effort on every other step in the same function.
//
// The method shapes mirror usidmap.VRFTable for consistency and testability,
// including a process-local generation. Reconcile is not wired into any
// production sweep, since CNI DEL owns cleanup; it exists for parity, test
// coverage, and as a backstop should one ever be needed, such as for a forced
// delete that skips CNI DEL.
package ifindexvrfmap
