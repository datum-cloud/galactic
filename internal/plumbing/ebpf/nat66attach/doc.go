// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nat66attach loads internal/plumbing/ebpf/nat66prog's compiled XDP
// program and attaches it to one interface -- one NAT66 shard's own
// fabric-facing uplink -- mirroring internal/plumbing/ebpf/edgeattach's
// mechanics almost verbatim (pinned maps, verifier-error unwrapping,
// incompatible-map recreation on a schema change; native-driver-mode-only
// XDP attach with no generic-mode fallback). See edgeattach's own doc
// comment for the full rationale behind each of those choices -- it
// applies unchanged here, this package is not repeating it.
//
// # No kernel preflight check here
//
// Unlike edgeattach.Load, this package's Load does not run a kernel
// preflight check before loading: internal/plumbing/ebpf/edgepreflight is
// scoped specifically to edgeprog's own map types (its own doc comment
// lists BPF_MAP_TYPE_HASH, not BPF_MAP_TYPE_LRU_HASH -- nat66_conn_table's
// actual type), and internal/plumbing/ebpf/preflight is scoped to the SRv6
// uSID TC-BPF datapath. Neither is a correct fit, and inventing a third,
// nat66-specific preflight package is out of scope for this phase --
// LoadAndAssign's own verifier-error unwrapping already surfaces "this
// kernel can't load this program" clearly at load time, just later than a
// dedicated preflight check would.
//
// # One attach target, no Watch-style re-attachment
//
// Same as edgeattach: this program has exactly one attach target (a fixed,
// operator-configured interface name, config.NAT66Config.UplinkInterface),
// attached once at process startup by cmd/galactic-nat66. There is no
// external network event this package needs to notice on its own.
package nat66attach
