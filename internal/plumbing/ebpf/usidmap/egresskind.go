// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

// Egress kind values for vrf_table's value field, mirroring usid.c's
// `enum egress_kind` (EGRESS_KIND_VETH/EGRESS_KIND_TAP). Hand-kept in sync
// with usid.c because bpf2go's -type flag cannot generate a Go type for a
// C enum that is only ever used as a literal constant, never as a
// variable/field the compiler retains distinct BTF for (see
// usidmap/function.go's BehaviorEndDT46/BehaviorEndDT2 constants and
// prog/dropreason.go for the identical reason/pattern).
//
// This selects which redirect helper usid_ingress's step 9 uses: a veth
// attachment's egress interface has a peer in a different netns
// (bpf_redirect_peer); a tap attachment (internal/cni/tap) never moves its
// interface out of this netns, so it has no peer and needs plain
// bpf_redirect instead. EgressKindVeth is the zero value so a Register call
// that never sets it explicitly defaults to the pre-existing (and still
// most common) veth behavior.
const (
	EgressKindVeth uint32 = 0
	EgressKindTap  uint32 = 1
)
