// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

// Egress kind values, mirroring the datapath's own enum. Hand-kept in sync with
// the C source, because the generator cannot produce a Go type for an enum used
// only as a literal constant.
//
// The value selects which redirect helper the datapath uses to deliver into an
// attachment's host-side interface: a veth has a peer in another namespace,
// while a tap never leaves this one and so has no peer. The datapath reads it
// per interface, from ifindex_egress_kind_table. vrf_table still carries a copy
// only so that a datapath rolled back to an older build keeps working.
const (
	EgressKindVeth uint32 = 0
	EgressKindTap  uint32 = 1
)
