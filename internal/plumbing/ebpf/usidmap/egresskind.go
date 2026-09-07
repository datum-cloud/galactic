// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package usidmap

// Egress kind values for vrf_table's value field, mirroring the datapath's own
// enum. Hand-kept in sync with the C source, because the generator cannot
// produce a Go type for an enum used only as a literal constant.
//
// The value selects which redirect helper the datapath uses: a veth
// attachment's egress interface has a peer in another namespace, while a tap
// never leaves this one and so has no peer. EgressKindVeth is the zero value, so
// a registration that never sets it explicitly defaults to the more common veth
// behavior.
const (
	EgressKindVeth uint32 = 0
	EgressKindTap  uint32 = 1
)
