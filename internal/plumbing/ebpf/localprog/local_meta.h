// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// local_meta.h is the XDP metadata a public receive program hands Worker's
// Local module (#1435): a dispatcher slot program that wants a packet
// delivered to a tenant TAP sets this metadata with bpf_xdp_adjust_meta and
// returns XDP_PASS, and local_rx, the Local tc program on the same
// interface, delivers it. The layout is ABI between the two; it only grows by
// appending fields and raising the magic.
//
// Only an XDP program can write skb metadata, so a packet from the wire
// cannot carry it. local_rx still delivers only to a TAP Worker authorized
// for a Local claim.

#ifndef GALACTIC_LOCAL_META_H
#define GALACTIC_LOCAL_META_H

// "GLM1"
#define GALACTIC_LOCAL_META_MAGIC 0x474c4d31

struct galactic_local_meta {
	__u32 magic;
	// tap_ifindex is the tenant TAP the packet is for.
	__u32 tap_ifindex;
};

#endif
