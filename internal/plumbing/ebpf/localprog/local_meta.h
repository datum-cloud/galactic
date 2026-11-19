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
// Two layouts are accepted, told apart by the magic:
//
//   GLM1  magic and tap_ifindex, GALACTIC_LOCAL_META_V1_LEN bytes. local_rx
//         delivers the IPv6 packet unchanged.
//   GLM2  GLM1 plus backend_sid, GALACTIC_LOCAL_META_V2_LEN bytes, written by
//         the gateway's load balancer (#1438). local_rx checks the SID names
//         this node and the TAP's VRF, then translates the VIP to the
//         backend the SID's slot names, as usid_ingress does for an
//         encapsulated packet, before delivering.
//
// The kernel takes metadata in multiples of 4 bytes and at most 32 bytes
// (bpf_xdp_adjust_meta), so a later layout has 8 bytes left to append.
//
// Only an XDP program can write skb metadata, so a packet from the wire
// cannot carry it. local_rx still delivers only to a TAP Worker authorized
// for a Local claim.

#ifndef GALACTIC_LOCAL_META_H
#define GALACTIC_LOCAL_META_H

// "GLM1"
#define GALACTIC_LOCAL_META_MAGIC 0x474c4d31
// "GLM2"
#define GALACTIC_LOCAL_META_MAGIC_V2 0x474c4d32

#define GALACTIC_LOCAL_META_V1_LEN 8
#define GALACTIC_LOCAL_META_V2_LEN 24

struct galactic_local_meta {
	__u32 magic;
	// tap_ifindex is the tenant TAP the packet is for.
	__u32 tap_ifindex;
	// backend_sid, GLM2 only, is the backend uSID the load balancer selected:
	// this node's locator, the End.DT46 function, the tenant VRF's argument
	// and the backend slot in bytes 10-11. A GLM1 writer reserves only the
	// fields above, so this field is not there to read.
	__u8 backend_sid[16];
};

_Static_assert(sizeof(struct galactic_local_meta) == GALACTIC_LOCAL_META_V2_LEN,
	       "galactic_local_meta must match GALACTIC_LOCAL_META_V2_LEN");
_Static_assert(GALACTIC_LOCAL_META_V2_LEN % 4 == 0 && GALACTIC_LOCAL_META_V2_LEN <= 32,
	       "XDP metadata is a multiple of 4 bytes and at most 32");

#endif
