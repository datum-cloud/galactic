//go:build ignore

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// dispatch.h is the shared half of the XDP dispatcher: the maps every
// datapath sharing a node's XDP hook agrees on, and dispatch_from, the walk
// over them. The root program (dispatch.c) runs it from slot 0. A datapath
// that has to pass on a packet it does not claim includes this header and
// calls dispatch_next, so the packet still reaches every later slot.
//
// A datapath that includes this header gets its own copy of these map
// definitions in its ELF. The Go loader swaps each for the pinned map
// (CollectionOptions.MapReplacements), so every program on a node reads and
// tail-calls through the same maps.
//
// The layout below is ABI. A field or slot is never renumbered or removed. A
// change that cannot be made by appending a slot or a role bit gets a new
// pin directory (v2) instead, since recreating a pinned prog array empties
// every slot in it at once, including the slots of the other datapaths.
#ifndef GALACTIC_XDP_DISPATCH_H
#define GALACTIC_XDP_DISPATCH_H

#include <linux/bpf.h>

#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif
#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

#define XDPD_ALWAYS_INLINE inline __attribute__((always_inline))

// Prefixed so they never collide with the includer's own declarations of the
// same helpers.
static void *(*xdpd_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;
static __u64 (*xdpd_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;
static long (*xdpd_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *) BPF_FUNC_tail_call;

// XDPD_MAX_SLOTS is the slot count. Slots run in index order.
#define XDPD_MAX_SLOTS 8

// Slot numbers, mirrored by the Go Slot constants.
#define XDPD_SLOT_GATEWAY_LB 0
#define XDPD_SLOT_GATEWAY_RETURN 1
#define XDPD_SLOT_NAT 2

// Role bits, mirrored by the Go Role constants. Bit N lets slot N run on an
// interface.
#define XDPD_ROLE_PUBLIC_LB (1u << XDPD_SLOT_GATEWAY_LB)
#define XDPD_ROLE_INTERNAL_RETURN (1u << XDPD_SLOT_GATEWAY_RETURN)
#define XDPD_ROLE_EGRESS (1u << XDPD_SLOT_NAT)

// dispatch_progs holds one program per slot. An empty slot makes the tail call
// return, and the walk moves on.
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, XDPD_MAX_SLOTS);
	__type(key, __u32);
	__type(value, __u32);
} dispatch_progs SEC(".maps");

// iface_roles maps an ingress ifindex to its role bits. An interface with no
// row runs no slot.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u32);
} iface_roles SEC(".maps");

// slot_lease holds each slot's expiry as a CLOCK_MONOTONIC time in
// nanoseconds, the clock bpf_ktime_get_ns reads. The slot's owner renews it
// while running. A slot whose lease has passed is skipped, so a datapath that
// was removed, or that has been down longer than one lease, stops claiming
// packets instead of acting on state nobody maintains.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, XDPD_MAX_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} slot_lease SEC(".maps");

// xdpd_slot_permitted reports whether roles let slot run. The return program
// never runs on an interface that also carries the public role: it forwards
// anything sourced from a VIP, which on the public uplink would forward a
// spoofed packet.
static XDPD_ALWAYS_INLINE int xdpd_slot_permitted(__u32 roles, __u32 slot)
{
	if (!(roles & (1u << slot)))
		return 0;
	if (slot == XDPD_SLOT_GATEWAY_RETURN && (roles & XDPD_ROLE_PUBLIC_LB))
		return 0;
	return 1;
}

// dispatch_from tail-calls the first slot at or after first that the ingress
// interface's roles permit, whose lease is live and which holds a program. It
// returns XDP_PASS when no slot takes the packet.
static XDPD_ALWAYS_INLINE int dispatch_from(struct xdp_md *ctx, __u32 first)
{
	__u32 ifindex = ctx->ingress_ifindex;
	__u32 *roles = xdpd_map_lookup_elem(&iface_roles, &ifindex);
	if (!roles)
		return XDP_PASS;
	__u32 mask = *roles;
	__u64 now = xdpd_ktime_get_ns();

#pragma unroll
	for (__u32 slot = 0; slot < XDPD_MAX_SLOTS; slot++) {
		if (slot < first || !xdpd_slot_permitted(mask, slot))
			continue;
		__u32 key = slot;
		__u64 *expiry = xdpd_map_lookup_elem(&slot_lease, &key);
		if (!expiry || *expiry <= now)
			continue;
		xdpd_tail_call(ctx, &dispatch_progs, slot);
	}
	return XDP_PASS;
}

// dispatch_next passes a packet the calling slot did not claim to the slots
// after it.
static XDPD_ALWAYS_INLINE int dispatch_next(struct xdp_md *ctx, __u32 my_slot)
{
	return dispatch_from(ctx, my_slot + 1);
}

#endif // GALACTIC_XDP_DISPATCH_H
