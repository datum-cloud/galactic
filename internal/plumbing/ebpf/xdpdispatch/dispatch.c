//go:build ignore

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// xdp_dispatch is the one program attached to the XDP hook of every interface
// a galactic datapath needs. An interface takes one native XDP program, so the
// edge gateway and the egress shard cannot each attach their own. This root
// holds the hook for both and tail-calls their programs through
// dispatch_progs, in slot order, as dispatch.h describes.
//
// The root owns no packet logic and claims nothing itself, so a node needs to
// replace it only when the dispatch ABI changes, and never when a datapath
// does. Its link is pinned, so it stays attached across a restart of either
// datapath.
#include "dispatch.h"

SEC("xdp")
int xdp_dispatch(struct xdp_md *ctx)
{
	return dispatch_from(ctx, 0);
}

// dispatch_meta records what the pinned maps and root are. Index 0 is the ABI
// version, index 1 the revision of the pinned root. No program reads it; it
// lives here so the loader pins it beside the other maps.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} dispatch_meta SEC(".maps");

char _license[] SEC("license") = "GPL";
