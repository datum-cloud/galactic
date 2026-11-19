//go:build ignore

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// fixture.c holds test stand-ins for the XDP programs other services run at
// the Local handoffs, so Worker's Local programs can be tested end to end. It
// is never deployed. They grew from the prototypes #1444 proved
// (tests/handoffs/probe/handoff.c).
//
//   ltf_gateway  a dispatcher slot program on a receiving device, as the
//                gateway runs (#1438): it marks a VIP packet for its TAP with
//                galactic_local_meta and returns XDP_PASS, and translates the
//                return half of a NAT flow back to its guest and redirects it
//                into the NAT end of the VPC's pair.
//   ltf_nat      the NAT shard's program on a pair's NAT end (#1437): it
//                translates the guest's source to the shard address and
//                redirects the packet out of the receiving device, pushing a
//                VLAN tag itself when the device is a VLAN.
//
// Both rewrite the L4 checksum as a complete one, as the probe's prototypes
// did, so a partial checksum reaching them is corrupted, as on a real host.

#include <linux/bpf.h>
#include "../local_meta.h"

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define LTF_INLINE inline __attribute__((always_inline))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define LTF_HTONS(x) __builtin_bswap16(x)
#else
#define LTF_HTONS(x) (x)
#endif

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *) BPF_FUNC_redirect;
static long (*bpf_xdp_adjust_meta)(void *ctx, int delta) = (void *) BPF_FUNC_xdp_adjust_meta;
static long (*bpf_xdp_adjust_head)(void *ctx, int delta) = (void *) BPF_FUNC_xdp_adjust_head;
static __s64 (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size,
			      __u32 seed) = (void *) BPF_FUNC_csum_diff;

#define LTF_ETH_P_IPV6 0x86DD
#define LTF_ETH_P_8021Q 0x8100

struct ltf_eth {
	__u8 dst[6];
	__u8 src[6];
	__be16 proto;
};

struct ltf_ip6 {
	__u8 vtc[4];
	__be16 plen;
	__u8 nexthdr;
	__u8 hlim;
	__u8 saddr[16];
	__u8 daddr[16];
};

struct ltf_in6 {
	__u8 a[16];
};

struct ltf_vip_value {
	__u32 tap_ifindex;
	// magic is the metadata magic written; a test writes a wrong one.
	__u32 magic;
};

struct ltf_shard_value {
	__u32 peer_ifindex;
	__u32 pad;
	__u8 guest[16];
	__u8 smac[6];
	__u8 dmac[6];
};

struct ltf_snat_value {
	__u32 out_ifindex;
	// vid is nonzero when out_ifindex is a VLAN's lower device, whose tag
	// the program pushes.
	__u32 vid;
	__u8 guest[16];
	__u8 shard[16];
	__u8 smac[6];
	__u8 dmac[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, struct ltf_in6);
	__type(value, struct ltf_vip_value);
} ltf_vip SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, struct ltf_in6);
	__type(value, struct ltf_shard_value);
} ltf_shard SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, struct ltf_snat_value);
} ltf_snat SEC(".maps");

static LTF_INLINE __u16 ltf_fold(__s64 sum)
{
	__u64 s = (__u64) sum;

	s = (s & 0xffffffff) + (s >> 32);
	s = (s & 0xffff) + (s >> 16);
	s = (s & 0xffff) + (s >> 16);
	return (__u16) s;
}

static LTF_INLINE int ltf_eq16(const __u8 *a, const __u8 *b)
{
	const __u64 *x = (const __u64 *) a;
	const __u64 *y = (const __u64 *) b;

	return x[0] == y[0] && x[1] == y[1];
}

// ltf_rewrite replaces the address at addr in ip6 with to and updates a TCP,
// UDP or ICMPv6 checksum as if it were complete.
static LTF_INLINE int ltf_rewrite(struct xdp_md *ctx, struct ltf_ip6 *ip6, __u8 *addr, const __u8 *to)
{
	void *end = (void *) (long) ctx->data_end;
	int off = -1;
	__u8 from[16];
	__u8 next[16];

	switch (ip6->nexthdr) {
	case 6:
		off = 16;
		break;
	case 17:
		off = 6;
		break;
	case 58:
		off = 2;
		break;
	}
	__builtin_memcpy(from, addr, 16);
	__builtin_memcpy(next, to, 16);
	if (off >= 0) {
		__u16 *csum = (void *) (ip6 + 1) + off;

		if ((void *) (csum + 1) > end)
			return -1;
		if (!(ip6->nexthdr == 17 && *csum == 0)) {
			__u32 seed = (~(__u32) *csum) & 0xffff;

			*csum = ~ltf_fold(bpf_csum_diff((__be32 *) from, 16, (__be32 *) next, 16, seed));
		}
	}
	__builtin_memcpy(addr, next, 16);
	return 0;
}

SEC("xdp")
int ltf_gateway(struct xdp_md *ctx)
{
	void *data = (void *) (long) ctx->data;
	void *end = (void *) (long) ctx->data_end;
	struct ltf_eth *eth = data;
	__u32 l3 = sizeof(*eth);
	int tagged = 0;

	if ((void *) (eth + 1) > end)
		return XDP_PASS;
	if (eth->proto == LTF_HTONS(LTF_ETH_P_8021Q)) {
		__be16 *tci = data + sizeof(*eth);

		if ((void *) (tci + 2) > end || tci[1] != LTF_HTONS(LTF_ETH_P_IPV6))
			return XDP_PASS;
		l3 += 4;
		tagged = 1;
	} else if (eth->proto != LTF_HTONS(LTF_ETH_P_IPV6)) {
		return XDP_PASS;
	}

	struct ltf_ip6 *ip6 = data + l3;

	if ((void *) (ip6 + 1) > end)
		return XDP_PASS;

	struct ltf_in6 dst;

	__builtin_memcpy(dst.a, ip6->daddr, 16);

	struct ltf_vip_value *vip = bpf_map_lookup_elem(&ltf_vip, &dst);

	if (vip) {
		__u32 tap = vip->tap_ifindex;
		__u32 magic = vip->magic;

		if (bpf_xdp_adjust_meta(ctx, -(int) sizeof(struct galactic_local_meta)) == 0) {
			struct galactic_local_meta *meta = (void *) (long) ctx->data_meta;

			if ((void *) (meta + 1) <= (void *) (long) ctx->data) {
				meta->magic = magic;
				meta->tap_ifindex = tap;
			}
		}
		return XDP_PASS;
	}

	struct ltf_shard_value *shard = bpf_map_lookup_elem(&ltf_shard, &dst);

	if (!shard)
		return XDP_PASS;
	if (ltf_rewrite(ctx, ip6, ip6->daddr, shard->guest))
		return XDP_PASS;
	if (tagged) {
		__u8 macs[12];

		if ((void *) ((__u8 *) data + 16) > end)
			return XDP_PASS;
		__builtin_memcpy(macs, data, 12);
		__builtin_memcpy((__u8 *) data + 4, macs, 12);
		if (bpf_xdp_adjust_head(ctx, 4))
			return XDP_PASS;
		data = (void *) (long) ctx->data;
		end = (void *) (long) ctx->data_end;
		eth = data;
		if ((void *) (eth + 1) > end)
			return XDP_PASS;
	}
	__builtin_memcpy(eth->src, shard->smac, 6);
	__builtin_memcpy(eth->dst, shard->dmac, 6);
	return bpf_redirect(shard->peer_ifindex, 0);
}

SEC("xdp")
int ltf_nat(struct xdp_md *ctx)
{
	__u32 ifindex = ctx->ingress_ifindex;
	struct ltf_snat_value *v = bpf_map_lookup_elem(&ltf_snat, &ifindex);
	void *data = (void *) (long) ctx->data;
	void *end = (void *) (long) ctx->data_end;
	struct ltf_eth *eth = data;
	struct ltf_ip6 *ip6 = (void *) (eth + 1);

	if (!v || (void *) (ip6 + 1) > end || eth->proto != LTF_HTONS(LTF_ETH_P_IPV6))
		return XDP_PASS;
	if (!ltf_eq16(ip6->saddr, v->guest))
		return XDP_PASS;
	if (ltf_rewrite(ctx, ip6, ip6->saddr, v->shard))
		return XDP_PASS;

	__u32 out = v->out_ifindex;
	__u32 vid = v->vid;
	__u8 smac[6];
	__u8 dmac[6];

	__builtin_memcpy(smac, v->smac, 6);
	__builtin_memcpy(dmac, v->dmac, 6);
	if (vid) {
		if (bpf_xdp_adjust_head(ctx, -4))
			return XDP_PASS;
		data = (void *) (long) ctx->data;
		end = (void *) (long) ctx->data_end;
		eth = data;
		__be16 *tag = data + 12;

		if ((void *) (eth + 1) > end || (void *) (tag + 3) > end)
			return XDP_ABORTED;
		__builtin_memcpy(eth->dst, dmac, 6);
		__builtin_memcpy(eth->src, smac, 6);
		tag[0] = LTF_HTONS(LTF_ETH_P_8021Q);
		tag[1] = LTF_HTONS((__u16) (vid & 0x0fff));
		tag[2] = LTF_HTONS(LTF_ETH_P_IPV6);
		return bpf_redirect(out, 0);
	}
	__builtin_memcpy(eth->src, smac, 6);
	__builtin_memcpy(eth->dst, dmac, 6);
	return bpf_redirect(out, 0);
}

char __license[] SEC("license") = "GPL";
