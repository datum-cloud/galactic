//go:build ignore

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// handoff.c holds the prototype programs for the Local kernel handoffs that
// docs/worker/qualification.md lists (#1444). It is test code: the lab's
// handoff-probe loads it on a scratch rig and never on a production hook.
//
// It includes the uSID datapath source so the prototypes decide traffic
// policy with the product's own tp_capture and tp_decide, against the maps
// galactic-cni pinned. The loader replaces every map these programs use with
// that pin and refuses to create one.
//
// Programs, by handoff:
//
//   local.tap        hp_xdp_public (dispatcher slot on the receiving device)
//                    sets metadata and returns XDP_PASS; hp_tc_tenant_rx (tc
//                    ingress of the same device) delivers to the tenant TAP.
//                    hp_tc_tap_rx sends the guest's reply back out.
//   local.veth_pair  hp_tc_tap_rx sends the guest's NAT flow into the tenant
//                    end of the pair; hp_xdp_pair_peer (XDP on the peer)
//                    translates and forwards it. On return hp_xdp_public
//                    redirects into the peer and hp_tc_pair_rx (tc ingress of
//                    the tenant end) delivers it to the TAP.
//   local.routed_link
//                    hp_tc_link_guard (tc ingress of the host end) admits only
//                    the link's own source addresses.

#include "../../../internal/plumbing/ebpf/prog/usid.c"

static long (*hp_xdp_adjust_meta)(void *ctx, int delta) = (void *) BPF_FUNC_xdp_adjust_meta;
static long (*hp_xdp_adjust_head)(void *ctx, int delta) = (void *) BPF_FUNC_xdp_adjust_head;

#define HP_INLINE inline __attribute__((always_inline))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define HP_HTONS(x) __builtin_bswap16(x)
#else
#define HP_HTONS(x) (x)
#endif

#define HP_ETH_P_IPV6 0x86DD
#define HP_ETH_P_8021Q 0x8100
#define HP_IPPROTO_TCP 6
#define HP_IPPROTO_UDP 17
#define HP_IPPROTO_ICMPV6 58
#define HP_META_MAGIC 0x48503434 // "HP44"

// Counters, read by handoff-probe counters. Append only; the Go side names
// them by index.
enum hp_stat {
	HP_STAT_XDP_VIP = 0,
	HP_STAT_XDP_META_SET,
	HP_STAT_XDP_META_FAIL,
	HP_STAT_XDP_SHARD,
	HP_STAT_XDP_SHARD_VLAN_POP,
	HP_STAT_TC_META_OK,
	HP_STAT_TC_META_MISSING,
	HP_STAT_TC_TENANT_DENY,
	HP_STAT_TC_TENANT_REDIRECT,
	HP_STAT_TAP_REPLY,
	HP_STAT_TAP_REPLY_DENY,
	HP_STAT_TAP_NAT,
	HP_STAT_TAP_NAT_DENY,
	HP_STAT_PEER_SNAT,
	HP_STAT_PEER_REDIRECT,
	HP_STAT_PEER_PASS,
	HP_STAT_PAIR_RX,
	HP_STAT_PAIR_RX_DENY,
	HP_STAT_GUARD_PASS,
	HP_STAT_GUARD_DROP,
	HP_STAT_MAX_SEEN_LEN,
	HP_STAT_PEER_VLAN_PUSH,
	HP_STAT_COUNT = 32,
};

struct hp_vip_value {
	__u32 tap_ifindex;
	// decide is 1 when hp_tc_tenant_rx decides the receiver's policy on the
	// PublicService path and marks the packet decided, 0 when it leaves the
	// decision to tp_deliver, which takes the Private path.
	__u32 decide;
	__u8 guest[16];
};

struct hp_shard_value {
	__u32 peer_ifindex;
	__u32 pad;
	__u8 guest[16];
	__u8 smac[6];
	__u8 dmac[6];
};

struct hp_tap_value {
	__u32 dut_ifindex;
	__u32 pair_ifindex;
	__u8 vip[16];
	__u8 client_prefix[8]; // a /64
	__u8 pair_smac[6];
	__u8 pair_dmac[6];
};

struct hp_snat_value {
	__u32 redirect; // 1: XDP_REDIRECT through bpf_fib_lookup; 0: XDP_PASS
	// When bpf_fib_lookup answers vlan_ifindex, a VLAN device, the program
	// pushes the vid tag itself and redirects to lower_ifindex, the VLAN's
	// lower device: a VLAN device has no XDP transmit.
	__u32 vlan_ifindex;
	__u32 lower_ifindex;
	__u32 vid;
	__u8 guest[16];
	__u8 shard[16];
};

struct hp_pair_rx_value {
	__u32 tap_ifindex;
	__u32 pad;
	__u8 guest[16];
};

struct hp_guard_value {
	__u8 prefix[16]; // a /127
};

struct hp_cfg_value {
	__u32 vlan_id; // nonzero: hp_xdp_public parses this 802.1Q tag
	__u32 pad;
};

struct hp_meta {
	__u32 magic;
	__u32 tap_ifindex;
};

struct hp_in6 {
	__u8 a[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, struct hp_in6);
	__type(value, struct hp_vip_value);
} hp_vip SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, struct hp_in6);
	__type(value, struct hp_shard_value);
} hp_shard SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, struct hp_tap_value);
} hp_tap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, struct hp_snat_value);
} hp_snat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, struct hp_pair_rx_value);
} hp_pair_rx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, struct hp_guard_value);
} hp_guard SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct hp_cfg_value);
} hp_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, HP_STAT_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} hp_stats SEC(".maps");

static HP_INLINE void hp_count(__u32 stat)
{
	__u64 *v = bpf_map_lookup_elem(&hp_stats, &stat);

	if (v)
		__sync_fetch_and_add(v, 1);
}

static HP_INLINE void hp_seen_len(__u64 len)
{
	__u32 key = HP_STAT_MAX_SEEN_LEN;
	__u64 *v = bpf_map_lookup_elem(&hp_stats, &key);

	if (v && len > *v)
		*v = len;
}

static HP_INLINE int hp_eq16(const __u8 *a, const __u8 *b)
{
	const __u64 *x = (const __u64 *) a;
	const __u64 *y = (const __u64 *) b;

	return x[0] == y[0] && x[1] == y[1];
}

static HP_INLINE void hp_copy16(__u8 *dst, const __u8 *src)
{
	__builtin_memcpy(dst, src, 16);
}

static HP_INLINE __u16 hp_fold(__s64 sum)
{
	__u64 s = (__u64) sum;

	s = (s & 0xffffffff) + (s >> 32);
	s = (s & 0xffff) + (s >> 16);
	s = (s & 0xffff) + (s >> 16);
	return (__u16) s;
}

// hp_l4_csum_off returns the offset of the L4 checksum from the start of the
// L4 header, or -1 for a protocol it does not rewrite.
static HP_INLINE int hp_l4_csum_off(__u8 nexthdr)
{
	switch (nexthdr) {
	case HP_IPPROTO_TCP:
		return 16;
	case HP_IPPROTO_UDP:
		return 6;
	case HP_IPPROTO_ICMPV6:
		return 2;
	}
	return -1;
}

// hp_xdp_rewrite_addr replaces the 16-byte address at addr, inside an IPv6
// header at ip6, with to, and updates the L4 checksum that covers it through
// the pseudo-header. The checksum is updated as a complete one, which is
// what a receive path carries.
static HP_INLINE int hp_xdp_rewrite_addr(struct xdp_md *ctx, struct usid_ip6hdr *ip6, __u8 *addr, const __u8 *to)
{
	void *end = (void *) (long) ctx->data_end;
	int off = hp_l4_csum_off(ip6->nexthdr);
	__u8 from[16];
	__u8 next[16];

	hp_copy16(from, addr);
	hp_copy16(next, to);
	if (off >= 0) {
		__u16 *csum = (void *) (ip6 + 1) + off;

		if ((void *) (csum + 1) > end)
			return -1;
		if (!(ip6->nexthdr == HP_IPPROTO_UDP && *csum == 0)) {
			__u32 seed = (~(__u32) *csum) & 0xffff;
			__s64 sum = bpf_csum_diff((__be32 *) from, 16, (__be32 *) next, 16, seed);

			*csum = ~hp_fold(sum);
		}
	}
	hp_copy16(addr, next);
	return 0;
}

// hp_xdp_public is the dispatcher slot program on the device under test. A
// packet for a VIP gets metadata naming its TAP and is passed to the kernel,
// where hp_tc_tenant_rx takes it. A packet for a shard address is the return
// half of a NAT flow: it is translated back to the guest and redirected into
// the NAT side of the internal veth pair.
SEC("xdp")
int hp_xdp_public(struct xdp_md *ctx)
{
	void *data = (void *) (long) ctx->data;
	void *end = (void *) (long) ctx->data_end;
	struct usid_ethhdr *eth = data;
	__u32 l3 = sizeof(*eth);
	__u32 zero = 0;
	int tagged = 0;

	if ((void *) (eth + 1) > end)
		return XDP_PASS;
	hp_seen_len((__u64) (end - data));
	if (eth->h_proto == HP_HTONS(HP_ETH_P_8021Q)) {
		struct hp_cfg_value *cfg = bpf_map_lookup_elem(&hp_cfg, &zero);
		__be16 *tci = data + sizeof(*eth); // TCI, then the inner EtherType

		if (!cfg || !cfg->vlan_id || (void *) (tci + 2) > end)
			return XDP_PASS;
		if ((HP_HTONS(tci[0]) & 0x0fff) != cfg->vlan_id || tci[1] != HP_HTONS(HP_ETH_P_IPV6))
			return XDP_PASS;
		l3 += 4;
		tagged = 1;
	} else if (eth->h_proto != HP_HTONS(HP_ETH_P_IPV6)) {
		return XDP_PASS;
	}

	struct usid_ip6hdr *ip6 = data + l3;

	if ((void *) (ip6 + 1) > end)
		return XDP_PASS;

	struct hp_in6 dst;

	hp_copy16(dst.a, ip6->daddr);

	struct hp_vip_value *vip = bpf_map_lookup_elem(&hp_vip, &dst);

	if (vip) {
		hp_count(HP_STAT_XDP_VIP);
		if (hp_xdp_adjust_meta(ctx, -(int) sizeof(struct hp_meta)) == 0) {
			struct hp_meta *meta = (void *) (long) ctx->data_meta;

			if ((void *) (meta + 1) <= (void *) (long) ctx->data) {
				meta->magic = HP_META_MAGIC;
				meta->tap_ifindex = vip->tap_ifindex;
				hp_count(HP_STAT_XDP_META_SET);
			}
		} else {
			hp_count(HP_STAT_XDP_META_FAIL);
		}
		return XDP_PASS;
	}

	struct hp_shard_value *shard = bpf_map_lookup_elem(&hp_shard, &dst);

	if (!shard)
		return XDP_PASS;
	if (hp_xdp_rewrite_addr(ctx, ip6, ip6->daddr, shard->guest))
		return XDP_PASS;
	if (tagged) {
		// Drop the tag in place: move both MAC addresses forward over it.
		__u8 macs[12];

		__builtin_memcpy(macs, data, 12);
		if ((void *) ((__u8 *) data + 16) > end)
			return XDP_PASS;
		__builtin_memcpy((__u8 *) data + 4, macs, 12);
		if (hp_xdp_adjust_head(ctx, 4))
			return XDP_PASS;
		data = (void *) (long) ctx->data;
		end = (void *) (long) ctx->data_end;
		eth = data;
		if ((void *) (eth + 1) > end)
			return XDP_PASS;
		hp_count(HP_STAT_XDP_SHARD_VLAN_POP);
	}
	__builtin_memcpy(eth->h_source, shard->smac, 6);
	__builtin_memcpy(eth->h_dest, shard->dmac, 6);
	hp_count(HP_STAT_XDP_SHARD);
	return bpf_redirect(shard->peer_ifindex, 0);
}

static HP_INLINE struct usid_ip6hdr *hp_skb_ip6(struct __sk_buff *skb)
{
	void *data = (void *) (long) skb->data;
	void *end = (void *) (long) skb->data_end;
	struct usid_ethhdr *eth = data;
	struct usid_ip6hdr *ip6 = (void *) (eth + 1);

	if ((void *) (ip6 + 1) > end || eth->h_proto != HP_HTONS(HP_ETH_P_IPV6))
		return 0;
	return ip6;
}

// hp_tc_tenant_rx runs at tc ingress of the device under test, after
// hp_xdp_public passed a VIP packet. It takes the TAP from the metadata, or
// from the VIP when the metadata did not survive, decides the receiver's
// policy and delivers to the TAP through the kernel neighbor.
SEC("tc")
int hp_tc_tenant_rx(struct __sk_buff *skb)
{
	if (bpf_skb_pull_data(skb, sizeof(struct usid_ethhdr) + sizeof(struct usid_ip6hdr)))
		return TC_ACT_UNSPEC;

	__u32 meta_tap = 0;
	struct hp_meta *meta = (void *) (long) skb->data_meta;

	if ((void *) (meta + 1) <= (void *) (long) skb->data && meta->magic == HP_META_MAGIC)
		meta_tap = meta->tap_ifindex;

	struct usid_ip6hdr *ip6 = hp_skb_ip6(skb);

	if (!ip6)
		return TC_ACT_UNSPEC;

	struct hp_in6 dst;

	hp_copy16(dst.a, ip6->daddr);

	struct hp_vip_value *vip = bpf_map_lookup_elem(&hp_vip, &dst);

	if (!vip)
		return TC_ACT_UNSPEC;
	if (meta_tap == vip->tap_ifindex)
		hp_count(HP_STAT_TC_META_OK);
	else
		hp_count(HP_STAT_TC_META_MISSING);

	__u32 tap = vip->tap_ifindex;

	if (vip->decide) {
		tp_capture(skb, TP_DIR_INGRESS, tap, 0);
		if (tp_decide(tap, TP_DIR_INGRESS, TP_PATH_PUBLIC_SERVICE)) {
			hp_count(HP_STAT_TC_TENANT_DENY);
			return TC_ACT_SHOT;
		}
		skb->mark |= tp_ingress_mark();
	}

	struct bpf_redir_neigh nh = {};

	nh.nh_family = USID_AF_INET6;
	__builtin_memcpy(nh.ipv6_nh, vip->guest, 16);
	hp_count(HP_STAT_TC_TENANT_REDIRECT);
	return bpf_redirect_neigh(tap, &nh, sizeof(nh), 0);
}

// hp_tc_tap_rx runs at tc ingress of the tenant TAP, after usid_egress has
// passed the packet through its Local pass-through entry. A reply from the
// VIP leaves through the device under test; any other packet to the client
// prefix is a NAT flow and enters the tenant end of the internal veth pair.
SEC("tc")
int hp_tc_tap_rx(struct __sk_buff *skb)
{
	__u32 ifindex = skb->ifindex;
	struct hp_tap_value *v = bpf_map_lookup_elem(&hp_tap, &ifindex);

	if (!v)
		return TC_ACT_UNSPEC;
	if (bpf_skb_pull_data(skb, sizeof(struct usid_ethhdr) + sizeof(struct usid_ip6hdr)))
		return TC_ACT_UNSPEC;

	struct usid_ip6hdr *ip6 = hp_skb_ip6(skb);

	if (!ip6)
		return TC_ACT_UNSPEC;
	if (*(__u64 *) ip6->daddr != *(__u64 *) v->client_prefix)
		return TC_ACT_UNSPEC;

	if (hp_eq16(ip6->saddr, v->vip)) {
		tp_capture(skb, TP_DIR_EGRESS, ifindex, 0);
		if (tp_decide(ifindex, TP_DIR_EGRESS, TP_PATH_PUBLIC_SERVICE)) {
			hp_count(HP_STAT_TAP_REPLY_DENY);
			return TC_ACT_SHOT;
		}
		hp_count(HP_STAT_TAP_REPLY);
		return bpf_redirect_neigh(v->dut_ifindex, 0, 0, 0);
	}

	tp_capture(skb, TP_DIR_EGRESS, ifindex, 0);
	if (tp_decide(ifindex, TP_DIR_EGRESS, TP_PATH_PUBLIC_NAT)) {
		hp_count(HP_STAT_TAP_NAT_DENY);
		return TC_ACT_SHOT;
	}

	void *data = (void *) (long) skb->data;
	void *end = (void *) (long) skb->data_end;
	struct usid_ethhdr *eth = data;

	if ((void *) (eth + 1) > end)
		return TC_ACT_SHOT;
	__builtin_memcpy(eth->h_source, v->pair_smac, 6);
	__builtin_memcpy(eth->h_dest, v->pair_dmac, 6);
	hp_count(HP_STAT_TAP_NAT);
	return bpf_redirect(v->pair_ifindex, 0);
}

// hp_xdp_pair_peer is XDP on the NAT side of the internal veth pair. It
// stands in for the NAT shard: it translates the guest's source to the
// shard's address and forwards the packet toward the client.
SEC("xdp")
int hp_xdp_pair_peer(struct xdp_md *ctx)
{
	__u32 ifindex = ctx->ingress_ifindex;
	struct hp_snat_value *v = bpf_map_lookup_elem(&hp_snat, &ifindex);
	void *data = (void *) (long) ctx->data;
	void *end = (void *) (long) ctx->data_end;
	struct usid_ethhdr *eth = data;
	struct usid_ip6hdr *ip6 = (void *) (eth + 1);

	if (!v || (void *) (ip6 + 1) > end || eth->h_proto != HP_HTONS(HP_ETH_P_IPV6))
		return XDP_PASS;
	hp_seen_len((__u64) (end - data));
	if (!hp_eq16(ip6->saddr, v->guest))
		return XDP_PASS;
	if (hp_xdp_rewrite_addr(ctx, ip6, ip6->saddr, v->shard))
		return XDP_PASS;
	hp_count(HP_STAT_PEER_SNAT);
	if (!v->redirect) {
		hp_count(HP_STAT_PEER_PASS);
		return XDP_PASS;
	}

	struct bpf_fib_lookup fib = {};

	fib.family = USID_AF_INET6;
	fib.ifindex = ifindex;
	__builtin_memcpy(fib.ipv6_src, ip6->saddr, 16);
	__builtin_memcpy(fib.ipv6_dst, ip6->daddr, 16);
	if (bpf_fib_lookup(ctx, &fib, sizeof(fib), 0) != BPF_FIB_LKUP_RET_SUCCESS) {
		hp_count(HP_STAT_PEER_PASS);
		return XDP_PASS;
	}
	__u8 smac[6];
	__u8 dmac[6];

	__builtin_memcpy(smac, fib.smac, 6);
	__builtin_memcpy(dmac, fib.dmac, 6);
	if (v->vlan_ifindex && fib.ifindex == v->vlan_ifindex) {
		__u32 vid = v->vid;
		__u32 lower = v->lower_ifindex;

		if (hp_xdp_adjust_head(ctx, -4))
			return XDP_PASS;
		data = (void *) (long) ctx->data;
		end = (void *) (long) ctx->data_end;
		eth = data;
		__be16 *tag = data + 12;

		if ((void *) (eth + 1) > end || (void *) (tag + 3) > end)
			return XDP_ABORTED;
		__builtin_memcpy(eth->h_dest, dmac, 6);
		__builtin_memcpy(eth->h_source, smac, 6);
		tag[0] = HP_HTONS(HP_ETH_P_8021Q);
		tag[1] = HP_HTONS((__u16) (vid & 0x0fff));
		tag[2] = HP_HTONS(HP_ETH_P_IPV6);
		hp_count(HP_STAT_PEER_VLAN_PUSH);
		hp_count(HP_STAT_PEER_REDIRECT);
		return bpf_redirect(lower, 0);
	}
	__builtin_memcpy(eth->h_source, smac, 6);
	__builtin_memcpy(eth->h_dest, dmac, 6);
	hp_count(HP_STAT_PEER_REDIRECT);
	return bpf_redirect(fib.ifindex, 0);
}

// hp_tc_pair_rx is the reverse tc receive on the tenant end of the internal
// veth pair. It decides the receiver's policy on the PublicNAT path and
// delivers to the TAP.
SEC("tc")
int hp_tc_pair_rx(struct __sk_buff *skb)
{
	__u32 ifindex = skb->ifindex;
	struct hp_pair_rx_value *v = bpf_map_lookup_elem(&hp_pair_rx, &ifindex);

	if (!v)
		return TC_ACT_UNSPEC;
	if (bpf_skb_pull_data(skb, sizeof(struct usid_ethhdr) + sizeof(struct usid_ip6hdr)))
		return TC_ACT_UNSPEC;

	struct usid_ip6hdr *ip6 = hp_skb_ip6(skb);

	if (!ip6 || !hp_eq16(ip6->daddr, v->guest))
		return TC_ACT_UNSPEC;

	__u32 tap = v->tap_ifindex;

	tp_capture(skb, TP_DIR_INGRESS, tap, 0);
	if (tp_decide(tap, TP_DIR_INGRESS, TP_PATH_PUBLIC_NAT)) {
		hp_count(HP_STAT_PAIR_RX_DENY);
		return TC_ACT_SHOT;
	}
	skb->mark |= tp_ingress_mark();

	struct bpf_redir_neigh nh = {};

	nh.nh_family = USID_AF_INET6;
	__builtin_memcpy(nh.ipv6_nh, v->guest, 16);
	hp_count(HP_STAT_PAIR_RX);
	return bpf_redirect_neigh(tap, &nh, sizeof(nh), 0);
}

// hp_tc_link_guard runs at tc ingress of the host end of a pod-to-host routed
// link. The link joins the pod to the tenant VRF, so a source the link was
// not given would let the pod speak as any address in the VPC.
SEC("tc")
int hp_tc_link_guard(struct __sk_buff *skb)
{
	__u32 ifindex = skb->ifindex;
	struct hp_guard_value *v = bpf_map_lookup_elem(&hp_guard, &ifindex);

	if (!v)
		return TC_ACT_UNSPEC;
	if (bpf_skb_pull_data(skb, sizeof(struct usid_ethhdr) + sizeof(struct usid_ip6hdr)))
		return TC_ACT_SHOT;

	struct usid_ip6hdr *ip6 = hp_skb_ip6(skb);

	if (!ip6)
		return TC_ACT_UNSPEC;
	// Link-local sources carry Neighbor Discovery on the link itself.
	if (ip6->saddr[0] == 0xfe && (ip6->saddr[1] & 0xc0) == 0x80) {
		hp_count(HP_STAT_GUARD_PASS);
		return TC_ACT_UNSPEC;
	}

	const __u64 *s = (const __u64 *) ip6->saddr;
	const __u64 *p = (const __u64 *) v->prefix;
	// A /127: every bit but the last.
	__u64 mask = HP_HTONS(1) == 1 ? ~1ULL : ~(1ULL << 56);

	if (s[0] == p[0] && (s[1] & mask) == (p[1] & mask)) {
		hp_count(HP_STAT_GUARD_PASS);
		return TC_ACT_UNSPEC;
	}
	hp_count(HP_STAT_GUARD_DROP);
	return TC_ACT_SHOT;
}
