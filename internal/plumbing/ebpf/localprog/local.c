//go:build ignore

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// local.c holds the tc programs of Worker's Local module (#1435): the
// same-host handoffs between a service's handoff point and tenant interfaces
// that docs/worker/contract.md#local-handoffs specifies. They grew from the
// prototypes #1444 proved (tests/handoffs/probe/handoff.c).
//
// It includes the uSID datapath source, so every policy decision runs the
// product's tp_capture and tp_decide. The loader replaces every uSID map these
// programs use with the map galactic-cni pinned and never creates one; the
// lt_* maps are Local's own, written only by Worker.
//
// Programs and their hooks:
//
//   local_rx          tc ingress of a public receiving device, after
//                     galactic-cni's filter. Delivers a packet a dispatcher
//                     slot marked with galactic_local_meta to the TAP it
//                     names (local.tap), translating a gateway VIP to its
//                     backend first when the metadata is GLM2.
//   local_link_rx     tc ingress of a tenant interface, after galactic-cni's
//                     filters. Returns a local.tap reply out of the device the
//                     flow arrived on, or sends a flow into the VPC's
//                     service-internal veth pair (local.veth_pair).
//   local_pair_rx     tc ingress of the pair's tenant end. Delivers what the
//                     NAT end sent back to the tenant it is for.
//   local_link_guard  tc ingress of a routed link's host end. Drops any
//                     source the link was not given (local.routed_link).
//   local_pair_napi   XDP of a pair's tenant end. Passes everything: a veth
//                     receives what a native XDP_REDIRECT sends into its
//                     peer only while it runs NAPI, which an XDP program
//                     turns on whatever the kernel does with GRO.
//
// Every program that delivers to a tenant decides the receiver's policy on
// its own path and sets the decided mark itself, so tp_deliver skips it
// (contract amendment: per-path policy). None trusts a mark already on the
// packet: a packet reaches a Local delivery only after its own decision. A
// target Worker did not authorize, such as a TAP no claim names, is dropped.

#include "../prog/usid.c"
#include "local_meta.h"

static long (*lt_check_mtu)(void *ctx, __u32 ifindex, __u32 *mtu_len, __s32 len_diff,
			    __u64 flags) = (void *) BPF_FUNC_check_mtu;

#define LT_INLINE inline __attribute__((always_inline))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define LT_HTONS(x) __builtin_bswap16(x)
#else
#define LT_HTONS(x) (x)
#endif

#define LT_ETH_P_IPV6 0x86DD
#define LT_IPPROTO_TCP 6
#define LT_IPPROTO_UDP 17
#define LT_IPPROTO_HOPOPTS 0
#define LT_IPPROTO_ROUTING 43
#define LT_IPPROTO_FRAGMENT 44
#define LT_IPPROTO_DSTOPTS 60
// LT_EXT_HDRS is how many extension headers lt_fragment walks before a
// fragment header.
#define LT_EXT_HDRS 4
#define LT_IPPROTO_ICMPV6 58
// BPF_MTU_CHK_SEGS: check each segment of a GSO packet against the MTU.
#define LT_MTU_CHK_SEGS 1
// egress_route_key's fixed prefix: table_id and family.
#define LT_ROUTE_KEY_FIXED_BITS 40
// egressroutemap.PassThroughLocalNAT.
#define LT_OWNER_LOCAL_NAT 3
#define LT_GUARD_ADDRS 4

// Counters, read by internal/plumbing/ebpf/localprog. Append only; the Go
// side names them by index.
enum lt_stat {
	LT_STAT_RX_NO_META = 0,
	LT_STAT_RX_UNCLAIMED,
	LT_STAT_RX_NOT_IPV6,
	LT_STAT_RX_FRAGMENT,
	LT_STAT_RX_TOO_BIG,
	LT_STAT_RX_DENY,
	LT_STAT_RX_DELIVER,
	LT_STAT_LINK_REPLY,
	LT_STAT_LINK_REPLY_DENY,
	LT_STAT_LINK_NAT,
	LT_STAT_LINK_NAT_DENY,
	LT_STAT_PAIR_UNCLAIMED,
	LT_STAT_PAIR_NOT_IPV6,
	LT_STAT_PAIR_FRAGMENT,
	LT_STAT_PAIR_TOO_BIG,
	LT_STAT_PAIR_DENY,
	LT_STAT_PAIR_DELIVER,
	LT_STAT_GUARD_PASS,
	LT_STAT_GUARD_DROP,
	LT_STAT_LINK_TOO_BIG,
	LT_STAT_LINK_LOCAL_SHARD,
	LT_STAT_LINK_LOCAL_SHARD_NO_PAIR,
	LT_STAT_RX_SID_MISMATCH,
	LT_STAT_RX_NO_BINDING,
	LT_STAT_RX_XLAT_REFUSED,
	LT_STAT_RX_XLAT_FAILED,
	LT_STAT_COUNT = 32,
};

// lt_tap_value is a TAP a local.tap claim authorizes. Keyed by the TAP's
// ifindex.
struct lt_tap_value {
	// nh is the guest address local_rx resolves the neighbor of; all zero
	// resolves the packet's destination instead.
	__u8 nh[16];
	__u32 table_id;
	__u32 pad;
};

// lt_link_value is a tenant interface Local returns traffic from. Keyed by
// its ifindex.
struct lt_link_value {
	__u32 table_id;
	// pair_ifindex is the tenant end of the VPC's service-internal veth
	// pair, or 0 when the VPC has none on this node.
	__u32 pair_ifindex;
	__u8 pair_smac[6];
	__u8 pair_dmac[6];
};

// lt_guest_key is a destination address the pair may deliver to, in one
// VPC's table. Two VPCs may use the same address.
struct lt_guest_key {
	__u32 table_id;
	__u8 addr[16];
};

struct lt_guest_value {
	__u32 link_ifindex;
	__u32 pad;
};

// lt_pair_value is a service-internal veth pair's tenant end. Keyed by its
// ifindex.
struct lt_pair_value {
	__u32 table_id;
	__u32 pad;
};

// lt_guard_value lists the sources a routed link's host end admits, besides
// link-local and unspecified ones. Keyed by the host end's ifindex.
struct lt_guard_value {
	__u32 count;
	__u32 pad;
	__u8 addr[LT_GUARD_ADDRS][16];
};

// lt_flow_key is one local.tap flow as the guest sends its replies: local is
// the guest side, peer the public client.
struct lt_flow_key {
	__u32 link_ifindex;
	__u8 proto;
	__u8 pad;
	__u16 pad2;
	__u16 local_port;
	__u16 peer_port;
	__u8 local[16];
	__u8 peer[16];
};

struct lt_flow_value {
	// rx_ifindex is the device the flow's request arrived on, which its
	// replies leave through.
	__u32 rx_ifindex;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct lt_tap_value);
} lt_tap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct lt_link_value);
} lt_link SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct lt_guest_key);
	__type(value, struct lt_guest_value);
} lt_guest SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct lt_pair_value);
} lt_pair SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct lt_guard_value);
} lt_guard SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct lt_flow_key);
	__type(value, struct lt_flow_value);
} lt_flow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, LT_STAT_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} lt_stats SEC(".maps");

static LT_INLINE void lt_count(__u32 stat)
{
	__u64 *v = bpf_map_lookup_elem(&lt_stats, &stat);

	if (v)
		*v += 1;
}

static LT_INLINE int lt_eq16(const __u8 *a, const __u8 *b)
{
	const __u64 *x = (const __u64 *) a;
	const __u64 *y = (const __u64 *) b;

	return x[0] == y[0] && x[1] == y[1];
}

static LT_INLINE int lt_zero16(const __u8 *a)
{
	const __u64 *x = (const __u64 *) a;

	return x[0] == 0 && x[1] == 0;
}

// lt_ip6 returns the packet's IPv6 header after pulling it, and the first 8
// bytes of what follows when the packet has them, or 0 when the packet is
// not IPv6.
static LT_INLINE struct usid_ip6hdr *lt_ip6(struct __sk_buff *skb)
{
	if (bpf_skb_pull_data(skb, sizeof(struct usid_ethhdr) + sizeof(struct usid_ip6hdr)))
		return 0;
	// Best effort: a packet with no transport header has no ports.
	bpf_skb_pull_data(skb, sizeof(struct usid_ethhdr) + sizeof(struct usid_ip6hdr) + 8);

	void *data = (void *) (long) skb->data;
	void *end = (void *) (long) skb->data_end;
	struct usid_ethhdr *eth = data;
	struct usid_ip6hdr *ip6 = (void *) (eth + 1);

	if ((void *) (ip6 + 1) > end || eth->h_proto != LT_HTONS(LT_ETH_P_IPV6))
		return 0;
	return ip6;
}

// lt_ports reads the source and destination ports of a TCP or UDP packet,
// and the ICMPv6 echo identifier as both. Other protocols, and a packet
// whose transport header follows extension headers, have none.
static LT_INLINE void lt_ports(struct __sk_buff *skb, struct usid_ip6hdr *ip6, __u16 *sport, __u16 *dport)
{
	void *end = (void *) (long) skb->data_end;
	__u16 *l4 = (void *) (ip6 + 1);

	*sport = 0;
	*dport = 0;
	switch (ip6->nexthdr) {
	case LT_IPPROTO_TCP:
	case LT_IPPROTO_UDP:
		if ((void *) (l4 + 2) <= end) {
			*sport = l4[0];
			*dport = l4[1];
		}
		break;
	case LT_IPPROTO_ICMPV6:
		// type, code, checksum, then an echo's identifier.
		if ((void *) (l4 + 3) <= end) {
			*sport = l4[2];
			*dport = l4[2];
		}
		break;
	}
}

// lt_fragment reports whether the IPv6 packet ip6 heads is a fragment: a
// fragment header first, or after up to LT_EXT_HDRS hop-by-hop, routing or
// destination options headers. A chain longer than that counts as one, so
// it is refused rather than delivered unchecked.
static LT_INLINE int lt_fragment(struct __sk_buff *skb, struct usid_ip6hdr *ip6)
{
	__u8 next = ip6->nexthdr;
	__u32 off = sizeof(struct usid_ethhdr) + sizeof(struct usid_ip6hdr);

#pragma unroll
	for (int i = 0; i < LT_EXT_HDRS; i++) {
		if (next == LT_IPPROTO_FRAGMENT)
			return 1;
		if (next != LT_IPPROTO_HOPOPTS && next != LT_IPPROTO_ROUTING && next != LT_IPPROTO_DSTOPTS)
			return 0;
		__u8 hdr[2];

		if (bpf_skb_load_bytes(skb, off, hdr, sizeof(hdr)))
			return 1;
		next = hdr[0];
		off += ((__u32) hdr[1] + 1) * 8;
	}
	return next == LT_IPPROTO_FRAGMENT || next == LT_IPPROTO_HOPOPTS || next == LT_IPPROTO_ROUTING ||
	       next == LT_IPPROTO_DSTOPTS;
}

// lt_fits reports whether skb fits ifindex's MTU, segment by segment for a
// GSO packet. A redirect does not enforce the receiver's MTU itself.
static LT_INLINE int lt_fits(struct __sk_buff *skb, __u32 ifindex)
{
	__u32 mtu = 0;

	return lt_check_mtu(skb, ifindex, &mtu, 0, LT_MTU_CHK_SEGS) == 0;
}

// lt_sid is a GLM2 backend uSID decoded the way usid_ingress decodes an
// outer destination.
struct lt_sid {
	__u64 block;
	__u16 argument;
	__u16 slot;
};

// lt_decode_sid decodes sid as usid_ingress decodes an outer destination and
// reports whether it names this node (locator_table), an End.DT46 function
// (function_table), a backend slot, and a VRF (vrf_table) whose Linux table is
// table_id, the TAP's. This is the trust check on a GLM2 handoff: the slot
// program names the TAP, and Worker checks that the backend it chose is one
// this node serves in that TAP's VPC.
static LT_INLINE int lt_decode_sid(const __u8 *sid, __u32 table_id, struct lt_sid *out)
{
	__u64 locator_key = read_be64(sid);

	if (!bpf_map_lookup_elem(&locator_table, &locator_key))
		return 0;

	__u64 block = locator_key >> 16;
	__u64 function_key = (block << 4) | (sid[8] >> 4);
	struct function_value *fn = bpf_map_lookup_elem(&function_table, &function_key);

	if (!fn || fn->behavior != BEHAVIOR_END_DT46)
		return 0;

	__u16 argument = ((__u16) (sid[8] & 0x0F) << 8) | sid[9];
	__u16 slot = ((__u16) sid[10] << 8) | sid[11];

	if (slot == 0)
		return 0;

	__u64 vrf_key = (block << 12) | argument;
	struct vrf_value *vrf = bpf_map_lookup_elem(&vrf_table, &vrf_key);

	if (!vrf || vrf->vrf_table_id != table_id)
		return 0;
	out->block = block;
	out->argument = argument;
	out->slot = slot;
	return 1;
}

// lt_xlat_vip translates a GLM2 packet's VIP destination to the backend
// address and port vip_xlat_table's ingress row for the SID's slot names, as
// usid_ingress does after decapsulating: an IPv4 packet through
// vip_siit_ingress, to an IPv6 packet from 64:ff9b::<client>, and an IPv6
// packet through lookup_vip_xlat and apply_vip_xlat, skipping an IPv4-mapped
// destination as usid_ingress does. It returns -1 after counting the drop, or
// 0 with the packet translated.
//
// No MSS clamp, unlike usid_ingress: the client's segments reach the guest
// unencapsulated, so the fabric's encapsulation overhead does not apply to
// them, and the guest's SYN-ACK is clamped by usid_egress on its way out.
static LT_INLINE int lt_xlat_vip(struct __sk_buff *skb, const struct lt_sid *sid)
{
	void *data = (void *) (long) skb->data;
	void *end = (void *) (long) skb->data_end;
	struct usid_ethhdr *eth = data;

	if ((void *) (eth + 1) > end) {
		lt_count(LT_STAT_RX_NOT_IPV6);
		return -1;
	}

	if (eth->h_proto == LT_HTONS(USID_ETH_P_IP)) {
		int rc = vip_siit_ingress(skb, sid->block, sid->argument, sid->slot);

		switch (rc) {
		case USID_SIIT_TRANSLATED:
			break;
		case USID_SIIT_PASS:
			lt_count(LT_STAT_RX_NO_BINDING);
			return -1;
		case USID_SIIT_FRAGMENT:
			lt_count(LT_STAT_RX_FRAGMENT);
			return -1;
		case USID_SIIT_UDP_NO_CHECKSUM:
		case USID_SIIT_IPV4_BACKEND:
		case USID_SIIT_TTL_EXCEEDED:
			lt_count(LT_STAT_RX_XLAT_REFUSED);
			return -1;
		default:
			lt_count(LT_STAT_RX_XLAT_FAILED);
			return -1;
		}
		// bpf_skb_change_proto changes skb->protocol, not the Ethernet
		// header, which the TAP's guest reads.
		data = (void *) (long) skb->data;
		end = (void *) (long) skb->data_end;
		eth = data;
		if ((void *) (eth + 1) > end) {
			lt_count(LT_STAT_RX_XLAT_FAILED);
			return -1;
		}
		eth->h_proto = LT_HTONS(LT_ETH_P_IPV6);
		return 0;
	}

	struct usid_ip6hdr *ip6 = lt_ip6(skb);

	if (!ip6) {
		lt_count(LT_STAT_RX_NOT_IPV6);
		return -1;
	}
	if (lt_fragment(skb, ip6)) {
		lt_count(LT_STAT_RX_FRAGMENT);
		return -1;
	}
	ip6 = lt_ip6(skb);
	if (!ip6)
		return -1;
	end = (void *) (long) skb->data_end;

	struct usid_l4ports *ports = (void *) (ip6 + 1);
	__u8 proto = ip6->nexthdr;

	if ((proto != USID_IPPROTO_TCP && proto != USID_IPPROTO_UDP) || usid_is_v4_mapped(ip6->daddr) ||
	    (void *) (ports + 1) > end) {
		lt_count(LT_STAT_RX_NO_BINDING);
		return -1;
	}

	struct vip_xlat_value *vv = lookup_vip_xlat(sid->block, sid->argument, sid->slot, proto,
						    USID_VIP_XLAT_DIR_INGRESS, ports->dest, ip6->daddr);

	if (!vv) {
		lt_count(LT_STAT_RX_NO_BINDING);
		return -1;
	}

	__u32 csum_off = USID_L3_OFFSET + sizeof(struct usid_ip6hdr) +
			 (proto == USID_IPPROTO_TCP ? USID_TCP_CSUM_OFFSET : USID_UDP_CSUM_OFFSET);
	__u32 addr_off = USID_L3_OFFSET + USID_OFFSETOF(struct usid_ip6hdr, daddr);
	__u32 port_off = USID_L3_OFFSET + (__u32) sizeof(struct usid_ip6hdr) + USID_OFFSETOF(struct usid_l4ports, dest);

	if (apply_vip_xlat(skb, addr_off, port_off, csum_off, proto, ip6->daddr, ports->dest, vv)) {
		lt_count(LT_STAT_RX_XLAT_FAILED);
		return -1;
	}
	return 0;
}

// local_rx delivers a public packet a dispatcher slot program marked for a
// tenant TAP. A packet without the metadata is not Local's and goes on to the
// kernel unchanged. One naming a TAP no claim authorizes, an IPv6 fragment,
// which a TAP guest was measured not to take, and one too big for the TAP are
// dropped.
//
// GLM1 metadata delivers the IPv6 packet as it is. GLM2 metadata, the
// gateway's, also names the backend uSID the gateway selected: the uSID must
// name this node and the TAP's VRF (lt_decode_sid), and the VIP is translated
// to that backend (lt_xlat_vip), IPv4 or IPv6, before the checks and the
// policy decision below, so they see the packet the guest receives. The
// guest's reply leaves through usid_egress's VIP branch, which translates it
// back.
SEC("tc")
int local_rx(struct __sk_buff *skb)
{
	struct galactic_local_meta *meta = (void *) (long) skb->data_meta;
	void *meta_end = (void *) (long) skb->data;
	__u32 tap;
	// Zeroed so every path defines it: clang keeps parts of it in registers
	// across the two GLM2 branches, which the verifier does not correlate.
	__u8 sid[16] = {};
	int glm2;

	// The metadata is read before any helper call moves the packet.
	if ((void *) meta + GALACTIC_LOCAL_META_V1_LEN > meta_end ||
	    (meta->magic != GALACTIC_LOCAL_META_MAGIC && meta->magic != GALACTIC_LOCAL_META_MAGIC_V2)) {
		lt_count(LT_STAT_RX_NO_META);
		return TC_ACT_UNSPEC;
	}
	glm2 = meta->magic == GALACTIC_LOCAL_META_MAGIC_V2;
	tap = meta->tap_ifindex;
	if (glm2) {
		// Only an XDP program writes metadata, so a short GLM2 is a broken
		// writer, not a packet for the kernel.
		if ((void *) (meta + 1) > meta_end) {
			lt_count(LT_STAT_RX_SID_MISMATCH);
			return TC_ACT_SHOT;
		}
		__builtin_memcpy(sid, meta->backend_sid, 16);
	}

	struct lt_tap_value *tv = bpf_map_lookup_elem(&lt_tap, &tap);

	if (!tv) {
		lt_count(LT_STAT_RX_UNCLAIMED);
		return TC_ACT_SHOT;
	}

	__u8 nh[16];
	__u32 table_id = tv->table_id;

	__builtin_memcpy(nh, tv->nh, 16);

	if (glm2) {
		struct lt_sid decoded = {};

		if (!lt_decode_sid(sid, table_id, &decoded)) {
			lt_count(LT_STAT_RX_SID_MISMATCH);
			return TC_ACT_SHOT;
		}
		if (lt_xlat_vip(skb, &decoded))
			return TC_ACT_SHOT;
	}

	struct usid_ip6hdr *ip6 = lt_ip6(skb);

	if (!ip6) {
		lt_count(LT_STAT_RX_NOT_IPV6);
		return TC_ACT_SHOT;
	}
	if (lt_fragment(skb, ip6)) {
		lt_count(LT_STAT_RX_FRAGMENT);
		return TC_ACT_SHOT;
	}
	ip6 = lt_ip6(skb);
	if (!ip6)
		return TC_ACT_SHOT;

	struct lt_flow_key fk = {};
	struct lt_flow_value fv = {};

	fk.link_ifindex = tap;
	fk.proto = ip6->nexthdr;
	lt_ports(skb, ip6, &fk.peer_port, &fk.local_port);
	__builtin_memcpy(fk.local, ip6->daddr, 16);
	__builtin_memcpy(fk.peer, ip6->saddr, 16);
	fv.rx_ifindex = skb->ifindex;

	if (!lt_fits(skb, tap)) {
		lt_count(LT_STAT_RX_TOO_BIG);
		return TC_ACT_SHOT;
	}
	tp_capture(skb, TP_DIR_INGRESS, tap, 0);
	if (tp_decide(tap, TP_DIR_INGRESS, TP_PATH_PUBLIC_SERVICE)) {
		lt_count(LT_STAT_RX_DENY);
		return TC_ACT_SHOT;
	}
	skb->mark |= tp_ingress_mark();
	bpf_map_update_elem(&lt_flow, &fk, &fv, BPF_ANY);
	lt_count(LT_STAT_RX_DELIVER);
	if (lt_zero16(nh))
		return bpf_redirect_neigh(tap, 0, 0, 0);

	struct bpf_redir_neigh p = {};

	p.nh_family = USID_AF_INET6;
	__builtin_memcpy(p.ipv6_nh, nh, 16);
	return bpf_redirect_neigh(tap, &p, sizeof(p), 0);
}

// lt_nat_route reports whether dst's entry in table steers into the VPC's
// service-internal veth pair: a pass-through entry PassThroughLocalNAT owns.
static LT_INLINE int lt_nat_route(__u32 table, const __u8 *dst)
{
	struct egress_route_key k = {};

	k.prefixlen = LT_ROUTE_KEY_FIXED_BITS + 128;
	k.table_id = table;
	k.family = USID_EGRESS_ROUTE_FAMILY_INET6;
	__builtin_memcpy(k.addr, dst, 16);

	struct egress_route_value *v = bpf_map_lookup_elem(&egress_route_table, &k);

	return v && v->link_ifindex == 0 && v->sid[0] == LT_OWNER_LOCAL_NAT;
}

// local_link_rx runs on a tenant interface after usid_egress has passed the
// packet on. A reply to a flow local_rx delivered leaves through the device
// the flow arrived on. A packet whose destination's entry steers into the
// VPC's service-internal veth pair enters the pair. Anything else goes on
// to the kernel.
SEC("tc")
int local_link_rx(struct __sk_buff *skb)
{
	__u32 ifindex = skb->ifindex;
	struct lt_link_value *lv = bpf_map_lookup_elem(&lt_link, &ifindex);

	if (!lv)
		return TC_ACT_UNSPEC;

	__u32 table = lv->table_id;
	__u32 pair = lv->pair_ifindex;
	__u8 smac[6];
	__u8 dmac[6];

	__builtin_memcpy(smac, lv->pair_smac, 6);
	__builtin_memcpy(dmac, lv->pair_dmac, 6);

	struct usid_ip6hdr *ip6 = lt_ip6(skb);

	if (!ip6)
		return TC_ACT_UNSPEC;

	struct lt_flow_key fk = {};

	fk.link_ifindex = ifindex;
	fk.proto = ip6->nexthdr;
	lt_ports(skb, ip6, &fk.local_port, &fk.peer_port);
	__builtin_memcpy(fk.local, ip6->saddr, 16);
	__builtin_memcpy(fk.peer, ip6->daddr, 16);

	struct lt_flow_value *fv = bpf_map_lookup_elem(&lt_flow, &fk);

	if (fv) {
		__u32 rx = fv->rx_ifindex;

		if (!lt_fits(skb, rx)) {
			lt_count(LT_STAT_LINK_TOO_BIG);
			return TC_ACT_SHOT;
		}
		tp_capture(skb, TP_DIR_EGRESS, ifindex, 0);
		if (tp_decide(ifindex, TP_DIR_EGRESS, TP_PATH_PUBLIC_SERVICE)) {
			lt_count(LT_STAT_LINK_REPLY_DENY);
			return TC_ACT_SHOT;
		}
		lt_count(LT_STAT_LINK_REPLY);
		return bpf_redirect_neigh(rx, 0, 0, 0);
	}

	// usid_egress placed the packet on this node's own NAT shard and left
	// the marker (USID_CB_LOCAL_SHARD) with the VRF table it decided in. Only
	// a marker for this interface's own table counts; it is cleared so no
	// later program reads it again.
	int local_shard = skb->cb[0] == USID_CB_LOCAL_SHARD && skb->cb[1] == table;

	if (local_shard) {
		skb->cb[0] = 0;
		if (!pair) {
			lt_count(LT_STAT_LINK_LOCAL_SHARD_NO_PAIR);
			return TC_ACT_SHOT;
		}
	} else {
		__u8 dst[16];

		__builtin_memcpy(dst, ip6->daddr, 16);
		if (!pair || !lt_nat_route(table, dst))
			return TC_ACT_UNSPEC;
	}
	if (!lt_fits(skb, pair)) {
		lt_count(LT_STAT_LINK_TOO_BIG);
		return TC_ACT_SHOT;
	}

	tp_capture(skb, TP_DIR_EGRESS, ifindex, 0);
	if (tp_decide(ifindex, TP_DIR_EGRESS, TP_PATH_PUBLIC_NAT)) {
		lt_count(LT_STAT_LINK_NAT_DENY);
		return TC_ACT_SHOT;
	}

	void *data = (void *) (long) skb->data;
	void *end = (void *) (long) skb->data_end;
	struct usid_ethhdr *eth = data;

	if ((void *) (eth + 1) > end)
		return TC_ACT_SHOT;
	__builtin_memcpy(eth->h_source, smac, 6);
	__builtin_memcpy(eth->h_dest, dmac, 6);
	lt_count(local_shard ? LT_STAT_LINK_LOCAL_SHARD : LT_STAT_LINK_NAT);
	return bpf_redirect(pair, 0);
}

// local_pair_rx runs on the tenant end of a service-internal veth pair. The
// NAT end sends it the return half of a tenant's flow; it delivers to the
// tenant the destination address names in the pair's VPC, and drops a packet
// for any address no claim authorizes.
SEC("tc")
int local_pair_rx(struct __sk_buff *skb)
{
	__u32 ifindex = skb->ifindex;
	struct lt_pair_value *pv = bpf_map_lookup_elem(&lt_pair, &ifindex);

	if (!pv) {
		lt_count(LT_STAT_PAIR_UNCLAIMED);
		return TC_ACT_SHOT;
	}

	struct lt_guest_key gk = {};

	gk.table_id = pv->table_id;

	struct usid_ip6hdr *ip6 = lt_ip6(skb);

	if (!ip6) {
		lt_count(LT_STAT_PAIR_NOT_IPV6);
		return TC_ACT_SHOT;
	}
	if (lt_fragment(skb, ip6)) {
		lt_count(LT_STAT_PAIR_FRAGMENT);
		return TC_ACT_SHOT;
	}
	ip6 = lt_ip6(skb);
	if (!ip6)
		return TC_ACT_SHOT;
	__builtin_memcpy(gk.addr, ip6->daddr, 16);

	struct lt_guest_value *gv = bpf_map_lookup_elem(&lt_guest, &gk);

	if (!gv) {
		lt_count(LT_STAT_PAIR_UNCLAIMED);
		return TC_ACT_SHOT;
	}

	__u32 link = gv->link_ifindex;

	if (!lt_fits(skb, link)) {
		lt_count(LT_STAT_PAIR_TOO_BIG);
		return TC_ACT_SHOT;
	}
	tp_capture(skb, TP_DIR_INGRESS, link, 0);
	if (tp_decide(link, TP_DIR_INGRESS, TP_PATH_PUBLIC_NAT)) {
		lt_count(LT_STAT_PAIR_DENY);
		return TC_ACT_SHOT;
	}
	skb->mark |= tp_ingress_mark();
	lt_count(LT_STAT_PAIR_DELIVER);

	struct bpf_redir_neigh p = {};

	p.nh_family = USID_AF_INET6;
	__builtin_memcpy(p.ipv6_nh, gk.addr, 16);
	return bpf_redirect_neigh(link, &p, sizeof(p), 0);
}

// lt_link_scoped reports whether addr is link-local unicast or multicast:
// an address that never leaves the link the packet is on.
static LT_INLINE int lt_link_scoped(const __u8 *addr)
{
	return addr[0] == 0xff || (addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80);
}

// local_link_guard runs on the host end of a pod-to-host routed link. The link
// joins the pod to the tenant VRF, so a source it was not given would let the
// pod speak as any address in the VPC. A link-local source is admitted only
// toward a link-local or multicast destination, and the unspecified source
// only for ICMPv6 toward one, which is how Neighbor Discovery and MLD use
// them; neither is forwarded into the VPC. Anything else not IPv6 is
// dropped.
SEC("tc")
int local_link_guard(struct __sk_buff *skb)
{
	__u32 ifindex = skb->ifindex;
	struct lt_guard_value *gv = bpf_map_lookup_elem(&lt_guard, &ifindex);

	if (!gv) {
		lt_count(LT_STAT_GUARD_DROP);
		return TC_ACT_SHOT;
	}

	__u32 count = gv->count;
	struct usid_ip6hdr *ip6 = lt_ip6(skb);

	if (!ip6) {
		lt_count(LT_STAT_GUARD_DROP);
		return TC_ACT_SHOT;
	}
	int link_dst = lt_link_scoped(ip6->daddr);

	if (link_dst && ((ip6->saddr[0] == 0xfe && (ip6->saddr[1] & 0xc0) == 0x80) ||
			 (lt_zero16(ip6->saddr) && ip6->nexthdr == LT_IPPROTO_ICMPV6))) {
		lt_count(LT_STAT_GUARD_PASS);
		return TC_ACT_UNSPEC;
	}

	__u8 src[16];

	__builtin_memcpy(src, ip6->saddr, 16);
	gv = bpf_map_lookup_elem(&lt_guard, &ifindex);
	if (!gv)
		return TC_ACT_SHOT;
#pragma unroll
	for (int i = 0; i < LT_GUARD_ADDRS; i++) {
		if (i < count && lt_eq16(src, gv->addr[i])) {
			lt_count(LT_STAT_GUARD_PASS);
			return TC_ACT_UNSPEC;
		}
	}
	lt_count(LT_STAT_GUARD_DROP);
	return TC_ACT_SHOT;
}

// local_pair_napi runs on the tenant end of a service-internal veth pair, so
// the NAT end's return, which a dispatcher slot redirects into the pair, is
// received; local_pair_rx then decides it.
SEC("xdp")
int local_pair_napi(struct xdp_md *ctx)
{
	return XDP_PASS;
}
