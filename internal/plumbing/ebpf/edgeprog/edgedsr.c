//go:build ignore

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// edgedsr.c implements the XDP ingress datapath for the edge gateway's Maglev
// direct-server-return load balancer. IPv6-only, plain TCP and UDP, no
// extension headers.
//
// It does no address or port rewriting at all. It picks a backend by consistent
// hashing on the client's own address and port, then pushes an SRv6 outer
// header addressed to that backend's worker node; the original packet travels
// inside unmodified. The backend answers the client directly, so reply traffic
// never re-enters this program. That has three consequences:
//
//   - No connection table. A full-NAT datapath needs one to remember which
//     backend and translated port a flow was assigned, because that state must
//     persist for the life of the connection. Here the same hash table produces
//     the same backend for the same flow on every packet, with no state.
//   - No return or decap branch, since this node never sees replies.
//   - No port allocation and no checksum touch anywhere in this file, the
//     packet's own checksum already being correct for its unmodified content.
//
// Packet path:
//
//  1. Parse the outer Ethernet and IPv6 header, bounds-checked. Not IPv6, or
//     unparseable: XDP_PASS to the kernel stack.
//  2. Parse the L4 header, TCP or UDP only. Only the ports are read, and
//     nothing is ever rewritten.
//  3. Match (proto, destination port, destination address) against vip_table. A
//     VIP is globally unique by construction, so no tenant dimension is needed.
//     No match: XDP_PASS.
//  4. Claimed past this point. Bump vip_stats_table's counters, creating the
//     row on first match. Stats live in their own map so a control-plane
//     read-modify-write can never race these per-packet increments.
//  5. An empty backend list is a counted drop. Otherwise hash the client's
//     address and port and index the precomputed Maglev table to get a backend.
//     Every gateway node computes the same index for the same flow from the
//     same inputs, which is what makes this safe under anycast: a flow landing
//     on a different node mid-connection still resolves to the same backend.
//  6. Push a fresh 40-byte outer IPv6 header addressed to that backend's
//     worker-node uSID, sourced from this node's encap_config_table entry,
//     which is simply this node's SRv6-reachable address and is never compared
//     against anything on a receive path. Resolve the L2 next hop and XDP_TX
//     back out the same interface.
//
// The verifier's bounds-narrowing behavior described at EDGE_BARRIER_VAR
// applies to the backend-index lookup below, a plain byte read from a map
// rather than an expression the verifier can bound.
#include <linux/bpf.h>

// __u8/__u16/__u32/__u64/__s16/__s32/__be16/__be32 all come transitively
// from <linux/bpf.h> -> <linux/types.h> -> <asm-generic/int-ll64.h>.

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define EDGE_ALWAYS_INLINE inline __attribute__((always_inline))

// EDGE_BARRIER_VAR forces the compiler to treat var as opaque immediately
// before a bounds-narrowing operation on it, so that operation survives
// dead-code elimination even where clang can prove the narrowing redundant.
#define EDGE_BARRIER_VAR(var) asm volatile("" : "=r"(var) : "0"(var))

// ---------------------------------------------------------------------
// BPF helper function declarations.
// ---------------------------------------------------------------------

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
				    __u64 flags) = (void *) BPF_FUNC_map_update_elem;
static long (*bpf_xdp_adjust_head)(void *ctx, int delta) = (void *) BPF_FUNC_xdp_adjust_head;
static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, __s32 plen,
			       __u32 flags) = (void *) BPF_FUNC_fib_lookup;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;

// ---------------------------------------------------------------------
// Constants.
// ---------------------------------------------------------------------

#define EDGE_AF_INET6 10
#define EDGE_ETH_P_IPV6 0x86DD
#define EDGE_IPPROTO_TCP 6
#define EDGE_IPPROTO_UDP 17
#define EDGE_IPPROTO_IPV6 41 // this program's own pushed outer header's Next Header, always

// EDGE_MAX_BACKENDS matches the CRD's own maximum backend count. It must stay a
// power of two for the masking below to be equivalent to a range check.
#define EDGE_MAX_BACKENDS 64

// EDGE_MAGLEV_TABLE_SIZE is the per-VIP Maglev lookup table size, mirrored here
// as a flat backend-index array.
//
// The Maglev paper recommends at least 100 times the backend count for its
// disruption bound to hold with wide margin, which at this backend cap would be
// 6400 or more. That figure is for a single datacenter-wide table; this is per
// VIP, so 1021, prime and roughly 16 times the backend cap, keeps each row's
// memory cost near 3KB while still bounding disruption meaningfully. Revisit if
// a deployment's measured disruption on backend-set changes needs tighter.
#define EDGE_MAGLEV_TABLE_SIZE 1021

// ---------------------------------------------------------------------
// Minimal, self-contained header structs, byte-exact to the wire formats, with
// one external header dependency.
// ---------------------------------------------------------------------

struct edge_ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
} __attribute__((packed));

struct edge_ip6hdr {
	__u8 vtc_flow[4];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
} __attribute__((packed));

// Only the ports are ever read, and TCP and UDP place them at the same offset,
// so one shared struct covers both.
struct edge_l4ports {
	__be16 source;
	__be16 dest;
} __attribute__((packed));

// ---------------------------------------------------------------------
// Map key/value types.
// ---------------------------------------------------------------------

// struct backend is one load-balancing target. addr and port are carried
// through as identifying metadata for the control plane; only usid is used, as
// the encapsulation destination.
struct backend {
	__u8 addr[16];
	__be16 port;
	__u8 usid[16];
};

// struct vip_key is vip_table's key -- identical composition to edgenat.c's
// former rule_key (proto, dst port, VIP address). No tenant dimension: a
// VIP is globally unique by construction.
struct vip_key {
	__u8 proto;
	__u8 pad[1];
	__be16 port;
	__u8 vip[16];
};

// struct vip_value is vip_table's value: the backend set for one VIP, port, and
// protocol, plus a precomputed Maglev table mapping each slot to an index into
// backends. generation is a monotonic reading stamped by the control plane on
// every registration, backing the crash-safe reconcile cutoff, and is never
// read here.
//
// Deliberately no counters: see struct vip_stats_value below, a separate map
// only this program writes.
struct vip_value {
	__u32 backend_count;
	struct backend backends[EDGE_MAX_BACKENDS];
	__u8 maglev_table[EDGE_MAGLEV_TABLE_SIZE];
	__u64 generation;
};

// struct vip_stats_value is vip_stats_table's value. It is a separate map
// because the control plane never writes it, so this program's per-packet
// atomic increments can never race a control-plane read-modify-write.
struct vip_stats_value {
	__u64 packets;
	__u64 bytes;
	__u64 dropped_packets;
	__u64 last_seen_ns;
};

// struct encap_config is encap_config_table's single-entry value: this gateway
// node's SRv6-reachable address, used as the outer source of every pushed
// header. It is never compared against anything on a receive path, since no
// return traffic passes through this node.
struct encap_config {
	__u8 encap_src[16];
};

// Drop reason indices into the drop_reasons map -- a much smaller set than
// edgenat.c's former enum edge_drop_reason, since DSR has no conn_table,
// no PAT allocation, and no return/decap branch to fail in.
enum edge_drop_reason {
	DROP_REASON_EMPTY_BACKEND_LIST = 0,
	DROP_REASON_NO_ENCAP_CONFIG    = 1,
	DROP_REASON_FIB_NO_NEIGH       = 2,
	DROP_REASON_FIB_UNREACHABLE    = 3,
	DROP_REASON_FIB_FRAG_NEEDED    = 4,
	DROP_REASON_FIB_LOOKUP_FAILED  = 5,
	DROP_REASON_ADJUST_HEAD_FAILED = 6,
	DROP_REASON_COUNT              = 7,
};

// ---------------------------------------------------------------------
// Maps.
// ---------------------------------------------------------------------

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct vip_key);
	__type(value, struct vip_value);
} vip_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct vip_key);
	__type(value, struct vip_stats_value);
} vip_stats_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct encap_config);
} encap_config_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, DROP_REASON_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} drop_reasons SEC(".maps");

static EDGE_ALWAYS_INLINE void count_drop(__u32 reason)
{
	__u64 *counter = bpf_map_lookup_elem(&drop_reasons, &reason);
	if (counter)
		*counter += 1;
}

static EDGE_ALWAYS_INLINE void count_claimed_drop(__u32 reason, struct vip_stats_value *stats)
{
	count_drop(reason);
	if (stats)
		__sync_fetch_and_add(&stats->dropped_packets, 1);
}

// fnv1a_flow is a deterministic, stateless hash of a flow's client-facing
// tuple. It feeds Maglev slot selection rather than a direct modulo over the
// backend count, which is what makes a backend-set change reassign roughly one
// flow in N instead of nearly all of them.
static EDGE_ALWAYS_INLINE __u32 fnv1a_flow(const __u8 addr[16], __be16 port)
{
	__u32 h = 2166136261u;
	for (int i = 0; i < 16; i++) {
		h ^= addr[i];
		h *= 16777619u;
	}
	h ^= (__u8) (port & 0xff);
	h *= 16777619u;
	h ^= (__u8) (port >> 8);
	h *= 16777619u;
	return h;
}

// resolve_fib_and_write_eth and push_outer_header carry the encapsulation
// mechanics: grow the packet, write a fresh Ethernet and IPv6 header at the
// front, and resolve the L2 next hop. They are duplicated rather than shared
// through a header because each datapath file defines its own header structs
// under the one-external-dependency convention.
static EDGE_ALWAYS_INLINE long resolve_fib_and_write_eth(void *ctx, __u32 ifindex,
							  const __u8 src[16], const __u8 dst[16],
							  __u16 tot_len, struct edge_ethhdr *eth)
{
	struct bpf_fib_lookup fib_params;
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.family = EDGE_AF_INET6;
	__builtin_memcpy(&fib_params.ipv6_src, src, 16);
	__builtin_memcpy(&fib_params.ipv6_dst, dst, 16);
	fib_params.ifindex = ifindex;
	fib_params.tot_len = tot_len;

	long fib_rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS)
		return fib_rc;

	__builtin_memcpy(eth->h_dest, fib_params.dmac, sizeof(eth->h_dest));
	__builtin_memcpy(eth->h_source, fib_params.smac, sizeof(eth->h_source));
	eth->h_proto = __builtin_bswap16(EDGE_ETH_P_IPV6);
	return BPF_FIB_LKUP_RET_SUCCESS;
}

static EDGE_ALWAYS_INLINE void count_fib_drop(long fib_rc)
{
	if (fib_rc == BPF_FIB_LKUP_RET_NO_NEIGH)
		count_drop(DROP_REASON_FIB_NO_NEIGH);
	else if (fib_rc == BPF_FIB_LKUP_RET_UNREACHABLE || fib_rc == BPF_FIB_LKUP_RET_BLACKHOLE ||
		 fib_rc == BPF_FIB_LKUP_RET_PROHIBIT)
		count_drop(DROP_REASON_FIB_UNREACHABLE);
	else if (fib_rc == BPF_FIB_LKUP_RET_FRAG_NEEDED)
		count_drop(DROP_REASON_FIB_FRAG_NEEDED);
	else
		count_drop(DROP_REASON_FIB_LOOKUP_FAILED);
}

static EDGE_ALWAYS_INLINE int push_outer_header(struct xdp_md *ctx, const __u8 src[16],
						 const __u8 dst[16], __be16 inner_payload_len_plus_ip6hdr)
{
	if (bpf_xdp_adjust_head(ctx, -40) != 0) {
		count_drop(DROP_REASON_ADJUST_HEAD_FAILED);
		return -1;
	}

	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	if (data + sizeof(struct edge_ethhdr) + sizeof(struct edge_ip6hdr) > data_end) {
		count_drop(DROP_REASON_ADJUST_HEAD_FAILED);
		return -1;
	}

	struct edge_ethhdr *eth = data;
	struct edge_ip6hdr *outer = (void *) (eth + 1);

	// vtc_flow's first nibble is the IPv6 version and must be 6 rather than a
	// zeroed default. A synthetic program run never validates this, but any
	// receiver downstream parses such a header as invalid IPv6 with version 0.
	// usid_ingress's decap reads fields at fixed offsets and never checks the
	// version, so this is invisible on that path, while any version-checking
	// hop or receiver would reject every packet pushed.
	__builtin_memset(outer->vtc_flow, 0, sizeof(outer->vtc_flow));
	outer->vtc_flow[0] = 0x60;
	outer->payload_len = inner_payload_len_plus_ip6hdr;
	outer->nexthdr = EDGE_IPPROTO_IPV6;
	outer->hop_limit = 64;
	__builtin_memcpy(outer->saddr, src, 16);
	__builtin_memcpy(outer->daddr, dst, 16);

	long fib_rc = resolve_fib_and_write_eth(ctx, ctx->ingress_ifindex, src, dst,
						 (__u16) (sizeof(*outer) + __builtin_bswap16(inner_payload_len_plus_ip6hdr)),
						 eth);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS) {
		count_fib_drop(fib_rc);
		return -1;
	}
	return 0;
}

// ---------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------

SEC("xdp")
int edge_lb(struct xdp_md *ctx)
{
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	struct edge_ethhdr *eth = data;
	if ((void *) (eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != __builtin_bswap16(EDGE_ETH_P_IPV6))
		return XDP_PASS;

	struct edge_ip6hdr *ip6 = (void *) (eth + 1);
	if ((void *) (ip6 + 1) > data_end)
		return XDP_PASS;

	if (ip6->nexthdr != EDGE_IPPROTO_TCP && ip6->nexthdr != EDGE_IPPROTO_UDP)
		return XDP_PASS;

	struct edge_l4ports *ports = (void *) (ip6 + 1);
	if ((void *) (ports + 1) > data_end)
		return XDP_PASS;

	struct vip_key vk;
	__builtin_memset(&vk, 0, sizeof(vk));
	vk.proto = ip6->nexthdr;
	vk.port = ports->dest;
	__builtin_memcpy(vk.vip, ip6->daddr, 16);

	struct vip_value *rule = bpf_map_lookup_elem(&vip_table, &vk);
	if (!rule)
		return XDP_PASS; // not one of this gateway's VIPs

	// Claimed past this point -- every subsequent failure is a drop, not
	// a pass-through (this gateway owns this VIP+port+protocol).
	struct vip_stats_value *stats = bpf_map_lookup_elem(&vip_stats_table, &vk);
	if (!stats) {
		struct vip_stats_value init;
		__builtin_memset(&init, 0, sizeof(init));
		bpf_map_update_elem(&vip_stats_table, &vk, &init, BPF_NOEXIST);
		stats = bpf_map_lookup_elem(&vip_stats_table, &vk);
	}
	if (stats) {
		__sync_fetch_and_add(&stats->packets, 1);
		__sync_fetch_and_add(&stats->bytes, (__u64) ((char *) data_end - (char *) data));
		stats->last_seen_ns = bpf_ktime_get_ns();
	}

	if (rule->backend_count == 0) {
		count_claimed_drop(DROP_REASON_EMPTY_BACKEND_LIST, stats);
		return XDP_DROP;
	}

	// Maglev slot selection. Unlike a literal array index, the verifier does
	// not track a bounded range through clang's division-by-constant sequence
	// for this modulo: the table size is prime, so clang lowers it to a
	// multiply-and-shift reciprocal rather than a mask, and the read below is
	// rejected as unbounded without help. The same barrier-then-clamp technique
	// the backend index needs is applied here, as an explicit range clamp
	// rather than a mask, since no bitmask bounds a prime.
	__u32 slot = fnv1a_flow(ip6->saddr, ports->source) % EDGE_MAGLEV_TABLE_SIZE;
	EDGE_BARRIER_VAR(slot);
	if (slot >= EDGE_MAGLEV_TABLE_SIZE)
		slot = EDGE_MAGLEV_TABLE_SIZE - 1;
	__u8 backend_idx = rule->maglev_table[slot];

	// backend_idx is a plain byte read from a map value, not derived from an
	// expression the verifier can bound. EDGE_MAX_BACKENDS must stay a power of
	// two for this mask to be equivalent to a range check, and the barrier
	// keeps clang from eliminating the mask as dead once it proves it redundant
	// given the declared type.
	EDGE_BARRIER_VAR(backend_idx);
	backend_idx &= (EDGE_MAX_BACKENDS - 1);
	struct backend *b = &rule->backends[backend_idx];

	__u32 cfg_key = 0;
	struct encap_config *cfg = bpf_map_lookup_elem(&encap_config_table, &cfg_key);
	if (!cfg) {
		count_claimed_drop(DROP_REASON_NO_ENCAP_CONFIG, stats);
		return XDP_DROP;
	}

	// The inner packet is pushed completely unmodified: no translation and no
	// checksum touch, the client's packet travelling inside untouched to the
	// backend, which replies to the client directly.
	//
	// The outer header's payload length must cover the entire inner packet
	// including its own 40-byte IPv6 header, not just the transport payload the
	// inner payload_len names. Passing that field directly undercounts the outer
	// length by exactly 40 bytes on every packet, which a receiver parses as an
	// invalid length. usid_ingress's decap reads at fixed offsets and never
	// validates the length, so this is invisible on that path while any
	// length-validating hop would reject every packet pushed.
	__be16 inner_payload_len_plus_ip6hdr =
		__builtin_bswap16((__u16) sizeof(struct edge_ip6hdr) + __builtin_bswap16(ip6->payload_len));

	if (push_outer_header(ctx, cfg->encap_src, b->usid, inner_payload_len_plus_ip6hdr) != 0)
		return XDP_DROP;

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
