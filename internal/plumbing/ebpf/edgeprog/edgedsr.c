//go:build ignore

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// edgedsr.c implements the XDP ingress datapath for the edge gateway's
// Maglev/DSR (Direct Server Return) consistent-hash load-balancing engine,
// IPv6-only, phase 1 scope (plain TCP/UDP, no extension headers) -- see the
// design plan's §0 for the full architectural rationale. This replaces
// edgenat.c's Full-NAT (DNAT+SNAT) datapath entirely, not a mode alongside
// it: breaking change, no migration path, per the redesign's explicit
// decision to drop Full-NAT rather than grow a second personality.
//
// The defining simplification versus edgenat.c: this program does NO
// address or port rewriting at all. It picks a backend via consistent
// hashing on the client's own (address, port) and pushes an SRv6 outer
// header addressed to that backend's worker node -- the untouched original
// packet travels inside, unmodified. The backend answers the client
// *directly* (internal/plumbing/vip's loopback bind, or the tap-boundary
// substitution in internal/plumbing/ebpf/prog/usid.c, for a VM backend) --
// reply traffic never re-enters this program at all. Consequences that
// follow directly from that:
//
//   - No conn_table. Full-NAT needed one to remember which backend/SNAT
//     port a flow was assigned, because DNAT/SNAT state has to persist for
//     the life of the connection. DSR has nothing to remember: the same
//     consistent-hash table produces the same backend for the same flow on
//     every packet, forwards or not, with no state at all.
//   - No return/decap branch. Full-NAT's handle_return existed solely to
//     route its own SNAT'd replies back through this node. DSR never sees
//     replies, so there is nothing to decap here.
//   - No PAT/SNAT-port allocation, no L3/L4 checksum touch anywhere in this
//     file -- the packet's own checksum is already correct for its own,
//     completely unmodified content.
//
// What IS reused from edgenat.c, unchanged: push_outer_header/
// resolve_fib_and_write_eth's SRv6 encap-push mechanics (one
// bpf_xdp_adjust_head(-40) growing the packet, a fresh 54-byte
// Ethernet+IPv6 header written at the front, bpf_fib_lookup resolving the
// L2 next-hop) -- encapsulating toward a backend's worker-node uSID is
// identical work whether or not the datapath also NATs, so this file
// copies that mechanism rather than reinventing it.
//
// Packet path:
//
//  1. Parse the outer Ethernet + IPv6 header (bounds-checked). Not IPv6, or
//     unparseable -- XDP_PASS (falls through to the kernel stack).
//  2. Parse the L4 header (TCP or UDP only; anything else -- XDP_PASS).
//     Only source/destination port are read; nothing here is ever
//     rewritten, so no pointer-to-field resolution is needed the way
//     edgenat.c's parse_l4/l4_view needed for its later rewrite.
//  3. Match (proto, dst port, dst addr) against vip_table, keyed
//     identically to edgenat.c's former rule_table -- a VIP is globally
//     unique by construction, no tenant dimension needed. No match --
//     XDP_PASS (not one of this gateway's VIPs).
//  4. Claimed past this point (this gateway owns this VIP+port+protocol):
//     bump vip_stats_table's hit counters (packets/bytes/last_seen_ns),
//     lazily creating the row on first match -- same split-from-vip_table
//     convention edgenat.c's rule_stats_table used, and for the identical
//     reason (issue #361: a control-plane Register's read-modify-write
//     must never race this program's own per-packet increments).
//  5. Empty backend list -- drop, counted (EMPTY_BACKEND_LIST). Otherwise,
//     hash the client's own (address, port) and look up the precomputed
//     Maglev table (vip_table's own maglev_table field, populated by the
//     Go control plane's internal/maglev.Table -- see edgemap's doc
//     comment) to get a backend index, deterministically and statelessly:
//     every gateway node computes the identical index for the identical
//     flow from the identical (VIP, backend list) input, which is what
//     makes this design safe under anycast/ECMP (design plan §0's go/no-go
//     spike) -- a flow's packets landing on a different gateway node
//     mid-connection still resolve to the same backend.
//  6. Push a fresh 40-byte outer IPv6 header addressed to the chosen
//     backend's own worker-node SRv6 uSID (vip_table's per-backend field,
//     resolved by the Go control plane the same way any other cross-node
//     SRv6 destination is -- srv6.ComputeSID over the backend's
//     BGPRouter/BGPAdvertisement), sourced from this node's own
//     encap_config_table entry (this node's plain SRv6-reachable address --
//     unlike edgenat.c's gw_config, this is never a NAT/SNAT source and
//     never needs to match anything on a return path, since there is no
//     return path through this node at all). Resolve the L2 next-hop via
//     bpf_fib_lookup and XDP_TX back out this same interface.
//
// The same eBPF-verifier bounds-narrowing gotcha edgenat.c's own header
// comment documents applies to the backend-index lookup below (a Maglev
// table entry is a plain byte read from a map, not derived from a %
// expression the verifier can bound on its own) -- EDGE_BARRIER_VAR is
// reused unchanged.
#include <linux/bpf.h>

// __u8/__u16/__u32/__u64/__s16/__s32/__be16/__be32 all come transitively
// from <linux/bpf.h> -> <linux/types.h> -> <asm-generic/int-ll64.h>.

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define EDGE_ALWAYS_INLINE inline __attribute__((always_inline))

// EDGE_BARRIER_VAR forces the compiler to treat var as opaque immediately
// before a bounds-narrowing operation on it, so that operation survives
// dead-code elimination even when clang can otherwise prove the narrowing
// is redundant -- see edgenat.c's identical macro and header-comment
// gotcha; unchanged here.
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

// EDGE_MAX_BACKENDS matches NetworkRuleSpec.Backends' own
// +kubebuilder:validation:MaxItems=64 (go.datum.net/network's rule_types.go)
// -- edgenat.c's identical constant was fixed at 8, silently below the
// CRD's own advertised limit; closed here as a natural side effect of this
// rewrite rather than carried forward unexamined. Must stay a power of two
// for the EDGE_BARRIER_VAR mask trick below.
#define EDGE_MAX_BACKENDS 64

// EDGE_MAGLEV_TABLE_SIZE is this program's per-VIP Maglev lookup table
// size (internal/maglev.Table, mirrored here as a flat backend-index
// array -- see edgemap's doc comment for the Go-side construction). The
// Maglev paper recommends >=100x the backend count for its disruption
// bound to hold with wide margin; at EDGE_MAX_BACKENDS=64 that would be
// 6400+, but this is a *per-VIP* table (bounded by vip_table's own
// max_entries below), not the paper's single datacenter-wide table -- 1021
// (prime, ~16x this program's own backend cap) keeps each vip_table row's
// memory cost modest (~3KB) while still giving a meaningfully bounded
// disruption fraction (internal/maglev.Table's own tests pin the bound at
// this multiplier). Revisit if a real deployment's measured disruption on
// backend-set changes needs a tighter bound than this ratio gives.
#define EDGE_MAGLEV_TABLE_SIZE 1021

// ---------------------------------------------------------------------
// Minimal, self-contained header structs -- byte-exact to the wire
// formats, matching edgenat.c/usid.c's own convention (one external header
// dependency: <linux/bpf.h>).
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

// Only source/dest port are ever read (both TCP and UDP place them at the
// identical offset) -- unlike edgenat.c's edge_tcphdr/edge_udphdr, no
// other field of either header is ever touched, so one shared struct
// suffices instead of two protocol-specific ones.
struct edge_l4ports {
	__be16 source;
	__be16 dest;
} __attribute__((packed));

// ---------------------------------------------------------------------
// Map key/value types.
// ---------------------------------------------------------------------

// struct backend is one load-balancing target -- identical fields to
// edgenat.c's struct backend (this file's own encap-push needs exactly the
// same three fields; DSR just never touches addr/port for rewriting,
// only carries them through as identifying metadata the Go control plane
// may want for telemetry, and usid for the actual encap destination).
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

// struct vip_value is vip_table's value: the backend set for one
// VIP+port+protocol, plus a precomputed Maglev lookup table mapping each
// of EDGE_MAGLEV_TABLE_SIZE slots to an index into backends[]. generation
// is a __u64 monotonic-clock reading stamped by the Go control plane on
// every Register call, backing the same crash-safe Reconcile cutoff
// pattern usid.c's vrf_value.generation and edgenat.c's former
// rule_value.generation already use -- this program never reads it.
//
// Deliberately no packet/byte/drop counters here, for the identical
// issue-#361 reason edgenat.c's own rule_value doc comment gives: see
// struct vip_stats_value below, a separate map this program alone writes.
struct vip_value {
	__u32 backend_count;
	struct backend backends[EDGE_MAX_BACKENDS];
	__u8 maglev_table[EDGE_MAGLEV_TABLE_SIZE];
	__u64 generation;
};

// struct vip_stats_value is vip_stats_table's value -- identical shape and
// identical reason for existing as its own map as edgenat.c's former
// rule_stats_value (issue #361): the Go control plane's Register never
// writes this map at all, so its own per-packet __sync_fetch_and_add calls
// here never race a control-plane read-modify-write.
struct vip_stats_value {
	__u64 packets;
	__u64 bytes;
	__u64 dropped_packets;
	__u64 last_seen_ns;
};

// struct encap_config is encap_config_table's single-entry value: this
// gateway node's own plain SRv6-reachable address, used as the outer
// source for every pushed header. Unlike edgenat.c's gw_config (which
// doubled as the Full-NAT return-branch match address), this is never
// compared against anything on a receive path -- DSR has no return branch
// through this node at all -- so it is exactly this node's own
// loaddr.Detect()-equivalent address, nothing more.
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
// tuple -- identical technique to edgenat.c's own fnv1a_flow, reused here
// as the sole input to Maglev slot selection (hash % EDGE_MAGLEV_TABLE_SIZE)
// rather than a direct hash % backend_count: this is exactly what makes
// backend-set changes reassign only ~1/N of flows instead of ~100% of
// them (see internal/maglev's own doc comment).
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

// resolve_fib_and_write_eth and push_outer_header are edgenat.c's own
// encap-push mechanics, unchanged (see edgenat.c's identical functions for
// the full byte-level rationale) -- copied rather than shared via a common
// header because the two datapaths' surrounding types (struct edge_ip6hdr
// etc.) are independently defined in each file per this codebase's
// existing one-external-header-dependency convention; duplicating ~40
// lines of proven, unchanging mechanism is judged preferable to a shared
// header neither file otherwise needs.
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

	__builtin_memset(outer->vtc_flow, 0, sizeof(outer->vtc_flow));
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

	// Maglev slot selection: confirmed empirically via BPF_PROG_TEST_RUN
	// that, unlike a literal array index, the verifier does NOT track a
	// bounded range through clang's emitted division-by-constant sequence
	// for hash % EDGE_MAGLEV_TABLE_SIZE (1021 is prime, so clang lowers
	// the mod to a multiply-and-shift reciprocal trick, not a mask) --
	// "R2 unbounded memory access" at the maglev_table read below without
	// this. The same EDGE_BARRIER_VAR-then-clamp technique the
	// backend_idx step already needs (for a different reason: a plain
	// byte read from a map, not derivable from any expression at all) is
	// applied here too, just as an explicit range clamp instead of a mask
	// (EDGE_MAGLEV_TABLE_SIZE is prime, not a power of two, so no bitmask
	// is equivalent to bounding it).
	__u32 slot = fnv1a_flow(ip6->saddr, ports->source) % EDGE_MAGLEV_TABLE_SIZE;
	EDGE_BARRIER_VAR(slot);
	if (slot >= EDGE_MAGLEV_TABLE_SIZE)
		slot = EDGE_MAGLEV_TABLE_SIZE - 1;
	__u8 backend_idx = rule->maglev_table[slot];

	// backend_idx is a plain byte read from a map value, not derived from
	// a %-expression the verifier can bound on its own -- the same
	// bounds-narrowing gotcha edgenat.c's own header comment and
	// EDGE_BARRIER_VAR macro document, reused unchanged: EDGE_MAX_BACKENDS
	// must stay a power of two for this mask to be equivalent to a
	// range-check, and the barrier call keeps clang from eliminating it
	// as dead code once it (correctly, but unhelpfully for the verifier)
	// proves the mask redundant given backend_idx's declared type.
	EDGE_BARRIER_VAR(backend_idx);
	backend_idx &= (EDGE_MAX_BACKENDS - 1);
	struct backend *b = &rule->backends[backend_idx];

	__u32 cfg_key = 0;
	struct encap_config *cfg = bpf_map_lookup_elem(&encap_config_table, &cfg_key);
	if (!cfg) {
		count_claimed_drop(DROP_REASON_NO_ENCAP_CONFIG, stats);
		return XDP_DROP;
	}

	// The inner packet is pushed completely unmodified -- this is DSR's
	// entire premise (design plan §0): no DNAT, no SNAT, no checksum
	// touch, the client's own packet travels inside untouched all the way
	// to the backend, which replies to the client directly.
	__be16 inner_payload_len = ip6->payload_len;

	if (push_outer_header(ctx, cfg->encap_src, b->usid, inner_payload_len) != 0)
		return XDP_DROP;

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
