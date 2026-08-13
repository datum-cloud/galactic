//go:build ignore

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// edgenat.c implements the XDP ingress datapath for the edge gateway's
// Full-NAT (DNAT+SNAT) load-balancing engine, IPv6-only, phase 1 scope
// (plain TCP/UDP, no extension headers, deterministic FNV-1a-hash-of-flow
// backend selection, no active conn_table GC -- conn_table is
// BPF_MAP_TYPE_LRU_HASH, self-evicting under pressure, same convention
// gwprog's earlier, rejected Geneve-based conn_table used).
//
// One program, one attach point per gateway node (the node's single
// public/underlay-facing uplink interface -- there is no separate
// "public" vs "fabric" NIC in this topology, and no Geneve device to demux
// direction by ifindex the way the rejected gwprog design did). Direction
// is decided by matching the packet's outer IPv6 destination against this
// node's own configured gw_addr (gw_config_table), exactly the way
// internal/plumbing/ebpf/prog/usid.c already decides "is this mine" by
// locator match, just against a single address instead of a locator
// block/function/argument hierarchy -- this program has no VRF concept at
// all (see the design plan's decision #4: because the outer SRv6 header is
// written directly from this program's own rule_table/conn_table, there is
// no kernel VRF/FIB route this program depends on for the encap itself).
//
// Packet path:
//
//  1. Parse the outer Ethernet + IPv6 header (bounds-checked). Not IPv6,
//     or too short to parse -- XDP_PASS (this program only ever claims
//     traffic it can fully parse and match; anything else falls through
//     to the normal kernel stack, e.g. BGP/SSH to the node itself).
//
//  2. RETURN/DECAP BRANCH: if the outer destination matches this node's
//     own gw_addr (gw_config_table), this is a reply this node SNAT'd on
//     the way out -- see handle_return(). The outer next header must be
//     41 (IPv6-in-IPv6, the same ENCAP_RED wire format
//     internal/plumbing/srv6/egress.go's RouteEgressAdd already uses for
//     every other cross-node SRv6 packet in this codebase -- no SRH, the
//     single segment is fully expressed by the outer destination address)
//     -- anything else is a malformed/unexpected packet claimed by this
//     address and is dropped, not passed through (once claimed, silent
//     pass-through would misdeliver it, same fail-closed reasoning as
//     usid.c's own claimed-packet drops).
//
//     Strip the outer header (two bpf_xdp_adjust_head calls -- see the
//     comment at handle_return's strip_outer_header call site for why one
//     flat +40 does not work), look up conn_table by the revealed inner
//     packet's own 5-tuple (this is the *reverse* row: (proto,
//     backend_addr:backend_port -> gw_addr:snat_port)), and if found,
//     rewrite the inner packet's addresses/ports back to the client's
//     original view (saddr=VIP, sport=VIP port; daddr/dport = the
//     original client's own address/port) -- un-SNAT and un-DNAT in one
//     step, since Full-NAT changed both on the way in. Fix the L4
//     checksum via bpf_csum_diff (bpf_l4_csum_replace/
//     bpf_l3_csum_replace require __sk_buff and are unavailable to an XDP
//     program -- see edgepreflight's doc comment). Resolve the new L2
//     next-hop toward the client via bpf_fib_lookup and XDP_TX back out
//     this same interface. No conn_table hit -- this address is claimed,
//     so drop rather than pass through.
//
//  3. FORWARD/INGRESS BRANCH: otherwise, parse the L4 header (TCP or UDP
//     only; anything else -- XDP_PASS) and match (proto, dst port, dst
//     addr) against rule_table, keyed by VIP+port only, no tenant
//     dimension needed -- a VIP is globally unique by construction, the
//     same invariant gwprog's own gw_pub_ingress relied on. No match --
//     XDP_PASS (not one of this gateway's VIPs).
//
//     Look up conn_table by the *forward* row key
//     (proto, client_addr:client_port -> VIP:VIP port). A hit reuses the
//     already-assigned backend and SNAT port (so a flow's translation
//     never changes mid-connection even if rule_table's backend list
//     changes later). A miss allocates fresh state -- but only for a TCP
//     SYN or any UDP packet (there is no other correct point to start a
//     new translated flow); anything else with no existing state is
//     dropped, not passed through (this address is claimed).
//
//     New-flow allocation: pick a backend by
//     hash(client_addr,client_port) % rule->backend_count (deterministic
//     per-flow, same technique gwprog used), then claim a SNAT port for
//     (backend_addr,backend_port) by probing a small, bounded number of
//     candidate ports (starting from a hash of the client's own tuple) and
//     inserting the *reverse* conn_table row with BPF_NOEXIST -- this is
//     the actual atomic claim, and it is also the sole liveness mechanism
//     for port reuse: once a flow's conn_table rows are LRU-evicted, the
//     same reverse-row insert simply succeeds again for a new flow,
//     without any separate GC or explicit free needed. Note this design
//     only needs to avoid a same-(SNAT port, backend) collision -- two
//     different flows sharing a SNAT port but going to *different*
//     backends never collide, because backend_addr/backend_port are part
//     of the reverse key. Every probe attempt failing -- drop
//     (PAT_EXHAUSTED), not pass through.
//
//     DNAT the destination to the chosen backend, SNAT the source to this
//     node's own gw_addr:allocated-port, fix the L4 checksum, then push a
//     fresh 40-byte outer IPv6 header addressed to the backend's own
//     worker-node SRv6 uSID (rule_table's per-backend field, resolved by
//     the Go control plane the same way any other cross-node SRv6
//     destination is -- srv6.ComputeSID over the backend's BGPRouter/
//     BGPAdvertisement, see internal/gateway's doc comment) via a single
//     bpf_xdp_adjust_head(-40) call (see push_outer_header's comment for
//     why one call suffices here, unlike the two-call strip). Resolve the
//     new L2 next-hop via bpf_fib_lookup and XDP_TX back out this same
//     interface.
//
// A real eBPF verifier gotcha carried over from gwprog's own header
// comment: the backend-selection index (hash % backend_count, then
// rule->backends[idx]) needs an explicit bounds-narrowing op for the
// *verifier* specifically -- it does not propagate a range bound from %'s
// divisor onto the result. clang can independently prove the bound and
// eliminate a naive narrowing op as dead code, so this file uses the same
// EDGE_BARRIER_VAR macro gwprog used (an opaquing asm volatile no-op) to
// force the mask to survive as a real instruction the verifier can see.
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
// is redundant -- see the header comment above and gwprog/gwnat.c's
// identical gotcha.
#define EDGE_BARRIER_VAR(var) asm volatile("" : "=r"(var) : "0"(var))

// ---------------------------------------------------------------------
// BPF helper function declarations, using the enum bpf_func_id constants
// from <linux/bpf.h> rather than hardcoded helper IDs.
// ---------------------------------------------------------------------

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
				    __u64 flags) = (void *) BPF_FUNC_map_update_elem;

// Growing/shrinking the packet for the pushed/stripped outer SRv6 header.
// Unlike TC-BPF's bpf_skb_adjust_room(..., BPF_ADJ_ROOM_MAC, ...), this
// helper has no mode that automatically relocates the Ethernet header for
// us -- see push_outer_header/strip_outer_header for the manual technique
// this program uses instead.
static long (*bpf_xdp_adjust_head)(void *ctx, int delta) = (void *) BPF_FUNC_xdp_adjust_head;

// The XDP-safe checksum-fixup helper -- bpf_l4_csum_replace/
// bpf_l3_csum_replace require __sk_buff and are unavailable here.
static __s64 (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size,
			       __wsum seed) = (void *) BPF_FUNC_csum_diff;

static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, __s32 plen,
			       __u32 flags) = (void *) BPF_FUNC_fib_lookup;

// Timestamps rule_value.last_seen_ns (Phase E hit counters) -- CLOCK_MONOTONIC
// nanoseconds since boot, same clock source usid.c's vrf_value.last_seen_ns
// and gwnat.c's identical field already use.
static __u64 (*bpf_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;

// ---------------------------------------------------------------------
// Address-family / protocol constants (fixed kernel ABI, never change).
// ---------------------------------------------------------------------

#define EDGE_AF_INET6 10
#define EDGE_ETH_P_IPV6 0x86DD
#define EDGE_IPPROTO_TCP 6
#define EDGE_IPPROTO_UDP 17

// EDGE_IPPROTO_IPV6 (41) is the outer Next Header value this program's own
// pushed header always uses, and the only one its return branch accepts --
// the same plain IPv6-in-IPv6, no-SRH wire format
// internal/plumbing/srv6/egress.go's RouteEgressAdd already installs for
// every other cross-node SRv6 packet in this codebase (SEG6_IPTUN_MODE_
// ENCAP_RED). Using the same format means the destination worker node's
// existing internal/plumbing/ebpf/prog/usid.c decaps this program's own
// pushed packets with zero changes on that end.
#define EDGE_IPPROTO_IPV6 41

#define EDGE_TCP_FLAG_SYN 0x02

// ---------------------------------------------------------------------
// Minimal, self-contained header structs -- byte-exact to the wire
// formats, hand-rolled so this file has exactly one external header
// dependency (<linux/bpf.h>), matching usid.c's own convention.
// ---------------------------------------------------------------------

struct edge_ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
} __attribute__((packed));

// Deliberately not the kernel's bitfield-based struct ipv6hdr (endian
// dependent) -- this program never reads version/traffic-class/flow
// label, so vtc_flow is left as an opaque 4-byte blob, matching usid.c's
// usid_ip6hdr.
struct edge_ip6hdr {
	__u8 vtc_flow[4];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
} __attribute__((packed));

// Only the fields this program reads/writes: source/dest port and the
// SYN flag. TCP options (anything past byte 20) are never inspected --
// phase 1 scope excludes extension/option parsing, matching gwprog's own
// "plain TCP/UDP" precedent.
struct edge_tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u8 doff_reserved;
	__u8 flags;
	__be16 window;
	__be16 check;
	__be16 urg_ptr;
} __attribute__((packed));

struct edge_udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
} __attribute__((packed));

// ---------------------------------------------------------------------
// Map key/value types.
// ---------------------------------------------------------------------

#define EDGE_MAX_BACKENDS 8

// struct backend is one load-balancing target: the Pod's own address, the
// port traffic is forwarded to, and the SRv6 uSID of the worker node that
// address is reachable through -- resolved by the Go control plane via
// the same srv6.ComputeSID path any other cross-node destination uses
// (internal/gateway's doc comment), never parsed from a packet.
struct backend {
	__u8 addr[16];
	__be16 port;
	__u8 usid[16];
};

// struct rule_key is rule_table's key: an ingress VIP+port+protocol. No
// tenant dimension -- a VIP is globally unique by construction (design
// plan decision #1), so (proto, port, vip) alone disambiguates every rule
// on this node.
struct rule_key {
	__u8 proto;
	__u8 pad[1];
	__be16 port;
	__u8 vip[16];
};

// struct rule_value is rule_table's value: the load-balancing target set
// for one VIP+port+protocol, plus per-rule hit counters (Phase E) backing
// internal/gateway's QuotaEnforcer/TelemetryEmitter -- same
// packets/bytes/dropped_packets/last_seen_ns convention as an earlier,
// rejected design's equivalent rule_value, deliberately deferred out
// of Phase B/C's scope (see internal/gateway/datapath.go's QuotaEnforcer
// doc comment for why) rather than spread across two phases' worth of
// speculative fields. generation is a __u64 monotonic-clock reading
// stamped by the Go control plane's edgemap.RuleTable.Register on every
// write, backing its crash-safe Reconcile cutoff (same pattern as
// internal/plumbing/ebpf/usidmap's locator_value.generation and gwprog's
// identical rule_value.generation) -- this program never reads this field
// itself, so widening or repurposing it has no effect on the packet path.
//
// Deliberately NOT __attribute__((packed)) -- a map value has no
// on-the-wire byte-layout requirement (bpf2go derives the matching Go
// struct from BTF, padding included, regardless), and packing this one
// specifically would misalign the u64 counter fields below out of natural
// 8-byte alignment, which __sync_fetch_and_add requires (clang warns
// -Wsync-alignment; some architectures fault outright on a misaligned
// atomic op). Same unpacked choice as gwnat.c's identical struct, for the
// same reason.
struct rule_value {
	__u32 backend_count;
	struct backend backends[EDGE_MAX_BACKENDS];
	__u64 packets;
	__u64 bytes;
	__u64 dropped_packets;
	__u64 last_seen_ns;
	__u64 generation;
};

// struct conn_key is conn_table's key: a plain 5-tuple, oriented however
// the packet being looked up actually appears on the wire -- the forward
// row is keyed by the client-facing tuple (saddr/sport = client,
// daddr/dport = VIP); the reverse row is keyed by the backend-facing
// tuple (saddr/sport = backend, daddr/dport = this node's own
// gw_addr:allocated SNAT port). Both rows are written with the *same*
// conn_value (see below), so either lookup direction yields everything
// needed to rewrite the packet.
struct conn_key {
	__u8 proto;
	__u8 pad[1];
	__be16 sport;
	__be16 dport;
	__u8 saddr[16];
	__u8 daddr[16];
};

// struct conn_value carries the full picture of one translated flow.
struct conn_value {
	__u8 client_addr[16];
	__be16 client_port;
	__u8 vip_addr[16];
	__be16 vip_port;
	__u8 backend_addr[16];
	__be16 backend_port;
	__u8 backend_usid[16];
	__u8 gw_addr[16];
	__be16 gw_port;
	__u8 proto;
	__u8 pad[1];
};

// struct gw_config is gw_config_table's single-entry value: this gateway
// node's own SRv6-reachable address, used both as the Full-NAT SNAT
// source and as the return-branch match address (design plan's
// NetworkGatewayStatus.SRv6Address).
struct gw_config {
	__u8 gw_addr[16];
};

// Drop reason indices into the drop_reasons map -- see dropreason.go for
// the exported Go constants any caller outside this package should use
// instead of a hand-kept copy of this enum (bpf2go's -type flag cannot
// generate a Go type for a C enum that is only ever used as a literal
// constant, same rationale as prog/dropreason.go's identical note).
enum edge_drop_reason {
	DROP_REASON_NO_BACKENDS       = 0,
	DROP_REASON_NO_CONN_NOT_SYN   = 1,
	DROP_REASON_PAT_EXHAUSTED     = 2,
	DROP_REASON_MALFORMED_RETURN  = 3,
	DROP_REASON_NO_RETURN_CONN    = 4,
	DROP_REASON_FIB_NO_NEIGH      = 5,
	DROP_REASON_FIB_UNREACHABLE   = 6,
	DROP_REASON_FIB_FRAG_NEEDED   = 7,
	DROP_REASON_FIB_LOOKUP_FAILED = 8,
	// push_outer_header's own bpf_xdp_adjust_head(-40) growing the packet
	// for the pushed outer header, or the bounds check immediately after
	// it, failed -- distinct from the FIB failures above (which run
	// *inside* push_outer_header too, just further along, once the outer
	// header has already been written): this reason means the header
	// itself was never written at all.
	DROP_REASON_ADJUST_HEAD_FAILED = 9,
	DROP_REASON_COUNT              = 10,
};

// ---------------------------------------------------------------------
// Maps.
// ---------------------------------------------------------------------

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct rule_key);
	__type(value, struct rule_value);
} rule_table SEC(".maps");

// BPF_MAP_TYPE_LRU_HASH: self-evicting under pressure rather than failing
// closed once full -- see edgepreflight's doc comment on why this map
// type specifically is a required kernel capability, and this file's
// header comment on why eviction alone (no separate GC pass) is a
// sufficient port-reclaim mechanism.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, struct conn_value);
} conn_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct gw_config);
} gw_config_table SEC(".maps");

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

// count_claimed_drop records a drop that happened after rule was already
// matched against rule_table -- i.e. this gateway definitely owns this
// VIP+port+protocol, so the drop counts against that rule's own
// dropped_packets in addition to the global drop_reasons counter (same
// convention as an earlier, rejected design's equivalent). Unlike
// drop_reasons (BPF_MAP_TYPE_PERCPU_ARRAY, so count_drop's plain
// increment is race-free), rule_table is a plain HASH shared across CPUs,
// so this uses __sync_fetch_and_add.
static EDGE_ALWAYS_INLINE void count_claimed_drop(__u32 reason, struct rule_value *rule)
{
	count_drop(reason);
	__sync_fetch_and_add(&rule->dropped_packets, 1);
}

// ---------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------

static EDGE_ALWAYS_INLINE int addr6_eq(const __u8 a[16], const __u8 b[16])
{
	for (int i = 0; i < 16; i++) {
		if (a[i] != b[i])
			return 0;
	}
	return 1;
}

// fnv1a_flow is a deterministic, stateless hash of a flow's client-facing
// tuple, used both for backend selection (hash % backend_count) and as the
// starting point for SNAT port probing. Same technique gwprog's own
// gw_pub_ingress used for backend selection.
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

// csum_fold_add applies diff (as returned by bpf_csum_diff) to an existing
// ones'-complement checksum field, folding carries -- the standard
// incremental-checksum-update technique (RFC 1624), used here because
// bpf_l3_csum_replace/bpf_l4_csum_replace (which fold this automatically)
// require __sk_buff and are unavailable to an XDP program.
static EDGE_ALWAYS_INLINE __be16 csum_fold_add(__be16 check, __s64 diff)
{
	__s64 sum = (__u16) ~check;
	sum += diff;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__be16) ~((__u16) sum);
}

// EDGE_PAT_PROBE_LIMIT bounds the linear probe below at compile time (a
// verifier-friendly, fully unrolled loop rather than relying on
// kernel-version-dependent bounded-loop support).
#define EDGE_PAT_PROBE_LIMIT 8
#define EDGE_PAT_PORT_BASE 32768
#define EDGE_PAT_PORT_RANGE 28000

// ---------------------------------------------------------------------
// Forward/ingress branch.
// ---------------------------------------------------------------------

// struct l4_view carries out sport/dport/is_syn plus DIRECT, already-typed
// pointers to the fields a later rewrite needs to touch (source port, dest
// port, checksum) -- resolved once, at parse_l4's own bounds-checked call
// site, and never re-derived from a type-erased void* cast on a
// proto-based branch taken again later. An earlier version of this
// program stored a single `void *l4hdr` here and re-cast it to
// struct edge_tcphdr*/edge_udphdr* at the point of use based on a
// re-evaluated proto comparison -- the verifier rejected that (a
// pointer's proven safe-range, tracked per register/stack-slot, did not
// survive being read back and reinterpreted at a different program point
// than its own bounds check): "invalid access to packet ... R2 min value
// is outside of the allowed memory range". Resolving typed field pointers
// exactly once, adjacent to the one bounds check that proves them safe,
// removes that whole class of problem.
struct l4_view {
	__be16 sport;
	__be16 dport;
	__u8 is_syn;
	__be16 *sport_ptr;
	__be16 *dport_ptr;
	__be16 *check_ptr;
};

static EDGE_ALWAYS_INLINE int parse_l4(__u8 proto, void *l4, void *data_end, struct l4_view *out)
{
	if (proto == EDGE_IPPROTO_TCP) {
		struct edge_tcphdr *tcp = l4;
		if ((void *) (tcp + 1) > data_end)
			return -1;
		out->sport = tcp->source;
		out->dport = tcp->dest;
		out->is_syn = (tcp->flags & EDGE_TCP_FLAG_SYN) != 0;
		out->sport_ptr = &tcp->source;
		out->dport_ptr = &tcp->dest;
		out->check_ptr = &tcp->check;
		return 0;
	}
	if (proto == EDGE_IPPROTO_UDP) {
		struct edge_udphdr *udp = l4;
		if ((void *) (udp + 1) > data_end)
			return -1;
		out->sport = udp->source;
		out->dport = udp->dest;
		out->is_syn = 1; // any UDP packet may start a new flow
		out->sport_ptr = &udp->source;
		out->dport_ptr = &udp->dest;
		out->check_ptr = &udp->check;
		return 0;
	}
	return -1;
}

// fix_l4_checksum applies the combined address+port checksum delta for a
// Full-NAT rewrite (both addresses and both ports changed) to *check_ptr
// -- already resolved to the correct field by parse_l4, so this function
// needs no proto parameter of its own.
static EDGE_ALWAYS_INLINE void fix_l4_checksum(__be16 *check_ptr,
						const __u8 old_saddr[16], const __u8 old_daddr[16],
						__be16 old_sport, __be16 old_dport,
						const __u8 new_saddr[16], const __u8 new_daddr[16],
						__be16 new_sport, __be16 new_dport)
{
	__be32 old_words[9];
	__be32 new_words[9];

	__builtin_memcpy(&old_words[0], old_saddr, 16);
	__builtin_memcpy(&old_words[4], old_daddr, 16);
	old_words[8] = ((__be32) old_sport << 16) | (__be32) old_dport;

	__builtin_memcpy(&new_words[0], new_saddr, 16);
	__builtin_memcpy(&new_words[4], new_daddr, 16);
	new_words[8] = ((__be32) new_sport << 16) | (__be32) new_dport;

	__s64 diff = bpf_csum_diff(old_words, sizeof(old_words), new_words, sizeof(new_words), 0);
	*check_ptr = csum_fold_add(*check_ptr, diff);
}

// resolve_fib_and_write_eth resolves the L2 next-hop for dst via
// bpf_fib_lookup and writes it into eth's dest/source fields, setting
// h_proto to IPv6. ifindex is the interface this program is attached to
// (ctx->ingress_ifindex) -- the resolved egress interface for
// BPF_FIB_LOOKUP_DIRECT is expected to be the same interface XDP_TX
// retransmits out of; this program has no VRF/tbid scoping (design plan
// decision #4), unlike usid.c's own FIB lookup.
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
		// No ICMPv6 Packet Too Big is generated here -- the same
		// accepted PMTUD gap usid.c's own FIB lookup has (see
		// docs/agents/ARCHITECTURE-GATEWAY.md's Known Constraints).
		count_drop(DROP_REASON_FIB_FRAG_NEEDED);
	else
		count_drop(DROP_REASON_FIB_LOOKUP_FAILED);
}

// push_outer_header grows the packet by exactly 40 bytes and writes a
// fresh 54-byte block (14-byte Ethernet + 40-byte outer IPv6 header) at
// the new front. This single bpf_xdp_adjust_head(-40) call is sufficient
// -- unlike strip_outer_header's two-call technique below -- because the
// 14 bytes of the *old* Ethernet header, after the grow, land squarely
// inside the 54-byte region this function overwrites anyway (grow-by-40
// shifts all old content 40 bytes later; the old Ethernet header, 14
// bytes, was already immediately followed by where the old IPv6 header
// starts, so old-Ethernet-plus-new-outer-header together occupy exactly
// the first 54 bytes post-grow, and the untouched old IPv6 header +
// payload already sits correctly positioned as the "inner packet"
// starting at byte 54). Returns 0 on success.
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

static EDGE_ALWAYS_INLINE int handle_forward(struct xdp_md *ctx, struct edge_ip6hdr *ip6, void *l4,
					      __u8 proto, void *data_end)
{
	struct l4_view l4v;
	if (parse_l4(proto, l4, data_end, &l4v) != 0)
		return XDP_PASS;

	struct rule_key rk;
	__builtin_memset(&rk, 0, sizeof(rk));
	rk.proto = proto;
	rk.port = l4v.dport;
	__builtin_memcpy(rk.vip, ip6->daddr, 16);

	struct rule_value *rule = bpf_map_lookup_elem(&rule_table, &rk);
	if (!rule)
		return XDP_PASS; // not one of this gateway's VIPs

	// Claimed past this point: this gateway owns this VIP+port+protocol,
	// so every packet reaching here counts toward the rule's hit
	// counters regardless of what happens next -- a PAT-exhausted or
	// no-backends drop still legitimately consumed this rule's capacity
	// (same convention as an earlier, rejected design's equivalent).
	__sync_fetch_and_add(&rule->packets, 1);
	__sync_fetch_and_add(&rule->bytes,
			      (__u64) ((char *) data_end - (char *) (long) ctx->data));
	rule->last_seen_ns = bpf_ktime_get_ns();

	struct conn_key fwd_key;
	__builtin_memset(&fwd_key, 0, sizeof(fwd_key));
	fwd_key.proto = proto;
	__builtin_memcpy(fwd_key.saddr, ip6->saddr, 16);
	fwd_key.sport = l4v.sport;
	__builtin_memcpy(fwd_key.daddr, ip6->daddr, 16);
	fwd_key.dport = l4v.dport;

	struct conn_value *existing = bpf_map_lookup_elem(&conn_table, &fwd_key);
	struct conn_value cv;

	if (existing) {
		__builtin_memcpy(&cv, existing, sizeof(cv));
	} else {
		if (!l4v.is_syn) {
			count_claimed_drop(DROP_REASON_NO_CONN_NOT_SYN, rule);
			return XDP_DROP;
		}
		if (rule->backend_count == 0 || rule->backend_count > EDGE_MAX_BACKENDS) {
			count_claimed_drop(DROP_REASON_NO_BACKENDS, rule);
			return XDP_DROP;
		}

		// EDGE_MAX_BACKENDS must stay a power of two -- the mask below
		// is what makes the bounds-narrowing survive as a real
		// instruction (see this file's header comment and
		// EDGE_BARRIER_VAR's doc comment): clang can independently
		// prove idx < backend_count <= EDGE_MAX_BACKENDS from the
		// %-divisor's own already-checked [1,EDGE_MAX_BACKENDS] range
		// above, and eliminates a naive `if (idx >= MAX) idx = 0;` (or
		// an unbarriered mask) as dead code -- which then fails to
		// load, because the *verifier* does not propagate a range
		// bound from %'s divisor onto its result the way clang's own
		// optimizer does. A single EDGE_BARRIER_VAR call immediately
		// before the mask forces clang to treat idx as opaque, so the
		// mask survives as a real instruction the verifier can see and
		// use to bound the following array index.
		__u32 idx = fnv1a_flow(ip6->saddr, l4v.sport) % rule->backend_count;
		EDGE_BARRIER_VAR(idx);
		idx &= (EDGE_MAX_BACKENDS - 1);
		struct backend *b = &rule->backends[idx];

		__u32 cfg_key = 0;
		struct gw_config *cfg = bpf_map_lookup_elem(&gw_config_table, &cfg_key);
		if (!cfg) {
			count_claimed_drop(DROP_REASON_NO_BACKENDS, rule);
			return XDP_DROP;
		}

		__builtin_memset(&cv, 0, sizeof(cv));
		__builtin_memcpy(cv.client_addr, ip6->saddr, 16);
		cv.client_port = l4v.sport;
		__builtin_memcpy(cv.vip_addr, ip6->daddr, 16);
		cv.vip_port = l4v.dport;
		__builtin_memcpy(cv.backend_addr, b->addr, 16);
		cv.backend_port = b->port;
		__builtin_memcpy(cv.backend_usid, b->usid, 16);
		__builtin_memcpy(cv.gw_addr, cfg->gw_addr, 16);
		cv.proto = proto;

		__u32 base = fnv1a_flow(ip6->saddr, l4v.sport) ^ (__u32) l4v.dport;
		int claimed = 0;

		#pragma unroll
		for (int i = 0; i < EDGE_PAT_PROBE_LIMIT; i++) {
			__u16 candidate = EDGE_PAT_PORT_BASE + ((base + (__u32) i) % EDGE_PAT_PORT_RANGE);
			cv.gw_port = __builtin_bswap16(candidate);

			struct conn_key rev_key;
			__builtin_memset(&rev_key, 0, sizeof(rev_key));
			rev_key.proto = proto;
			__builtin_memcpy(rev_key.saddr, b->addr, 16);
			rev_key.sport = b->port;
			__builtin_memcpy(rev_key.daddr, cfg->gw_addr, 16);
			rev_key.dport = cv.gw_port;

			if (bpf_map_update_elem(&conn_table, &rev_key, &cv, BPF_NOEXIST) == 0) {
				claimed = 1;
				break;
			}
		}

		if (!claimed) {
			count_claimed_drop(DROP_REASON_PAT_EXHAUSTED, rule);
			return XDP_DROP;
		}

		bpf_map_update_elem(&conn_table, &fwd_key, &cv, BPF_ANY);
	}

	__u8 old_saddr[16], old_daddr[16];
	__builtin_memcpy(old_saddr, ip6->saddr, 16);
	__builtin_memcpy(old_daddr, ip6->daddr, 16);
	__be16 old_sport = l4v.sport;
	__be16 old_dport = l4v.dport;

	fix_l4_checksum(l4v.check_ptr, old_saddr, old_daddr, old_sport, old_dport,
			cv.gw_addr, cv.backend_addr, cv.gw_port, cv.backend_port);

	__builtin_memcpy(ip6->saddr, cv.gw_addr, 16);
	__builtin_memcpy(ip6->daddr, cv.backend_addr, 16);
	*l4v.sport_ptr = cv.gw_port;
	*l4v.dport_ptr = cv.backend_port;

	__be16 inner_payload_len = ip6->payload_len;

	if (push_outer_header(ctx, cv.gw_addr, cv.backend_usid, inner_payload_len) != 0)
		return XDP_DROP;

	return XDP_TX;
}

// ---------------------------------------------------------------------
// Return/decap branch.
// ---------------------------------------------------------------------

// strip_outer_header removes the outer Ethernet+IPv6 header (54 bytes)
// entirely and then regrows exactly 14 bytes for a fresh Ethernet header
// -- two bpf_xdp_adjust_head calls, unlike push_outer_header's one. A
// single flat +40 would remove "the old Ethernet header plus the first 26
// bytes of the outer IPv6 header," which is not the region that needs to
// disappear (the Ethernet header must be *preserved*, just relocated to
// sit immediately before the inner packet, not discarded) -- bpf_skb_
// adjust_room's BPF_ADJ_ROOM_MAC mode handles this automatically for
// TC-BPF; bpf_xdp_adjust_head has no equivalent, so this program does the
// two-step remove-then-regrow by hand. Returns 0 on success, with *eth_out
// pointing at the (uninitialized) fresh Ethernet header slot to fill in.
static EDGE_ALWAYS_INLINE int strip_outer_header(struct xdp_md *ctx, struct edge_ethhdr **eth_out)
{
	if (bpf_xdp_adjust_head(ctx, (int) (sizeof(struct edge_ethhdr) + sizeof(struct edge_ip6hdr))) != 0)
		return -1;
	if (bpf_xdp_adjust_head(ctx, -(int) sizeof(struct edge_ethhdr)) != 0)
		return -1;

	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	if (data + sizeof(struct edge_ethhdr) > data_end)
		return -1;

	*eth_out = data;
	return 0;
}

static EDGE_ALWAYS_INLINE int handle_return(struct xdp_md *ctx, struct edge_ip6hdr *outer, void *data_end)
{
	if (outer->nexthdr != EDGE_IPPROTO_IPV6) {
		count_drop(DROP_REASON_MALFORMED_RETURN);
		return XDP_DROP;
	}

	__u8 gw_addr[16];
	__builtin_memcpy(gw_addr, outer->daddr, 16);

	struct edge_ethhdr *eth;
	if (strip_outer_header(ctx, &eth) != 0) {
		count_drop(DROP_REASON_MALFORMED_RETURN);
		return XDP_DROP;
	}

	data_end = (void *) (long) ctx->data_end;

	struct edge_ip6hdr *inner = (void *) (eth + 1);
	if ((void *) (inner + 1) > data_end) {
		count_drop(DROP_REASON_MALFORMED_RETURN);
		return XDP_DROP;
	}
	if (inner->nexthdr != EDGE_IPPROTO_TCP && inner->nexthdr != EDGE_IPPROTO_UDP) {
		count_drop(DROP_REASON_MALFORMED_RETURN);
		return XDP_DROP;
	}

	struct l4_view l4v;
	if (parse_l4(inner->nexthdr, (void *) (inner + 1), data_end, &l4v) != 0) {
		count_drop(DROP_REASON_MALFORMED_RETURN);
		return XDP_DROP;
	}

	struct conn_key rev_key;
	__builtin_memset(&rev_key, 0, sizeof(rev_key));
	rev_key.proto = inner->nexthdr;
	__builtin_memcpy(rev_key.saddr, inner->saddr, 16);
	rev_key.sport = l4v.sport;
	__builtin_memcpy(rev_key.daddr, inner->daddr, 16);
	rev_key.dport = l4v.dport;

	struct conn_value *cv = bpf_map_lookup_elem(&conn_table, &rev_key);
	if (!cv) {
		count_drop(DROP_REASON_NO_RETURN_CONN);
		return XDP_DROP;
	}

	__u8 old_saddr[16], old_daddr[16];
	__builtin_memcpy(old_saddr, inner->saddr, 16);
	__builtin_memcpy(old_daddr, inner->daddr, 16);
	__be16 old_sport = l4v.sport;
	__be16 old_dport = l4v.dport;

	fix_l4_checksum(l4v.check_ptr, old_saddr, old_daddr, old_sport, old_dport,
			cv->vip_addr, cv->client_addr, cv->vip_port, cv->client_port);

	__builtin_memcpy(inner->saddr, cv->vip_addr, 16);
	__builtin_memcpy(inner->daddr, cv->client_addr, 16);
	*l4v.sport_ptr = cv->vip_port;
	*l4v.dport_ptr = cv->client_port;

	long fib_rc = resolve_fib_and_write_eth(ctx, ctx->ingress_ifindex, cv->vip_addr, cv->client_addr,
						 __builtin_bswap16(inner->payload_len) + (__u16) sizeof(*inner), eth);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS) {
		count_fib_drop(fib_rc);
		return XDP_DROP;
	}

	return XDP_TX;
}

// ---------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------

SEC("xdp")
int edge_nat(struct xdp_md *ctx)
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

	__u32 cfg_key = 0;
	struct gw_config *cfg = bpf_map_lookup_elem(&gw_config_table, &cfg_key);
	if (cfg && addr6_eq(ip6->daddr, cfg->gw_addr))
		return handle_return(ctx, ip6, data_end);

	if (ip6->nexthdr != EDGE_IPPROTO_TCP && ip6->nexthdr != EDGE_IPPROTO_UDP)
		return XDP_PASS;

	return handle_forward(ctx, ip6, (void *) (ip6 + 1), ip6->nexthdr, data_end);
}

char _license[] SEC("license") = "GPL";
