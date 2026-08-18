//go:build ignore

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// nat66.c implements the XDP datapath for one shard of galactic-nat66's
// sharded, stateful NAT66 egress tier (design plan §3) -- a component
// deliberately kept off galactic-gateway's own ingress datapath (edgedsr.c)
// entirely: tenant egress (backend -> arbitrary internet destination) is a
// different traffic pattern from ingress (fixed VIP, fixed backend pool)
// and gets its own placement ring, own state, own self-routing return
// path, with no shared map or hash ring between the two tiers.
//
// This shard's own identity is two addresses (shard_config_table):
// shard_sid, a real SRv6 uSID (uFMT 48+16, same encoding
// internal/plumbing/ebpf/prog/usid.c's own decap already uses) other nodes'
// tenant-VRF default routes encapsulate toward, with the Argument nibble
// carrying the *requesting tenant's own VRFID* -- reusing the existing
// per-node Argument-allocation mechanism rather than inventing a second
// one, and giving this program tenant isolation for free, the same way
// usid_ingress's own vrf_table lookup does; and shard_pub_addr, a plain
// publicly-routable address used as the masquerade source for every flow
// this shard NATs -- ordinary unicast routing delivers a reply to
// shard_pub_addr back to this exact shard with no hashing or cross-shard
// lookup needed on the return path at all (design plan §3.3's "the
// destination address already names the owner").
//
// Packet path -- one program, dispatched on the outer IPv6 destination:
//
//  1. Parse the outer Ethernet + IPv6 header (bounds-checked). Not IPv6 --
//     XDP_PASS.
//  2. daddr == shard_pub_addr: this is a reply arriving from the internet,
//     addressed to a masquerade source this shard itself allocated --
//     handle_return(): reverse nat66_conn_table lookup by the packet's own
//     (proto, dest-facing tuple), un-SNAT back to the tenant backend's own
//     view, and re-encapsulate toward that backend's worker node via SRv6
//     (the same push_outer_header push/FIB-lookup mechanic
//     internal/plumbing/ebpf/edgeprog/edgedsr.c already uses for its own
//     encap -- copied here for the identical reason edgedsr.c's own header
//     comment gives for copying it from edgenat.c: proven, unchanging
//     mechanism, not worth threading through a shared header neither file
//     otherwise needs). No matching conn_table row -- drop (this address
//     is claimed).
//  3. Outer daddr's top 64 bits (Block+Node-ID) match this shard's own
//     shard_sid, and nexthdr is 41 (IPv6-in-IPv6, no SRH) -- this is a
//     tenant's own outbound egress packet, encapsulated the same way any
//     other cross-node SRv6 destination is (RouteEgressAdd's own
//     SEG6_IPTUN_MODE_ENCAP_RED wire format). handle_forward(): strip the
//     outer header, read the Argument nibble as this flow's tenant_arg
//     (isolation key -- two tenants' colliding backend ULA addresses never
//     share a nat66_conn_table row, because tenant_arg is part of the
//     forward key), allocate (or reuse) a masquerade port via the same
//     probe-then-BPF_NOEXIST-claim technique
//     internal/plumbing/ebpf/edgeprog/edgedsr.c's Full-NAT predecessor
//     used for SNAT-port allocation, SNAT the source to
//     shard_pub_addr:allocated_port, fix the checksum via bpf_csum_diff
//     (this is XDP, no __sk_buff, so bpf_l4_csum_replace is unavailable --
//     same constraint edgenat.c's own header comment documents), and
//     XDP_PASS: once SNAT'd to a real public address, this is an ordinary
//     internet-routable packet needing no further SRv6 handling -- the
//     kernel's own default route takes it from here, so this program does
//     not do its own bpf_fib_lookup for the general-internet leg the way
//     it does for the encap-back-to-tenant leg in handle_return.
//  4. Anything else -- XDP_PASS (not this shard's traffic at all).
//
// No tenant-identity check beyond the Argument nibble itself: a forged
// Argument only misdirects the forger's *own* isolation bucket, never a
// legitimate tenant's, but this program trusts that only legitimate
// SRv6-fabric-internal traffic ever reaches it at all -- the same
// trust-boundary/anti-spoofing question the design plan's §5 already
// flags as needing its own security pass before real traffic, not
// something this file's own logic resolves.
#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define NAT66_ALWAYS_INLINE inline __attribute__((always_inline))

// NAT66_BARRIER_VAR: same verifier bounds-narrowing gotcha as
// edgedsr.c/edgenat.c's EDGE_BARRIER_VAR -- see either file's header
// comment. Reused here under this file's own naming convention rather
// than importing a macro from either (each file is deliberately
// self-contained, one external header dependency, per this codebase's
// established convention).
#define NAT66_BARRIER_VAR(var) asm volatile("" : "=r"(var) : "0"(var))

// ---------------------------------------------------------------------
// BPF helper function declarations.
// ---------------------------------------------------------------------

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
				    __u64 flags) = (void *) BPF_FUNC_map_update_elem;
static long (*bpf_xdp_adjust_head)(void *ctx, int delta) = (void *) BPF_FUNC_xdp_adjust_head;
static __s64 (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size,
			       __wsum seed) = (void *) BPF_FUNC_csum_diff;
static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, __s32 plen,
			       __u32 flags) = (void *) BPF_FUNC_fib_lookup;

// ---------------------------------------------------------------------
// Constants.
// ---------------------------------------------------------------------

#define NAT66_AF_INET6 10
#define NAT66_ETH_P_IPV6 0x86DD
#define NAT66_IPPROTO_TCP 6
#define NAT66_IPPROTO_UDP 17
#define NAT66_IPPROTO_IPV6 41 // both this shard's own pushed header, and the tenant's inbound one

#define NAT66_PAT_PROBE_LIMIT 8
#define NAT66_PAT_PORT_BASE 32768
#define NAT66_PAT_PORT_RANGE 28000

// ---------------------------------------------------------------------
// Minimal, self-contained header structs -- byte-exact to the wire
// formats, matching usid.c/edgedsr.c's own convention.
// ---------------------------------------------------------------------

struct nat66_ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
} __attribute__((packed));

struct nat66_ip6hdr {
	__u8 vtc_flow[4];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
} __attribute__((packed));

struct nat66_tcphdr {
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

struct nat66_udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
} __attribute__((packed));

// ---------------------------------------------------------------------
// Map key/value types.
// ---------------------------------------------------------------------

// struct conn_key: the forward row is keyed by the tenant backend's
// own facing tuple (proto, tenant_arg, backend_addr:backend_port ->
// dest_addr:dest_port) -- tenant_arg (this flow's VRFID, read from the
// SRv6 Argument nibble) is part of the key specifically so two tenants
// presenting the identical backend ULA never collide on this row, the
// same reasoning component 2 (NPTv6)'s VRFID-keyed nptv6_table already
// uses. The reverse row is keyed by (proto, tenant_arg=0,
// dest_addr:dest_port -> shard_pub_addr:masq_port) -- tenant_arg is
// unused/zero there, since shard_pub_addr:masq_port is already globally
// unique by construction (this shard allocated it, from its own address).
struct conn_key {
	__u8 proto;
	__u8 pad[1];
	__u16 tenant_arg;
	__be16 sport;
	__be16 dport;
	__u8 saddr[16];
	__u8 daddr[16];
};

// struct conn_value carries the full picture of one translated
// egress flow -- both directions read the same value, oriented by which
// key found it.
struct conn_value {
	__u8 backend_addr[16];
	__be16 backend_port;
	__u8 dest_addr[16];
	__be16 dest_port;
	__be16 shard_port;
	__u8 backend_usid[16];
	__u8 proto;
	__u8 pad[1];
};

// struct shard_config is shard_config_table's single-entry value.
struct shard_config {
	__u8 shard_sid[16];
	__u8 shard_pub_addr[16];
};

enum nat66_drop_reason {
	DROP_REASON_NAT66_NO_RETURN_CONN     = 0,
	DROP_REASON_NAT66_MALFORMED_RETURN   = 1,
	DROP_REASON_NAT66_PAT_EXHAUSTED      = 2,
	DROP_REASON_NAT66_MALFORMED_FORWARD  = 3,
	DROP_REASON_NAT66_FIB_NO_NEIGH       = 4,
	DROP_REASON_NAT66_FIB_UNREACHABLE    = 5,
	DROP_REASON_NAT66_FIB_FRAG_NEEDED    = 6,
	DROP_REASON_NAT66_FIB_LOOKUP_FAILED  = 7,
	DROP_REASON_NAT66_ADJUST_HEAD_FAILED = 8,
	DROP_REASON_NAT66_COUNT              = 9,
};

// ---------------------------------------------------------------------
// Maps.
// ---------------------------------------------------------------------

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, struct conn_value);
} nat66_conn_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shard_config);
} shard_config_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, DROP_REASON_NAT66_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} drop_reasons SEC(".maps");

static NAT66_ALWAYS_INLINE void count_drop(__u32 reason)
{
	__u64 *counter = bpf_map_lookup_elem(&drop_reasons, &reason);
	if (counter)
		*counter += 1;
}

static NAT66_ALWAYS_INLINE int addr6_eq(const __u8 a[16], const __u8 b[16])
{
	for (int i = 0; i < 16; i++) {
		if (a[i] != b[i])
			return 0;
	}
	return 1;
}

// locator_matches checks only the top 64 bits (Block(48)+Node-ID(16)) of
// daddr against this shard's own shard_sid -- the same "is this mine"
// granularity internal/plumbing/ebpf/prog/usid.c's own locator_table
// match uses, since the Argument nibble below it varies per tenant.
static NAT66_ALWAYS_INLINE int locator_matches(const __u8 daddr[16], const __u8 shard_sid[16])
{
	for (int i = 0; i < 8; i++) {
		if (daddr[i] != shard_sid[i])
			return 0;
	}
	return 1;
}

// read_argument extracts the 12-bit Argument nibble from a uFMT 48+16
// address at bits 69-80 (daddr bytes 8-9) -- identical bit positions and
// composition to internal/plumbing/ebpf/uformat's Go-side encoding and
// usid.c's own step 5 read.
static NAT66_ALWAYS_INLINE __u16 read_argument(const __u8 daddr[16])
{
	return ((__u16) (daddr[8] & 0x0F) << 8) | daddr[9];
}

static NAT66_ALWAYS_INLINE __u32 fnv1a_flow(const __u8 addr[16], __be16 port)
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

static NAT66_ALWAYS_INLINE __be16 csum_fold_add(__be16 check, __s64 diff)
{
	__s64 sum = (__u16) ~check;
	sum += diff;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__be16) ~((__u16) sum);
}

// struct l4_view mirrors edgenat.c's identical type and identical
// rationale (see that file's own doc comment): direct, already-typed
// pointers to the L4 fields a rewrite needs, resolved exactly once,
// adjacent to the bounds check that proves them safe.
struct l4_view {
	__be16 sport;
	__be16 dport;
	__be16 *sport_ptr;
	__be16 *dport_ptr;
	__be16 *check_ptr;
};

static NAT66_ALWAYS_INLINE int parse_l4(__u8 proto, void *l4, void *data_end, struct l4_view *out)
{
	if (proto == NAT66_IPPROTO_TCP) {
		struct nat66_tcphdr *tcp = l4;
		if ((void *) (tcp + 1) > data_end)
			return -1;
		out->sport = tcp->source;
		out->dport = tcp->dest;
		out->sport_ptr = &tcp->source;
		out->dport_ptr = &tcp->dest;
		out->check_ptr = &tcp->check;
		return 0;
	}
	if (proto == NAT66_IPPROTO_UDP) {
		struct nat66_udphdr *udp = l4;
		if ((void *) (udp + 1) > data_end)
			return -1;
		out->sport = udp->source;
		out->dport = udp->dest;
		out->sport_ptr = &udp->source;
		out->dport_ptr = &udp->dest;
		out->check_ptr = &udp->check;
		return 0;
	}
	return -1;
}

// fix_l4_checksum applies the combined address+port checksum delta for a
// masquerade rewrite (one address, one port changed; the peer's own
// address/port are unchanged) -- edgenat.c's identical fix_l4_checksum
// covered a full 4-tuple rewrite (both addresses, both ports); this one is
// simplified to the 2-field case NAT66 masquerade actually needs, still
// via the same bpf_csum_diff technique (XDP has no __sk_buff, so
// bpf_l4_csum_replace is unavailable).
static NAT66_ALWAYS_INLINE void fix_l4_checksum(__be16 *check_ptr, const __u8 old_addr[16], __be16 old_port,
						 const __u8 new_addr[16], __be16 new_port)
{
	__be32 old_words[9];
	__be32 new_words[9];

	__builtin_memcpy(&old_words[0], old_addr, 16);
	__builtin_memset(&old_words[4], 0, 16);
	old_words[8] = (__be32) old_port;

	__builtin_memcpy(&new_words[0], new_addr, 16);
	__builtin_memset(&new_words[4], 0, 16);
	new_words[8] = (__be32) new_port;

	__s64 diff = bpf_csum_diff(old_words, sizeof(old_words), new_words, sizeof(new_words), 0);
	*check_ptr = csum_fold_add(*check_ptr, diff);
}

static NAT66_ALWAYS_INLINE long resolve_fib_and_write_eth(void *ctx, __u32 ifindex, const __u8 src[16],
							   const __u8 dst[16], __u16 tot_len,
							   struct nat66_ethhdr *eth)
{
	struct bpf_fib_lookup fib_params;
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.family = NAT66_AF_INET6;
	__builtin_memcpy(&fib_params.ipv6_src, src, 16);
	__builtin_memcpy(&fib_params.ipv6_dst, dst, 16);
	fib_params.ifindex = ifindex;
	fib_params.tot_len = tot_len;

	long fib_rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS)
		return fib_rc;

	__builtin_memcpy(eth->h_dest, fib_params.dmac, sizeof(eth->h_dest));
	__builtin_memcpy(eth->h_source, fib_params.smac, sizeof(eth->h_source));
	eth->h_proto = __builtin_bswap16(NAT66_ETH_P_IPV6);
	return BPF_FIB_LKUP_RET_SUCCESS;
}

static NAT66_ALWAYS_INLINE void count_fib_drop(long fib_rc)
{
	if (fib_rc == BPF_FIB_LKUP_RET_NO_NEIGH)
		count_drop(DROP_REASON_NAT66_FIB_NO_NEIGH);
	else if (fib_rc == BPF_FIB_LKUP_RET_UNREACHABLE || fib_rc == BPF_FIB_LKUP_RET_BLACKHOLE ||
		 fib_rc == BPF_FIB_LKUP_RET_PROHIBIT)
		count_drop(DROP_REASON_NAT66_FIB_UNREACHABLE);
	else if (fib_rc == BPF_FIB_LKUP_RET_FRAG_NEEDED)
		count_drop(DROP_REASON_NAT66_FIB_FRAG_NEEDED);
	else
		count_drop(DROP_REASON_NAT66_FIB_LOOKUP_FAILED);
}

// push_outer_header: identical mechanism to edgedsr.c/edgenat.c's own
// function of the same name -- see either's header comment for the full
// byte-level rationale. Copied, not shared, per this codebase's existing
// convention (each program's surrounding types are independently defined).
static NAT66_ALWAYS_INLINE int push_outer_header(struct xdp_md *ctx, const __u8 src[16], const __u8 dst[16],
						  __be16 inner_payload_len_plus_ip6hdr)
{
	if (bpf_xdp_adjust_head(ctx, -40) != 0) {
		count_drop(DROP_REASON_NAT66_ADJUST_HEAD_FAILED);
		return -1;
	}

	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	if (data + sizeof(struct nat66_ethhdr) + sizeof(struct nat66_ip6hdr) > data_end) {
		count_drop(DROP_REASON_NAT66_ADJUST_HEAD_FAILED);
		return -1;
	}

	struct nat66_ethhdr *eth = data;
	struct nat66_ip6hdr *outer = (void *) (eth + 1);

	// vtc_flow[0]'s high nibble is the IPv6 version field -- see
	// edgedsr.c's identical fix (push_outer_header) for the full story:
	// a real, previously uncaught bug inherited from the removed
	// edgenat.c, found via live-kernel investigation, not
	// BPF_PROG_TEST_RUN (which never validates this field).
	__builtin_memset(outer->vtc_flow, 0, sizeof(outer->vtc_flow));
	outer->vtc_flow[0] = 0x60;
	outer->payload_len = inner_payload_len_plus_ip6hdr;
	outer->nexthdr = NAT66_IPPROTO_IPV6;
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

static NAT66_ALWAYS_INLINE int strip_outer_header(struct xdp_md *ctx, struct nat66_ethhdr **eth_out)
{
	if (bpf_xdp_adjust_head(ctx, (int) (sizeof(struct nat66_ethhdr) + sizeof(struct nat66_ip6hdr))) != 0)
		return -1;
	if (bpf_xdp_adjust_head(ctx, -(int) sizeof(struct nat66_ethhdr)) != 0)
		return -1;

	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	if (data + sizeof(struct nat66_ethhdr) > data_end)
		return -1;

	*eth_out = data;
	return 0;
}

// handle_forward: a tenant's own outbound egress packet, SRv6-encapsulated
// toward this shard. Strips the outer header, resolves tenant_arg from the
// Argument nibble, allocates (or reuses) a masquerade port, SNATs the
// source, and passes the now-plain-internet-routable packet to the
// kernel's own routing (XDP_PASS) -- see this file's header comment for
// why no FIB lookup of its own is needed on this leg.
static NAT66_ALWAYS_INLINE int handle_forward(struct xdp_md *ctx, struct nat66_ip6hdr *outer,
					       struct shard_config *cfg)
{
	__u16 tenant_arg = read_argument(outer->daddr);
	// outer->saddr (the tenant's own worker-node uSID, needed below to
	// build the reply's own re-encap destination) must be captured now,
	// into a plain local array -- strip_outer_header calls
	// bpf_xdp_adjust_head twice, which invalidates every packet pointer
	// derived before it, `outer` included; reading outer->saddr *after*
	// the strip is a stale-pointer access the verifier rejects (confirmed
	// empirically: "R9 invalid mem access 'scalar'" without this).
	__u8 tenant_usid[16];
	__builtin_memcpy(tenant_usid, outer->saddr, 16);

	struct nat66_ethhdr *eth;
	if (strip_outer_header(ctx, &eth) != 0) {
		count_drop(DROP_REASON_NAT66_MALFORMED_FORWARD);
		return XDP_DROP;
	}

	void *data_end = (void *) (long) ctx->data_end;
	struct nat66_ip6hdr *inner = (void *) (eth + 1);
	if ((void *) (inner + 1) > data_end) {
		count_drop(DROP_REASON_NAT66_MALFORMED_FORWARD);
		return XDP_DROP;
	}
	if (inner->nexthdr != NAT66_IPPROTO_TCP && inner->nexthdr != NAT66_IPPROTO_UDP) {
		count_drop(DROP_REASON_NAT66_MALFORMED_FORWARD);
		return XDP_DROP;
	}

	struct l4_view l4v;
	if (parse_l4(inner->nexthdr, (void *) (inner + 1), data_end, &l4v) != 0) {
		count_drop(DROP_REASON_NAT66_MALFORMED_FORWARD);
		return XDP_DROP;
	}

	struct conn_key fwd_key;
	__builtin_memset(&fwd_key, 0, sizeof(fwd_key));
	fwd_key.proto = inner->nexthdr;
	fwd_key.tenant_arg = tenant_arg;
	__builtin_memcpy(fwd_key.saddr, inner->saddr, 16);
	fwd_key.sport = l4v.sport;
	__builtin_memcpy(fwd_key.daddr, inner->daddr, 16);
	fwd_key.dport = l4v.dport;

	struct conn_value *existing = bpf_map_lookup_elem(&nat66_conn_table, &fwd_key);
	struct conn_value cv;

	if (existing) {
		__builtin_memcpy(&cv, existing, sizeof(cv));
	} else {
		__builtin_memset(&cv, 0, sizeof(cv));
		__builtin_memcpy(cv.backend_addr, inner->saddr, 16);
		cv.backend_port = l4v.sport;
		__builtin_memcpy(cv.dest_addr, inner->daddr, 16);
		cv.dest_port = l4v.dport;
		__builtin_memcpy(cv.backend_usid, tenant_usid, 16); // the tenant's own worker-node uSID
		cv.proto = inner->nexthdr;

		__u32 base = fnv1a_flow(inner->saddr, l4v.sport) ^ (__u32) l4v.dport ^ tenant_arg;
		int claimed = 0;

		#pragma unroll
		for (int i = 0; i < NAT66_PAT_PROBE_LIMIT; i++) {
			__u16 candidate = NAT66_PAT_PORT_BASE + ((base + (__u32) i) % NAT66_PAT_PORT_RANGE);
			cv.shard_port = __builtin_bswap16(candidate);

			struct conn_key rev_key;
			__builtin_memset(&rev_key, 0, sizeof(rev_key));
			rev_key.proto = inner->nexthdr;
			__builtin_memcpy(rev_key.saddr, inner->daddr, 16);
			rev_key.sport = l4v.dport;
			__builtin_memcpy(rev_key.daddr, cfg->shard_pub_addr, 16);
			rev_key.dport = cv.shard_port;

			if (bpf_map_update_elem(&nat66_conn_table, &rev_key, &cv, BPF_NOEXIST) == 0) {
				claimed = 1;
				break;
			}
		}

		if (!claimed) {
			count_drop(DROP_REASON_NAT66_PAT_EXHAUSTED);
			return XDP_DROP;
		}

		bpf_map_update_elem(&nat66_conn_table, &fwd_key, &cv, BPF_ANY);
	}

	fix_l4_checksum(l4v.check_ptr, inner->saddr, l4v.sport, cfg->shard_pub_addr, cv.shard_port);
	__builtin_memcpy(inner->saddr, cfg->shard_pub_addr, 16);
	*l4v.sport_ptr = cv.shard_port;

	return XDP_PASS;
}

// handle_return: a reply from the internet, addressed to this shard's own
// masquerade source. Un-SNATs back to the tenant backend's own view and
// re-encapsulates toward that backend's worker node via SRv6.
static NAT66_ALWAYS_INLINE int handle_return(struct xdp_md *ctx, struct nat66_ip6hdr *ip6, void *data_end,
					      struct shard_config *cfg)
{
	if (ip6->nexthdr != NAT66_IPPROTO_TCP && ip6->nexthdr != NAT66_IPPROTO_UDP) {
		count_drop(DROP_REASON_NAT66_MALFORMED_RETURN);
		return XDP_DROP;
	}

	struct l4_view l4v;
	if (parse_l4(ip6->nexthdr, (void *) (ip6 + 1), data_end, &l4v) != 0) {
		count_drop(DROP_REASON_NAT66_MALFORMED_RETURN);
		return XDP_DROP;
	}

	struct conn_key rev_key;
	__builtin_memset(&rev_key, 0, sizeof(rev_key));
	rev_key.proto = ip6->nexthdr;
	__builtin_memcpy(rev_key.saddr, ip6->saddr, 16);
	rev_key.sport = l4v.sport;
	__builtin_memcpy(rev_key.daddr, ip6->daddr, 16);
	rev_key.dport = l4v.dport;

	struct conn_value *cv = bpf_map_lookup_elem(&nat66_conn_table, &rev_key);
	if (!cv) {
		count_drop(DROP_REASON_NAT66_NO_RETURN_CONN);
		return XDP_DROP;
	}

	fix_l4_checksum(l4v.check_ptr, ip6->daddr, l4v.dport, cv->backend_addr, cv->backend_port);
	__builtin_memcpy(ip6->daddr, cv->backend_addr, 16);
	*l4v.dport_ptr = cv->backend_port;

	// Must include the inner IPv6 header's own 40 bytes, not just its
	// payload -- see edgedsr.c's identical fix (its handle_forward call
	// site) for the full story: a real, previously uncaught bug
	// inherited from the removed edgenat.c, found via live-kernel
	// investigation, not BPF_PROG_TEST_RUN.
	__be16 inner_payload_len_plus_ip6hdr =
		__builtin_bswap16((__u16) sizeof(struct nat66_ip6hdr) + __builtin_bswap16(ip6->payload_len));

	// Outer source is this shard's own SRv6-reachable identity
	// (shard_sid), not any field of cv -- the tenant's worker node
	// decaps this exactly like any other cross-node SRv6 packet, and
	// does not care about (or validate) the encap source, but it must
	// still be a real, this-node address, not the internet peer's own
	// address cv->dest_addr holds.
	if (push_outer_header(ctx, cfg->shard_sid, cv->backend_usid, inner_payload_len_plus_ip6hdr) != 0)
		return XDP_DROP;

	return XDP_TX;
}

SEC("xdp")
int nat66_ingress(struct xdp_md *ctx)
{
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	struct nat66_ethhdr *eth = data;
	if ((void *) (eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != __builtin_bswap16(NAT66_ETH_P_IPV6))
		return XDP_PASS;

	struct nat66_ip6hdr *ip6 = (void *) (eth + 1);
	if ((void *) (ip6 + 1) > data_end)
		return XDP_PASS;

	__u32 cfg_key = 0;
	struct shard_config *cfg = bpf_map_lookup_elem(&shard_config_table, &cfg_key);
	if (!cfg)
		return XDP_PASS; // not yet configured -- fail open, not claimed

	if (addr6_eq(ip6->daddr, cfg->shard_pub_addr))
		return handle_return(ctx, ip6, data_end, cfg);

	if (locator_matches(ip6->daddr, cfg->shard_sid) && ip6->nexthdr == NAT66_IPPROTO_IPV6)
		return handle_forward(ctx, ip6, cfg);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
