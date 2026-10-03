//go:build ignore

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// nat.c implements the XDP datapath for one shard of the sharded, stateful
// egress translation tier. It serves two address families: NAT66 (IPv6 -> IPv6
// PAT) and NAT64 (IPv6 -> IPv4, RFC 6146). They are the same function --
// stateful egress PAT with a VRF-scoped session table, port allocation, and
// decap/re-encap on the return path -- so they share one session table, one
// port allocator, and one set of drop counters rather than existing as two
// near-duplicate programs.
//
// Both directions leave from the driver. A shard resolves its own next hop and
// transmits every packet it claims, forward and return alike, and hands nothing
// up to the kernel's forwarding path. That is a property, not an optimization:
// a shard's return leg is claimed at ingress and re-encapsulated back out
// before netfilter runs, so any leg that did go up would open connection
// tracking state whose other half never arrives. The kernel would then hold a
// TCP flow permanently in SYN_SENT and adjudicate the tenant's own ACK against
// it -- INVALID, by the state table, and dropped by any invalid-state rule on
// the node. Either both directions are visible to conntrack or neither is, and
// the return leg cannot be without giving up the SRv6 re-encapsulation it
// exists to perform. So: neither.
//
// The cost is that a shard node's netfilter rules do not see tenant egress at
// all, and that routing this program performs is a bpf_fib_lookup rather than
// the kernel's full output path -- no policy routing, no neighbour resolution
// it can wait on, no ICMP error generated on its behalf. Each of those surfaces
// as a named drop counter instead.
//
// The whole tier is deliberately separate from the gateway's ingress datapath:
// tenant egress toward an arbitrary internet destination is a different traffic
// pattern from ingress toward a fixed VIP and backend pool, and gets its own
// placement ring, state, and return path, sharing no map or hash ring with that
// tier.
//
// A shard's identity is a SID plus one public address per family it serves.
// shard_sid is a real SRv6 uSID that other nodes' tenant-VRF egress routes
// encapsulate toward, with the Argument carrying the requesting tenant's VRFID:
// that reuses the existing per-node Argument allocation rather than inventing a
// second one, and gives this program tenant isolation the same way the ingress
// datapath's vrf_table lookup does. One SID serves both families -- which
// translation a packet gets is decided from the inner destination, not from a
// second SID, so a tenant VRF needs no second route and no second shard
// assignment to gain NAT64. shard_pub_addr6 (IPv6) and shard_pub_addr4 (IPv4)
// are the masquerade sources for their respective families, so ordinary unicast
// routing returns a reply to this exact shard with no hashing or cross-shard
// lookup on the return path.
//
// ---------------------------------------------------------------------
// Program structure: one dispatcher, tail-called leaves.
// ---------------------------------------------------------------------
//
// nat_ingress is the only program attached to the wire. It parses just far
// enough to decide which translation path a packet belongs to, then tail-calls
// into it:
//
//   nat66_forward       tenant -> IPv6 internet    (PAT, no header-family change)
//   nat66_return        IPv6 internet -> tenant
//   nat64_forward       tenant -> IPv4 internet    (RFC 6146/7915 translation)
//   nat64_return        IPv4 internet -> tenant
//   nat66_icmp_forward  tenant's ICMPv6 -> IPv6 internet
//   nat66_icmp_return   IPv6 internet's ICMPv6 -> tenant
//   nat64_icmp_forward  tenant's ICMPv6 -> IPv4 internet as ICMPv4
//   nat64_icmp_return   IPv4 internet's ICMPv4 -> tenant as ICMPv6
//
// The ICMP leaves are their own programs rather than branches in the TCP/UDP
// ones for the same budget reason the families are split: an ICMP error carries
// a second, quoted packet to parse and rewrite, and none of that belongs in the
// instruction count of a leaf that never sees one.
//
// Each leaf ends in leave_via: XDP_TX where the route egresses the interface
// the packet arrived on, XDP_REDIRECT where it does not. No leaf ends in
// XDP_PASS once it has touched the packet.
//
// The split is not stylistic. A single program holding both families' full
// translation paths -- each with its own header synthesis, checksum handling,
// and an unrolled port-allocation probe loop, all force-inlined -- is a
// verifier complexity risk with no upside. Tail calls give each leaf its own
// instruction budget, and keep a defect in one family's translation from
// growing the other's program at all. The dispatcher itself only reads.
//
// Dispatch, on the outer header:
//
//  1. Not IPv6 and not IPv4: XDP_PASS. Not configured yet, serving neither
//     family: XDP_PASS, this shard claiming nothing until it knows its own
//     identity.
//  2. IPv6 destination equal to shard_pub_addr6 is a reply from the IPv6
//     internet addressed to a masquerade source this shard allocated ->
//     nat66_return, or nat66_icmp_return for an ICMPv6 next header.
//  3. IPv6 destination whose top 64 bits match shard_sid, with an
//     IPv6-in-IPv6 next header, is a tenant's outbound packet encapsulated the
//     way any cross-node SRv6 destination is. The *inner* destination decides
//     the family: inside nat64_prefix -> nat64_forward, otherwise
//     nat66_forward; or the _icmp_ leaf of the same family for an inner
//     ICMPv6 packet.
//  4. IPv4 destination equal to shard_pub_addr4 is a reply from the IPv4
//     internet -> nat64_return, or nat64_icmp_return for ICMPv4.
//  5. Anything else: XDP_PASS.
//
// Step 3 always reads the inner header, which the IPv6-only dispatch did not
// need to before ICMP: the inner next header picks the leaf.
//
// ---------------------------------------------------------------------
// Scope.
// ---------------------------------------------------------------------
//
// TCP, UDP, and ICMPv6 for NAT66; TCP, UDP, and ICMP Echo for NAT64. ICMPv4
// error translation (RFC 6146 section 3.5) and fragment handling (section 3.4)
// are deliberately absent, not overlooked: each is a subsystem rather than a
// branch, and each is tracked as its own follow-on. Their absence is counted,
// not silent -- an IPv4 fragment, a packet carrying IPv4 options, or an ICMPv4
// error on the return path increments a named drop reason, so "NAT64 works
// except for X" is a readable counter rather than a support ticket. Until they
// land, this is not a complete RFC 6146 implementation, and PMTUD across the
// NAT64 translator does not work.
//
// NAT66 ICMPv6 covers what a tenant behind a translator needs: its own ping,
// and the errors the internet sends back about its flows. A tenant's Echo
// Request is translated like a UDP datagram, the Echo Identifier standing in
// for the port. Destination Unreachable, Packet Too Big, Time Exceeded, and
// Parameter Problem are matched by the packet they quote -- which is the packet
// this shard sent -- and rewritten so the tenant sees an error about the packet
// it sent. Neighbor Discovery is passed to the kernel untouched; every other
// ICMPv6 message addressed to a masquerade address is dropped against a named
// reason. NAT64 translates a tenant's ping the same way, ICMPv6 Echo to ICMPv4
// Echo and back. This shard generates no ICMP error of its own.
//
// An Echo Request addressed to a masquerade address itself is answered only
// when the operator turns on the echo responder (NAT_SHARD_FLAG_ECHO_RESPONDER),
// and every reply comes out of a per-CPU token bucket (icmp_rate_bucket).
//
// There is no tenant-identity check beyond the Argument itself. A forged
// Argument misdirects only the forger's own isolation bucket, never a
// legitimate tenant's, but this program trusts that only fabric-internal
// traffic reaches it at all. The trust boundary is a separate security
// question, not something this file resolves.
#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define NAT_ALWAYS_INLINE inline __attribute__((always_inline))

// NAT_BARRIER_VAR handles the same verifier bounds-narrowing behavior the
// other datapath files document under their own names. Each file is
// self-contained with one external header dependency, so the macro is repeated
// rather than imported.
#define NAT_BARRIER_VAR(var) asm volatile("" : "=r"(var) : "0"(var))

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
static long (*bpf_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *) BPF_FUNC_tail_call;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *) BPF_FUNC_redirect;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;

// ---------------------------------------------------------------------
// Constants.
// ---------------------------------------------------------------------

#define NAT_AF_INET 2
#define NAT_AF_INET6 10
#define NAT_ETH_P_IPV6 0x86DD
#define NAT_ETH_P_IP 0x0800
#define NAT_IPPROTO_TCP 6
#define NAT_IPPROTO_UDP 17
#define NAT_IPPROTO_IPV6 41 // both this shard's own pushed header, and the tenant's inbound one
#define NAT_IPPROTO_ICMPV6 58
#define NAT_IPPROTO_ICMP 1

// ICMPv4 message types (RFC 792).
#define NAT_ICMP_ECHO_REPLY 0
#define NAT_ICMP_ECHO_REQUEST 8

// ICMPv6 message types (RFC 4443, RFC 4861). The four error types share one
// layout -- an 8-byte header followed by as much of the offending packet as
// fits -- and are contiguous, which the return leaf's range test relies on.
#define NAT_ICMPV6_DEST_UNREACH 1
#define NAT_ICMPV6_PACKET_TOO_BIG 2
#define NAT_ICMPV6_TIME_EXCEEDED 3
#define NAT_ICMPV6_PARAM_PROBLEM 4
#define NAT_ICMPV6_ECHO_REQUEST 128
#define NAT_ICMPV6_ECHO_REPLY 129
#define NAT_ICMPV6_ND_FIRST 133 // Router Solicitation
#define NAT_ICMPV6_ND_LAST 137  // Redirect

#define NAT_PAT_PROBE_LIMIT 8
#define NAT_PAT_PORT_BASE 32768
#define NAT_PAT_PORT_RANGE 28000

// conn_key.family discriminates the two families' rows inside the one session
// table. A NAT64 row stores its IPv4 addresses IPv4-mapped into the 16-byte
// address fields, which without this byte could alias a genuine IPv6 flow to
// ::ffff:0:0/96. Making the family part of the key is what keeps the two
// families' entries structurally separate rather than merely unlikely to
// collide.
#define NAT_FAMILY_V6 6
#define NAT_FAMILY_V4 4

// Tail-call slots in nat_progs. Kept in sync with natprog's Go constants and
// with natattach's population order.
#define NAT_PROG_NAT66_FORWARD 0
#define NAT_PROG_NAT66_RETURN 1
#define NAT_PROG_NAT64_FORWARD 2
#define NAT_PROG_NAT64_RETURN 3
#define NAT_PROG_NAT66_ICMP_FORWARD 4
#define NAT_PROG_NAT66_ICMP_RETURN 5
#define NAT_PROG_NAT64_ICMP_FORWARD 6
#define NAT_PROG_NAT64_ICMP_RETURN 7
#define NAT_PROG_COUNT 8

// shard_config.flags bits.
//
// ECHO_RESPONDER makes the shard answer an Echo Request addressed to one of its
// own masquerade addresses, which it otherwise drops as unsolicited. Off unless
// an operator turns it on (GALACTIC_NAT_ECHO_RESPONDER): an internet-facing
// address that answers pings is a policy choice, not a default.
#define NAT_SHARD_FLAG_ECHO_RESPONDER 0x1

// The ICMP this shard emits on its own behalf -- echo-responder replies -- is
// limited by one token bucket per CPU: NAT_ICMP_RATE messages a second with a
// burst of NAT_ICMP_BURST, per CPU. See icmp_rate_bucket.
#define NAT_ICMP_RATE 1000
#define NAT_ICMP_BURST 100
#define NAT_ICMP_COST_NS (1000000000ULL / NAT_ICMP_RATE)

// The IPv6 and IPv4 fixed header sizes, and the difference a NAT64 translation
// adds to or removes from the front of a packet.
#define NAT_IP6HDR_LEN 40
#define NAT_IP4HDR_LEN 20
#define NAT_V6_V4_DELTA (NAT_IP6HDR_LEN - NAT_IP4HDR_LEN)

// ---------------------------------------------------------------------
// Minimal, self-contained header structs, byte-exact to the wire formats.
// ---------------------------------------------------------------------

struct nat_ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
} __attribute__((packed));

struct nat_ip6hdr {
	__u8 vtc_flow[4];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
} __attribute__((packed));

struct nat_iphdr {
	__u8 version_ihl;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__be16 check;
	__be32 saddr;
	__be32 daddr;
} __attribute__((packed));

struct nat_tcphdr {
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

struct nat_udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
} __attribute__((packed));

// struct nat_icmphdr is the fixed 8-byte header every ICMP message this program
// reads starts with. id and seq are an Echo message's Identifier and Sequence
// Number; on an error message the same four bytes are the type-specific word
// (unused, an MTU, or a pointer), which this program does not rewrite.
struct nat_icmphdr {
	__u8 type;
	__u8 code;
	__be16 check;
	__be16 id;
	__be16 seq;
} __attribute__((packed));

// ---------------------------------------------------------------------
// Map key/value types.
// ---------------------------------------------------------------------

// struct conn_key. The forward row is keyed by the tenant backend's facing
// tuple, plus the two fields that together identify which tenant it belongs to.
// The reverse row is keyed by the internet peer's tuple against this shard's
// public address for the family and the masquerade port, with both tenant
// fields zero: that pair is already globally unique, this shard having
// allocated it from its own address.
//
// Tenant identity is composed, not carried in one field:
//
//   encap_src   the source of the SRv6 outer header -- the address of the
//               worker node the flow was encapsulated from, unique per node
//   tenant_arg  this flow's VRFID, read from the SRv6 Argument, unique per
//               *node* because Arguments are allocated per BGPRouter
//
// Neither alone identifies a tenant fabric-wide. Together they do, which is why
// both are in the key. Without encap_src, two tenants on different nodes
// holding the same node-local Argument -- an ordinary occurrence, since the
// allocator's uniqueness scope is one router -- share a row whenever their
// inner tuples also match, and the second tenant's replies are re-encapsulated
// toward the first tenant's node.
//
// encap_src is doing all the work today: nothing yet writes a per-tenant
// Argument into a shard SID, so tenant_arg is whatever constant the operator
// configured and is identical for every tenant. That is a gap in route
// installation, not here; this key is correct either way, and becomes
// fully per-tenant once the Argument is threaded through.
//
// family separates the two address families' rows; see NAT_FAMILY_V4.
//
// An ICMP Echo flow has no ports, so its Echo Identifier takes the port's
// place on the side this shard rewrites and the other side is zero: the
// forward row holds the tenant's Identifier in sport, the reverse row the
// masquerade Identifier in dport. proto keeps those rows apart from TCP and UDP
// rows over the same addresses, so the masquerade Identifiers are allocated
// from the same probe and range as ports without ever colliding with one.
struct conn_key {
	__u8 family;
	__u8 proto;
	__u16 tenant_arg;
	__be16 sport;
	__be16 dport;
	__u8 saddr[16];
	__u8 daddr[16];
	__u8 encap_src[16];
};

// struct conn_value carries the full picture of one translated
// egress flow -- both directions read the same value, oriented by which
// key found it.
//
// For a NAT64 flow, dest_addr holds the *synthesized* IPv6 destination the
// tenant originally sent to (nat64_prefix plus the peer's IPv4 address), not
// the peer's IPv4 address alone. The return path needs it verbatim as the IPv6
// source it rebuilds toward the tenant: a reply whose source is anything else
// does not match the socket the tenant opened.
struct conn_value {
	__u8 backend_addr[16];
	__be16 backend_port;
	__u8 dest_addr[16];
	__be16 dest_port;
	__be16 shard_port;
	__u8 backend_usid[16];
	__u8 proto;
	__u8 family;
};

// struct shard_config is shard_config_table's single-entry value.
//
// serves_v6 and serves_v4 are explicit rather than inferred from an address
// being non-zero: "this shard performs NAT64" is a deployment decision, and
// making it a flag keeps a half-written config from being read as a working
// one. A shard with serves_v4 == 0 never executes an instruction of NAT64
// translation.
struct shard_config {
	__u8 shard_sid[16];
	__u8 shard_pub_addr6[16];
	__u8 nat64_prefix[16];
	__be32 shard_pub_addr4;
	__u8 serves_v6;
	__u8 serves_v4;
	__u8 flags; // NAT_SHARD_FLAG_*
	__u8 pad;
};

enum nat_drop_reason {
	// 0-8 keep the indices they had when this file served NAT66 alone, so an
	// existing counter series stays the same series after the generalization.
	DROP_REASON_NAT66_NO_RETURN_CONN     = 0,
	DROP_REASON_NAT66_MALFORMED_RETURN   = 1,
	DROP_REASON_NAT66_PAT_EXHAUSTED      = 2,
	DROP_REASON_NAT66_MALFORMED_FORWARD  = 3,
	DROP_REASON_NAT_FIB_NO_NEIGH         = 4,
	DROP_REASON_NAT_FIB_UNREACHABLE      = 5,
	DROP_REASON_NAT_FIB_FRAG_NEEDED      = 6,
	DROP_REASON_NAT_FIB_LOOKUP_FAILED    = 7,
	DROP_REASON_NAT_ADJUST_HEAD_FAILED   = 8,
	DROP_REASON_NAT64_NO_RETURN_CONN     = 9,
	DROP_REASON_NAT64_MALFORMED_RETURN   = 10,
	DROP_REASON_NAT64_PAT_EXHAUSTED      = 11,
	DROP_REASON_NAT64_MALFORMED_FORWARD  = 12,
	DROP_REASON_NAT64_V4_FRAGMENT        = 13,
	DROP_REASON_NAT64_V4_OPTIONS         = 14,
	DROP_REASON_NAT64_SHARD_UNAVAILABLE  = 15,
	// 16-18 arrived with the forward legs' own transmit. Appended rather than
	// slotted in beside the other forward-path reasons, so every counter series
	// that existed before keeps its index.
	DROP_REASON_NAT_HOP_LIMIT_EXCEEDED   = 16,
	DROP_REASON_NAT_NO_EGRESS_IFINDEX    = 17,
	DROP_REASON_NAT_REDIRECT_FAILED      = 18,
	// 19 onward arrived with ICMP, appended for the same reason.
	//
	// malformed and no_conn mirror the TCP/UDP pair. untranslatable is a
	// well-formed message this shard has no translation for -- an ICMP type it
	// does not handle, or an error quoting a packet it could not have sent --
	// and is a policy outcome, not a parse failure; unsolicited is an Echo
	// Request addressed to the masquerade address itself rather than a reply
	// to anything a tenant sent.
	DROP_REASON_NAT66_ICMP_MALFORMED     = 19,
	DROP_REASON_NAT66_ICMP_NO_CONN       = 20,
	DROP_REASON_NAT_ICMP_UNTRANSLATABLE  = 21,
	DROP_REASON_NAT_ICMP_UNSOLICITED     = 22,
	DROP_REASON_NAT64_ICMP_MALFORMED     = 23,
	DROP_REASON_NAT64_ICMP_NO_CONN       = 24,
	// A message this shard would have emitted on its own behalf, refused by
	// icmp_rate_bucket.
	DROP_REASON_NAT_ICMP_RATE_LIMITED    = 25,
	DROP_REASON_NAT_COUNT                = 26,
};

// ---------------------------------------------------------------------
// Maps.
// ---------------------------------------------------------------------

// nat_conn_table holds every session this shard translates, ICMP included.
//
// ICMP Echo rows share the table, and its 65536-entry LRU, with TCP and UDP
// rather than living in a map of their own. That is a deliberate trade: a burst
// of tenant pings to many destinations can evict live TCP and UDP sessions,
// whose next reply then counts as no_return_conn. It is accepted because a
// tenant pinging at a rate that churns the table would churn it just as hard
// with UDP, and a second map would split one capacity budget into two that
// have to be sized separately. RFC 6146's shorter ICMP query timeout has no
// counterpart here: no row in this table carries a timer, and LRU eviction is
// the only expiry any row gets. If the trade ever stops holding, ICMP rows move
// to a separate, smaller LRU, and only the ICMP leaves change.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, struct conn_value);
} nat_conn_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shard_config);
} shard_config_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, NAT_PROG_COUNT);
	__type(key, __u32);
	__type(value, __u32);
} nat_progs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, DROP_REASON_NAT_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} drop_reasons SEC(".maps");

// struct icmp_bucket is one CPU's token bucket, held as nanoseconds of credit
// rather than whole tokens so a refill is an addition, with no division on the
// packet path: each message costs NAT_ICMP_COST_NS, and credit accrues one
// nanosecond per nanosecond up to NAT_ICMP_BURST messages' worth.
struct icmp_bucket {
	__u64 last_ns;
	__u64 credit_ns;
};

// icmp_rate_bucket limits the ICMP this shard emits on its own behalf, with one
// independent bucket per CPU and no locking.
//
// That makes the effective limit for the whole shard the per-CPU rate times the
// number of CPUs receiving traffic, which scales with the uplinks' RSS queue
// count rather than being one fixed number per shard. It is also not per peer:
// one peer that drains a CPU's bucket suppresses this shard's messages to every
// other peer hashed to that CPU until it refills. Both are accepted for now; a
// per-peer or global limiter is the follow-up if either shows up in practice,
// and every refusal is counted as icmp_rate_limited so it will.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct icmp_bucket);
} icmp_rate_bucket SEC(".maps");

static NAT_ALWAYS_INLINE void count_drop(__u32 reason)
{
	__u64 *counter = bpf_map_lookup_elem(&drop_reasons, &reason);
	if (counter)
		*counter += 1;
}

// take_icmp_token reports whether this CPU's bucket can pay for one more
// message, and spends it if so.
//
// A clock reading behind last_ns earns nothing rather than underflowing into
// a full bucket. The monotonic clock does not run backwards, but a bucket is
// only ever written by its own CPU, and treating a stale or future stamp as
// "no time passed" is the reading that can never over-admit.
static NAT_ALWAYS_INLINE int take_icmp_token(void)
{
	__u32 key = 0;
	struct icmp_bucket *b = bpf_map_lookup_elem(&icmp_rate_bucket, &key);
	if (!b)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	__u64 credit = b->credit_ns + (now > b->last_ns ? now - b->last_ns : 0);
	if (credit > NAT_ICMP_BURST * NAT_ICMP_COST_NS)
		credit = NAT_ICMP_BURST * NAT_ICMP_COST_NS;
	if (now > b->last_ns)
		b->last_ns = now;

	if (credit < NAT_ICMP_COST_NS) {
		b->credit_ns = credit;
		return 0;
	}
	b->credit_ns = credit - NAT_ICMP_COST_NS;
	return 1;
}

static NAT_ALWAYS_INLINE int addr6_eq(const __u8 a[16], const __u8 b[16])
{
	for (int i = 0; i < 16; i++) {
		if (a[i] != b[i])
			return 0;
	}
	return 1;
}

// locator_matches checks only the top 64 bits of daddr against this shard's
// shard_sid, the same "is this mine" granularity the ingress datapath's locator
// match uses. The Argument below it varies per tenant and is read afterward, so
// it is deliberately not part of the question.
//
// That granularity requires shard_sid's Block and Node-ID to be reserved and
// disjoint from every other uSID identity sharing this node's uplink. In
// particular, a shard's Node-ID must differ from the one any co-located
// tenant-delivery BGPRouter on the same node uses. Reusing it means ordinary
// tenant ingress traffic addressed to that node's real delivery uSID, which
// shares the Block and Node-ID and also carries an IPv6-in-IPv6 next header, is
// silently hijacked here before reaching the ingress hook.
//
// That is an address-allocation conflict this function cannot detect, not a
// flaw in the 64-bit match. Widening to a full 128-bit compare breaks the
// intended case of two tenants' egress packets sharing this shard_sid with
// different Argument values.
static NAT_ALWAYS_INLINE int locator_matches(const __u8 daddr[16], const __u8 shard_sid[16])
{
	for (int i = 0; i < 8; i++) {
		if (daddr[i] != shard_sid[i])
			return 0;
	}
	return 1;
}

// nat64_prefix_matches tests an inner destination against the shard's NAT64
// Network-Specific Prefix. The prefix is a /96 -- RFC 6052's only length that
// places the embedded IPv4 address in one aligned 4-byte run, which is why this
// implementation supports that length alone -- so the first 12 bytes decide it.
static NAT_ALWAYS_INLINE int nat64_prefix_matches(const __u8 daddr[16], const __u8 prefix[16])
{
	for (int i = 0; i < 12; i++) {
		if (daddr[i] != prefix[i])
			return 0;
	}
	return 1;
}

// read_argument extracts the 12-bit Argument from a uFMT 48+16 address at bits
// 69-80, the same bit positions the Go encoding and the ingress datapath use.
static NAT_ALWAYS_INLINE __u16 read_argument(const __u8 daddr[16])
{
	return ((__u16) (daddr[8] & 0x0F) << 8) | daddr[9];
}

// v4_mapped writes addr into out as ::ffff:a.b.c.d, the form an IPv4 address
// takes inside conn_key's 16-byte fields. conn_key.family, not this encoding,
// is what keeps such a row from aliasing a real IPv6 flow.
static NAT_ALWAYS_INLINE void v4_mapped(__u8 out[16], __be32 addr)
{
	__builtin_memset(out, 0, 16);
	out[10] = 0xff;
	out[11] = 0xff;
	__builtin_memcpy(out + 12, &addr, 4);
}

static NAT_ALWAYS_INLINE __u32 fnv1a_flow(const __u8 addr[16], __be16 port)
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

static NAT_ALWAYS_INLINE __be16 csum_fold_add(__be16 check, __s64 diff)
{
	__s64 sum = (__u16) ~check;
	sum += diff;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__be16) ~((__u16) sum);
}

// ---------------------------------------------------------------------
// L4 parsing and checksum fixups.
// ---------------------------------------------------------------------

// struct l4_view holds already-typed pointers to the L4 fields a rewrite needs,
// resolved exactly once, adjacent to the bounds check that proves them safe.
struct l4_view {
	__be16 sport;
	__be16 dport;
	__be16 *sport_ptr;
	__be16 *dport_ptr;
	__be16 *check_ptr;
};

static NAT_ALWAYS_INLINE int parse_l4(__u8 proto, void *l4, void *data_end, struct l4_view *out)
{
	if (proto == NAT_IPPROTO_TCP) {
		struct nat_tcphdr *tcp = l4;
		if ((void *) (tcp + 1) > data_end)
			return -1;
		out->sport = tcp->source;
		out->dport = tcp->dest;
		out->sport_ptr = &tcp->source;
		out->dport_ptr = &tcp->dest;
		out->check_ptr = &tcp->check;
		return 0;
	}
	if (proto == NAT_IPPROTO_UDP) {
		struct nat_udphdr *udp = l4;
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

// parse_echo resolves an ICMP Echo message into the same view parse_l4 gives a
// TCP or UDP header, so the translation legs need not know which they hold. The
// Echo Identifier is the port on the side this shard rewrites -- the source on
// the way out, where the tenant's Identifier is replaced by a masquerade one,
// and the destination on the way back, where it is restored -- and the other
// side reads as zero, which is what the session rows store for it.
static NAT_ALWAYS_INLINE int parse_echo(void *l4, void *data_end, int outbound, struct l4_view *out)
{
	struct nat_icmphdr *icmp = l4;
	if ((void *) (icmp + 1) > data_end)
		return -1;
	out->sport = outbound ? icmp->id : 0;
	out->dport = outbound ? 0 : icmp->id;
	out->sport_ptr = &icmp->id;
	out->dport_ptr = &icmp->id;
	out->check_ptr = &icmp->check;
	return 0;
}

// struct quoted_view holds the transport fields of the packet an ICMP error
// quotes. That packet is one this shard sent toward the internet, so its source
// side carries the masquerade port or Identifier and its destination side the
// peer's port.
struct quoted_view {
	__be16 masq;
	__be16 peer_port;
	__be16 *masq_ptr;
};

// parse_quoted reads the quoted packet's transport fields. It returns -1 when
// the quote is too short to hold them and 1 when it is a packet this shard
// could not have sent: neither TCP, UDP, nor an Echo Request of the given ICMP
// protocol and type.
//
// Only the first four bytes of a quoted TCP or UDP header are read, not
// parse_l4's whole header. RFC 4443 guarantees an error quotes as much of the
// offending packet as fits, which in practice is all of it, but RFC 792 for
// ICMPv4 guarantees only the first eight bytes of the transport header, and a
// full-header bounds check would reject a legitimate minimal quote.
static NAT_ALWAYS_INLINE int parse_quoted(__u8 proto, void *l4, void *data_end, __u8 icmp_proto,
					  __u8 echo_request_type, struct quoted_view *out)
{
	if (proto == NAT_IPPROTO_TCP || proto == NAT_IPPROTO_UDP) {
		__be16 *ports = l4;
		if ((void *) (ports + 2) > data_end)
			return -1;
		out->masq = ports[0];
		out->peer_port = ports[1];
		out->masq_ptr = &ports[0];
		return 0;
	}
	if (proto == icmp_proto) {
		struct nat_icmphdr *echo = l4;
		if ((void *) (echo + 1) > data_end)
			return -1;
		if (echo->type != echo_request_type)
			return 1;
		out->masq = echo->id;
		out->peer_port = 0;
		out->masq_ptr = &echo->id;
		return 0;
	}
	return 1;
}

// fix_l4_checksum applies the combined address and port checksum delta for a
// masquerade rewrite, where one address and one port change and the peer's are
// unchanged. It uses a checksum diff because XDP has no sk_buff and the
// incremental L4 helper is unavailable.
static NAT_ALWAYS_INLINE void fix_l4_checksum(__be16 *check_ptr, const __u8 old_addr[16], __be16 old_port,
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

// fix_l4_checksum_xlat applies the delta for a NAT64 translation, where the
// pseudo-header changes address *family* as well as value.
//
// Only the addresses and the one rewritten port contribute. The IPv6 and IPv4
// pseudo-headers differ in three fields -- addresses, upper-layer length, and
// the protocol/zero padding -- but the length is the same L4 length in both
// (the IPv6 form's extra 16 high bits are zero for any length that fits an
// IPv4 packet) and the protocol byte is unchanged by translation, so both
// cancel and neither needs to appear here.
//
// Both buffers are the same size and 4-byte aligned throughout, which keeps
// every 16-bit summand on the same parity it had on the wire -- the property
// that makes a positional checksum diff valid at all.
static NAT_ALWAYS_INLINE void fix_l4_checksum_xlat(__be16 *check_ptr, const __be32 *old_words,
						    const __be32 *new_words)
{
	__s64 diff = bpf_csum_diff((__be32 *) old_words, 36, (__be32 *) new_words, 36, 0);
	*check_ptr = csum_fold_add(*check_ptr, diff);
}

// xlat_words packs an address pair and a port into the 9-word form
// fix_l4_checksum_xlat compares. An IPv4 address occupies one word and the
// remaining address words stay zero; the port keeps word 8 in both forms so the
// two buffers line up.
static NAT_ALWAYS_INLINE void xlat_words6(__be32 out[9], const __u8 src[16], const __u8 dst[16], __be16 port)
{
	__builtin_memcpy(&out[0], src, 16);
	__builtin_memcpy(&out[4], dst, 16);
	out[8] = (__be32) port;
}

static NAT_ALWAYS_INLINE void xlat_words4(__be32 out[9], __be32 src, __be32 dst, __be16 port)
{
	__builtin_memset(out, 0, 36);
	out[0] = src;
	out[4] = dst;
	out[8] = (__be32) port;
}

// ipv4_header_csum computes the IPv4 header checksum over a header whose own
// check field has already been zeroed. IPv6 carries no header checksum, so
// unlike every other checksum here this one is computed outright rather than
// adjusted.
static NAT_ALWAYS_INLINE __be16 ipv4_header_csum(const struct nat_iphdr *ip4)
{
	const __u16 *words = (const __u16 *) ip4;
	__u32 sum = 0;

	#pragma unroll
	for (int i = 0; i < NAT_IP4HDR_LEN / 2; i++)
		sum += words[i];

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__be16) ~((__u16) sum);
}

// udp_zero_checksum_fixup keeps a translated UDP datagram legal. A computed
// checksum of zero means "no checksum" in IPv4 and must be sent as 0xFFFF
// instead; the two are numerically equivalent in ones' complement. IPv6 forbids
// a zero UDP checksum outright, so the reverse direction needs the same
// treatment for the opposite reason.
static NAT_ALWAYS_INLINE void udp_zero_checksum_fixup(__u8 proto, __be16 *check_ptr)
{
	if (proto == NAT_IPPROTO_UDP && *check_ptr == 0)
		*check_ptr = 0xffff;
}

// fix_icmp_type adjusts an ICMP checksum for a change of message type alone,
// which is all an echo responder's reply differs by: swapping the addresses
// leaves the ICMPv6 pseudo-header's sum unchanged, and ICMPv4 has none.
static NAT_ALWAYS_INLINE void fix_icmp_type(struct nat_icmphdr *icmp, __u8 new_type)
{
	__be32 old_word = 0;
	__be32 new_word = 0;
	((__u8 *) &old_word)[0] = icmp->type;
	((__u8 *) &new_word)[0] = new_type;
	__s64 diff = bpf_csum_diff(&old_word, 4, &new_word, 4, 0);
	icmp->check = csum_fold_add(icmp->check, diff);
	icmp->type = new_type;
}

// fix_echo_checksum_xlat adjusts an Echo message's checksum across a NAT64
// translation (RFC 7915 sections 4.2 and 5.2), in either direction.
//
// Unlike TCP and UDP, nothing cancels. ICMPv6's checksum covers the IPv6
// pseudo-header and ICMPv4's covers no pseudo-header at all, so the whole
// pseudo-header leaves the sum on the way to IPv4 and joins it on the way back,
// alongside the type (128/129 against 8/0) and the Identifier the shard
// rewrites. Each side is one 48-byte image -- the pseudo-header, or zeros where
// IPv4 has none, then the header's two words with the checksum held at zero --
// so one diff carries all of it. The code and Sequence Number appear in neither
// image: they are the same on both sides and would only cancel.
static NAT_ALWAYS_INLINE void fix_echo_checksum_xlat(__be16 *check_ptr, const int to_v4,
						      const __u8 src6[16], const __u8 dst6[16],
						      __u16 icmp_len, __u8 type6, __be16 id6,
						      __u8 type4, __be16 id4)
{
	__be32 v6[12];
	__be32 v4[12];
	__builtin_memset(v4, 0, sizeof(v4));
	__builtin_memcpy(&v6[0], src6, 16);
	__builtin_memcpy(&v6[4], dst6, 16);
	v6[8] = __builtin_bswap32((__u32) icmp_len);
	v6[9] = __builtin_bswap32(NAT_IPPROTO_ICMPV6);
	v6[10] = 0;
	v6[11] = 0;
	((__u8 *) &v6[10])[0] = type6;
	((__u8 *) &v4[10])[0] = type4;
	__builtin_memcpy(&v6[11], &id6, 2);
	__builtin_memcpy(&v4[11], &id4, 2);

	__s64 diff = to_v4 ? bpf_csum_diff(v6, sizeof(v6), v4, sizeof(v4), 0) :
			     bpf_csum_diff(v4, sizeof(v4), v6, sizeof(v6), 0);
	*check_ptr = csum_fold_add(*check_ptr, diff);
}

// ---------------------------------------------------------------------
// Encapsulation helpers.
// ---------------------------------------------------------------------

// The ingress interface goes in as the lookup's scope, and the interface the
// route egresses comes back out through egress_ifindex: bpf_fib_lookup
// overwrites fib_params.ifindex with it on success. leave_via below needs that
// value; discarding it is what put every encapsulated packet on the wrong wire
// in the sibling edge datapath, which resolved it the same way.
static NAT_ALWAYS_INLINE long resolve_fib_and_write_eth(void *ctx, __u32 ifindex, const __u8 src[16],
							 const __u8 dst[16], __u16 tot_len,
							 struct nat_ethhdr *eth, __u32 *egress_ifindex)
{
	struct bpf_fib_lookup fib_params;
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.family = NAT_AF_INET6;
	__builtin_memcpy(&fib_params.ipv6_src, src, 16);
	__builtin_memcpy(&fib_params.ipv6_dst, dst, 16);
	fib_params.ifindex = ifindex;
	fib_params.tot_len = tot_len;

	long fib_rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS)
		return fib_rc;

	__builtin_memcpy(eth->h_dest, fib_params.dmac, sizeof(eth->h_dest));
	__builtin_memcpy(eth->h_source, fib_params.smac, sizeof(eth->h_source));
	eth->h_proto = __builtin_bswap16(NAT_ETH_P_IPV6);
	*egress_ifindex = fib_params.ifindex;
	return BPF_FIB_LKUP_RET_SUCCESS;
}

// resolve_fib_and_write_eth4 is the same lookup for the one leg that leaves
// this program as IPv4: a NAT64 forward packet, already translated. A separate
// function rather than a family parameter, because bpf_fib_lookup reads a
// different member of each address union depending on family and the EtherType
// written below differs too, so the two share no line worth merging.
static NAT_ALWAYS_INLINE long resolve_fib_and_write_eth4(void *ctx, __u32 ifindex, __be32 src,
							  __be32 dst, __u16 tot_len,
							  struct nat_ethhdr *eth, __u32 *egress_ifindex)
{
	struct bpf_fib_lookup fib_params;
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.family = NAT_AF_INET;
	fib_params.ipv4_src = src;
	fib_params.ipv4_dst = dst;
	fib_params.ifindex = ifindex;
	fib_params.tot_len = tot_len;

	long fib_rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS)
		return fib_rc;

	__builtin_memcpy(eth->h_dest, fib_params.dmac, sizeof(eth->h_dest));
	__builtin_memcpy(eth->h_source, fib_params.smac, sizeof(eth->h_source));
	eth->h_proto = __builtin_bswap16(NAT_ETH_P_IP);
	*egress_ifindex = fib_params.ifindex;
	return BPF_FIB_LKUP_RET_SUCCESS;
}

static NAT_ALWAYS_INLINE void count_fib_drop(long fib_rc)
{
	if (fib_rc == BPF_FIB_LKUP_RET_NO_NEIGH)
		count_drop(DROP_REASON_NAT_FIB_NO_NEIGH);
	else if (fib_rc == BPF_FIB_LKUP_RET_UNREACHABLE || fib_rc == BPF_FIB_LKUP_RET_BLACKHOLE ||
		 fib_rc == BPF_FIB_LKUP_RET_PROHIBIT)
		count_drop(DROP_REASON_NAT_FIB_UNREACHABLE);
	else if (fib_rc == BPF_FIB_LKUP_RET_FRAG_NEEDED)
		count_drop(DROP_REASON_NAT_FIB_FRAG_NEEDED);
	else
		count_drop(DROP_REASON_NAT_FIB_LOOKUP_FAILED);
}

// leave_via turns a resolved egress interface into this packet's verdict, for a
// packet whose Ethernet header one of the two resolvers above has already
// written. Every leg of this program ends here: the forward legs so the kernel
// never sees a flow whose reply it will never see, and the return legs because
// they always did.
//
// Leave over the interface the route selected, which is not in general the one
// the packet arrived on. A shard reaches the fabric and the internet over the
// same uplink in the simple case, and XDP_TX is both correct and cheaper there,
// but a multi-homed shard node routes the two directions out different links.
// XDP_TX retransmits out the ingress interface unconditionally, so on those
// nodes it puts a frame carrying the egress link's source and next-hop MACs
// onto the wrong wire, where the neighbour discards it -- and the FIB lookup
// having succeeded, nothing counts that as a failure.
static NAT_ALWAYS_INLINE int leave_via(struct xdp_md *ctx, __u32 egress_ifindex)
{
	if (egress_ifindex == 0) {
		count_drop(DROP_REASON_NAT_NO_EGRESS_IFINDEX);
		return XDP_DROP;
	}
	if (egress_ifindex == ctx->ingress_ifindex)
		return XDP_TX;

	if (bpf_redirect(egress_ifindex, 0) != XDP_REDIRECT) {
		count_drop(DROP_REASON_NAT_REDIRECT_FAILED);
		return XDP_DROP;
	}
	return XDP_REDIRECT;
}

// push_outer_header uses the same mechanism as the other datapath programs'
// function of the same name. Copied rather than shared, since each program
// defines its own surrounding header structs.
static NAT_ALWAYS_INLINE int push_outer_header(struct xdp_md *ctx, const __u8 src[16], const __u8 dst[16],
						__be16 inner_payload_len_plus_ip6hdr,
						__u32 *egress_ifindex)
{
	if (bpf_xdp_adjust_head(ctx, -NAT_IP6HDR_LEN) != 0) {
		count_drop(DROP_REASON_NAT_ADJUST_HEAD_FAILED);
		return -1;
	}

	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	if (data + sizeof(struct nat_ethhdr) + sizeof(struct nat_ip6hdr) > data_end) {
		count_drop(DROP_REASON_NAT_ADJUST_HEAD_FAILED);
		return -1;
	}

	struct nat_ethhdr *eth = data;
	struct nat_ip6hdr *outer = (void *) (eth + 1);

	// The high nibble of vtc_flow[0] is the IPv6 version and must be set: a
	// zeroed default produces a header receivers parse as invalid IPv6, which a
	// synthetic program run never validates.
	__builtin_memset(outer->vtc_flow, 0, sizeof(outer->vtc_flow));
	outer->vtc_flow[0] = 0x60;
	outer->payload_len = inner_payload_len_plus_ip6hdr;
	outer->nexthdr = NAT_IPPROTO_IPV6;
	outer->hop_limit = 64;
	__builtin_memcpy(outer->saddr, src, 16);
	__builtin_memcpy(outer->daddr, dst, 16);

	long fib_rc = resolve_fib_and_write_eth(ctx, ctx->ingress_ifindex, src, dst,
						 (__u16) (sizeof(*outer) + __builtin_bswap16(inner_payload_len_plus_ip6hdr)),
						 eth, egress_ifindex);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS) {
		count_fib_drop(fib_rc);
		return -1;
	}
	return 0;
}

// strip_outer_header removes the SRv6 outer IPv6 header, leaving the inner
// packet behind its own Ethernet header.
//
// The link header has to be carried across the move explicitly. Widening the
// head past it and then reclaiming 14 bytes exposes whatever the old packet
// held at that offset -- the tail of the outer destination address and the
// front of the inner IPv6 header -- not a link header, and there is nothing
// for the forward leg's FIB resolution to overwrite the addresses of.
static NAT_ALWAYS_INLINE int strip_outer_header(struct xdp_md *ctx, struct nat_ethhdr **eth_out)
{
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	if (data + sizeof(struct nat_ethhdr) > data_end)
		return -1;

	__u8 saved_eth[sizeof(struct nat_ethhdr)];
	__builtin_memcpy(saved_eth, data, sizeof(saved_eth));

	if (bpf_xdp_adjust_head(ctx, (int) (sizeof(struct nat_ethhdr) + sizeof(struct nat_ip6hdr))) != 0)
		return -1;
	if (bpf_xdp_adjust_head(ctx, -(int) sizeof(struct nat_ethhdr)) != 0)
		return -1;

	data = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;
	if (data + sizeof(struct nat_ethhdr) > data_end)
		return -1;

	// Restored verbatim, then overwritten: each forward leg resolves its own
	// next hop and writes real source and destination MACs over these before
	// transmitting. What the restore buys is a well-formed header to overwrite
	// on every path, including the ones that drop before resolution.
	__builtin_memcpy(data, saved_eth, sizeof(saved_eth));

	*eth_out = data;
	return 0;
}

// ---------------------------------------------------------------------
// Shared session-table logic.
// ---------------------------------------------------------------------

// claim_masquerade_port probes for a free (shard address, port) pair for a new
// flow and installs the reverse row under it, returning the claimed port in
// network order or 0 when every probe collided.
//
// Installing the reverse row *is* the claim: BPF_NOEXIST makes the map itself
// the allocator, so two CPUs racing for the same candidate cannot both win. The
// forward row is written by the caller afterward.
//
// rev_key is mutated in place rather than copied per probe. A copy inside an
// unrolled loop is a second whole key on the stack, and this program's 512-byte
// BPF stack has no room for one; the caller owns the key and has no use for it
// after this returns, so there is nothing to preserve by copying. Its dport is
// left holding whichever candidate was tried last.
static NAT_ALWAYS_INLINE __be16 claim_masquerade_port(struct conn_key *rev_key,
						       struct conn_value *cv, __u32 hash_base)
{
	#pragma unroll
	for (int i = 0; i < NAT_PAT_PROBE_LIMIT; i++) {
		__u16 candidate = NAT_PAT_PORT_BASE + ((hash_base + (__u32) i) % NAT_PAT_PORT_RANGE);
		__be16 port = __builtin_bswap16(candidate);

		rev_key->dport = port;
		cv->shard_port = port;

		if (bpf_map_update_elem(&nat_conn_table, rev_key, cv, BPF_NOEXIST) == 0)
			return port;
	}
	return 0;
}

// ---------------------------------------------------------------------
// NAT66: IPv6 tenant -> IPv6 internet.
// ---------------------------------------------------------------------

// nat66_forward processes a tenant's outbound IPv6 packet encapsulated toward
// this shard. It strips the outer header, resolves the tenant key from the
// Argument, allocates or reuses a masquerade port, translates the source, and
// transmits the now internet-routable packet over the interface its own FIB
// lookup selected.
//
// It resolves and transmits rather than handing the packet up because the
// return leg does: a reply is claimed at ingress and re-encapsulated straight
// back out of the driver, so netfilter never sees one. Passing the forward leg
// up opened a conntrack entry that could never leave SYN_SENT, which made the
// tenant's own ACK arrive against a half-seen flow, be marked INVALID, and be
// dropped by any invalid-state rule on the node -- kube-proxy installs one --
// with every drop counter here flat, because nothing here had dropped it.
//
// nat66_forward and nat66_icmp_forward are this one leg, specialized at compile
// time on icmp: the two differ only in how the transport header is read, and
// in which counters a packet that cannot be translated lands on.
static NAT_ALWAYS_INLINE int nat66_forward_leg(struct xdp_md *ctx, const int icmp)
{
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	struct nat_ethhdr *eth = data;
	if ((void *) (eth + 1) > data_end)
		return XDP_PASS;
	struct nat_ip6hdr *outer = (void *) (eth + 1);
	if ((void *) (outer + 1) > data_end)
		return XDP_PASS;

	__u32 cfg_key = 0;
	struct shard_config *cfg = bpf_map_lookup_elem(&shard_config_table, &cfg_key);
	if (!cfg)
		return XDP_PASS;

	__u32 tenant_arg = read_argument(outer->daddr);
	// The tenant's worker-node uSID, needed below to build the reply's
	// re-encapsulation destination, must be captured into a local now. Stripping
	// the outer header adjusts the packet head twice, which invalidates every
	// pointer derived before it, so reading it afterward is a stale access the
	// verifier rejects.
	__u8 tenant_usid[16];
	__builtin_memcpy(tenant_usid, outer->saddr, 16);

	const __u32 malformed = icmp ? DROP_REASON_NAT66_ICMP_MALFORMED : DROP_REASON_NAT66_MALFORMED_FORWARD;

	if (strip_outer_header(ctx, &eth) != 0) {
		count_drop(malformed);
		return XDP_DROP;
	}

	data_end = (void *) (long) ctx->data_end;
	struct nat_ip6hdr *inner = (void *) (eth + 1);
	if ((void *) (inner + 1) > data_end) {
		count_drop(malformed);
		return XDP_DROP;
	}

	struct l4_view l4v;
	if (icmp) {
		if (inner->nexthdr != NAT_IPPROTO_ICMPV6 ||
		    parse_echo((void *) (inner + 1), data_end, 1, &l4v) != 0) {
			count_drop(malformed);
			return XDP_DROP;
		}
		// An Echo Request is the only ICMPv6 message a tenant can open a flow
		// with. Anything else it sends outward -- an Echo Reply, an error about
		// a packet it received -- answers a flow this shard has no row for.
		struct nat_icmphdr *echo = (void *) (inner + 1);
		if (echo->type != NAT_ICMPV6_ECHO_REQUEST) {
			count_drop(DROP_REASON_NAT_ICMP_UNTRANSLATABLE);
			return XDP_DROP;
		}
	} else {
		if (inner->nexthdr != NAT_IPPROTO_TCP && inner->nexthdr != NAT_IPPROTO_UDP) {
			count_drop(malformed);
			return XDP_DROP;
		}
		if (parse_l4(inner->nexthdr, (void *) (inner + 1), data_end, &l4v) != 0) {
			count_drop(malformed);
			return XDP_DROP;
		}
	}

	// The hop decrement is this program's job now that the packet leaves from
	// the driver: the kernel's forwarding path used to do it, and without it a
	// routing loop through this shard never expires. Checked before the session
	// lookup so an expiring packet costs no port allocation. A router owes the
	// sender an ICMPv6 Time Exceeded here, which this program does not generate
	// (see Scope) -- the drop is counted instead.
	if (inner->hop_limit <= 1) {
		count_drop(DROP_REASON_NAT_HOP_LIMIT_EXCEEDED);
		return XDP_DROP;
	}
	inner->hop_limit--;

	struct conn_key fwd_key;
	__builtin_memset(&fwd_key, 0, sizeof(fwd_key));
	fwd_key.family = NAT_FAMILY_V6;
	fwd_key.proto = inner->nexthdr;
	fwd_key.tenant_arg = (__u16) tenant_arg;
	__builtin_memcpy(fwd_key.saddr, inner->saddr, 16);
	fwd_key.sport = l4v.sport;
	__builtin_memcpy(fwd_key.daddr, inner->daddr, 16);
	fwd_key.dport = l4v.dport;
	__builtin_memcpy(fwd_key.encap_src, tenant_usid, 16);

	struct conn_value *existing = bpf_map_lookup_elem(&nat_conn_table, &fwd_key);
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
		cv.family = NAT_FAMILY_V6;

		struct conn_key rev_key;
		__builtin_memset(&rev_key, 0, sizeof(rev_key));
		rev_key.family = NAT_FAMILY_V6;
		rev_key.proto = inner->nexthdr;
		__builtin_memcpy(rev_key.saddr, inner->daddr, 16);
		rev_key.sport = l4v.dport;
		__builtin_memcpy(rev_key.daddr, cfg->shard_pub_addr6, 16);

		__u32 base = fnv1a_flow(inner->saddr, l4v.sport) ^ (__u32) l4v.dport ^ tenant_arg;
		if (claim_masquerade_port(&rev_key, &cv, base) == 0) {
			count_drop(DROP_REASON_NAT66_PAT_EXHAUSTED);
			return XDP_DROP;
		}

		bpf_map_update_elem(&nat_conn_table, &fwd_key, &cv, BPF_ANY);
	}

	fix_l4_checksum(l4v.check_ptr, inner->saddr, l4v.sport, cfg->shard_pub_addr6, cv.shard_port);
	__builtin_memcpy(inner->saddr, cfg->shard_pub_addr6, 16);
	*l4v.sport_ptr = cv.shard_port;

	// Resolved from the translated source, not the tenant's: the reply has to
	// come back to this shard's own masquerade address, and a route selected
	// for any other source may leave over a different interface entirely.
	__u8 dst_addr[16];
	__builtin_memcpy(dst_addr, inner->daddr, 16);
	__u16 tot_len = (__u16) (NAT_IP6HDR_LEN + __builtin_bswap16(inner->payload_len));

	__u32 egress_ifindex = 0;
	long fib_rc = resolve_fib_and_write_eth(ctx, ctx->ingress_ifindex, cfg->shard_pub_addr6,
						 dst_addr, tot_len, eth, &egress_ifindex);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS) {
		count_fib_drop(fib_rc);
		return XDP_DROP;
	}

	return leave_via(ctx, egress_ifindex);
}

SEC("xdp")
int nat66_forward(struct xdp_md *ctx)
{
	return nat66_forward_leg(ctx, 0);
}

// nat66_icmp_forward: a tenant's outbound ICMPv6 Echo Request, translated like
// a UDP datagram with the Echo Identifier masqueraded in the source port's
// place.
SEC("xdp")
int nat66_icmp_forward(struct xdp_md *ctx)
{
	return nat66_forward_leg(ctx, 1);
}

// reencap_to_tenant is the last step every NAT66 return leg shares: push the
// SRv6 outer header toward the tenant's worker node and transmit. ip6 is the
// already-rewritten packet, read here only for its length before the head moves.
static NAT_ALWAYS_INLINE int reencap_to_tenant(struct xdp_md *ctx, struct shard_config *cfg,
						struct nat_ip6hdr *ip6, const __u8 usid[16])
{
	// Must include the inner IPv6 header's own 40 bytes, not just its payload.
	// Passing the inner payload length alone undercounts the outer header's
	// declared length on every packet, which a validating receiver rejects.
	__be16 inner_payload_len_plus_ip6hdr =
		__builtin_bswap16((__u16) sizeof(struct nat_ip6hdr) + __builtin_bswap16(ip6->payload_len));

	__u8 backend_usid[16];
	__builtin_memcpy(backend_usid, usid, 16);

	// The outer source is this shard's own SRv6-reachable identity, not any
	// field of the connection row. The tenant's worker node decapsulates this
	// like any cross-node SRv6 packet and does not validate the encapsulation
	// source, but it must still be a real address on this node rather than the
	// internet peer's.
	__u32 egress_ifindex = 0;
	if (push_outer_header(ctx, cfg->shard_sid, backend_usid, inner_payload_len_plus_ip6hdr,
			       &egress_ifindex) != 0)
		return XDP_DROP;

	return leave_via(ctx, egress_ifindex);
}

// nat66_return_leg un-SNATs a reply whose transport view the caller has already
// resolved -- a TCP or UDP header, or an Echo Reply's Identifier -- back to the
// tenant backend's own view and re-encapsulates it. no_conn is the counter a
// reply matching no session lands on, which differs by protocol so an operator
// can tell a stale TCP flow from an unanswered ping.
static NAT_ALWAYS_INLINE int nat66_return_leg(struct xdp_md *ctx, struct shard_config *cfg,
					       struct nat_ip6hdr *ip6, struct l4_view *l4v, __u32 no_conn)
{
	struct conn_key rev_key;
	__builtin_memset(&rev_key, 0, sizeof(rev_key));
	rev_key.family = NAT_FAMILY_V6;
	rev_key.proto = ip6->nexthdr;
	__builtin_memcpy(rev_key.saddr, ip6->saddr, 16);
	rev_key.sport = l4v->sport;
	__builtin_memcpy(rev_key.daddr, ip6->daddr, 16);
	rev_key.dport = l4v->dport;

	struct conn_value *cv = bpf_map_lookup_elem(&nat_conn_table, &rev_key);
	if (!cv) {
		count_drop(no_conn);
		return XDP_DROP;
	}

	fix_l4_checksum(l4v->check_ptr, ip6->daddr, l4v->dport, cv->backend_addr, cv->backend_port);
	__builtin_memcpy(ip6->daddr, cv->backend_addr, 16);
	*l4v->dport_ptr = cv->backend_port;

	return reencap_to_tenant(ctx, cfg, ip6, cv->backend_usid);
}

// nat66_return: a reply from the IPv6 internet, addressed to this shard's own
// masquerade source. Un-SNATs back to the tenant backend's own view and
// re-encapsulates toward that backend's worker node via SRv6.
SEC("xdp")
int nat66_return(struct xdp_md *ctx)
{
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	struct nat_ethhdr *eth = data;
	if ((void *) (eth + 1) > data_end)
		return XDP_PASS;
	struct nat_ip6hdr *ip6 = (void *) (eth + 1);
	if ((void *) (ip6 + 1) > data_end)
		return XDP_PASS;

	__u32 cfg_key = 0;
	struct shard_config *cfg = bpf_map_lookup_elem(&shard_config_table, &cfg_key);
	if (!cfg)
		return XDP_PASS;

	if (ip6->nexthdr != NAT_IPPROTO_TCP && ip6->nexthdr != NAT_IPPROTO_UDP) {
		count_drop(DROP_REASON_NAT66_MALFORMED_RETURN);
		return XDP_DROP;
	}

	struct l4_view l4v;
	if (parse_l4(ip6->nexthdr, (void *) (ip6 + 1), data_end, &l4v) != 0) {
		count_drop(DROP_REASON_NAT66_MALFORMED_RETURN);
		return XDP_DROP;
	}

	return nat66_return_leg(ctx, cfg, ip6, &l4v, DROP_REASON_NAT66_NO_RETURN_CONN);
}

// nat66_icmp_error translates an ICMPv6 error about a packet this shard sent.
//
// The quoted packet is that packet as it left: shard_pub_addr6 and a masquerade
// port or Identifier toward the peer. Read with its two sides swapped, it is
// exactly the reverse row a direct reply would be looked up by, one header
// deeper. Because every reverse row's destination is shard_pub_addr6, an error
// quoting any other source matches nothing -- the check that this shard really
// sent the packet costs no instruction of its own.
//
// Three fields change, all under the one ICMPv6 checksum: the outer destination
// (in the pseudo-header), so the error reaches the tenant, and the quoted source
// address and port or Identifier, so the tenant's stack matches it to the socket
// that sent the packet. The quoted packet's own transport checksum is left
// stale: it covers bytes the quote may have truncated, and no receiver checks
// it. The error's type-specific word is untouched, so a Packet Too Big reaches
// the tenant with the MTU the path reported -- right as it stands, since the
// tenant's packet crossed the internet path decapsulated, at the size it sent.
static NAT_ALWAYS_INLINE int nat66_icmp_error(struct xdp_md *ctx, struct shard_config *cfg,
					       struct nat_ip6hdr *ip6, struct nat_icmphdr *icmp,
					       void *data_end)
{
	struct nat_ip6hdr *quoted = (void *) (icmp + 1);
	if ((void *) (quoted + 1) > data_end) {
		count_drop(DROP_REASON_NAT66_ICMP_MALFORMED);
		return XDP_DROP;
	}

	struct quoted_view q;
	int rc = parse_quoted(quoted->nexthdr, (void *) (quoted + 1), data_end, NAT_IPPROTO_ICMPV6,
			      NAT_ICMPV6_ECHO_REQUEST, &q);
	if (rc < 0) {
		count_drop(DROP_REASON_NAT66_ICMP_MALFORMED);
		return XDP_DROP;
	}
	if (rc > 0) {
		count_drop(DROP_REASON_NAT_ICMP_UNTRANSLATABLE);
		return XDP_DROP;
	}

	struct conn_key rev_key;
	__builtin_memset(&rev_key, 0, sizeof(rev_key));
	rev_key.family = NAT_FAMILY_V6;
	rev_key.proto = quoted->nexthdr;
	__builtin_memcpy(rev_key.saddr, quoted->daddr, 16);
	rev_key.sport = q.peer_port;
	__builtin_memcpy(rev_key.daddr, quoted->saddr, 16);
	rev_key.dport = q.masq;

	struct conn_value *cv = bpf_map_lookup_elem(&nat_conn_table, &rev_key);
	if (!cv) {
		count_drop(DROP_REASON_NAT66_ICMP_NO_CONN);
		return XDP_DROP;
	}

	// Two diffs rather than one: fix_l4_checksum pairs one address with one
	// port, and the outer destination has no port of its own. Passing zero for
	// both ports makes the first diff an address change alone.
	fix_l4_checksum(&icmp->check, ip6->daddr, 0, cv->backend_addr, 0);
	fix_l4_checksum(&icmp->check, quoted->saddr, q.masq, cv->backend_addr, cv->backend_port);
	__builtin_memcpy(ip6->daddr, cv->backend_addr, 16);
	__builtin_memcpy(quoted->saddr, cv->backend_addr, 16);
	*q.masq_ptr = cv->backend_port;

	return reencap_to_tenant(ctx, cfg, ip6, cv->backend_usid);
}

// echo_respond6 is echo_respond4 for shard_pub_addr6. Swapping the addresses
// leaves the ICMPv6 pseudo-header's sum unchanged, so the type is the only
// change the checksum has to account for.
static NAT_ALWAYS_INLINE int echo_respond6(struct xdp_md *ctx, struct shard_config *cfg,
					    struct nat_ethhdr *eth, struct nat_ip6hdr *ip6,
					    struct nat_icmphdr *icmp)
{
	if (!(cfg->flags & NAT_SHARD_FLAG_ECHO_RESPONDER)) {
		count_drop(DROP_REASON_NAT_ICMP_UNSOLICITED);
		return XDP_DROP;
	}
	if (!take_icmp_token()) {
		count_drop(DROP_REASON_NAT_ICMP_RATE_LIMITED);
		return XDP_DROP;
	}

	fix_icmp_type(icmp, NAT_ICMPV6_ECHO_REPLY);
	__u8 peer[16];
	__builtin_memcpy(peer, ip6->saddr, 16);
	__builtin_memcpy(ip6->saddr, ip6->daddr, 16);
	__builtin_memcpy(ip6->daddr, peer, 16);
	ip6->hop_limit = 64;

	__u8 self[16];
	__builtin_memcpy(self, ip6->saddr, 16);
	__u16 tot_len = (__u16) (NAT_IP6HDR_LEN + __builtin_bswap16(ip6->payload_len));
	__u32 egress_ifindex = 0;
	long fib_rc = resolve_fib_and_write_eth(ctx, ctx->ingress_ifindex, self, peer, tot_len, eth,
						 &egress_ifindex);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS) {
		count_fib_drop(fib_rc);
		return XDP_DROP;
	}
	return leave_via(ctx, egress_ifindex);
}

// nat66_icmp_return handles every ICMPv6 message addressed to shard_pub_addr6:
// an Echo Reply to a tenant's ping, an error about one of its flows, or
// something that is neither.
SEC("xdp")
int nat66_icmp_return(struct xdp_md *ctx)
{
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	struct nat_ethhdr *eth = data;
	if ((void *) (eth + 1) > data_end)
		return XDP_PASS;
	struct nat_ip6hdr *ip6 = (void *) (eth + 1);
	if ((void *) (ip6 + 1) > data_end)
		return XDP_PASS;

	__u32 cfg_key = 0;
	struct shard_config *cfg = bpf_map_lookup_elem(&shard_config_table, &cfg_key);
	if (!cfg)
		return XDP_PASS;

	struct nat_icmphdr *icmp = (void *) (ip6 + 1);
	if (ip6->nexthdr != NAT_IPPROTO_ICMPV6 || (void *) (icmp + 1) > data_end) {
		count_drop(DROP_REASON_NAT66_ICMP_MALFORMED);
		return XDP_DROP;
	}

	__u8 type = icmp->type;
	if (type == NAT_ICMPV6_ECHO_REPLY) {
		struct l4_view l4v;
		if (parse_echo(icmp, data_end, 0, &l4v) != 0) {
			count_drop(DROP_REASON_NAT66_ICMP_MALFORMED);
			return XDP_DROP;
		}
		return nat66_return_leg(ctx, cfg, ip6, &l4v, DROP_REASON_NAT66_ICMP_NO_CONN);
	}
	if (type >= NAT_ICMPV6_DEST_UNREACH && type <= NAT_ICMPV6_PARAM_PROBLEM)
		return nat66_icmp_error(ctx, cfg, ip6, icmp, data_end);

	// Neighbor Discovery is the kernel's. A masquerade address is normally a
	// routed /128 that no neighbour solicits, but where an operator has made one
	// on-link, dropping its Neighbor Solicitations would make the address
	// unreachable. The packet is untouched, so passing it keeps this program's
	// rule that nothing it has modified goes up.
	if (type >= NAT_ICMPV6_ND_FIRST && type <= NAT_ICMPV6_ND_LAST)
		return XDP_PASS;

	if (type == NAT_ICMPV6_ECHO_REQUEST)
		return echo_respond6(ctx, cfg, eth, ip6, icmp);

	count_drop(DROP_REASON_NAT_ICMP_UNTRANSLATABLE);
	return XDP_DROP;
}

// ---------------------------------------------------------------------
// NAT64: IPv6 tenant -> IPv4 internet (RFC 6146 stateful, RFC 7915 header
// translation).
// ---------------------------------------------------------------------

// nat64_forward processes a tenant's outbound packet whose destination sits
// inside the NAT64 prefix. It strips the SRv6 outer header, allocates or reuses
// a masquerade port against this shard's IPv4 address, rewrites the IPv6 header
// as IPv4, and resolves and transmits it exactly as the NAT66 forward path
// does -- for the same reason, and with the one difference that the packet
// leaving here is IPv4, so its FIB lookup is too.
//
// nat64_forward and nat64_icmp_forward are this one leg, specialized on icmp
// the way the NAT66 forward leg is. An ICMPv6 Echo Request leaves as an ICMPv4
// Echo, which changes its protocol number and its checksum's coverage as well
// as its header.
static NAT_ALWAYS_INLINE int nat64_forward_leg(struct xdp_md *ctx, const int icmp)
{
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	struct nat_ethhdr *eth = data;
	if ((void *) (eth + 1) > data_end)
		return XDP_PASS;
	struct nat_ip6hdr *outer = (void *) (eth + 1);
	if ((void *) (outer + 1) > data_end)
		return XDP_PASS;

	__u32 cfg_key = 0;
	struct shard_config *cfg = bpf_map_lookup_elem(&shard_config_table, &cfg_key);
	if (!cfg)
		return XDP_PASS;

	__u32 tenant_arg = read_argument(outer->daddr);

	// A shard advertising a NAT64 prefix it has no public IPv4 address to
	// translate into would otherwise fail as an unexplained forward-path drop.
	// Counting it per-tenant, distinctly from a limit refusal, is what makes
	// "this shard cannot serve you" separable from "you are over budget".
	if (cfg->shard_pub_addr4 == 0) {
		count_drop(DROP_REASON_NAT64_SHARD_UNAVAILABLE);
		return XDP_DROP;
	}

	__u8 tenant_usid[16];
	__builtin_memcpy(tenant_usid, outer->saddr, 16);

	const __u32 malformed = icmp ? DROP_REASON_NAT64_ICMP_MALFORMED : DROP_REASON_NAT64_MALFORMED_FORWARD;

	if (strip_outer_header(ctx, &eth) != 0) {
		count_drop(malformed);
		return XDP_DROP;
	}

	data_end = (void *) (long) ctx->data_end;
	struct nat_ip6hdr *inner = (void *) (eth + 1);
	if ((void *) (inner + 1) > data_end) {
		count_drop(malformed);
		return XDP_DROP;
	}

	struct l4_view l4v;
	if (icmp) {
		if (inner->nexthdr != NAT_IPPROTO_ICMPV6 ||
		    parse_echo((void *) (inner + 1), data_end, 1, &l4v) != 0) {
			count_drop(malformed);
			return XDP_DROP;
		}
		// The only ICMPv6 message a tenant opens a flow with; see the NAT66
		// forward leg.
		struct nat_icmphdr *echo = (void *) (inner + 1);
		if (echo->type != NAT_ICMPV6_ECHO_REQUEST) {
			count_drop(DROP_REASON_NAT_ICMP_UNTRANSLATABLE);
			return XDP_DROP;
		}
	} else {
		if (inner->nexthdr != NAT_IPPROTO_TCP && inner->nexthdr != NAT_IPPROTO_UDP) {
			count_drop(malformed);
			return XDP_DROP;
		}
		if (parse_l4(inner->nexthdr, (void *) (inner + 1), data_end, &l4v) != 0) {
			count_drop(malformed);
			return XDP_DROP;
		}
	}

	// Everything the rewritten IPv4 header needs, captured before the head
	// moves and invalidates every pointer above.
	__u8 saved_eth[sizeof(struct nat_ethhdr)];
	__builtin_memcpy(saved_eth, eth, sizeof(saved_eth));

	// Decremented here rather than on the IPv4 header below, which RFC 7915
	// section 5.1 allows either side of the translation, and which keeps the
	// check identical to the NAT66 leg's. See that leg on why the decrement is
	// this program's job at all, and on the ICMP error a router owes here.
	if (inner->hop_limit <= 1) {
		count_drop(DROP_REASON_NAT_HOP_LIMIT_EXCEEDED);
		return XDP_DROP;
	}

	// The forward row keeps the protocol the tenant sent; the reverse row and
	// the translated header carry the IPv4 one, because the reply this row
	// must match arrives as ICMPv4, not ICMPv6.
	__u8 proto = inner->nexthdr;
	const __u8 proto4 = icmp ? NAT_IPPROTO_ICMP : proto;
	__u8 hop_limit = (__u8) (inner->hop_limit - 1);
	__be16 payload_len = inner->payload_len;
	// Traffic Class spans the low nibble of vtc_flow[0] and the high nibble of
	// vtc_flow[1]; IPv4's TOS byte is exactly that field (RFC 7915 section 5.1).
	__u8 tos = (__u8) (((inner->vtc_flow[0] & 0x0F) << 4) | ((inner->vtc_flow[1] & 0xF0) >> 4));

	__u8 src6[16];
	__u8 dst6[16];
	__builtin_memcpy(src6, inner->saddr, 16);
	__builtin_memcpy(dst6, inner->daddr, 16);

	// RFC 6052: in a /96, the embedded IPv4 address is the last four bytes.
	__be32 dst4;
	__builtin_memcpy(&dst4, dst6 + 12, 4);

	__be16 sport = l4v.sport;
	__be16 dport = l4v.dport;

	struct conn_key fwd_key;
	__builtin_memset(&fwd_key, 0, sizeof(fwd_key));
	fwd_key.family = NAT_FAMILY_V4;
	fwd_key.proto = proto;
	fwd_key.tenant_arg = (__u16) tenant_arg;
	__builtin_memcpy(fwd_key.saddr, src6, 16);
	fwd_key.sport = sport;
	__builtin_memcpy(fwd_key.daddr, dst6, 16);
	fwd_key.dport = dport;
	__builtin_memcpy(fwd_key.encap_src, tenant_usid, 16);

	struct conn_value *existing = bpf_map_lookup_elem(&nat_conn_table, &fwd_key);
	struct conn_value cv;

	if (existing) {
		__builtin_memcpy(&cv, existing, sizeof(cv));
	} else {
		__builtin_memset(&cv, 0, sizeof(cv));
		__builtin_memcpy(cv.backend_addr, src6, 16);
		cv.backend_port = sport;
		// The synthesized IPv6 destination, not the embedded IPv4 address:
		// the return path rebuilds it verbatim as the reply's IPv6 source.
		__builtin_memcpy(cv.dest_addr, dst6, 16);
		cv.dest_port = dport;
		__builtin_memcpy(cv.backend_usid, tenant_usid, 16);
		cv.proto = proto;
		cv.family = NAT_FAMILY_V4;

		struct conn_key rev_key;
		__builtin_memset(&rev_key, 0, sizeof(rev_key));
		rev_key.family = NAT_FAMILY_V4;
		rev_key.proto = proto4;
		v4_mapped(rev_key.saddr, dst4);
		rev_key.sport = dport;
		v4_mapped(rev_key.daddr, cfg->shard_pub_addr4);

		__u32 base = fnv1a_flow(src6, sport) ^ (__u32) dport ^ tenant_arg;
		if (claim_masquerade_port(&rev_key, &cv, base) == 0) {
			count_drop(DROP_REASON_NAT64_PAT_EXHAUSTED);
			return XDP_DROP;
		}

		bpf_map_update_elem(&nat_conn_table, &fwd_key, &cv, BPF_ANY);
	}

	// Shrink the front by the 20 bytes an IPv4 header saves over an IPv6 one.
	// Every old offset drops by that amount, which puts the untouched L4 header
	// at exactly the offset a 14-byte Ethernet plus 20-byte IPv4 header ends at,
	// so nothing after the network header has to move.
	if (bpf_xdp_adjust_head(ctx, NAT_V6_V4_DELTA) != 0) {
		count_drop(DROP_REASON_NAT_ADJUST_HEAD_FAILED);
		return XDP_DROP;
	}

	data = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;
	if (data + sizeof(struct nat_ethhdr) + sizeof(struct nat_iphdr) > data_end) {
		count_drop(DROP_REASON_NAT_ADJUST_HEAD_FAILED);
		return XDP_DROP;
	}

	struct nat_ethhdr *new_eth = data;
	__builtin_memcpy(new_eth, saved_eth, sizeof(saved_eth));
	// Set here and again by the IPv4 resolver below, which cannot be reached
	// from every path: a packet dropped between the two still has to carry an
	// EtherType matching the header behind it.
	new_eth->h_proto = __builtin_bswap16(NAT_ETH_P_IP);

	struct nat_iphdr *ip4 = (void *) (new_eth + 1);
	ip4->version_ihl = 0x45;
	ip4->tos = tos;
	ip4->tot_len = __builtin_bswap16((__u16) (NAT_IP4HDR_LEN + __builtin_bswap16(payload_len)));
	ip4->id = 0;
	// DF set, offset zero. This translator does not fragment, and an unfragmented
	// datagram marked DF is what makes a too-large packet surface as a PTB from
	// the path rather than as silent truncation.
	ip4->frag_off = __builtin_bswap16(0x4000);
	// Already decremented, on the IPv6 hop limit this was read from.
	ip4->ttl = hop_limit;
	ip4->protocol = proto4;
	ip4->check = 0;
	ip4->saddr = cfg->shard_pub_addr4;
	ip4->daddr = dst4;
	ip4->check = ipv4_header_csum(ip4);

	struct l4_view out_l4v;
	if ((icmp ? parse_echo((void *) (ip4 + 1), data_end, 1, &out_l4v) :
		    parse_l4(proto, (void *) (ip4 + 1), data_end, &out_l4v)) != 0) {
		count_drop(malformed);
		return XDP_DROP;
	}

	// Each branch's pseudo-header images live only inside it: 72 bytes of this
	// program's 512-byte stack for TCP and UDP and 96 for ICMP, and the FIB
	// lookup below needs its own 64. Ending their lifetime explicitly is what
	// lets the compiler put them in the same slots instead of stacking them
	// and overflowing.
	if (icmp) {
		fix_echo_checksum_xlat(out_l4v.check_ptr, 1, src6, dst6, __builtin_bswap16(payload_len),
				       NAT_ICMPV6_ECHO_REQUEST, sport, NAT_ICMP_ECHO_REQUEST, cv.shard_port);
		struct nat_icmphdr *echo = (void *) (ip4 + 1);
		if ((void *) (echo + 1) > data_end) {
			count_drop(malformed);
			return XDP_DROP;
		}
		echo->type = NAT_ICMP_ECHO_REQUEST;
	} else {
		__be32 old_words[9];
		__be32 new_words[9];
		xlat_words6(old_words, src6, dst6, sport);
		xlat_words4(new_words, cfg->shard_pub_addr4, dst4, cv.shard_port);
		fix_l4_checksum_xlat(out_l4v.check_ptr, old_words, new_words);
	}
	udp_zero_checksum_fixup(proto, out_l4v.check_ptr);

	*out_l4v.sport_ptr = cv.shard_port;

	__u32 egress_ifindex = 0;
	long fib_rc = resolve_fib_and_write_eth4(ctx, ctx->ingress_ifindex, cfg->shard_pub_addr4, dst4,
						  (__u16) (NAT_IP4HDR_LEN + __builtin_bswap16(payload_len)),
						  new_eth, &egress_ifindex);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS) {
		count_fib_drop(fib_rc);
		return XDP_DROP;
	}

	return leave_via(ctx, egress_ifindex);
}

SEC("xdp")
int nat64_forward(struct xdp_md *ctx)
{
	return nat64_forward_leg(ctx, 0);
}

// nat64_icmp_forward: a tenant's outbound ICMPv6 Echo Request to a NAT64
// address, leaving as an ICMPv4 Echo with its Identifier masqueraded.
SEC("xdp")
int nat64_icmp_forward(struct xdp_md *ctx)
{
	return nat64_forward_leg(ctx, 1);
}

// nat64_v4_header_ok refuses, and counts, the IPv4 headers no NAT64 return leg
// translates.
//
// Options would move the L4 header off the fixed offset every bounds check
// assumes, and translating them has no IPv6 equivalent (RFC 7915 discards
// them). Fragment handling is an explicit non-goal for now (see this file's
// header comment). Both are counted rather than passed, since a silently
// forwarded untranslated packet is worse than a visible drop.
static NAT_ALWAYS_INLINE int nat64_v4_header_ok(struct nat_iphdr *ip4)
{
	if ((ip4->version_ihl & 0x0F) != NAT_IP4HDR_LEN / 4) {
		count_drop(DROP_REASON_NAT64_V4_OPTIONS);
		return 0;
	}
	if ((ip4->frag_off & __builtin_bswap16(0x3FFF)) != 0) {
		count_drop(DROP_REASON_NAT64_V4_FRAGMENT);
		return 0;
	}
	return 1;
}

// nat64_return_leg rewrites an IPv4 reply, whose transport view the caller has
// resolved, back to the IPv6 packet the tenant is expecting -- source being the
// synthesized NAT64 address it originally sent to -- and re-encapsulates it
// toward the tenant's worker node, the same last step nat66_return takes.
// Specialized on icmp like the forward leg: an ICMPv4 Echo Reply becomes an
// ICMPv6 one. no_conn is the counter a reply matching no session lands on.
static NAT_ALWAYS_INLINE int nat64_return_leg(struct xdp_md *ctx, struct shard_config *cfg,
					       struct nat_iphdr *ip4, struct l4_view *l4v,
					       __u32 no_conn, const int icmp)
{
	const __u32 malformed = icmp ? DROP_REASON_NAT64_ICMP_MALFORMED : DROP_REASON_NAT64_MALFORMED_RETURN;

	struct conn_key rev_key;
	__builtin_memset(&rev_key, 0, sizeof(rev_key));
	rev_key.family = NAT_FAMILY_V4;
	rev_key.proto = ip4->protocol;
	v4_mapped(rev_key.saddr, ip4->saddr);
	rev_key.sport = l4v->sport;
	v4_mapped(rev_key.daddr, ip4->daddr);
	rev_key.dport = l4v->dport;

	struct conn_value *found = bpf_map_lookup_elem(&nat_conn_table, &rev_key);
	if (!found) {
		count_drop(no_conn);
		return XDP_DROP;
	}

	struct conn_value cv;
	__builtin_memcpy(&cv, found, sizeof(cv));

	// The caller proved the header in bounds, but through its own pointer; the
	// verifier needs this one proven too before it is read.
	struct nat_ethhdr *eth = (void *) (long) ctx->data;
	if ((void *) (eth + 1) > (void *) (long) ctx->data_end)
		return XDP_DROP;
	__u8 saved_eth[sizeof(struct nat_ethhdr)];
	__builtin_memcpy(saved_eth, eth, sizeof(saved_eth));

	// The IPv6 next header is the protocol the tenant sent, which for an Echo
	// is ICMPv6, not the ICMPv4 this reply arrived as.
	__u8 proto = icmp ? NAT_IPPROTO_ICMPV6 : ip4->protocol;
	__u8 tos = ip4->tos;
	__u8 ttl = ip4->ttl;
	__be16 tot_len = ip4->tot_len;
	__be32 src4 = ip4->saddr;
	__be32 dst4 = ip4->daddr;
	__be16 dport = l4v->dport;

	__u16 l4_len = (__u16) (__builtin_bswap16(tot_len) - NAT_IP4HDR_LEN);

	// Grow the front by the 20 bytes an IPv6 header costs over an IPv4 one --
	// the exact inverse of the forward path's shrink.
	if (bpf_xdp_adjust_head(ctx, -NAT_V6_V4_DELTA) != 0) {
		count_drop(DROP_REASON_NAT_ADJUST_HEAD_FAILED);
		return XDP_DROP;
	}

	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	if (data + sizeof(struct nat_ethhdr) + sizeof(struct nat_ip6hdr) > data_end) {
		count_drop(DROP_REASON_NAT_ADJUST_HEAD_FAILED);
		return XDP_DROP;
	}

	struct nat_ethhdr *new_eth = data;
	__builtin_memcpy(new_eth, saved_eth, sizeof(saved_eth));
	new_eth->h_proto = __builtin_bswap16(NAT_ETH_P_IPV6);

	struct nat_ip6hdr *ip6 = (void *) (new_eth + 1);
	__builtin_memset(ip6->vtc_flow, 0, sizeof(ip6->vtc_flow));
	// Version 6 in the high nibble, then the IPv4 TOS byte split back across the
	// Traffic Class field's two nibbles.
	ip6->vtc_flow[0] = (__u8) (0x60 | (tos >> 4));
	ip6->vtc_flow[1] = (__u8) ((tos & 0x0F) << 4);
	ip6->payload_len = __builtin_bswap16(l4_len);
	ip6->nexthdr = proto;
	ip6->hop_limit = ttl;
	__builtin_memcpy(ip6->saddr, cv.dest_addr, 16);
	__builtin_memcpy(ip6->daddr, cv.backend_addr, 16);

	struct l4_view out_l4v;
	if ((icmp ? parse_echo((void *) (ip6 + 1), data_end, 0, &out_l4v) :
		    parse_l4(proto, (void *) (ip6 + 1), data_end, &out_l4v)) != 0) {
		count_drop(malformed);
		return XDP_DROP;
	}

	// The destination port, or Identifier, is what changes on the return leg:
	// the masquerade value this shard allocated goes back to the one the
	// tenant's socket is actually bound to.
	if (icmp) {
		fix_echo_checksum_xlat(out_l4v.check_ptr, 0, cv.dest_addr, cv.backend_addr, l4_len,
				       NAT_ICMPV6_ECHO_REPLY, cv.backend_port, NAT_ICMP_ECHO_REPLY, dport);
		struct nat_icmphdr *echo = (void *) (ip6 + 1);
		if ((void *) (echo + 1) > data_end) {
			count_drop(malformed);
			return XDP_DROP;
		}
		echo->type = NAT_ICMPV6_ECHO_REPLY;
	} else {
		__be32 old_words[9];
		__be32 new_words[9];
		xlat_words4(old_words, src4, dst4, dport);
		xlat_words6(new_words, cv.dest_addr, cv.backend_addr, cv.backend_port);
		fix_l4_checksum_xlat(out_l4v.check_ptr, old_words, new_words);
	}
	udp_zero_checksum_fixup(proto, out_l4v.check_ptr);

	*out_l4v.dport_ptr = cv.backend_port;

	__be16 inner_payload_len_plus_ip6hdr =
		__builtin_bswap16((__u16) (sizeof(struct nat_ip6hdr) + l4_len));

	__u32 egress_ifindex = 0;
	if (push_outer_header(ctx, cfg->shard_sid, cv.backend_usid, inner_payload_len_plus_ip6hdr,
			       &egress_ifindex) != 0)
		return XDP_DROP;

	return leave_via(ctx, egress_ifindex);
}

// nat64_return: a TCP or UDP reply from the IPv4 internet, addressed to this
// shard's own IPv4 masquerade source.
SEC("xdp")
int nat64_return(struct xdp_md *ctx)
{
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	struct nat_ethhdr *eth = data;
	if ((void *) (eth + 1) > data_end)
		return XDP_PASS;
	struct nat_iphdr *ip4 = (void *) (eth + 1);
	if ((void *) (ip4 + 1) > data_end)
		return XDP_PASS;

	__u32 cfg_key = 0;
	struct shard_config *cfg = bpf_map_lookup_elem(&shard_config_table, &cfg_key);
	if (!cfg)
		return XDP_PASS;

	if (!nat64_v4_header_ok(ip4))
		return XDP_DROP;
	if (ip4->protocol != NAT_IPPROTO_TCP && ip4->protocol != NAT_IPPROTO_UDP) {
		count_drop(DROP_REASON_NAT64_MALFORMED_RETURN);
		return XDP_DROP;
	}

	struct l4_view l4v;
	if (parse_l4(ip4->protocol, (void *) (ip4 + 1), data_end, &l4v) != 0) {
		count_drop(DROP_REASON_NAT64_MALFORMED_RETURN);
		return XDP_DROP;
	}

	return nat64_return_leg(ctx, cfg, ip4, &l4v, DROP_REASON_NAT64_NO_RETURN_CONN, 0);
}

// echo_respond4 answers an Echo Request addressed to shard_pub_addr4, when the
// operator has enabled the echo responder and this CPU's bucket can pay for it.
// The reply is built in place and leaves the way a forward leg does: this
// program resolves its own next hop and transmits from the driver.
static NAT_ALWAYS_INLINE int echo_respond4(struct xdp_md *ctx, struct shard_config *cfg,
					    struct nat_ethhdr *eth, struct nat_iphdr *ip4,
					    struct nat_icmphdr *icmp)
{
	if (!(cfg->flags & NAT_SHARD_FLAG_ECHO_RESPONDER)) {
		count_drop(DROP_REASON_NAT_ICMP_UNSOLICITED);
		return XDP_DROP;
	}
	if (!take_icmp_token()) {
		count_drop(DROP_REASON_NAT_ICMP_RATE_LIMITED);
		return XDP_DROP;
	}

	fix_icmp_type(icmp, NAT_ICMP_ECHO_REPLY);
	__be32 peer = ip4->saddr;
	ip4->saddr = ip4->daddr;
	ip4->daddr = peer;
	ip4->ttl = 64;
	ip4->check = 0;
	ip4->check = ipv4_header_csum(ip4);

	__u32 egress_ifindex = 0;
	long fib_rc = resolve_fib_and_write_eth4(ctx, ctx->ingress_ifindex, ip4->saddr, ip4->daddr,
						  __builtin_bswap16(ip4->tot_len), eth, &egress_ifindex);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS) {
		count_fib_drop(fib_rc);
		return XDP_DROP;
	}
	return leave_via(ctx, egress_ifindex);
}

// nat64_icmp_return handles every ICMPv4 message addressed to shard_pub_addr4:
// an Echo Reply to a tenant's ping, an Echo Request to the shard itself, or
// something this shard does not translate.
SEC("xdp")
int nat64_icmp_return(struct xdp_md *ctx)
{
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	struct nat_ethhdr *eth = data;
	if ((void *) (eth + 1) > data_end)
		return XDP_PASS;
	struct nat_iphdr *ip4 = (void *) (eth + 1);
	if ((void *) (ip4 + 1) > data_end)
		return XDP_PASS;

	__u32 cfg_key = 0;
	struct shard_config *cfg = bpf_map_lookup_elem(&shard_config_table, &cfg_key);
	if (!cfg)
		return XDP_PASS;

	if (!nat64_v4_header_ok(ip4))
		return XDP_DROP;

	struct nat_icmphdr *icmp = (void *) (ip4 + 1);
	if (ip4->protocol != NAT_IPPROTO_ICMP || (void *) (icmp + 1) > data_end) {
		count_drop(DROP_REASON_NAT64_ICMP_MALFORMED);
		return XDP_DROP;
	}

	__u8 type = icmp->type;
	if (type == NAT_ICMP_ECHO_REPLY) {
		struct l4_view l4v;
		if (parse_echo(icmp, data_end, 0, &l4v) != 0) {
			count_drop(DROP_REASON_NAT64_ICMP_MALFORMED);
			return XDP_DROP;
		}
		return nat64_return_leg(ctx, cfg, ip4, &l4v, DROP_REASON_NAT64_ICMP_NO_CONN, 1);
	}
	if (type == NAT_ICMP_ECHO_REQUEST)
		return echo_respond4(ctx, cfg, eth, ip4, icmp);

	count_drop(DROP_REASON_NAT_ICMP_UNTRANSLATABLE);
	return XDP_DROP;
}

// ---------------------------------------------------------------------
// Dispatcher.
// ---------------------------------------------------------------------

// nat_ingress is the only program attached to the uplink. It reads far enough
// to classify a packet and tail-calls the matching translation leaf. It never
// modifies the packet, so a tail call that cannot be made -- an unpopulated
// prog array during startup -- falls through to XDP_PASS with the packet
// untouched rather than half-translated.
SEC("xdp")
int nat_ingress(struct xdp_md *ctx)
{
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	struct nat_ethhdr *eth = data;
	if ((void *) (eth + 1) > data_end)
		return XDP_PASS;

	__u32 cfg_key = 0;
	struct shard_config *cfg = bpf_map_lookup_elem(&shard_config_table, &cfg_key);
	if (!cfg)
		return XDP_PASS;
	// An array map's lookup never misses, so an unconfigured shard reads its
	// all-zero row rather than NULL. Serving no family is what "not configured"
	// looks like, and it has to be tested here: a zero shard_sid still matches
	// every destination whose top 64 bits are zero.
	if (!cfg->serves_v6 && !cfg->serves_v4)
		return XDP_PASS; // not yet configured -- fail open, not claimed

	if (eth->h_proto == __builtin_bswap16(NAT_ETH_P_IPV6)) {
		struct nat_ip6hdr *ip6 = (void *) (eth + 1);
		if ((void *) (ip6 + 1) > data_end)
			return XDP_PASS;

		if (cfg->serves_v6 && addr6_eq(ip6->daddr, cfg->shard_pub_addr6)) {
			bpf_tail_call(ctx, &nat_progs, ip6->nexthdr == NAT_IPPROTO_ICMPV6 ?
						       NAT_PROG_NAT66_ICMP_RETURN : NAT_PROG_NAT66_RETURN);
			return XDP_PASS;
		}

		if (locator_matches(ip6->daddr, cfg->shard_sid) && ip6->nexthdr == NAT_IPPROTO_IPV6) {
			struct nat_ip6hdr *inner = (void *) (ip6 + 1);
			if ((void *) (inner + 1) > data_end) {
				count_drop(DROP_REASON_NAT66_MALFORMED_FORWARD);
				return XDP_DROP;
			}
			// The inner destination, not the outer one, decides the family.
			// A shard not serving IPv4 skips the prefix test entirely.
			if (cfg->serves_v4 && nat64_prefix_matches(inner->daddr, cfg->nat64_prefix)) {
				bpf_tail_call(ctx, &nat_progs, inner->nexthdr == NAT_IPPROTO_ICMPV6 ?
							       NAT_PROG_NAT64_ICMP_FORWARD : NAT_PROG_NAT64_FORWARD);
				return XDP_PASS;
			}
			bpf_tail_call(ctx, &nat_progs, inner->nexthdr == NAT_IPPROTO_ICMPV6 ?
						       NAT_PROG_NAT66_ICMP_FORWARD : NAT_PROG_NAT66_FORWARD);
			return XDP_PASS;
		}

		return XDP_PASS;
	}

	if (cfg->serves_v4 && eth->h_proto == __builtin_bswap16(NAT_ETH_P_IP)) {
		struct nat_iphdr *ip4 = (void *) (eth + 1);
		if ((void *) (ip4 + 1) > data_end)
			return XDP_PASS;
		if (cfg->shard_pub_addr4 != 0 && ip4->daddr == cfg->shard_pub_addr4) {
			bpf_tail_call(ctx, &nat_progs, ip4->protocol == NAT_IPPROTO_ICMP ?
						       NAT_PROG_NAT64_ICMP_RETURN : NAT_PROG_NAT64_RETURN);
			return XDP_PASS;
		}
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
