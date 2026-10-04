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
// it can wait on, and only the ICMP errors this program builds itself (see
// Scope). Each of the rest surfaces as a named drop counter instead.
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
//   nat64_icmp_return   IPv4 internet's ICMPv4 Echo -> tenant as ICMPv6
//   nat64_icmp_error    IPv4 internet's ICMPv4 errors -> tenant as ICMPv6
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
//     the family: inside nat64_prefix, or inside 64:ff9b::/96 when
//     NAT_SHARD_FLAG_WKP is set -> nat64_forward, otherwise nat66_forward;
//     or the _icmp_ leaf of the same family for an inner ICMPv6 packet.
//  4. IPv4 destination equal to shard_pub_addr4 is a reply from the IPv4
//     internet -> nat64_return; for ICMPv4, nat64_icmp_error for an error
//     type and nat64_icmp_return for anything else.
//  5. Anything else: XDP_PASS.
//
// Step 3 always reads the inner header, which the IPv6-only dispatch did not
// need to before ICMP: the inner next header picks the leaf.
//
// ---------------------------------------------------------------------
// Scope.
// ---------------------------------------------------------------------
//
// TCP, UDP, and ICMP, both families. Fragment handling (RFC 6146 section 3.4)
// is deliberately absent, not overlooked: it is a subsystem rather than a
// branch, tracked as its own follow-on. Its absence is counted, not silent --
// an IPv4 fragment or a packet carrying IPv4 options on the return path
// increments a named drop reason, so "NAT64 works except for X" is a readable
// counter rather than a support ticket.
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
// Echo and back, and translates the ICMPv4 errors the IPv4 internet sends
// about a tenant's flows into the ICMPv6 errors RFC 7915 section 4.2 maps them
// to, quoted packet included.
//
// The one error this shard sends on its own behalf is the one only it can: a
// reply that fits the internet path but not the fabric once re-encapsulated
// gets its sender a Packet Too Big, or a Fragmentation Needed over NAT64 (see
// send_too_big6). A tenant packet whose hop limit expires here is still
// dropped without a Time Exceeded, counted as hop_limit_exceeded.
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
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_delete_elem;
static long (*bpf_xdp_adjust_head)(void *ctx, int delta) = (void *) BPF_FUNC_xdp_adjust_head;
static __s64 (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size,
			       __wsum seed) = (void *) BPF_FUNC_csum_diff;
static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, __s32 plen,
			       __u32 flags) = (void *) BPF_FUNC_fib_lookup;
static long (*bpf_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *) BPF_FUNC_tail_call;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *) BPF_FUNC_redirect;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;
static long (*bpf_xdp_adjust_tail)(void *ctx, int delta) = (void *) BPF_FUNC_xdp_adjust_tail;

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
#define NAT_ICMP_DEST_UNREACH 3
#define NAT_ICMP_ECHO_REQUEST 8
#define NAT_ICMP_TIME_EXCEEDED 11
#define NAT_ICMP_PARAM_PROBLEM 12

// A translated ICMPv4 error has its front rebuilt: its own 8-byte header, the
// quoted packet's IPv6 header, and the first 8 bytes of the quoted transport
// header. Whatever the quote carries past those stays where it lies. See
// nat64_icmp_error.
#define NAT_QUOTED_L4_LEN 8
#define NAT_ICMP6_ERR_FRONT (8 + NAT_IP6HDR_LEN + NAT_QUOTED_L4_LEN)
// RFC 4443 section 2.4(c): an ICMPv6 error never makes its packet larger than
// the IPv6 minimum MTU. Beyond that, the quote is cut to the rebuilt front.
#define NAT_ICMP6_ERR_MAX (1280 - NAT_IP6HDR_LEN)

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

// Session idle timeouts, in seconds. A session expires once its reverse row has
// gone this long without a translated packet in either direction; see
// session_expired.
//
//   UDP              120  RFC 4787 REQ-5's floor (RFC 6146 UDP_MIN). The
//                         recommended 300 would hold a busy shard's table
//                         full of finished flows.
//   UDP, port 53      30  REQ-5a allows a shorter timer for a well-known
//                         port. A DNS exchange is one query and one answer,
//                         and a stub resolver gives up on it within a few
//                         5-second retries, so a row older than that only
//                         holds a port.
//   TCP established 7440  RFC 5382 REQ-5, RFC 6146 TCP_EST: 2h04m.
//   TCP transitory   240  RFC 5382 REQ-5, RFC 6146 TCP_TRANS: a session
//                         the peer has not answered yet, or one either side
//                         has sent FIN or RST on.
//   ICMP Echo         60  RFC 5508 REQ-2, RFC 6146 ICMP_TIMEOUT.
#define NAT_TIMEOUT_UDP 120
#define NAT_TIMEOUT_UDP_DNS 30
#define NAT_TIMEOUT_TCP_EST 7440
#define NAT_TIMEOUT_TCP_TRANS 240
#define NAT_TIMEOUT_ICMP 60
#define NAT_DNS_PORT 53

// conn_value.state bits, meaningful on a TCP session's reverse row.
#define NAT_SESS_TCP_EST 0x1
#define NAT_SESS_TCP_CLOSING 0x2

#define NAT_TCP_FIN 0x01
#define NAT_TCP_RST 0x04
#define NAT_TCP_ACK 0x10

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
#define NAT_PROG_NAT64_ICMP_ERROR 8
#define NAT_PROG_COUNT 9

// shard_config.flags bits.
//
// ECHO_RESPONDER makes the shard answer an Echo Request addressed to one of its
// own masquerade addresses, which it otherwise drops as unsolicited. Off unless
// an operator turns it on (GALACTIC_NAT_ECHO_RESPONDER): an internet-facing
// address that answers pings is a policy choice, not a default.
#define NAT_SHARD_FLAG_ECHO_RESPONDER 0x1
// WKP additionally translates the RFC 6052 Well-Known Prefix 64:ff9b::/96
// alongside nat64_prefix. Meaningful only with serves_v4.
#define NAT_SHARD_FLAG_WKP 0x2

// The ICMP this shard emits on its own behalf -- echo-responder replies, and
// the Packet Too Big and Fragmentation Needed it sends a sender whose reply
// the fabric cannot carry -- is limited by one token bucket per CPU: NAT_ICMP_RATE messages a second with a
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
// tenant originally sent to (whichever prefix it used plus the peer's IPv4
// address), not the peer's IPv4 address alone. The return path needs it
// verbatim as the IPv6 source it rebuilds toward the tenant: a reply whose
// source is anything else does not match the socket the tenant opened.
//
// The value holds every field of the forward key -- tenant_arg is here for
// that alone -- so a reverse row names its forward row. proto is the tenant's
// protocol, ICMPv6 for a NAT64 Echo whose reverse key holds ICMP.
//
// last_seen (seconds of the monotonic clock) and state are the session's, and
// only the reverse row's copy is kept current; a forward row's records when it
// was written.
struct conn_value {
	__u8 backend_addr[16];
	__be16 backend_port;
	__u8 dest_addr[16];
	__be16 dest_port;
	__be16 shard_port;
	__u8 backend_usid[16];
	__u8 proto;
	__u8 family;
	__u16 tenant_arg;
	__u8 state; // NAT_SESS_*
	__u8 pad;
	__u32 last_seen;
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
	// A tenant packet, Echo included, whose NAT64 destination embeds a
	// non-global IPv4 address (see v4_non_global).
	DROP_REASON_NAT64_NON_GLOBAL_DEST    = 26,
	DROP_REASON_NAT_COUNT                = 27,
};

// ---------------------------------------------------------------------
// Maps.
// ---------------------------------------------------------------------

// nat_conn_table holds every session this shard translates, ICMP included, as
// a forward row and a reverse row.
//
// A session expires after its protocol's idle timeout (NAT_TIMEOUT_*), with no
// sweeper: the reverse row carries the session's last_seen, which a translated
// packet in either direction refreshes, and every path that finds a row asks
// whether it has expired. An expired session translates nothing, its forward
// row is replaced by a fresh claim on the tenant's next packet, and its port is
// taken back by the first claim that collides with it (claim_masquerade_port).
// Until then it holds its slots, and the LRU still evicts under pressure.
//
// The LRU evicts each row on its own, so a session can lose one half. A forward
// row whose reverse row is gone, or names another session, is replaced by a
// fresh claim on the next packet. A reverse row whose forward row is gone keeps
// translating replies until it expires, and a claim for the same flow adopts
// it rather than leave its port held. A forward row left behind by a session
// that never sends again waits for the LRU; it holds no port.
//
// ICMP Echo rows share the table, and its 65536-entry LRU, with TCP and UDP
// rather than living in a map of their own. That is a deliberate trade: a burst
// of tenant pings to many destinations can evict live TCP and UDP sessions,
// whose next reply then counts as no_return_conn. It is accepted because a
// tenant pinging at a rate that churns the table would churn it just as hard
// with UDP, and a second map would split one capacity budget into two that
// have to be sized separately. If the trade ever stops holding, ICMP rows move
// to a separate, smaller LRU, and only the ICMP leaves change.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, struct conn_value);
} nat_conn_table SEC(".maps");

// struct session_scratch is a forward leg's session working set: the flow's
// two keys, the value a new session is written with, and the forward key
// release_session rebuilds from a reverse row. The NAT64 forward legs'
// translation already held 496 of their 512 stack bytes without it.
struct session_scratch {
	struct conn_key fwd;
	struct conn_key rev;
	struct conn_key victim;
	struct conn_value cv;
};

// nat_scratch is one session_scratch per CPU. A leg runs to completion on its
// CPU, so nothing else touches the entry while it is in use.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct session_scratch);
} nat_scratch SEC(".maps");

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

// wkp_matches tests an address against the RFC 6052 Well-Known Prefix,
// 64:ff9b::/96.
static NAT_ALWAYS_INLINE int wkp_matches(const __u8 addr[16])
{
	if (addr[0] != 0x00 || addr[1] != 0x64 || addr[2] != 0xff || addr[3] != 0x9b)
		return 0;
	for (int i = 4; i < 12; i++) {
		if (addr[i] != 0)
			return 0;
	}
	return 1;
}

// v4_non_global reports whether an IPv4 address, as its four wire-order bytes,
// falls in a block the IANA IPv4 Special-Purpose Address Registry marks not
// globally reachable, or in multicast or reserved space. RFC 6052 section 3.1
// forbids the Well-Known Prefix from carrying such an address; a NAT64 shard
// refuses them under any prefix. 192.0.0.0/24 is refused whole, including the
// two anycast /32s inside it the registry lists as global.
static NAT_ALWAYS_INLINE int v4_non_global(const __u8 a[4])
{
	__u8 o0 = a[0], o1 = a[1], o2 = a[2];

	if (o0 == 0 || o0 == 10 || o0 == 127 || o0 >= 224)
		return 1;
	if (o0 == 100)
		return (o1 & 0xC0) == 64;
	if (o0 == 169)
		return o1 == 254;
	if (o0 == 172)
		return (o1 & 0xF0) == 16;
	if (o0 == 192)
		return (o1 == 0 && (o2 == 0 || o2 == 2)) || (o1 == 88 && o2 == 99) || o1 == 168;
	if (o0 == 198)
		return (o1 & 0xFE) == 18 || (o1 == 51 && o2 == 100);
	if (o0 == 203)
		return o1 == 0 && o2 == 113;
	return 0;
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
	__u8 tcp_flags; // zero for anything but TCP
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
		out->tcp_flags = tcp->flags;
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
		out->tcp_flags = 0;
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
	out->tcp_flags = 0;
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
//
// A lookup refused for size reports the route's MTU through frag_mtu, when the
// caller passes one: the return legs answer that refusal rather than only
// counting it.
static NAT_ALWAYS_INLINE long resolve_fib_and_write_eth(void *ctx, __u32 ifindex, const __u8 src[16],
							 const __u8 dst[16], __u16 tot_len,
							 struct nat_ethhdr *eth, __u32 *egress_ifindex,
							 __u16 *frag_mtu)
{
	struct bpf_fib_lookup fib_params;
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.family = NAT_AF_INET6;
	__builtin_memcpy(&fib_params.ipv6_src, src, 16);
	__builtin_memcpy(&fib_params.ipv6_dst, dst, 16);
	fib_params.ifindex = ifindex;
	fib_params.tot_len = tot_len;

	long fib_rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
	if (fib_rc == BPF_FIB_LKUP_RET_FRAG_NEEDED && frag_mtu)
		*frag_mtu = fib_params.mtu_result;
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
//
// A packet the encapsulated route is too small for still counts as
// fib_frag_needed here, and also reports that route's MTU through frag_mtu so
// the caller can tell the sender.
static NAT_ALWAYS_INLINE int push_outer_header(struct xdp_md *ctx, const __u8 src[16], const __u8 dst[16],
						__be16 inner_payload_len_plus_ip6hdr,
						__u32 *egress_ifindex, __u16 *frag_mtu)
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
						 eth, egress_ifindex, frag_mtu);
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

// now_sec reads the monotonic clock in whole seconds, the unit last_seen and
// every idle timeout are kept in.
static NAT_ALWAYS_INLINE __u32 now_sec(void)
{
	return (__u32) (bpf_ktime_get_ns() / 1000000000ULL);
}

static NAT_ALWAYS_INLINE __u32 session_timeout(const struct conn_value *v)
{
	if (v->proto == NAT_IPPROTO_TCP)
		return (v->state & (NAT_SESS_TCP_EST | NAT_SESS_TCP_CLOSING)) == NAT_SESS_TCP_EST ?
			       NAT_TIMEOUT_TCP_EST : NAT_TIMEOUT_TCP_TRANS;
	if (v->proto == NAT_IPPROTO_UDP)
		return v->dest_port == __builtin_bswap16(NAT_DNS_PORT) ? NAT_TIMEOUT_UDP_DNS : NAT_TIMEOUT_UDP;
	return NAT_TIMEOUT_ICMP;
}

// session_expired asks the question of a reverse row. The subtraction wraps,
// so a stamp from before the clock's last 32-bit wrap still reads as its true
// age.
static NAT_ALWAYS_INLINE int session_expired(const struct conn_value *v, __u32 now)
{
	return (__u32) (now - v->last_seen) > session_timeout(v);
}

// touch_session refreshes a reverse row for a packet translated through it,
// and moves a TCP session between transitory and established: established
// once the peer has answered, transitory again for good once either side sends
// FIN or RST. Writes are skipped when nothing changes, so a busy session's row
// is written about once a second rather than once a packet.
static NAT_ALWAYS_INLINE void touch_session(struct conn_value *v, __u32 now, __u8 tcp_flags, const int inbound)
{
	if (v->last_seen != now)
		v->last_seen = now;
	if (v->proto != NAT_IPPROTO_TCP)
		return;
	__u8 state = v->state;
	if (tcp_flags & (NAT_TCP_FIN | NAT_TCP_RST))
		state |= NAT_SESS_TCP_CLOSING;
	else if (inbound && (tcp_flags & NAT_TCP_ACK))
		state |= NAT_SESS_TCP_EST;
	if (state != v->state)
		v->state = state;
}

// owns_session reports whether a reverse row belongs to the flow fwd_key names.
// The reverse key already pins the peer and the protocol, so the tenant side is
// all that is left to compare.
static NAT_ALWAYS_INLINE int owns_session(const struct conn_value *v, const struct conn_key *fwd_key)
{
	if (v->backend_port != fwd_key->sport || v->tenant_arg != fwd_key->tenant_arg)
		return 0;
	return addr6_eq(v->backend_addr, fwd_key->saddr) && addr6_eq(v->backend_usid, fwd_key->encap_src);
}

// release_session deletes an expired session: the reverse row at rev_key, and
// the forward row its value names, if that forward row still points here. One
// that has since moved to another port belongs to a newer session of the same
// flow and is left alone.
//
// Two CPUs can release the same session at once, and the second's delete can
// then remove the reverse row the first just claimed in its place. That first
// session's forward row is left naming a port it no longer holds, which its
// next packet notices and replaces with a fresh claim.
static NAT_ALWAYS_INLINE void release_session(struct conn_key *rev_key, const struct conn_value *v,
						struct conn_key *fwd)
{
	__builtin_memset(fwd, 0, sizeof(*fwd));
	fwd->family = v->family;
	fwd->proto = v->proto;
	fwd->tenant_arg = v->tenant_arg;
	__builtin_memcpy(fwd->saddr, v->backend_addr, 16);
	fwd->sport = v->backend_port;
	__builtin_memcpy(fwd->daddr, v->dest_addr, 16);
	fwd->dport = v->dest_port;
	__builtin_memcpy(fwd->encap_src, v->backend_usid, 16);
	struct conn_value *f = bpf_map_lookup_elem(&nat_conn_table, fwd);
	if (f && f->shard_port == rev_key->dport)
		bpf_map_delete_elem(&nat_conn_table, fwd);
	bpf_map_delete_elem(&nat_conn_table, rev_key);
}

// claim_masquerade_port probes for a free (shard address, port) pair for a new
// flow and installs the reverse row under it, returning the claimed port in
// network order or 0 when every probe collided with a live session.
//
// Installing the reverse row *is* the claim: BPF_NOEXIST makes the map itself
// the allocator, so two CPUs racing for the same candidate cannot both win. The
// forward row is written by the caller afterward.
//
// A candidate held by an expired session is released and claimed. One held by
// a live session of this same flow, whose forward row was lost, is adopted:
// its port is returned and the caller writes a forward row back for it.
//
// rev_key is mutated in place rather than copied per probe; the caller owns
// the key and has no use for it after this returns. Its dport is left holding
// whichever candidate was tried last. The loop is not unrolled: the release
// path would be copied into every probe.
static NAT_ALWAYS_INLINE __be16 claim_masquerade_port(struct session_scratch *ss, __u32 hash_base, __u32 now)
{
	struct conn_key *rev_key = &ss->rev;
	struct conn_value *cv = &ss->cv;

	#pragma clang loop unroll(disable)
	for (int i = 0; i < NAT_PAT_PROBE_LIMIT; i++) {
		__u16 candidate = NAT_PAT_PORT_BASE + ((hash_base + (__u32) i) % NAT_PAT_PORT_RANGE);
		__be16 port = __builtin_bswap16(candidate);

		rev_key->dport = port;
		cv->shard_port = port;

		if (bpf_map_update_elem(&nat_conn_table, rev_key, cv, BPF_NOEXIST) == 0)
			return port;

		struct conn_value *held = bpf_map_lookup_elem(&nat_conn_table, rev_key);
		if (!held)
			continue;
		if (!session_expired(held, now)) {
			if (!owns_session(held, &ss->fwd))
				continue;
			if (held->last_seen != now)
				held->last_seen = now;
			return port;
		}
		release_session(rev_key, held, &ss->victim);
		if (bpf_map_update_elem(&nat_conn_table, rev_key, cv, BPF_NOEXIST) == 0)
			return port;
	}
	return 0;
}

// session_port returns the masquerade port a tenant's outbound packet leaves
// with, claiming one for a new session, or 0 when none is free. ss arrives with
// fwd filled in, and rev with every field but dport.
//
// The reverse row decides whether a forward row is still live, which costs a
// second lookup per packet: a forward row whose reverse row expired, was
// evicted, or now names another flow is replaced by a fresh claim rather than
// sending traffic whose replies have nowhere to go.
static NAT_ALWAYS_INLINE __be16 session_port(struct session_scratch *ss, __u32 hash_base, __u8 tcp_flags)
{
	__u32 now = now_sec();
	const struct conn_key *fwd_key = &ss->fwd;

	struct conn_value *existing = bpf_map_lookup_elem(&nat_conn_table, fwd_key);
	if (existing) {
		ss->rev.dport = existing->shard_port;
		struct conn_value *rv = bpf_map_lookup_elem(&nat_conn_table, &ss->rev);
		if (rv && owns_session(rv, fwd_key) && !session_expired(rv, now)) {
			touch_session(rv, now, tcp_flags, 0);
			return ss->rev.dport;
		}
	}

	struct conn_value *cv = &ss->cv;
	__builtin_memset(cv, 0, sizeof(*cv));
	__builtin_memcpy(cv->backend_addr, fwd_key->saddr, 16);
	cv->backend_port = fwd_key->sport;
	__builtin_memcpy(cv->dest_addr, fwd_key->daddr, 16);
	cv->dest_port = fwd_key->dport;
	__builtin_memcpy(cv->backend_usid, fwd_key->encap_src, 16); // the tenant's own worker-node uSID
	cv->proto = fwd_key->proto;
	cv->family = fwd_key->family;
	cv->tenant_arg = fwd_key->tenant_arg;
	cv->last_seen = now;
	if (tcp_flags & (NAT_TCP_FIN | NAT_TCP_RST))
		cv->state = NAT_SESS_TCP_CLOSING;

	__be16 port = claim_masquerade_port(ss, hash_base, now);
	if (port)
		bpf_map_update_elem(&nat_conn_table, fwd_key, cv, BPF_ANY);
	return port;
}

// session_scratch_get returns this CPU's session_scratch, which an array map
// always has; the null check is for the verifier.
static NAT_ALWAYS_INLINE struct session_scratch *session_scratch_get(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&nat_scratch, &zero);
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

	// Unreachable for an array map, and counted as exhaustion if it ever is not.
	struct session_scratch *ss = session_scratch_get();
	if (!ss) {
		count_drop(DROP_REASON_NAT66_PAT_EXHAUSTED);
		return XDP_DROP;
	}
	struct conn_key *fwd_key = &ss->fwd;
	__builtin_memset(fwd_key, 0, sizeof(*fwd_key));
	fwd_key->family = NAT_FAMILY_V6;
	fwd_key->proto = inner->nexthdr;
	fwd_key->tenant_arg = (__u16) tenant_arg;
	__builtin_memcpy(fwd_key->saddr, inner->saddr, 16);
	fwd_key->sport = l4v.sport;
	__builtin_memcpy(fwd_key->daddr, inner->daddr, 16);
	fwd_key->dport = l4v.dport;
	__builtin_memcpy(fwd_key->encap_src, tenant_usid, 16);

	struct conn_key *rev_key = &ss->rev;
	__builtin_memset(rev_key, 0, sizeof(*rev_key));
	rev_key->family = NAT_FAMILY_V6;
	rev_key->proto = inner->nexthdr;
	__builtin_memcpy(rev_key->saddr, inner->daddr, 16);
	rev_key->sport = l4v.dport;
	__builtin_memcpy(rev_key->daddr, cfg->shard_pub_addr6, 16);

	__u32 base = fnv1a_flow(inner->saddr, l4v.sport) ^ (__u32) l4v.dport ^ tenant_arg;
	__be16 shard_port = session_port(ss, base, l4v.tcp_flags);
	if (shard_port == 0) {
		count_drop(DROP_REASON_NAT66_PAT_EXHAUSTED);
		return XDP_DROP;
	}

	fix_l4_checksum(l4v.check_ptr, inner->saddr, l4v.sport, cfg->shard_pub_addr6, shard_port);
	__builtin_memcpy(inner->saddr, cfg->shard_pub_addr6, 16);
	*l4v.sport_ptr = shard_port;

	// Resolved from the translated source, not the tenant's: the reply has to
	// come back to this shard's own masquerade address, and a route selected
	// for any other source may leave over a different interface entirely.
	__u8 dst_addr[16];
	__builtin_memcpy(dst_addr, inner->daddr, 16);
	__u16 tot_len = (__u16) (NAT_IP6HDR_LEN + __builtin_bswap16(inner->payload_len));

	__u32 egress_ifindex = 0;
	long fib_rc = resolve_fib_and_write_eth(ctx, ctx->ingress_ifindex, cfg->shard_pub_addr6,
						 dst_addr, tot_len, eth, &egress_ifindex, 0);
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

// ---------------------------------------------------------------------
// Errors this shard sends on its own behalf.
// ---------------------------------------------------------------------
//
// A reply from the internet that fits the internet path can still be too big
// for the fabric once the shard re-encapsulates it: 40 bytes bigger, or 60 for
// NAT64, whose translation adds 20 more. The fabric's MSS clamp keeps TCP below
// that; anything else used to be dropped at the shard with its sender never
// told. These two answer it the way a router would, with the error a path MTU
// discovery implementation reads: a Packet Too Big to an IPv6 sender, a
// Fragmentation Needed to an IPv4 one.
//
// The MTU reported is the encapsulated route's, less what the shard adds, so
// the sender's next packet fits once wrapped. The quote is the offending packet
// as the sender sent it -- captured before translation, since by the time the
// route refuses it, it no longer is -- cut to its IP header and first 8
// transport bytes: all RFC 792 guarantees and all a sender's stack matches an
// error on. Each message draws on icmp_rate_bucket, and none is sent about an
// ICMP error; the callers translating errors pass no quote.

// NAT_FRAG_QUOTE6/4 are the quoted bytes each error carries: an IP header and
// the first 8 transport bytes.
#define NAT_FRAG_QUOTE6 (NAT_IP6HDR_LEN + 8)
#define NAT_FRAG_QUOTE4 (NAT_IP4HDR_LEN + 8)

// send_too_big6 rewrites the frame, whatever it holds, into an ICMPv6 Packet
// Too Big from shard_pub_addr6 to the sender of quote, and transmits it.
static NAT_ALWAYS_INLINE int send_too_big6(struct xdp_md *ctx, struct shard_config *cfg,
					    const __be32 quote[NAT_FRAG_QUOTE6 / 4], __u32 mtu)
{
	if (!take_icmp_token()) {
		count_drop(DROP_REASON_NAT_ICMP_RATE_LIMITED);
		return XDP_DROP;
	}

	__be32 msg[(8 + NAT_FRAG_QUOTE6) / 4];
	__builtin_memset(msg, 0, 8);
	((__u8 *) msg)[0] = NAT_ICMPV6_PACKET_TOO_BIG;
	msg[1] = __builtin_bswap32(mtu);
	__builtin_memcpy(&msg[2], quote, NAT_FRAG_QUOTE6);

	// The sender is the quoted packet's source.
	__u8 peer[16];
	__builtin_memcpy(peer, &((const __u8 *) quote)[8], 16);
	__u8 self[16];
	__builtin_memcpy(self, cfg->shard_pub_addr6, 16);

	{
		__be32 pseudo[10];
		__builtin_memcpy(&pseudo[0], self, 16);
		__builtin_memcpy(&pseudo[4], peer, 16);
		pseudo[8] = __builtin_bswap32(sizeof(msg));
		pseudo[9] = __builtin_bswap32(NAT_IPPROTO_ICMPV6);
		__s64 sum = bpf_csum_diff(0, 0, pseudo, sizeof(pseudo), 0);
		sum = bpf_csum_diff(0, 0, msg, sizeof(msg), (__wsum) sum);
		__be16 check = csum_fold_add(0xFFFF, sum);
		__builtin_memcpy(&((__u8 *) msg)[2], &check, 2);
	}

	int cur = (int) ((long) ctx->data_end - (long) ctx->data);
	int want = (int) (sizeof(struct nat_ethhdr) + NAT_IP6HDR_LEN + sizeof(msg));
	if (bpf_xdp_adjust_tail(ctx, want - cur) != 0) {
		count_drop(DROP_REASON_NAT_ADJUST_HEAD_FAILED);
		return XDP_DROP;
	}
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	if (data + sizeof(struct nat_ethhdr) + NAT_IP6HDR_LEN + sizeof(msg) > data_end) {
		count_drop(DROP_REASON_NAT_ADJUST_HEAD_FAILED);
		return XDP_DROP;
	}

	struct nat_ethhdr *eth = data;
	eth->h_proto = __builtin_bswap16(NAT_ETH_P_IPV6);
	struct nat_ip6hdr *ip6 = (void *) (eth + 1);
	__builtin_memset(ip6->vtc_flow, 0, sizeof(ip6->vtc_flow));
	ip6->vtc_flow[0] = 0x60;
	ip6->payload_len = __builtin_bswap16(sizeof(msg));
	ip6->nexthdr = NAT_IPPROTO_ICMPV6;
	ip6->hop_limit = 64;
	__builtin_memcpy(ip6->saddr, self, 16);
	__builtin_memcpy(ip6->daddr, peer, 16);
	__builtin_memcpy((void *) (ip6 + 1), msg, sizeof(msg));

	__u32 egress_ifindex = 0;
	long fib_rc = resolve_fib_and_write_eth(ctx, ctx->ingress_ifindex, self, peer,
						 (__u16) (NAT_IP6HDR_LEN + sizeof(msg)), eth, &egress_ifindex, 0);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS) {
		count_fib_drop(fib_rc);
		return XDP_DROP;
	}
	return leave_via(ctx, egress_ifindex);
}

// send_frag_needed4 is send_too_big6 for an IPv4 sender: an ICMPv4
// Fragmentation Needed from shard_pub_addr4, the next-hop MTU in the low half
// of its word (RFC 1191).
static NAT_ALWAYS_INLINE int send_frag_needed4(struct xdp_md *ctx, struct shard_config *cfg,
						const __be32 quote[NAT_FRAG_QUOTE4 / 4], __u32 mtu)
{
	if (!take_icmp_token()) {
		count_drop(DROP_REASON_NAT_ICMP_RATE_LIMITED);
		return XDP_DROP;
	}

	__be32 msg[(8 + NAT_FRAG_QUOTE4) / 4];
	__builtin_memset(msg, 0, 8);
	((__u8 *) msg)[0] = NAT_ICMP_DEST_UNREACH;
	((__u8 *) msg)[1] = 4; // fragmentation needed and DF set
	msg[1] = __builtin_bswap32(mtu & 0xFFFF);
	__builtin_memcpy(&msg[2], quote, NAT_FRAG_QUOTE4);
	{
		__s64 sum = bpf_csum_diff(0, 0, msg, sizeof(msg), 0);
		__be16 check = csum_fold_add(0xFFFF, sum);
		__builtin_memcpy(&((__u8 *) msg)[2], &check, 2);
	}

	// The sender is the quoted packet's source.
	__be32 peer = quote[3];
	__be32 self = cfg->shard_pub_addr4;

	int cur = (int) ((long) ctx->data_end - (long) ctx->data);
	int want = (int) (sizeof(struct nat_ethhdr) + NAT_IP4HDR_LEN + sizeof(msg));
	if (bpf_xdp_adjust_tail(ctx, want - cur) != 0) {
		count_drop(DROP_REASON_NAT_ADJUST_HEAD_FAILED);
		return XDP_DROP;
	}
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;
	if (data + sizeof(struct nat_ethhdr) + NAT_IP4HDR_LEN + sizeof(msg) > data_end) {
		count_drop(DROP_REASON_NAT_ADJUST_HEAD_FAILED);
		return XDP_DROP;
	}

	struct nat_ethhdr *eth = data;
	eth->h_proto = __builtin_bswap16(NAT_ETH_P_IP);
	struct nat_iphdr *ip4 = (void *) (eth + 1);
	ip4->version_ihl = 0x45;
	ip4->tos = 0;
	ip4->tot_len = __builtin_bswap16(NAT_IP4HDR_LEN + sizeof(msg));
	ip4->id = 0;
	ip4->frag_off = 0;
	ip4->ttl = 64;
	ip4->protocol = NAT_IPPROTO_ICMP;
	ip4->check = 0;
	ip4->saddr = self;
	ip4->daddr = peer;
	ip4->check = ipv4_header_csum(ip4);
	__builtin_memcpy((void *) (ip4 + 1), msg, sizeof(msg));

	__u32 egress_ifindex = 0;
	long fib_rc = resolve_fib_and_write_eth4(ctx, ctx->ingress_ifindex, self, peer,
						  (__u16) (NAT_IP4HDR_LEN + sizeof(msg)), eth, &egress_ifindex);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS) {
		count_fib_drop(fib_rc);
		return XDP_DROP;
	}
	return leave_via(ctx, egress_ifindex);
}

// reencap_to_tenant is the last step every NAT66 return leg shares: push the
// SRv6 outer header toward the tenant's worker node and transmit. ip6 is the
// already-rewritten packet, read here only for its length before the head moves.
//
// quote is the packet as its sender sent it, for a Packet Too Big should the
// fabric be too small for it once encapsulated, or null where none may be sent:
// a translated ICMP error is never answered with another.
static NAT_ALWAYS_INLINE int reencap_to_tenant(struct xdp_md *ctx, struct shard_config *cfg,
						struct nat_ip6hdr *ip6, const __u8 usid[16],
						const __be32 *quote)
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
	__u16 frag_mtu = 0;
	if (push_outer_header(ctx, cfg->shard_sid, backend_usid, inner_payload_len_plus_ip6hdr,
			       &egress_ifindex, &frag_mtu) != 0) {
		if (quote && frag_mtu > NAT_IP6HDR_LEN)
			return send_too_big6(ctx, cfg, quote, frag_mtu - NAT_IP6HDR_LEN);
		return XDP_DROP;
	}

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

	// An expired session translates nothing: its mapping is gone, and an
	// inbound packet with no mapping is filtered (RFC 4787 section 5, RFC 6146
	// section 3.5).
	__u32 now = now_sec();
	struct conn_value *cv = bpf_map_lookup_elem(&nat_conn_table, &rev_key);
	if (!cv || session_expired(cv, now)) {
		count_drop(no_conn);
		return XDP_DROP;
	}
	touch_session(cv, now, l4v->tcp_flags, 1);

	// The packet as the sender sent it, in case it has to be told it was too
	// big; see send_too_big6. Every caller has proven at least 8 transport
	// bytes present.
	__be32 quote[NAT_FRAG_QUOTE6 / 4];
	__builtin_memcpy(quote, ip6, NAT_FRAG_QUOTE6);

	fix_l4_checksum(l4v->check_ptr, ip6->daddr, l4v->dport, cv->backend_addr, cv->backend_port);
	__builtin_memcpy(ip6->daddr, cv->backend_addr, 16);
	*l4v->dport_ptr = cv->backend_port;

	return reencap_to_tenant(ctx, cfg, ip6, cv->backend_usid, quote);
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

	// An error about an expired session has no session to reach, and an error
	// never refreshes one (RFC 5508 section 3.2).
	struct conn_value *cv = bpf_map_lookup_elem(&nat_conn_table, &rev_key);
	if (!cv || session_expired(cv, now_sec())) {
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

	return reencap_to_tenant(ctx, cfg, ip6, cv->backend_usid, 0);
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
						 &egress_ifindex, 0);
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

	if (v4_non_global(inner->daddr + 12)) {
		count_drop(DROP_REASON_NAT64_NON_GLOBAL_DEST);
		return XDP_DROP;
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

	// Unreachable for an array map, and counted as exhaustion if it ever is not.
	struct session_scratch *ss = session_scratch_get();
	if (!ss) {
		count_drop(DROP_REASON_NAT64_PAT_EXHAUSTED);
		return XDP_DROP;
	}
	struct conn_key *fwd_key = &ss->fwd;
	__builtin_memset(fwd_key, 0, sizeof(*fwd_key));
	fwd_key->family = NAT_FAMILY_V4;
	fwd_key->proto = proto;
	fwd_key->tenant_arg = (__u16) tenant_arg;
	__builtin_memcpy(fwd_key->saddr, src6, 16);
	fwd_key->sport = sport;
	__builtin_memcpy(fwd_key->daddr, dst6, 16);
	fwd_key->dport = dport;
	__builtin_memcpy(fwd_key->encap_src, tenant_usid, 16);

	struct conn_key *rev_key = &ss->rev;
	__builtin_memset(rev_key, 0, sizeof(*rev_key));
	rev_key->family = NAT_FAMILY_V4;
	rev_key->proto = proto4;
	v4_mapped(rev_key->saddr, dst4);
	rev_key->sport = dport;
	v4_mapped(rev_key->daddr, cfg->shard_pub_addr4);

	__u32 base = fnv1a_flow(src6, sport) ^ (__u32) dport ^ tenant_arg;
	__be16 shard_port = session_port(ss, base, l4v.tcp_flags);
	if (shard_port == 0) {
		count_drop(DROP_REASON_NAT64_PAT_EXHAUSTED);
		return XDP_DROP;
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
				       NAT_ICMPV6_ECHO_REQUEST, sport, NAT_ICMP_ECHO_REQUEST, shard_port);
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
		xlat_words4(new_words, cfg->shard_pub_addr4, dst4, shard_port);
		fix_l4_checksum_xlat(out_l4v.check_ptr, old_words, new_words);
	}
	udp_zero_checksum_fixup(proto, out_l4v.check_ptr);

	*out_l4v.sport_ptr = shard_port;

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

	// An expired session translates nothing; see nat66_return_leg.
	__u32 now = now_sec();
	struct conn_value *found = bpf_map_lookup_elem(&nat_conn_table, &rev_key);
	if (!found || session_expired(found, now)) {
		count_drop(no_conn);
		return XDP_DROP;
	}
	touch_session(found, now, l4v->tcp_flags, 1);

	struct conn_value cv;
	__builtin_memcpy(&cv, found, sizeof(cv));

	// The packet as the sender sent it, in case it has to be told it was too
	// big; see send_frag_needed4. Every caller has proven at least 8 transport
	// bytes present.
	__be32 quote[NAT_FRAG_QUOTE4 / 4];
	__builtin_memcpy(quote, ip4, NAT_FRAG_QUOTE4);

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
	__u16 frag_mtu = 0;
	if (push_outer_header(ctx, cfg->shard_sid, cv.backend_usid, inner_payload_len_plus_ip6hdr,
			       &egress_ifindex, &frag_mtu) != 0) {
		// The sender's packet grows by the translation's 20 bytes as well as
		// the encapsulation's 40.
		if (frag_mtu > NAT_IP6HDR_LEN + NAT_V6_V4_DELTA)
			return send_frag_needed4(ctx, cfg, quote, frag_mtu - NAT_IP6HDR_LEN - NAT_V6_V4_DELTA);
		return XDP_DROP;
	}

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

// rfc1191_plateau is the greatest RFC 1191 plateau MTU below tot_len, the path
// MTU estimate RFC 7915 section 4.2 has a translator report when an IPv4 router
// sent Fragmentation Needed without an MTU.
static NAT_ALWAYS_INLINE __u32 rfc1191_plateau(__u16 tot_len)
{
	if (tot_len > 32000)
		return 32000;
	if (tot_len > 17914)
		return 17914;
	if (tot_len > 8166)
		return 8166;
	if (tot_len > 4352)
		return 4352;
	if (tot_len > 2002)
		return 2002;
	if (tot_len > 1492)
		return 1492;
	if (tot_len > 1006)
		return 1006;
	if (tot_len > 508)
		return 508;
	if (tot_len > 296)
		return 296;
	return 68;
}

// struct icmp6_err is the ICMPv6 message an ICMPv4 error translates to: its
// type, code and type-specific word, in host order.
struct icmp6_err {
	__u8 type;
	__u8 code;
	__u32 word;
};

// icmp4_err_to_icmp6 maps an ICMPv4 error to its ICMPv6 counterpart, as RFC
// 7915 section 4.2 specifies, returning 0 when there is one and 1 for every
// type and code that section says to drop. quoted_tot_len is the quoted
// packet's own Total Length, which a Fragmentation Needed without an MTU is
// estimated from.
//
// A Fragmentation Needed MTU grows by 20 because the tenant's packet was 20
// bytes bigger before it was translated. RFC 7915 also bounds it by the
// translator's own next-hop MTUs, which this does not: the IPv6 side of this
// shard is the fabric, whose MTU a tenant's packet meets encapsulated and which
// the fabric's own MSS clamp covers (galactic#641 for the rest), not something
// an internet router's report can say anything about.
static NAT_ALWAYS_INLINE int icmp4_err_to_icmp6(const struct nat_icmphdr *icmp4, __u16 quoted_tot_len,
						struct icmp6_err *out)
{
	__u8 code = icmp4->code;
	out->word = 0;

	if (icmp4->type == NAT_ICMP_TIME_EXCEEDED) {
		out->type = NAT_ICMPV6_TIME_EXCEEDED;
		out->code = code;
		return 0;
	}

	if (icmp4->type == NAT_ICMP_DEST_UNREACH) {
		out->type = NAT_ICMPV6_DEST_UNREACH;
		switch (code) {
		case 0: case 1: case 5: case 6: case 7: case 8: case 11: case 12:
			out->code = 0; // no route to destination
			return 0;
		case 9: case 10: case 13: case 15:
			out->code = 1; // administratively prohibited
			return 0;
		case 3:
			out->code = 4; // port unreachable
			return 0;
		case 2:
			// Protocol Unreachable becomes a Parameter Problem pointing at
			// the IPv6 header's Next Header field.
			out->type = NAT_ICMPV6_PARAM_PROBLEM;
			out->code = 1;
			out->word = 6;
			return 0;
		case 4: {
			// Fragmentation Needed: the MTU is the low half of the
			// type-specific word, which this header names seq.
			__u32 mtu = __builtin_bswap16(icmp4->seq);
			if (mtu == 0)
				mtu = rfc1191_plateau(quoted_tot_len);
			out->type = NAT_ICMPV6_PACKET_TOO_BIG;
			out->code = 0;
			out->word = mtu + NAT_V6_V4_DELTA;
			return 0;
		}
		}
		return 1;
	}

	if (icmp4->type == NAT_ICMP_PARAM_PROBLEM && (code == 0 || code == 2)) {
		// The pointer is the word's first byte. Each IPv4 header field that
		// has an IPv6 counterpart points at it; the rest have none, and the
		// message is dropped.
		__u8 ptr = ((const __u8 *) &icmp4->id)[0];
		out->type = NAT_ICMPV6_PARAM_PROBLEM;
		out->code = 0;
		if (ptr == 0 || ptr == 1)
			out->word = ptr; // Version/IHL, Type of Service
		else if (ptr == 2 || ptr == 3)
			out->word = 4; // Total Length -> Payload Length
		else if (ptr == 8)
			out->word = 7; // Time to Live -> Hop Limit
		else if (ptr == 9)
			out->word = 6; // Protocol -> Next Header
		else if (ptr >= 12 && ptr <= 15)
			out->word = 8; // Source Address
		else if (ptr >= 16 && ptr <= 19)
			out->word = 24; // Destination Address
		else
			return 1;
		return 0;
	}

	return 1;
}

// nat64_icmp_error translates an ICMPv4 error about a packet this shard sent
// into the ICMPv6 error the tenant would have received had the path been IPv6
// end to end (RFC 7915 section 4.2), and re-encapsulates it toward the tenant.
//
// The quoted packet is matched exactly as nat66_icmp_error matches its own:
// read with its two sides swapped, it is the reverse session key. Its source
// is shard_pub_addr4 on every row, so an error quoting anything else matches
// nothing.
//
// Unlike NAT66, the quoted packet has to be translated too, and both its
// header and the outer one grow by 20 bytes. Together that is exactly the 40
// bytes the head moves back by, so every quoted byte past the first 8 of the
// transport header is already where the translated message needs it. Only the
// front is rebuilt -- outer IPv6 header, ICMPv6 header, quoted IPv6 header, and
// the first 8 transport bytes, the ones holding the ports or the Echo
// Identifier -- from fields read onto the stack before the move. The rest of
// the quote is carried untouched, and so is its quoted transport checksum, as
// in NAT66.
//
// The ICMPv6 checksum is then the ICMPv4 one adjusted for the front: the
// carried bytes sum the same in both, at the same parity. That holds while the
// whole quote is kept. Two cases cut it to the rebuilt front instead, with the
// checksum computed outright over that fixed size: a quote that would make the
// ICMPv6 packet larger than 1280 bytes, and an RFC 4884 multi-part message,
// whose length field sits at a different offset in each family. The 8 bytes
// kept are all RFC 792 guarantees an ICMPv4 error quotes, and all the kernel
// matches an error to a socket on.
//
// The outer source is the reporting router's IPv4 address synthesized into the
// NAT64 prefix, so the tenant sees which hop reported, as traceroute needs.
//
// It is its own tail-called program, not a branch of nat64_icmp_return: its
// rebuild holds more on the stack than fits in one program alongside that
// one's Echo Reply translation and echo responder.
SEC("xdp")
int nat64_icmp_error(struct xdp_md *ctx)
{
	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	struct nat_ethhdr *old_eth = data;
	if ((void *) (old_eth + 1) > data_end)
		return XDP_PASS;
	struct nat_iphdr *ip4 = (void *) (old_eth + 1);
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

	struct nat_iphdr *quoted = (void *) (icmp + 1);
	__u8 *quoted_l4 = (void *) (quoted + 1);
	if ((void *) (quoted_l4 + NAT_QUOTED_L4_LEN) > data_end) {
		count_drop(DROP_REASON_NAT64_ICMP_MALFORMED);
		return XDP_DROP;
	}
	// This shard sends no IPv4 options and never fragments, so a quote with
	// either is not of a packet it sent.
	if ((quoted->version_ihl & 0x0F) != NAT_IP4HDR_LEN / 4 ||
	    (quoted->frag_off & __builtin_bswap16(0x1FFF)) != 0) {
		count_drop(DROP_REASON_NAT_ICMP_UNTRANSLATABLE);
		return XDP_DROP;
	}

	struct icmp6_err err6;
	if (icmp4_err_to_icmp6(icmp, __builtin_bswap16(quoted->tot_len), &err6) != 0) {
		count_drop(DROP_REASON_NAT_ICMP_UNTRANSLATABLE);
		return XDP_DROP;
	}

	struct quoted_view q;
	int rc = parse_quoted(quoted->protocol, quoted_l4, data_end, NAT_IPPROTO_ICMP,
			      NAT_ICMP_ECHO_REQUEST, &q);
	if (rc < 0) {
		count_drop(DROP_REASON_NAT64_ICMP_MALFORMED);
		return XDP_DROP;
	}
	if (rc > 0) {
		count_drop(DROP_REASON_NAT_ICMP_UNTRANSLATABLE);
		return XDP_DROP;
	}

	struct conn_key rev_key;
	__builtin_memset(&rev_key, 0, sizeof(rev_key));
	rev_key.family = NAT_FAMILY_V4;
	rev_key.proto = quoted->protocol;
	v4_mapped(rev_key.saddr, quoted->daddr);
	rev_key.sport = q.peer_port;
	v4_mapped(rev_key.daddr, quoted->saddr);
	rev_key.dport = q.masq;

	// Expired or not refreshed, as in nat66_icmp_error.
	struct conn_value *cv = bpf_map_lookup_elem(&nat_conn_table, &rev_key);
	if (!cv || session_expired(cv, now_sec())) {
		count_drop(DROP_REASON_NAT64_ICMP_NO_CONN);
		return XDP_DROP;
	}
	// The reporting router's address is synthesized into the prefix the
	// tenant's flow used, which RFC 6052 section 3.1 forbids for a non-global
	// address under the Well-Known Prefix.
	if (wkp_matches(cv->dest_addr) && v4_non_global((const __u8 *) &ip4->saddr)) {
		count_drop(DROP_REASON_NAT_ICMP_UNTRANSLATABLE);
		return XDP_DROP;
	}

	// The ICMPv6 message's rebuilt front, on the stack as 14 words: header,
	// quoted IPv6 header, first 8 quoted transport bytes.
	__be32 msg[NAT_ICMP6_ERR_FRONT / 4];
	__u8 *m = (__u8 *) msg;
	__builtin_memset(msg, 0, sizeof(msg));
	m[0] = err6.type;
	m[1] = err6.code;
	msg[1] = __builtin_bswap32(err6.word);

	struct nat_ip6hdr *q6 = (struct nat_ip6hdr *) &m[8];
	q6->vtc_flow[0] = (__u8) (0x60 | (quoted->tos >> 4));
	q6->vtc_flow[1] = (__u8) ((quoted->tos & 0x0F) << 4);
	// The quoted packet's own length, as it was sent, not as truncated here.
	q6->payload_len = __builtin_bswap16((__u16) (__builtin_bswap16(quoted->tot_len) - NAT_IP4HDR_LEN));
	q6->nexthdr = quoted->protocol == NAT_IPPROTO_ICMP ? NAT_IPPROTO_ICMPV6 : quoted->protocol;
	q6->hop_limit = quoted->ttl;
	__builtin_memcpy(q6->saddr, cv->backend_addr, 16);
	__builtin_memcpy(q6->daddr, cv->dest_addr, 16);

	__u8 *ql4 = &m[8 + NAT_IP6HDR_LEN];
	__builtin_memcpy(ql4, quoted_l4, NAT_QUOTED_L4_LEN);
	// The masquerade port or Identifier goes back to the tenant's own, at the
	// same offset parse_quoted found it: bytes 0-1 of TCP or UDP, 4-5 of an
	// Echo. A quoted Echo Request also goes back to its ICMPv6 type.
	if (quoted->protocol == NAT_IPPROTO_ICMP) {
		ql4[0] = NAT_ICMPV6_ECHO_REQUEST;
		__builtin_memcpy(&ql4[4], &cv->backend_port, 2);
	} else {
		__builtin_memcpy(&ql4[0], &cv->backend_port, 2);
	}

	__u8 src6[16];
	__builtin_memcpy(src6, cv->dest_addr, 12);
	__builtin_memcpy(&src6[12], &ip4->saddr, 4);
	__u8 dst6[16];
	__builtin_memcpy(dst6, cv->backend_addr, 16);
	__u8 usid[16];
	__builtin_memcpy(usid, cv->backend_usid, 16);
	__u8 tos = ip4->tos;
	__u8 ttl = ip4->ttl;

	// Keep the whole quote unless it would outgrow 1280 bytes as ICMPv6, or
	// carries an RFC 4884 length (the second byte of the word). Kept whole,
	// the ICMPv6 message is exactly as long as the IPv4 packet was: it loses
	// the outer IPv4 header's 20 bytes and its quoted header gains 20. The
	// IPv4 Total Length, not the frame, says how long that is: a frame can
	// carry link padding past it.
	__u16 tot4 = __builtin_bswap16(ip4->tot_len);
	int cur = (int) ((long) data_end - (long) old_eth);
	int keep_all = ((const __u8 *) &icmp->id)[1] == 0 &&
		       tot4 >= NAT_IP4HDR_LEN + 8 + NAT_IP4HDR_LEN + NAT_QUOTED_L4_LEN &&
		       tot4 <= NAT_ICMP6_ERR_MAX &&
		       (int) sizeof(struct nat_ethhdr) + tot4 <= cur;
	__u32 kept = keep_all ? tot4 : NAT_ICMP6_ERR_FRONT;
	// Bounded for the verifier; keep_all already guarantees it.
	if (kept > NAT_ICMP6_ERR_MAX)
		kept = NAT_ICMP6_ERR_FRONT;

	{
		__be32 now6[10 + NAT_ICMP6_ERR_FRONT / 4];
		__builtin_memcpy(&now6[0], src6, 16);
		__builtin_memcpy(&now6[4], dst6, 16);
		now6[8] = __builtin_bswap32(kept);
		now6[9] = __builtin_bswap32(NAT_IPPROTO_ICMPV6);
		__builtin_memcpy(&now6[10], msg, sizeof(msg));
		__be16 check;
		if (keep_all) {
			// The ICMPv4 message's front as it arrived, checksum zeroed:
			// its header, the quoted IPv4 header, the first 8 transport
			// bytes.
			__be32 was4[(8 + NAT_IP4HDR_LEN + NAT_QUOTED_L4_LEN) / 4];
			__builtin_memcpy(was4, icmp, sizeof(was4));
			((__u8 *) was4)[2] = 0;
			((__u8 *) was4)[3] = 0;
			__s64 diff = bpf_csum_diff(was4, sizeof(was4), now6, sizeof(now6), 0);
			check = csum_fold_add(icmp->check, diff);
		} else {
			// csum_fold_add folds a diff into an existing checksum;
			// starting from 0xFFFF, the checksum of nothing, it folds a
			// whole sum.
			__s64 sum = bpf_csum_diff(0, 0, now6, sizeof(now6), 0);
			check = csum_fold_add(0xFFFF, sum);
		}
		__builtin_memcpy(&m[2], &check, 2);
	}

	__u8 saved_eth[sizeof(struct nat_ethhdr)];
	__builtin_memcpy(saved_eth, old_eth, sizeof(saved_eth));

	// Cut the frame to the Ethernet header plus the message's kept length --
	// which drops link padding, or the quote past the rebuilt front -- then
	// grow the front by both headers' 20 bytes. What is left is exactly the
	// result, the carried tail already where it belongs.
	int want = (int) (sizeof(struct nat_ethhdr) + kept);
	if (bpf_xdp_adjust_tail(ctx, want - cur) != 0 ||
	    bpf_xdp_adjust_head(ctx, -2 * NAT_V6_V4_DELTA) != 0) {
		count_drop(DROP_REASON_NAT_ADJUST_HEAD_FAILED);
		return XDP_DROP;
	}

	data = (void *) (long) ctx->data;
	data_end = (void *) (long) ctx->data_end;
	if (data + sizeof(struct nat_ethhdr) + NAT_IP6HDR_LEN + NAT_ICMP6_ERR_FRONT > data_end) {
		count_drop(DROP_REASON_NAT_ADJUST_HEAD_FAILED);
		return XDP_DROP;
	}

	struct nat_ethhdr *eth = data;
	__builtin_memcpy(eth, saved_eth, sizeof(saved_eth));
	eth->h_proto = __builtin_bswap16(NAT_ETH_P_IPV6);

	struct nat_ip6hdr *ip6 = (void *) (eth + 1);
	__builtin_memset(ip6->vtc_flow, 0, sizeof(ip6->vtc_flow));
	ip6->vtc_flow[0] = (__u8) (0x60 | (tos >> 4));
	ip6->vtc_flow[1] = (__u8) ((tos & 0x0F) << 4);
	ip6->payload_len = __builtin_bswap16((__u16) kept);
	ip6->nexthdr = NAT_IPPROTO_ICMPV6;
	ip6->hop_limit = ttl;
	__builtin_memcpy(ip6->saddr, src6, 16);
	__builtin_memcpy(ip6->daddr, dst6, 16);
	__builtin_memcpy((void *) (ip6 + 1), msg, sizeof(msg));

	return reencap_to_tenant(ctx, cfg, ip6, usid, 0);
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

// nat64_icmp_return handles every ICMPv4 message addressed to shard_pub_addr4
// that the dispatcher did not send to nat64_icmp_error: an Echo Reply to a
// tenant's ping, an Echo Request to the shard itself, or something this shard
// does not translate.
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
			if (cfg->serves_v4 && (nat64_prefix_matches(inner->daddr, cfg->nat64_prefix) ||
					       ((cfg->flags & NAT_SHARD_FLAG_WKP) && wkp_matches(inner->daddr)))) {
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
			__u32 slot = NAT_PROG_NAT64_RETURN;
			if (ip4->protocol == NAT_IPPROTO_ICMP) {
				// A short header goes to the Echo leaf, which counts it.
				struct nat_icmphdr *icmp = (void *) (ip4 + 1);
				slot = NAT_PROG_NAT64_ICMP_RETURN;
				if ((void *) (icmp + 1) <= data_end &&
				    (icmp->type == NAT_ICMP_DEST_UNREACH || icmp->type == NAT_ICMP_TIME_EXCEEDED ||
				     icmp->type == NAT_ICMP_PARAM_PROBLEM))
					slot = NAT_PROG_NAT64_ICMP_ERROR;
			}
			bpf_tail_call(ctx, &nat_progs, slot);
			return XDP_PASS;
		}
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
