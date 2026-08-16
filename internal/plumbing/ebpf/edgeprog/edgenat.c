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
//  4. EGRESS FORWARD BRANCH (datum-cloud/enhancements#865): if the outer
//     destination's uSID *locator* (Block+Node-ID, the top 64 bits)
//     matches this node's own configured egress_sid (egress_config_table)
//     -- masking off the Function/Argument/Padding bits, exactly the way
//     internal/plumbing/ebpf/prog/usid.c's own locator_table match works,
//     just against a single configured value instead of a table -- this
//     is a fresh outbound flow from a tenant VPC backend Pod toward an
//     arbitrary internet destination. The unmasked 12-bit uFMT Argument
//     value carried in the matched address is this flow's tenant/VRF
//     identifier (tenant_arg), extracted directly from the still-unmutated
//     packet before anything is stripped -- see handle_egress_forward().
//     This program never interprets egress_sid's Function nibble.
//
//     tenant_arg exists because #865's own motivation is that tenant ULA
//     space is not guaranteed unique (independent orgs' RFC 4193
//     self-generated prefixes can collide): without it, two different
//     tenants presenting the same colliding backend_addr:backend_port
//     toward the same dest_addr:dest_port would collide in the same
//     egress_conn_table row. This is an isolation fix, not an enablement
//     check -- whether a tenant can reach egress_sid at all stays a
//     routing-layer decision (does its VRF have a default route pointed
//     here), never a per-packet datapath lookup.
//
//     Outer next header must be 41 (the same plain IPv6-in-IPv6 wire
//     format every other cross-node SRv6 packet in this codebase uses --
//     a tenant VRF's default route needs zero new encap format). Strip
//     the outer header (reuse strip_outer_header verbatim), then dispatch
//     on the *inner* packet's own next header: TCP/UDP goes to
//     handle_egress_forward_l4 (the original SYN/any-UDP allocation logic,
//     unchanged); an ICMPv6 Echo Request goes to handle_egress_forward_icmp6
//     (galactic#404) -- the Identifier field stands in for the port
//     egress_conn_table is keyed by, the same technique Linux's own
//     nf_conntrack ICMP tracker uses, since ICMPv6 echo has no real ports.
//     Anything else is dropped (DROP_REASON_MALFORMED_EGRESS_FORWARD) --
//     this address is claimed the same as every other branch here.
//
//     Both l4 and icmp6 sub-branches share the same allocation shape: a
//     miss on a fresh flow (a TCP SYN, any UDP packet, or any Echo
//     Request) allocates a masq_port/masq_identifier via the same
//     linear-probe/BPF_NOEXIST technique handle_forward's own SNAT-port
//     claim uses, against the reverse key (proto, dest_addr:dest_port ->
//     masq_addr:masq_port) -- tenant_arg is fixed at 0 in that reverse
//     row, since masq_addr:masq_port is already globally unique by
//     construction (the claim itself guarantees it) and needs no tenant
//     dimension. SNAT saddr (and, for ICMPv6, the Identifier) to
//     masq_addr:masq_port, fix the checksum, and XDP_TX the *inner*
//     packet back out this same interface unwrapped -- no outer header
//     pushed. This is the one genuinely new tail shape in this file:
//     every other branch either pushes an outer header (handle_forward)
//     or has already stripped one before rewriting (handle_return); this
//     one strips one and sends the revealed inner packet on as a plain
//     IPv6 frame toward the real internet.
//
//  5. EGRESS RETURN BRANCH (#865): if the outer destination matches this
//     node's own configured masq_addr (egress_config_table) -- a plain
//     address compare, no nexthdr==41 requirement, since this arrives as
//     an ordinary internet-originated IPv6 packet, not an SRv6-encapsulated
//     one -- dispatch on next header. TCP/UDP looks up egress_conn_table
//     by the reverse key (proto, dest_addr:dest_port -> masq_addr:masq_port)
//     as before; no tenant_arg needed in this direction, masq_addr:masq_port
//     is already unique per flow by construction. A miss drops (claimed
//     address, no pass-through -- same fail-closed convention every other
//     claimed-address branch in this file already uses).
//
//     ICMPv6 (galactic#404) is no longer a blanket drop: an Echo Reply is
//     looked up the same way an Echo Request allocated its flow (Identifier
//     as the reverse key's pseudo-port) and un-masqueraded DNAT-style,
//     restoring both the destination address and the original Identifier
//     the tenant itself sent. Destination Unreachable/Packet Too Big/Time
//     Exceeded/Parameter Problem (RFC 4443 error messages) embed the IPv6
//     header and at least the first 8 bytes of the transport header of the
//     packet that triggered them -- for a packet this program itself SNAT'd,
//     that is masq_addr:masq_port -> dest_addr:dest_port, exactly
//     egress_conn_table's existing reverse key read one layer deeper. Path
//     MTU discovery rides on Packet Too Big specifically: dropping these
//     (the pre-#404 behavior) is what stalled large transfers instead of
//     letting them adapt. A recognized ICMPv6 message with no matching
//     egress_conn_table row drops (DROP_REASON_NO_EGRESS_ICMP_CONN, kept
//     distinct from the TCP/UDP path's own DROP_REASON_NO_EGRESS_RETURN_CONN
//     so operators can tell them apart from drop counters alone). Any other
//     ICMPv6 type, or any other protocol entirely (Neighbor Discovery, an
//     Echo Request targeting masq_addr directly, ...) is not a reply to any
//     tenant flow this program tracks -- XDP_PASS, not XDP_DROP, handing it
//     to the normal kernel stack instead of claiming and dropping it.
//
//     Every translated case (TCP/UDP, Echo Reply, and each ICMPv6 error
//     type) fixes its checksum and pushes a fresh 40-byte outer SRv6 header
//     (reusing push_outer_header verbatim) sourced from this node's own
//     gw_addr (gw_config_table -- the same "this node, as an SRv6 speaker"
//     identity handle_forward's own push already uses) and addressed to
//     backend_usid, then XDP_TX -- the return-trip mirror of the forward
//     branch above.
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

// EDGE_IPPROTO_ICMPV6 (58) is the next-header value for every ICMPv6
// message the egress return/forward branches special-case (galactic#404) --
// see struct edge_icmp6hdr/edge_icmp6_error_hdr/edge_icmp6_echo_hdr below.
#define EDGE_IPPROTO_ICMPV6 58

#define EDGE_TCP_FLAG_SYN 0x02

// ICMPv6 message types this program reads (RFC 4443). The four error
// types (1-4) share struct edge_icmp6_error_hdr's shape; the two echo
// types share struct edge_icmp6_echo_hdr's.
#define EDGE_ICMPV6_DEST_UNREACH   1
#define EDGE_ICMPV6_PACKET_TOO_BIG 2
#define EDGE_ICMPV6_TIME_EXCEEDED  3
#define EDGE_ICMPV6_PARAM_PROBLEM  4
#define EDGE_ICMPV6_ECHO_REQUEST   128
#define EDGE_ICMPV6_ECHO_REPLY     129

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

// struct edge_icmp6hdr is the common 4-byte prefix every ICMPv6 message
// starts with (RFC 4443 §2.1) -- used only to read type/code before
// dispatching to one of the two more specific shapes below (galactic#404).
struct edge_icmp6hdr {
	__u8 type;
	__u8 code;
	__be16 check;
} __attribute__((packed));

// struct edge_icmp6_error_hdr is the 8-byte header shape Destination
// Unreachable/Packet Too Big/Time Exceeded/Parameter Problem (RFC 4443 §3,
// types 1-4) all share: type, code, checksum, then 4 bytes whose meaning
// varies by type (unused for 1/3, MTU for 2, pointer for 4) that this
// program never reads. What follows is "as much of the invoking packet as
// possible," guaranteed to include at least the embedded IPv6 header's
// first 48 bytes (RFC 4443 §2.4(c)) -- the full 40-byte IPv6 header plus
// the first 8 bytes of whatever transport header follows, which is where
// both TCP and UDP keep their two 16-bit port fields (see
// parse_embedded_ports, deliberately not parse_l4 -- that guarantee falls
// short of a full struct edge_tcphdr).
struct edge_icmp6_error_hdr {
	__u8 type;
	__u8 code;
	__be16 check;
	__u8 unused[4];
} __attribute__((packed));

// struct edge_icmp6_echo_hdr is the Echo Request/Reply header (RFC 4443
// §4). identifier stands in for the port egress_conn_table is keyed by --
// the standard NAT66/NAT64 technique for a protocol with no real ports
// (Linux's own nf_conntrack ICMP tracker does the same) -- see
// handle_egress_forward_icmp6/handle_egress_return_icmp6_echo.
struct edge_icmp6_echo_hdr {
	__u8 type;
	__u8 code;
	__be16 check;
	__be16 identifier;
	__be16 sequence;
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

// struct egress_config is egress_config_table's single-entry value
// (datum-cloud/enhancements#865). A sibling of gw_config, not a repurposed
// field on it -- a schema change to the ingress gw_config wire format
// should never force a review of egress logic, and vice versa (same
// one-map-one-purpose convention struct backend/struct rule_value already
// follow). egress_sid is a uSID *locator* (only its top 64 bits, Block+
// Node-ID, are ever compared -- see locator_eq); masq_addr is a plain,
// publicly-routable address with no uSID structure at all, matched in
// full like gw_addr.
struct egress_config {
	__u8 egress_sid[16];
	__u8 masq_addr[16];
};

// struct egress_conn_key is egress_conn_table's key -- like conn_key, one
// struct shared by both the forward and reverse row of a flow, filled
// according to whichever direction's packet is actually being looked up:
// the forward row is keyed by the tenant backend Pod's own outbound tuple
// (saddr:sport = backend_addr:backend_port, daddr:dport =
// dest_addr:dest_port) plus tenant_arg (the uFMT Argument bits extracted
// from the packet's egress_sid destination address, design plan §3.1) --
// needed here because backend_addr alone is not guaranteed globally unique
// (independent tenants' RFC 4193 ULA prefixes can collide). The reverse
// row is keyed by the internet peer's reply tuple (saddr:sport =
// dest_addr:dest_port, daddr:dport = masq_addr:masq_port) with tenant_arg
// always 0 -- masq_addr:masq_port is already unique per flow by
// construction (the SNAT-port claim itself guarantees it), so the reverse
// direction needs no tenant dimension at all.
struct egress_conn_key {
	__u8 proto;
	__u8 pad[1];
	__be16 sport;
	__be16 dport;
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 tenant_arg;
};

// struct egress_conn_value carries the full picture of one translated
// egress flow. A new struct, not a repurposed conn_value: conn_value's
// fields (client_addr, vip_addr, backend_addr, gw_addr) are named for the
// ingress direction and don't map cleanly onto an egress flow's shape --
// there is no "client" or "VIP" here, only a backend's own address, an
// arbitrary internet destination, and the masquerade address. tenant_arg
// is carried here too (alongside the reverse row, where it is always 0)
// so both directions share one struct shape.
//
// For an ICMPv6 Echo flow (proto == EDGE_IPPROTO_ICMPV6, galactic#404),
// backend_port/dest_port/masq_port hold the Echo Identifier instead of a
// real port -- a deliberate reuse rather than dedicated identifier fields,
// the same "a field held equal old/new contributes zero diff" generic
// reuse fix_l4_checksum's own call sites already lean on elsewhere in this
// file (see handle_egress_forward_icmp6/handle_egress_return_icmp6_echo).
struct egress_conn_value {
	__u16 tenant_arg;
	__u8 backend_addr[16];
	__be16 backend_port;
	__u8 backend_usid[16];
	__u8 dest_addr[16];
	__be16 dest_port;
	__u8 masq_addr[16];
	__be16 masq_port;
	__u8 proto;
	__u8 pad[1];
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
	// Egress (masquerade) drop reasons (#865) -- see handle_egress_forward/
	// handle_egress_return. FIB and adjust-head failures on the egress
	// path reuse the FIB_*/ADJUST_HEAD_FAILED reasons above (shared
	// helpers, direction-agnostic); these four are specific to the new
	// branches' own claimed-packet checks.
	DROP_REASON_MALFORMED_EGRESS_FORWARD = 10,
	DROP_REASON_NO_EGRESS_CONN_NOT_SYN   = 11,
	DROP_REASON_EGRESS_PAT_EXHAUSTED     = 12,
	DROP_REASON_MALFORMED_EGRESS_RETURN  = 13,
	DROP_REASON_NO_EGRESS_RETURN_CONN    = 14,
	// ICMPv6 egress drop reasons (galactic#404) -- see
	// handle_egress_forward_icmp6/handle_egress_return_icmp6. Kept distinct
	// from the TCP/UDP-specific reasons above rather than reused: an
	// operator reading drop counters should be able to tell "this ICMPv6
	// message didn't parse" apart from "it parsed fine but matched no
	// flow," and apart from the TCP/UDP path's own equivalents -- the
	// original review comment on #381 flagged exactly this ambiguity
	// (DROP_REASON_MALFORMED_EGRESS_RETURN previously double-booked as
	// both "malformed" and "well-formed but not TCP/UDP," a protocol-policy
	// decision mislabeled as a parse failure).
	DROP_REASON_MALFORMED_EGRESS_ICMP = 15,
	DROP_REASON_NO_EGRESS_ICMP_CONN   = 16,
	DROP_REASON_COUNT                 = 17,
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

// egress_config_table and egress_conn_table (#865) -- see struct
// egress_config/egress_conn_key/egress_conn_value's own comments above.
// egress_conn_table is BPF_MAP_TYPE_LRU_HASH for the same reason
// conn_table is: self-evicting under pressure is the sole port-reclaim
// mechanism, no separate GC pass (this file's own header comment,
// design plan §2).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct egress_config);
} egress_config_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct egress_conn_key);
	__type(value, struct egress_conn_value);
} egress_conn_table SEC(".maps");

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

// locator_eq compares only the uSID *locator* portion (Block(48)+Node-ID
// (16), bytes 0-7) of an address against a configured locator, masking off
// Function/Argument/Padding (#865) -- mirrors
// internal/plumbing/ebpf/prog/usid.c's own locator_table match (its
// LocatorKey is the same top-64-bits read), just as a two-address compare
// instead of a table lookup, since this program has exactly one configured
// egress_sid rather than a table of many.
static EDGE_ALWAYS_INLINE int locator_eq(const __u8 daddr[16], const __u8 locator[16])
{
	for (int i = 0; i < 8; i++) {
		if (daddr[i] != locator[i])
			return 0;
	}
	return 1;
}

// egress_argument extracts the 12-bit uFMT Argument field (bits 69-80: the
// low nibble of byte 8 plus all of byte 9) directly from an unmutated
// address -- the packet's own tenant/VRF identifier for the egress
// datapath (#865), with no map lookup and no shift of the address itself.
// Same fixed-offset technique internal/plumbing/ebpf/prog/usid.c's own
// Argument read uses (design plan R2/R4 there); this program never
// interprets the uFMT Function nibble (bits 65-68) at all -- egress_sid's
// Function bits are unused by this datapath.
static EDGE_ALWAYS_INLINE __u16 egress_argument(const __u8 daddr[16])
{
	return ((__u16) (daddr[8] & 0x0F) << 8) | daddr[9];
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

// parse_embedded_ports reads the two 16-bit port fields both edge_tcphdr
// and edge_udphdr start with, bounds-checking only those 4 bytes --
// deliberately not parse_l4, whose full-struct bounds check (a complete
// struct edge_tcphdr, 20 bytes) would reject a validly-minimal ICMPv6
// error message's embedded TCP header: RFC 4443 guarantees only the first
// 8 bytes of the invoking transport header, and both TCP's and UDP's
// source/dest port fields sit in the first 4 of those, well within that
// minimum (galactic#404's handle_egress_return_icmp6_error).
static EDGE_ALWAYS_INLINE int parse_embedded_ports(void *l4, void *data_end, __be16 *sport, __be16 *dport)
{
	__be16 *ports = l4;
	if ((void *) (ports + 2) > data_end)
		return -1;
	*sport = ports[0];
	*dport = ports[1];
	return 0;
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
// Egress branch (masquerade) (datum-cloud/enhancements#865).
// ---------------------------------------------------------------------

// handle_egress_forward_l4 handles the TCP/UDP shape of a fresh (or
// already-established) egress flow -- factored out of handle_egress_forward
// unchanged (galactic#404 split this out to make room for
// handle_egress_forward_icmp6 as a sibling, not to change this path's own
// behavior).
static EDGE_ALWAYS_INLINE int handle_egress_forward_l4(struct xdp_md *ctx, struct edge_ethhdr *eth,
							 struct edge_ip6hdr *inner, __u16 tenant_arg,
							 const __u8 backend_usid[16], void *data_end)
{
	struct l4_view l4v;
	if (parse_l4(inner->nexthdr, (void *) (inner + 1), data_end, &l4v) != 0) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_FORWARD);
		return XDP_DROP;
	}

	// Forward key: the backend Pod's own outbound tuple, as it appears on
	// this packet, plus tenant_arg -- see struct egress_conn_key's comment
	// for why tenant_arg is part of this direction's key.
	struct egress_conn_key fwd_key;
	__builtin_memset(&fwd_key, 0, sizeof(fwd_key));
	fwd_key.proto = inner->nexthdr;
	__builtin_memcpy(fwd_key.saddr, inner->saddr, 16);
	fwd_key.sport = l4v.sport;
	__builtin_memcpy(fwd_key.daddr, inner->daddr, 16);
	fwd_key.dport = l4v.dport;
	fwd_key.tenant_arg = tenant_arg;

	struct egress_conn_value *existing = bpf_map_lookup_elem(&egress_conn_table, &fwd_key);
	struct egress_conn_value cv;

	if (existing) {
		__builtin_memcpy(&cv, existing, sizeof(cv));
	} else {
		if (!l4v.is_syn) {
			count_drop(DROP_REASON_NO_EGRESS_CONN_NOT_SYN);
			return XDP_DROP;
		}

		__u32 cfg_key = 0;
		struct egress_config *ecfg = bpf_map_lookup_elem(&egress_config_table, &cfg_key);
		if (!ecfg) {
			count_drop(DROP_REASON_NO_EGRESS_CONN_NOT_SYN);
			return XDP_DROP;
		}

		__builtin_memset(&cv, 0, sizeof(cv));
		cv.tenant_arg = tenant_arg;
		__builtin_memcpy(cv.backend_addr, inner->saddr, 16);
		cv.backend_port = l4v.sport;
		__builtin_memcpy(cv.backend_usid, backend_usid, 16);
		__builtin_memcpy(cv.dest_addr, inner->daddr, 16);
		cv.dest_port = l4v.dport;
		__builtin_memcpy(cv.masq_addr, ecfg->masq_addr, 16);
		cv.proto = inner->nexthdr;

		__u32 base = fnv1a_flow(inner->saddr, l4v.sport) ^ (__u32) l4v.dport;
		int claimed = 0;

		#pragma unroll
		for (int i = 0; i < EDGE_PAT_PROBE_LIMIT; i++) {
			__u16 candidate = EDGE_PAT_PORT_BASE + ((base + (__u32) i) % EDGE_PAT_PORT_RANGE);
			cv.masq_port = __builtin_bswap16(candidate);

			struct egress_conn_key rev_key;
			__builtin_memset(&rev_key, 0, sizeof(rev_key));
			rev_key.proto = inner->nexthdr;
			__builtin_memcpy(rev_key.saddr, inner->daddr, 16);
			rev_key.sport = l4v.dport;
			__builtin_memcpy(rev_key.daddr, ecfg->masq_addr, 16);
			rev_key.dport = cv.masq_port;
			// tenant_arg left at 0 in the reverse row -- see struct
			// egress_conn_key's comment.

			if (bpf_map_update_elem(&egress_conn_table, &rev_key, &cv, BPF_NOEXIST) == 0) {
				claimed = 1;
				break;
			}
		}

		if (!claimed) {
			count_drop(DROP_REASON_EGRESS_PAT_EXHAUSTED);
			return XDP_DROP;
		}

		bpf_map_update_elem(&egress_conn_table, &fwd_key, &cv, BPF_ANY);
	}

	// Source-only rewrite (SNAT): destination is left untouched, unlike
	// Full-NAT's four-field rewrite -- fix_l4_checksum is still safe to
	// call generically here since passing the same old/new value for
	// daddr/dport contributes zero diff for those fields.
	__u8 old_saddr[16];
	__builtin_memcpy(old_saddr, inner->saddr, 16);
	__be16 old_sport = l4v.sport;

	fix_l4_checksum(l4v.check_ptr, old_saddr, inner->daddr, old_sport, l4v.dport,
			cv.masq_addr, inner->daddr, cv.masq_port, l4v.dport);

	__builtin_memcpy(inner->saddr, cv.masq_addr, 16);
	*l4v.sport_ptr = cv.masq_port;

	long fib_rc = resolve_fib_and_write_eth(ctx, ctx->ingress_ifindex, cv.masq_addr, cv.dest_addr,
						 __builtin_bswap16(inner->payload_len) + (__u16) sizeof(*inner), eth);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS) {
		count_fib_drop(fib_rc);
		return XDP_DROP;
	}

	return XDP_TX;
}

// handle_egress_forward_icmp6 handles a tenant backend's own ICMPv6 Echo
// Request leaving via egress_sid -- the forward half of the ping round
// trip handle_egress_return_icmp6_echo completes on the way back
// (galactic#404). Any other ICMPv6 type from a tenant backend (Echo
// Reply, Router Solicitation, Neighbor Discovery, ...) has no defined
// masquerade behavior in this design and is dropped, not passed through --
// this address (egress_sid) is claimed the same as every other branch in
// this file.
static EDGE_ALWAYS_INLINE int handle_egress_forward_icmp6(struct xdp_md *ctx, struct edge_ethhdr *eth,
							    struct edge_ip6hdr *inner, __u16 tenant_arg,
							    const __u8 backend_usid[16], void *data_end)
{
	struct edge_icmp6_echo_hdr *echo = (void *) (inner + 1);
	if ((void *) (echo + 1) > data_end) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_ICMP);
		return XDP_DROP;
	}
	if (echo->type != EDGE_ICMPV6_ECHO_REQUEST) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_ICMP);
		return XDP_DROP;
	}

	// Forward key: identifier stands in for both sport/dport (struct
	// egress_conn_value's own comment) -- everything else mirrors
	// handle_egress_forward_l4's forward key exactly.
	struct egress_conn_key fwd_key;
	__builtin_memset(&fwd_key, 0, sizeof(fwd_key));
	fwd_key.proto = EDGE_IPPROTO_ICMPV6;
	__builtin_memcpy(fwd_key.saddr, inner->saddr, 16);
	fwd_key.sport = echo->identifier;
	__builtin_memcpy(fwd_key.daddr, inner->daddr, 16);
	fwd_key.dport = echo->identifier;
	fwd_key.tenant_arg = tenant_arg;

	struct egress_conn_value *existing = bpf_map_lookup_elem(&egress_conn_table, &fwd_key);
	struct egress_conn_value cv;

	if (existing) {
		__builtin_memcpy(&cv, existing, sizeof(cv));
	} else {
		// Every Echo Request may start a new flow -- there is no
		// SYN-equivalent concept for ICMP, the same "any UDP packet
		// may start a new flow" reasoning handle_egress_forward_l4
		// already applies to UDP.
		__u32 cfg_key = 0;
		struct egress_config *ecfg = bpf_map_lookup_elem(&egress_config_table, &cfg_key);
		if (!ecfg) {
			count_drop(DROP_REASON_NO_EGRESS_ICMP_CONN);
			return XDP_DROP;
		}

		__builtin_memset(&cv, 0, sizeof(cv));
		cv.tenant_arg = tenant_arg;
		__builtin_memcpy(cv.backend_addr, inner->saddr, 16);
		cv.backend_port = echo->identifier; // the tenant's own original identifier
		__builtin_memcpy(cv.backend_usid, backend_usid, 16);
		__builtin_memcpy(cv.dest_addr, inner->daddr, 16);
		cv.dest_port = echo->identifier;
		__builtin_memcpy(cv.masq_addr, ecfg->masq_addr, 16);
		cv.proto = EDGE_IPPROTO_ICMPV6;

		// Identifier-claim probe: the same bounded linear-probe/
		// BPF_NOEXIST technique handle_egress_forward_l4's masq_port
		// claim uses, over the same numeric range, just keyed by
		// identifier instead of port -- two different backend Pods
		// (or the same Pod's two concurrent pings) can legitimately
		// pick the same identifier value, and masq_addr has only one
		// address to share, so the identifier must be re-mapped
		// exactly like a SNAT port would be.
		__u32 base = fnv1a_flow(inner->saddr, echo->identifier);
		int claimed = 0;

		#pragma unroll
		for (int i = 0; i < EDGE_PAT_PROBE_LIMIT; i++) {
			__u16 candidate = EDGE_PAT_PORT_BASE + ((base + (__u32) i) % EDGE_PAT_PORT_RANGE);
			cv.masq_port = __builtin_bswap16(candidate);

			struct egress_conn_key rev_key;
			__builtin_memset(&rev_key, 0, sizeof(rev_key));
			rev_key.proto = EDGE_IPPROTO_ICMPV6;
			__builtin_memcpy(rev_key.saddr, inner->daddr, 16);
			rev_key.sport = cv.masq_port;
			__builtin_memcpy(rev_key.daddr, ecfg->masq_addr, 16);
			rev_key.dport = cv.masq_port;
			// tenant_arg left at 0 in the reverse row -- see struct
			// egress_conn_key's comment.

			if (bpf_map_update_elem(&egress_conn_table, &rev_key, &cv, BPF_NOEXIST) == 0) {
				claimed = 1;
				break;
			}
		}

		if (!claimed) {
			count_drop(DROP_REASON_EGRESS_PAT_EXHAUSTED);
			return XDP_DROP;
		}

		bpf_map_update_elem(&egress_conn_table, &fwd_key, &cv, BPF_ANY);
	}

	// Masquerade both the source address and the identifier -- mirroring
	// handle_egress_forward_l4's SNAT-only rewrite exactly, with
	// identifier standing in for port throughout. fix_l4_checksum is a
	// generic address+word-pair checksum-diff helper, not a Full-NAT-
	// specific one, so passing 0 for the unused dport-shaped word slot on
	// both sides (contributing zero diff) is safe -- the same technique
	// handle_egress_forward_l4's own SNAT-only comment documents.
	__u8 old_saddr[16];
	__builtin_memcpy(old_saddr, inner->saddr, 16);
	__be16 old_identifier = echo->identifier;

	fix_l4_checksum(&echo->check, old_saddr, inner->daddr, old_identifier, 0,
			cv.masq_addr, inner->daddr, cv.masq_port, 0);

	__builtin_memcpy(inner->saddr, cv.masq_addr, 16);
	echo->identifier = cv.masq_port;

	long fib_rc = resolve_fib_and_write_eth(ctx, ctx->ingress_ifindex, cv.masq_addr, cv.dest_addr,
						 __builtin_bswap16(inner->payload_len) + (__u16) sizeof(*inner), eth);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS) {
		count_fib_drop(fib_rc);
		return XDP_DROP;
	}

	return XDP_TX;
}

// handle_egress_forward is triggered when the outer destination's locator
// matches this node's own configured egress_sid and outer nexthdr == 41 --
// a fresh (or already-established) outbound flow from a tenant VPC backend
// Pod toward an arbitrary internet destination. tenant_arg is the uFMT
// Argument value already extracted from the packet's own destination
// address by the caller (edge_nat), before this function strips the outer
// header that address lives on. Strips the outer header, resolves the
// inner packet's own next header, and dispatches to handle_egress_forward_l4
// (TCP/UDP, the original logic) or handle_egress_forward_icmp6 (Echo
// Request, galactic#404) -- anything else drops, this address is claimed.
static EDGE_ALWAYS_INLINE int handle_egress_forward(struct xdp_md *ctx, struct edge_ip6hdr *outer,
						      __u16 tenant_arg, void *data_end)
{
	if (outer->nexthdr != EDGE_IPPROTO_IPV6) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_FORWARD);
		return XDP_DROP;
	}

	// The outer source is the originating worker node's own SRv6 address
	// -- the same node that encapsulated this packet via its tenant VRF's
	// default route toward egress_sid (internal/plumbing/srv6.
	// RouteEgressAdd's SEG6 encap route, design plan §4.4). Captured here,
	// before strip_outer_header discards the outer header entirely, and
	// remembered in egress_conn_value.backend_usid so the eventual reply
	// (handle_egress_return) knows which node to push a return SRv6
	// header toward -- there is no rule_table-equivalent policy entry for
	// egress (design plan §3.2), so this wire-derived value is the only
	// source of that address Phase B has.
	//
	// ASSUMPTION FLAGGED FOR REVIEW: this relies on the kernel's SEG6
	// encap route always selecting the node's own uSID address as the
	// pushed outer source, the same way it does for every other cross-
	// node SRv6 packet in this codebase. That has not been independently
	// verified against RouteEgressAdd's actual netlink-level source-
	// address-selection behavior as part of this phase -- worth
	// confirming before Phase D's e2e proof relies on it.
	__u8 backend_usid[16];
	__builtin_memcpy(backend_usid, outer->saddr, 16);

	struct edge_ethhdr *eth;
	if (strip_outer_header(ctx, &eth) != 0) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_FORWARD);
		return XDP_DROP;
	}

	data_end = (void *) (long) ctx->data_end;

	struct edge_ip6hdr *inner = (void *) (eth + 1);
	if ((void *) (inner + 1) > data_end) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_FORWARD);
		return XDP_DROP;
	}

	if (inner->nexthdr == EDGE_IPPROTO_ICMPV6)
		return handle_egress_forward_icmp6(ctx, eth, inner, tenant_arg, backend_usid, data_end);

	if (inner->nexthdr != EDGE_IPPROTO_TCP && inner->nexthdr != EDGE_IPPROTO_UDP) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_FORWARD);
		return XDP_DROP;
	}

	return handle_egress_forward_l4(ctx, eth, inner, tenant_arg, backend_usid, data_end);
}

// handle_egress_return_l4 handles the TCP/UDP shape of an egress reply --
// factored out of handle_egress_return unchanged (galactic#404 split this
// out to make room for the ICMPv6 siblings below, not to change this
// path's own behavior).
static EDGE_ALWAYS_INLINE int handle_egress_return_l4(struct xdp_md *ctx, struct edge_ip6hdr *ip6, void *data_end)
{
	struct l4_view l4v;
	if (parse_l4(ip6->nexthdr, (void *) (ip6 + 1), data_end, &l4v) != 0) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_RETURN);
		return XDP_DROP;
	}

	// Reverse key: the internet peer's reply tuple, as it appears on this
	// packet. tenant_arg is left at 0 -- masq_addr:masq_port is already
	// unique per flow by construction (struct egress_conn_key's comment).
	struct egress_conn_key rev_key;
	__builtin_memset(&rev_key, 0, sizeof(rev_key));
	rev_key.proto = ip6->nexthdr;
	__builtin_memcpy(rev_key.saddr, ip6->saddr, 16);
	rev_key.sport = l4v.sport;
	__builtin_memcpy(rev_key.daddr, ip6->daddr, 16);
	rev_key.dport = l4v.dport;

	struct egress_conn_value *cv = bpf_map_lookup_elem(&egress_conn_table, &rev_key);
	if (!cv) {
		count_drop(DROP_REASON_NO_EGRESS_RETURN_CONN);
		return XDP_DROP;
	}

	// Destination-only rewrite (DNAT): source address/port untouched.
	__u8 old_daddr[16];
	__builtin_memcpy(old_daddr, ip6->daddr, 16);
	__be16 old_dport = l4v.dport;

	fix_l4_checksum(l4v.check_ptr, ip6->saddr, old_daddr, l4v.sport, old_dport,
			ip6->saddr, cv->backend_addr, l4v.sport, cv->backend_port);

	__builtin_memcpy(ip6->daddr, cv->backend_addr, 16);
	*l4v.dport_ptr = cv->backend_port;

	__u32 cfg_key = 0;
	struct gw_config *cfg = bpf_map_lookup_elem(&gw_config_table, &cfg_key);
	if (!cfg) {
		count_drop(DROP_REASON_NO_EGRESS_RETURN_CONN);
		return XDP_DROP;
	}

	__be16 inner_payload_len = ip6->payload_len;

	if (push_outer_header(ctx, cfg->gw_addr, cv->backend_usid, inner_payload_len) != 0)
		return XDP_DROP;

	return XDP_TX;
}

// handle_egress_return_icmp6_echo handles an ICMPv6 Echo Reply addressed
// to masq_addr -- the reply half of the ping round trip
// handle_egress_forward_icmp6 started (galactic#404). Looks up
// egress_conn_table by identifier (the same pseudo-port key the forward
// allocation wrote) and un-masquerades both the destination address and
// the identifier DNAT-style -- restoring the identifier is the part easy
// to miss: leaving it at the masqueraded value would let the address
// rewrite succeed while the tenant's own ping process still doesn't
// recognize the reply, since the identifier it observes would not be the
// one it originally sent.
static EDGE_ALWAYS_INLINE int handle_egress_return_icmp6_echo(struct xdp_md *ctx, struct edge_ip6hdr *ip6, void *data_end)
{
	struct edge_icmp6_echo_hdr *echo = (void *) (ip6 + 1);
	if ((void *) (echo + 1) > data_end) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_ICMP);
		return XDP_DROP;
	}

	struct egress_conn_key rev_key;
	__builtin_memset(&rev_key, 0, sizeof(rev_key));
	rev_key.proto = EDGE_IPPROTO_ICMPV6;
	__builtin_memcpy(rev_key.saddr, ip6->saddr, 16);
	rev_key.sport = echo->identifier;
	__builtin_memcpy(rev_key.daddr, ip6->daddr, 16);
	rev_key.dport = echo->identifier;

	struct egress_conn_value *cv = bpf_map_lookup_elem(&egress_conn_table, &rev_key);
	if (!cv) {
		count_drop(DROP_REASON_NO_EGRESS_ICMP_CONN);
		return XDP_DROP;
	}

	// Two fields change: destination address (masq_addr -> backend_addr)
	// and identifier (the masqueraded value -> cv->backend_port, the
	// tenant's own original identifier) -- source address is untouched,
	// the same DNAT-only shape handle_egress_return_l4 applies to ports,
	// just for ICMP's identifier field instead.
	__u8 old_daddr[16];
	__builtin_memcpy(old_daddr, ip6->daddr, 16);
	__be16 old_identifier = echo->identifier;

	fix_l4_checksum(&echo->check, ip6->saddr, old_daddr, old_identifier, 0,
			ip6->saddr, cv->backend_addr, cv->backend_port, 0);

	__builtin_memcpy(ip6->daddr, cv->backend_addr, 16);
	echo->identifier = cv->backend_port;

	__u32 cfg_key = 0;
	struct gw_config *cfg = bpf_map_lookup_elem(&gw_config_table, &cfg_key);
	if (!cfg) {
		count_drop(DROP_REASON_NO_EGRESS_ICMP_CONN);
		return XDP_DROP;
	}

	__be16 inner_payload_len = ip6->payload_len;

	if (push_outer_header(ctx, cfg->gw_addr, cv->backend_usid, inner_payload_len) != 0)
		return XDP_DROP;

	return XDP_TX;
}

// handle_egress_return_icmp6_error handles Destination Unreachable/Packet
// Too Big/Time Exceeded/Parameter Problem addressed to masq_addr
// (galactic#404) -- the piece with actual teeth, since Packet Too Big is
// how path MTU discovery reaches a tenant. The embedded original datagram
// -- masq_addr:masq_port -> dest_addr:dest_port, exactly the packet
// handle_egress_forward_l4 last sent -- carries everything needed to key
// egress_conn_table's existing reverse row; no new map, no new key shape.
//
// Deliberately uses parse_embedded_ports, not parse_l4: RFC 4443
// guarantees only the first 8 bytes of the invoking transport header, and
// parse_l4's full-struct bounds check (20 bytes for TCP) would reject a
// validly-minimal error message the port-only read here does not need to
// reject.
static EDGE_ALWAYS_INLINE int handle_egress_return_icmp6_error(struct xdp_md *ctx, struct edge_ip6hdr *ip6, void *data_end)
{
	struct edge_icmp6_error_hdr *err = (void *) (ip6 + 1);
	struct edge_ip6hdr *embedded = (void *) (err + 1);
	if ((void *) (embedded + 1) > data_end) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_ICMP);
		return XDP_DROP;
	}
	if (embedded->nexthdr != EDGE_IPPROTO_TCP && embedded->nexthdr != EDGE_IPPROTO_UDP) {
		// The invoking packet wasn't one this program itself sent
		// (handle_egress_forward only ever emits TCP/UDP or ICMPv6
		// Echo Request) -- not attributable to a tenant flow.
		count_drop(DROP_REASON_MALFORMED_EGRESS_ICMP);
		return XDP_DROP;
	}

	__be16 embedded_sport, embedded_dport;
	if (parse_embedded_ports((void *) (embedded + 1), data_end, &embedded_sport, &embedded_dport) != 0) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_ICMP);
		return XDP_DROP;
	}

	// The embedded packet is masq_addr:masq_port -> dest_addr:dest_port --
	// exactly the packet handle_egress_forward_l4 last sent -- so this is
	// the *same reverse key* a direct TCP/UDP reply is looked up by, just
	// read one layer deeper.
	struct egress_conn_key rev_key;
	__builtin_memset(&rev_key, 0, sizeof(rev_key));
	rev_key.proto = embedded->nexthdr;
	__builtin_memcpy(rev_key.saddr, embedded->daddr, 16);
	rev_key.sport = embedded_dport;
	__builtin_memcpy(rev_key.daddr, embedded->saddr, 16);
	rev_key.dport = embedded_sport;

	struct egress_conn_value *cv = bpf_map_lookup_elem(&egress_conn_table, &rev_key);
	if (!cv) {
		count_drop(DROP_REASON_NO_EGRESS_ICMP_CONN);
		return XDP_DROP;
	}

	// Two rewrites land on the same checksum (ICMPv6's own, which covers
	// the whole message including the embedded bytes verbatim -- the
	// embedded packet's own stale L4 checksum is untouched and never
	// independently re-validated by anyone downstream): the outer
	// packet's destination (masq_addr -> backend_addr, so it routes to
	// the right worker node) and the embedded packet's own source
	// address/port (masq_addr:masq_port -> backend_addr:backend_port),
	// so the tenant's IP stack recognizes this error as belonging to a
	// socket it actually opened. Both old values are masq_addr/masq_port
	// by construction (this program's own earlier SNAT), so this is
	// genuinely two separate memory locations converging on one value
	// change apiece -- fix_l4_checksum's four word-slots don't have to
	// mean "one address's source/dest" here, just "two old values, two
	// new values, diffed together" (the same generic reuse its other
	// call sites in this file already lean on).
	__u8 old_outer_daddr[16], old_embedded_saddr[16];
	__builtin_memcpy(old_outer_daddr, ip6->daddr, 16);
	__builtin_memcpy(old_embedded_saddr, embedded->saddr, 16);

	fix_l4_checksum(&err->check, old_outer_daddr, old_embedded_saddr, 0, embedded_sport,
			cv->backend_addr, cv->backend_addr, 0, cv->backend_port);

	__builtin_memcpy(ip6->daddr, cv->backend_addr, 16);
	__builtin_memcpy(embedded->saddr, cv->backend_addr, 16);
	__be16 *embedded_ports = (void *) (embedded + 1);
	embedded_ports[0] = cv->backend_port;

	__u32 cfg_key = 0;
	struct gw_config *cfg = bpf_map_lookup_elem(&gw_config_table, &cfg_key);
	if (!cfg) {
		count_drop(DROP_REASON_NO_EGRESS_ICMP_CONN);
		return XDP_DROP;
	}

	__be16 inner_payload_len = ip6->payload_len;

	if (push_outer_header(ctx, cfg->gw_addr, cv->backend_usid, inner_payload_len) != 0)
		return XDP_DROP;

	return XDP_TX;
}

// handle_egress_return_icmp6 reads the common 4-byte ICMPv6 prefix and
// dispatches by type (galactic#404): Echo Reply and the four RFC 4443
// error types translate back to the originating tenant; anything else
// (Router Advertisement, Neighbor Solicitation/Advertisement, an Echo
// Request targeting masq_addr directly, ...) is not a reply to any tenant
// flow this program tracks -- XDP_PASS, not XDP_DROP, handing it to the
// normal kernel stack instead of claiming and dropping it.
static EDGE_ALWAYS_INLINE int handle_egress_return_icmp6(struct xdp_md *ctx, struct edge_ip6hdr *ip6, void *data_end)
{
	struct edge_icmp6hdr *icmp6 = (void *) (ip6 + 1);
	if ((void *) (icmp6 + 1) > data_end) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_ICMP);
		return XDP_DROP;
	}

	if (icmp6->type == EDGE_ICMPV6_ECHO_REPLY)
		return handle_egress_return_icmp6_echo(ctx, ip6, data_end);

	if (icmp6->type == EDGE_ICMPV6_DEST_UNREACH || icmp6->type == EDGE_ICMPV6_PACKET_TOO_BIG ||
	    icmp6->type == EDGE_ICMPV6_TIME_EXCEEDED || icmp6->type == EDGE_ICMPV6_PARAM_PROBLEM)
		return handle_egress_return_icmp6_error(ctx, ip6, data_end);

	return XDP_PASS;
}

// handle_egress_return is triggered when the outer destination matches this
// node's own configured masq_addr -- an ordinary internet-originated IPv6
// packet (no SRv6 encapsulation), the reply half of a flow
// handle_egress_forward already established. Dispatches on next header:
// TCP/UDP to handle_egress_return_l4 (the original logic), ICMPv6 to
// handle_egress_return_icmp6 (galactic#404); any other protocol is not
// this program's to translate -- XDP_PASS, mirroring step 1's own
// can't-fully-parse-or-match fallthrough, just decided per-protocol here
// since this address is otherwise claimed.
static EDGE_ALWAYS_INLINE int handle_egress_return(struct xdp_md *ctx, struct edge_ip6hdr *ip6, void *data_end)
{
	if (ip6->nexthdr == EDGE_IPPROTO_ICMPV6)
		return handle_egress_return_icmp6(ctx, ip6, data_end);

	if (ip6->nexthdr != EDGE_IPPROTO_TCP && ip6->nexthdr != EDGE_IPPROTO_UDP)
		return XDP_PASS;

	return handle_egress_return_l4(ctx, ip6, data_end);
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

	// Egress (masquerade) dispatch (#865): egress_config_table is a
	// single ARRAY entry holding both egress_sid and masq_addr, so this
	// is one extra map lookup covering both new address checks -- same
	// "read once per packet" shape as the gw_config_table lookup above,
	// no regression to existing ingress performance. A node not offering
	// egress leaves egress_config_table zeroed, and the zero address
	// never legitimately matches a real packet's daddr, so both checks
	// below are no-ops on such a node.
	struct egress_config *ecfg = bpf_map_lookup_elem(&egress_config_table, &cfg_key);
	if (ecfg && locator_eq(ip6->daddr, ecfg->egress_sid)) {
		__u16 tenant_arg = egress_argument(ip6->daddr);
		return handle_egress_forward(ctx, ip6, tenant_arg, data_end);
	}
	if (ecfg && addr6_eq(ip6->daddr, ecfg->masq_addr))
		return handle_egress_return(ctx, ip6, data_end);

	if (ip6->nexthdr != EDGE_IPPROTO_TCP && ip6->nexthdr != EDGE_IPPROTO_UDP)
		return XDP_PASS;

	return handle_forward(ctx, ip6, (void *) (ip6 + 1), ip6->nexthdr, data_end);
}

char _license[] SEC("license") = "GPL";
