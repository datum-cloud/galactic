//go:build ignore

// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// usid.c implements the TC-BPF ingress datapath for the uFMT 48+16 SRv6 uSID
// carrier format.
//
// Packet path. Every lookup is an exact hash match; nothing here matches looser
// than a full /64, and none of the lookup maps below is an LPM trie:
//
//  1. Parse the outer Ethernet and IPv6 header, bounds-checked. Not IPv6, or
//     too short to parse: TC_ACT_UNSPEC, handed to the next tc filter
//     unmodified.
//  2. Exact-match the destination's top 64 bits, Block and Node-ID read with no
//     shift, against locator_table. No match: TC_ACT_UNSPEC.
//  3. Read Function from the unmutated packet at its fixed offset.
//  4. Exact-match (Block, Function) against function_table. No match: drop,
//     counted, because step 2 already claimed this packet and passing it
//     through would duplicate-deliver it to the normal stack. A match whose
//     behavior is not End.DT46 is dropped and counted separately rather than
//     falling through: the two Function values are independent service
//     universes, so a DT2 entry reaching the steps below would parse an L2
//     frame as an inner IP packet.
//  5. Read Argument from the unmutated packet at its fixed offset. Argument
//     0x000 is reserved and never registered, so it always misses step 6 and
//     needs no special case.
//  6. Exact-match (Block, Argument) against vrf_table. No match: drop, counted.
//     Per-Argument counters are updated on every match reaching this step.
//     They count packets claimed, not forwarded: a claimed packet can still be
//     dropped by steps 7 through 9, which also bumps that entry's
//     dropped_packets, so packets minus dropped_packets is what left via step
//     9.
//  7. Strip the outer IPv6 header, exposing the inner IPv4 or IPv6 packet.
//  8. bpf_fib_lookup against the resolved Linux VRF table, scoped to that
//     table exactly as the kernel's own End.DT46 does.
//  9. Redirect to the resolved egress interface: bpf_redirect_peer for a veth
//     attachment, whose container-side peer is in another namespace, or plain
//     bpf_redirect for a tap, which already sits in this namespace. Which one
//     comes from vrf_table's egress_kind, set at registration time.
//
// This file depends on no libbpf headers. It declares only the helpers it
// calls, using the enum constants from the system's <linux/bpf.h>, and defines
// its own minimal header structs. That keeps the build's only external
// dependency on the kernel headers package and keeps the wire-format
// assumptions visible in one file.
//
// Compiled with CO-RE through BTF. It reads no unstable kernel-internal struct
// fields, so it needs no vmlinux.h: every packet field it touches is stable
// wire-format bytes read through bounds-checked pointer arithmetic.
//
// The ELF license section is a kernel-required declaration that gates which
// helpers the verifier allows. bpf_fib_lookup, called below, is GPL-only, and
// the verifier accepts only a fixed whitelist of strings, which this file's own
// SPDX identifier is not on. Declaring it verbatim makes the program fail to
// load, so "GPL" is declared instead. That section governs helper access and
// says nothing about the licensing of the surrounding project.

#include <linux/bpf.h>

// The fixed-width integer types all come transitively from <linux/bpf.h>; no
// separate include or typedef is needed.

// ---------------------------------------------------------------------
// Minimal BTF-map-definition and section macros (the same idiom used by
// libbpf and every modern eBPF loader, including cilium/ebpf; reproduced
// here directly rather than vendored, since it is a few generic lines with
// no meaningful creative content of its own).
// ---------------------------------------------------------------------

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define USID_ALWAYS_INLINE inline __attribute__((always_inline))

// USID_OFFSETOF reproduces offsetof, which is not otherwise available since
// this file includes no headers beyond <linux/bpf.h>.
#define USID_OFFSETOF(type, member) ((__u32) (unsigned long) &((type *) 0)->member)

// ---------------------------------------------------------------------
// BPF helper function declarations. Only the helpers this program calls
// are declared, using the enum bpf_func_id constants from the system's
// <linux/bpf.h> (BPF_FUNC_map_lookup_elem, etc.) rather than hardcoded
// helper IDs.
// ---------------------------------------------------------------------

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;

// Called once, unconditionally, at the top of usid_ingress. See its call site
// for why a defensive linearization pass runs before any direct packet read.
static long (*bpf_skb_pull_data)(struct __sk_buff *skb, __u32 len) = (void *) BPF_FUNC_skb_pull_data;

static long (*bpf_skb_adjust_room)(struct __sk_buff *skb, __s32 len_diff, __u32 mode,
				    __u64 flags) = (void *) BPF_FUNC_skb_adjust_room;

// Clears the outer transit VLAN off a decapsulated packet. A helper is needed
// rather than zeroing a field: skb->vlan_tci is not writable from BPF, and the
// tag lives there rather than in packet data whenever the NIC strips it on
// receive. See its call site in step 7.
static long (*bpf_skb_vlan_pop)(struct __sk_buff *skb) = (void *) BPF_FUNC_skb_vlan_pop;

// Used only on the IPv4-inner decap path, to retag skb->protocol. See step 7
// for why a helper is needed rather than a plain assignment.
static long (*bpf_skb_change_proto)(struct __sk_buff *skb, __be16 proto,
				     __u64 flags) = (void *) BPF_FUNC_skb_change_proto;

static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, __s32 plen,
			       __u32 flags) = (void *) BPF_FUNC_fib_lookup;

// Step 9 calls one of these two, chosen per entry through vrf_table's
// egress_kind: bpf_redirect_peer for a veth attachment, which crosses into the
// peer's namespace, and bpf_redirect for a tap, which does not.
static long (*bpf_redirect_peer)(__u32 ifindex, __u64 flags) = (void *) BPF_FUNC_redirect_peer;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *) BPF_FUNC_redirect;

static __u64 (*bpf_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;

// vip_xlat_table's rewrite is a genuine address and port substitution with no
// checksum-neutral shortcut, so it needs the incremental L4 checksum update any
// stateful NAT uses. Available here because both programs are TC-BPF with a
// real sk_buff, unlike an XDP context, which needs the heavier checksum-diff
// approach.
static long (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to,
				    __u64 flags) = (void *) BPF_FUNC_l4_csum_replace;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len,
				    __u64 flags) = (void *) BPF_FUNC_skb_store_bytes;

// Two checksum flags reproduced as plain constants, for the same reason as the
// TC verdict and address-family constants below: avoiding a second header
// dependency.
#define USID_BPF_F_PSEUDO_HDR (1U << 4)
#define USID_BPF_F_MARK_MANGLED_0 (1U << 5)

// ---------------------------------------------------------------------
// TC verdicts, reproduced as plain constants to avoid pulling in that header's
// transitive netlink dependencies for three integers.
// ---------------------------------------------------------------------

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_REDIRECT 7

// ---------------------------------------------------------------------
// Address-family constants. Fixed kernel ABI.
// ---------------------------------------------------------------------

#define USID_AF_INET 2
#define USID_AF_INET6 10

#define USID_ETH_P_IP 0x0800
#define USID_ETH_P_IPV6 0x86DD

// IPv6 Next Header values naming an inner IPv4 or IPv6 packet directly, that
// is, with no extension header between the outer uSID header and the real inner
// packet. Fixed kernel ABI.
#define USID_IPPROTO_IPIP 4
#define USID_IPPROTO_IPV6 41

// Transport protocol numbers, needed for the vip_xlat_table lookup. TCP and UDP
// place source and destination port at the same offset, so one struct covers
// both for the fields this file touches.
#define USID_IPPROTO_TCP 6
#define USID_IPPROTO_UDP 17

// TCP checksum field offset (bytes 16-17 of a TCP header); UDP's is at
// bytes 6-7. Used only by apply_vip_xlat's bpf_l4_csum_replace calls.
#define USID_TCP_CSUM_OFFSET 16
#define USID_UDP_CSUM_OFFSET 6

// USID_EGRESS_HOP_LIMIT is the hop limit usid_egress writes into the outer
// header it pushes. A fixed default rather than a copy of the inner packet's
// own: the outer header only needs to survive the underlay's hop count, not
// mirror whatever budget the original sender chose.
#define USID_EGRESS_HOP_LIMIT 64

// USID_L3_OFFSET is the fixed byte offset of the IPv6 header from skb->data, a
// compile-time constant.
//
// apply_vip_xlat's offset arguments must be constant-derived like this rather
// than computed by pointer subtraction. bpf_skb_store_bytes invalidates the
// verifier's tracked bounds on every previously derived packet pointer, and a
// scalar produced by subtracting two packet pointers loses precise range
// tracking across that boundary, which then fails the bounds check on the next
// dereference after the call.
#define USID_L3_OFFSET (sizeof(struct usid_ethhdr))

// ---------------------------------------------------------------------
// Minimal, self-contained header structs, byte-exact to the wire formats.
// Hand-rolled so this file has exactly one external header dependency.
// ---------------------------------------------------------------------

struct usid_ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
} __attribute__((packed));

// struct usid_ip6hdr is deliberately not the kernel's bitfield-based ipv6hdr,
// whose version and traffic-class layout is endian-dependent. This program
// never reads those fields, so vtc_flow stays an opaque 4-byte blob.
struct usid_ip6hdr {
	__u8 vtc_flow[4];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
} __attribute__((packed));

// struct usid_l4ports mirrors the first 4 bytes a TCP and a UDP header share,
// the source and destination ports, which are the only L4 fields the rewrite
// touches directly. The checksum is updated through a helper rather than as a
// struct field, since its offset differs between the two protocols.
struct usid_l4ports {
	__be16 source;
	__be16 dest;
} __attribute__((packed));

struct usid_iphdr {
	__u8 ver_ihl;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__u8 saddr[4];
	__u8 daddr[4];
} __attribute__((packed));

// ---------------------------------------------------------------------
// Map value types.
// ---------------------------------------------------------------------

// struct locator_value is locator_table's value. generation is 64-bit because
// userspace stamps it with a nanosecond-resolution monotonic reading, which
// overflows 32 bits in seconds. This program never reads it: the lookup only
// tests the returned pointer for a match.
struct locator_value {
	__u64 generation;
};

// struct function_value is function_table's value. End.DT46 is the only
// behavior this program implements; End.DT2 is reserved for a future L2 path.
// Step 4 reads this field only to reject anything that is not End.DT46.
enum function_behavior {
	BEHAVIOR_END_DT46 = 1,
	BEHAVIOR_END_DT2 = 2,
};

struct function_value {
	__u32 behavior;
};

// enum egress_kind selects which redirect helper step 9 uses for an entry's
// resolved egress interface. EGRESS_KIND_VETH, the zero value, uses
// bpf_redirect_peer; EGRESS_KIND_TAP uses plain bpf_redirect, since a tap
// device never has a namespace-crossing peer.
enum egress_kind {
	EGRESS_KIND_VETH = 0,
	EGRESS_KIND_TAP = 1,
};

// struct vrf_value is vrf_table's value: the Linux VRF table ID this Argument
// resolves to, per-Argument counters, an egress_kind, and a generation.
//
// generation is written only by userspace, at registration time, and never read
// here. It lets the GC sweep tell "existed before this sweep's snapshot" from
// "registered after", so a registration landing mid-sweep is never reaped.
//
// bytes is bumped by skb->len as read at step 6, before the strip, so it counts
// the whole tunneled frame including the outer header and Ethernet, not the
// inner payload that reaches the egress interface.
//
// dropped_packets counts packets that matched this entry, bumping packets, but
// were then dropped by steps 7 through 9 rather than forwarded. packets alone
// is a claimed count, and packets minus dropped_packets is what actually left.
// Without it, a VRF dropping everything still shows healthy per-Argument
// counters, since drop_reasons has no Block or Argument dimension.
//
// egress_kind occupies what was an alignment pad, and generation and
// dropped_packets are placed last, so every other field keeps its offset.
struct vrf_value {
	__u32 vrf_table_id;
	__u32 egress_kind;
	__u64 packets;
	__u64 bytes;
	__u64 last_seen_ns;
	__u64 generation;
	__u64 dropped_packets;
};

// ---------------------------------------------------------------------
// Per-VRF stateless NPTv6 and the VIP-boundary substitution. Both are consulted
// from two places: usid_ingress, inbound, after the strip and before the FIB
// lookup, using the (block, argument) steps 2 through 6 already resolved; and
// usid_egress, outbound, on a tenant's not-yet-encapsulated reply, intercepted
// per attachment. See usid_egress's header comment for why that attach point is
// the only one that can resolve the sending VRF unambiguously.
// ---------------------------------------------------------------------

// struct ifindex_vrf_value is ifindex_vrf_table's value: the (Block, Argument)
// the attachment on this ifindex belongs to. usid_egress runs on plain,
// not-yet-encapsulated traffic and has no outer destination to decode them
// from, so they are written once per attachment at CNI ADD time, keyed by that
// attachment's host-side ifindex, and removed at DEL.
struct ifindex_vrf_value {
	__u64 block;
	__u16 argument;
};

// struct nptv6_value is nptv6_table's value: one VRF's RFC 6296 mapping. The
// prefixes are zero-padded beyond prefix_len, as the control-plane side
// assumes. adjustment is the precomputed RFC 6296 value, in host-endian layout
// like every other non-wire field here, since it is never copied onto the
// wire.
struct nptv6_value {
	__u8 ula_prefix[16];
	__u8 public_prefix[16];
	__u8 prefix_len;
	__u16 adjustment;
};

// struct vip_xlat_key keys vip_xlat_table. block and argument identify the
// tenant VRF, kept as separate fields rather than pre-folded because a struct
// key has room to carry proto and port as well.
//
// port's meaning is direction-dependent: the ingress lookup keys on the
// packet's destination port, the VIP port a client dialed, and the egress
// lookup on its source port, the backend's real port. Each binding writes one
// row under each key.
//
// direction disambiguates those two rows when their ports coincide, which is
// ordinary rather than rare: a binding keeping port 80 on both sides would
// otherwise collapse them into one entry, and registering the second would
// silently overwrite the first, leaving traffic correctly matched at the edge
// and undeliverable at the backend. usid_ingress always builds its key with the
// ingress direction and usid_egress with the egress one.
//
// The trailing pad2 exists only to remove the struct's compiler-inserted
// padding. block's alignment rounds the struct to 16 bytes while the named
// members account for 14, and C zero-initializes an omitted named member but
// says nothing about true padding, which clang's BPF backend does not zero. The
// lookup then reads all 16 key bytes and the verifier rejects the two never
// written as an invalid stack read. Naming them as a member makes them an
// ordinary omitted-member zero.
#define USID_VIP_XLAT_DIR_INGRESS 0
#define USID_VIP_XLAT_DIR_EGRESS 1

struct vip_xlat_key {
	__u64 block;
	__u16 argument;
	__u8 proto;
	__u8 direction;
	__be16 port;
	__u16 pad2;
};

// struct vip_xlat_value is vip_xlat_table's value. Unlike nptv6_value this is a
// genuine substitution with no reserved bits to absorb a checksum-neutral
// adjustment into, so applying it needs an incremental checksum update rather
// than a plain add or subtract. addr and port are stored in wire byte order,
// since both are copied and diffed directly against packet bytes.
struct vip_xlat_value {
	__u8 addr[16];
	__be16 port;
};

// ---------------------------------------------------------------------
// TC-BPF egress-routing extension: an in-program header push replacing kernel
// SEG6 lwtunnel encapsulation, which reuses one dst_cache per route across its
// input and output resolution paths and returns a stale cached result once
// those contexts differ, as they do under per-tenant VRFs.
//
// A plain tunnel-header prepend, not a general SRH pusher: every call site
// installs exactly one segment, and the reduced encap mode already omits the
// SRH for that case, which is the shape usid_ingress's decap side requires.
// ---------------------------------------------------------------------

// struct egress_route_key is egress_route_table's LPM trie key.
//
// Keyed on the Linux VRF table ID rather than (block, argument): every Go-side
// caller already holds the table ID, that being the identity BGP path
// processing and shard resolution are scoped by, and none of them resolves a
// uSID identity at all. This program has no direct route from its own
// per-attachment identity to a table ID either, so it takes one extra vrf_table
// lookup rather than teaching a second, redundant identity scheme to two maps.
//
// family separates an IPv4 prefix from an IPv6 one whose leading bytes
// coincide, for instance a zero-extended IPv4 /24 against an IPv6 prefix with
// the same first four bytes. It sits inside the matched region and is always
// matched in full, so two entries can compare equal on address bits only once
// table_id and family already match exactly.
//
// prefixlen is in bits, per the trie's convention: at least 40 for the fixed
// table_id and family portion, up to 168 for a full IPv6 host route or 72 for a
// full IPv4 one.
//
// Packed, unlike the structs above. A trie compares only the first prefixlen
// bits, so trailing padding could not affect a lookup either way, but packing
// makes the byte layout this comment's bit offsets depend on unambiguous rather
// than incidental.
struct egress_route_key {
	__u32 prefixlen;
	__u32 table_id;
	__u8 family;
	__u8 addr[16];
} __attribute__((packed));

// The two values egress_route_key.family takes. Deliberately not the kernel's
// real address-family constants, which are sized and spaced for a different
// purpose: this field only disambiguates two prefixes within this map and names
// no address family to any kernel API.
#define USID_EGRESS_ROUTE_FAMILY_INET6 0
#define USID_EGRESS_ROUTE_FAMILY_INET4 1

// struct egress_route_value is egress_route_table's value: the SID to
// encapsulate toward, plus the precomputed link and L2 information needed to
// deliver that encapsulated packet.
//
// The link and L2 information is resolved by the Go control plane at
// registration time rather than by a per-packet bpf_fib_lookup here. That would
// be simpler and self-healing, but it does not work: a lookup from this
// program's attach point, the tenant's VRF-enslaved veth, unconditionally
// returns BPF_FIB_LKUP_RET_BLACKHOLE for a main-table destination that resolves
// fine outside BPF. With and without the direct and table-ID flags, and with
// fib_params.ifindex set to both skb->ifindex and a neutral non-enslaved index,
// all four combinations blackhole identically. That is the kernel's VRF and
// l3mdev isolation boundary asserting itself against the attaching skb's real
// device, independent of any lookup parameter.
//
// link_ifindex == 0 is a reserved sentinel meaning local pass-through: the
// entry exists only to win the longest-prefix lookup over a shorter one, in
// practice a VRF's ::/0 NAT66 default, and not to encapsulate anything.
// usid_egress checks for it and defers to the kernel before doing any encap
// work, as it already does for multicast and link-local destinations. 0 is
// never a legitimate ifindex, so it collides with no real registration.
//
// Such an entry is installed for every attachment's IPAM-assigned prefix at CNI
// ADD time. Without it, two attachments sharing a VRF on one node have the
// connected route between them hijacked by the ::/0 default, the same shape as
// the multicast carve-out below but for ordinary unicast peers.
struct egress_route_value {
	__u8 sid[16];
	__u32 link_ifindex;
	__u8 dmac[6];
	__u8 smac[6];
} __attribute__((packed));

// ---------------------------------------------------------------------

// enum drop_reason indexes drop_reasons, which is observability only.
enum drop_reason {
	DROP_REASON_UNKNOWN_FUNCTION = 0,
	DROP_REASON_UNKNOWN_ARGUMENT = 1,
	DROP_REASON_MALFORMED_INNER = 2,
	DROP_REASON_UNKNOWN_INNER_VERSION = 3,
	DROP_REASON_STRIP_FAILED = 4,
	DROP_REASON_FIB_LOOKUP_FAILED = 5,
	DROP_REASON_REDIRECT_FAILED = 6,
	DROP_REASON_FIB_NO_NEIGH = 7,
	DROP_REASON_FIB_UNREACHABLE = 8,
	DROP_REASON_FIB_FRAG_NEEDED = 9,
	// The outer next header names neither IPIP nor IPv6-in-IPv6, so an
	// extension header sits between the outer header and the real inner
	// packet and byte 40 is that header, not a version nibble. Counted apart
	// from UNKNOWN_INNER_VERSION, which it would otherwise fold into.
	DROP_REASON_UNEXPECTED_NEXTHDR = 10,
	// function_table matched, but the entry's behavior is not End.DT46, that
	// is, it is the L2 behavior this program does not implement. See step 4.
	DROP_REASON_UNSUPPORTED_BEHAVIOR = 11,
	// egress_route_table matched, so a route was configured, but growing room
	// for the new outer header failed. Essentially never expected, since the
	// same helper's shrink direction is trusted unconditionally on the ingress
	// side, and kept as its own reason so it is visible if it ever fires.
	DROP_REASON_EGRESS_ROUTE_ENCAP_FAILED = 12,
	// Unused. An earlier egress path resolved the matched SID's next hop with
	// its own per-packet FIB lookup and counted that failing. That does not
	// work from this attach point at all, for the reason struct
	// egress_route_value gives, and was replaced by Go-side precomputation,
	// which has nothing left to fail at packet time. Kept rather than
	// renumbering every slot after it.
	DROP_REASON_EGRESS_ROUTE_FIB_LOOKUP_FAILED = 13,
	// The redirect out the resolved physical interface failed.
	DROP_REASON_EGRESS_ROUTE_REDIRECT_FAILED = 14,
	// public_uplink_table matched, but the redirect to the resolved
	// fabric-uplink interface failed. See struct public_uplink_value.
	DROP_REASON_PUBLIC_UPLINK_REDIRECT_FAILED = 15,
	// TEMPORARY diagnostic checkpoints, not counted drops: markers of how far
	// usid_egress's egress-routing extension got. Remove once resolved.
	DROP_REASON_TRACE_MULTICAST_LL_BAIL = 16,
	DROP_REASON_TRACE_MISS_VRF = 17,
	DROP_REASON_TRACE_MISS_ROUTE = 18,
	DROP_REASON_TRACE_PASSTHROUGH_ENTRY = 19,
	DROP_REASON_TRACE_ADJUST_ROOM_OK = 20,
	DROP_REASON_TRACE_REACHED_REDIRECT = 21,
	DROP_REASON_TRACE_REDIRECT_OK = 22,
	// bpf_trace_printk is unavailable to this program type on this kernel, so
	// this checkpoint covers the one early return in usid_egress's entry
	// sequence that the checkpoints below do not: the ifindex_vrf_table miss
	// immediately above.
	DROP_REASON_TRACE_IFINDEX_MISS = 23,
	// Full entry-sequence bracketing. usid_egress's prefix has four more early
	// returns with no counter, so these close every remaining gap and
	// "nothing incremented" can no longer mean either "never invoked" or
	// "always took an uninstrumented path".
	DROP_REASON_TRACE_ENTRY = 24,
	DROP_REASON_TRACE_PULL_DATA_FAILED = 25,
	DROP_REASON_TRACE_ETH_BOUNDS_FAILED = 26,
	DROP_REASON_TRACE_ETHERTYPE_MISMATCH = 27,
	DROP_REASON_TRACE_IFINDEX_HIT = 28,
	// TEMPORARY diagnostic checkpoints for usid_ingress's steps 8 and 9, the
	// mirror of the egress ones above. Remove once resolved.
	//
	// The ingress path has no success counter, so a packet claimed at step 6
	// and then lost looks exactly like one delivered: the per-entry packets
	// counter moves, no drop counter moves, and nothing separates the two. On
	// a live tap attachment, packets moved by the number sent, dropped_packets
	// stayed flat, and the target tap's own transmit counter stayed flat, so
	// the packet was neither dropped here nor delivered.
	//
	// Everything between step 6 and the redirect is already counted, so what
	// remains is the redirect and what the kernel does with it after this
	// program returns. That discard happens post-return with nothing here able
	// to observe it, which a zero or otherwise unusable resolved ifindex would
	// cause.
	DROP_REASON_TRACE_ING_REACHED_REDIRECT = 29,
	DROP_REASON_TRACE_ING_REDIRECT_OK = 30,
	// Not a counter: set to the ifindex the FIB lookup resolved, so the
	// redirect target is observable rather than inferred. Read as a value.
	DROP_REASON_TRACE_ING_LAST_IFINDEX = 31,
	// A real drop, not a trace: the FIB lookup returned success with an
	// ifindex that cannot be redirected to. It sits in the temporary block
	// only to avoid renumbering the slots around it, which the Go mirror and
	// the lab tool's name table both key off, and should move into the real
	// block when those slots are removed.
	DROP_REASON_FIB_NO_IFINDEX = 32,
	// TEMPORARY, the ingress mirror of the egress entry-sequence checkpoints
	// above and added for the same reason: usid_ingress's entry sequence has
	// five exits with no counter, so "nothing incremented" cannot distinguish
	// "never invoked" from "always took an uninstrumented path".
	//
	// Two of the five are live hypotheses rather than completeness for its own
	// sake. ETHERTYPE_MISMATCH is where a VLAN tag left in packet data by a NIC
	// that does not strip it would land, silently. LOCATOR_MISS is where a
	// Block or Node-ID not matching this node's registration would land,
	// equally silently, and it is the one miss in the lookup chain with no
	// counter of its own.
	//
	// drop_reasons is a per-CPU array, so the unconditional entry counter is a
	// per-CPU increment with no cross-CPU contention, on a program that already
	// runs for every packet arriving on the fabric NICs.
	DROP_REASON_TRACE_ING_ENTRY = 33,
	DROP_REASON_TRACE_ING_PULL_DATA_FAILED = 34,
	DROP_REASON_TRACE_ING_ETH_BOUNDS_FAILED = 35,
	DROP_REASON_TRACE_ING_ETHERTYPE_MISMATCH = 36,
	DROP_REASON_TRACE_ING_IP6_BOUNDS_FAILED = 37,
	DROP_REASON_TRACE_ING_LOCATOR_MISS = 38,
	__DROP_REASON_MAX,
};

// ---------------------------------------------------------------------
// Maps. All three uSID lookup maps are hash maps, never LPM tries, since every
// uSID lookup is a fixed-width exact match rather than a prefix match.
//
// Keys are plain u64 exact-match keys, matching the control plane's own key
// composition:
//   locator_key  = top 8 bytes of the destination address, as-is.
//   function_key = Block << 4 | Function, 52 significant bits. Block and
//                  Function are never adjacent in the wire address, with
//                  Node-ID between them, so this is composed from two
//                  independently read values.
//   vrf_key      = Block << 12 | Argument, 60 significant bits, composed the
//                  same way.
// ---------------------------------------------------------------------

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64); // R7: more than one concurrent uSID Block.
	__type(key, __u64);
	__type(value, struct locator_value);
} locator_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128); // one entry per (active Block x defined Function).
	__type(key, __u64);
	__type(value, struct function_value);
} function_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	// One uSID Block caps at 4,095 usable Argument values, and a
	// make-before-break migration needs up to twice that per Block. 8192 covers
	// one Block's worst case with headroom, that is, roughly two Blocks' worth
	// of Argument space rather than the format's full Block range that
	// locator_table and function_table already support. A third concurrent
	// Block exhausts this map at registration time, surfacing as a failed CNI
	// ADD rather than a datapath drop.
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct vrf_value);
} vrf_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, __DROP_REASON_MAX);
	__type(key, __u32);
	__type(value, __u64);
} drop_reasons SEC(".maps");

// ifindex_vrf_table: see struct ifindex_vrf_value. Sized above vrf_table
// because it holds one row per attachment, potentially several per VRF, not one
// per VRF.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32); // ifindex
	__type(value, struct ifindex_vrf_value);
} ifindex_vrf_table SEC(".maps");

// nptv6_table: one row per VRF with NPTv6 configured, keyed like vrf_table.
// usid_ingress already holds that key locally, and usid_egress resolves it
// through ifindex_vrf_table.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct nptv6_value);
} nptv6_table SEC(".maps");

// vip_xlat_table: see struct vip_xlat_key's comment above.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct vip_xlat_key);
	__type(value, struct vip_xlat_value);
} vip_xlat_table SEC(".maps");

// egress_route_table: see struct egress_route_key. The only LPM trie in this
// file. Everything above is a hash map because uSID decode is always a
// fixed-width exact match, but egress routing is inherently a longest-prefix
// problem: an intra-VPC peer's specific prefix must win over a VRF's ::/0
// default. BPF_F_NO_PREALLOC is required by the kernel for this map type, not a
// tuning choice.
//
// Sized well above vrf_table because it holds routes, not VRFs: one VRF can
// have several peer entries plus a default, so entries per VRF are not 1:1.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 32768);
	__type(key, struct egress_route_key);
	__type(value, struct egress_route_value);
} egress_route_table SEC(".maps");

// node_src_addr_table: this node's underlay-facing source address, the value
// usid_egress writes into the outer header it pushes. A per-node constant
// rather than a per-route one, hence a single-entry array rather than a field
// on every egress_route_table entry, which would mean every route carrying the
// same 16 bytes and the Go writer needing this node's address just to register
// an unrelated destination. Rewritten idempotently on every CNI ADD, since it
// is cheap and there is no once-per-node hook.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[16]);
} node_src_addr_table SEC(".maps");

// struct public_uplink_value is public_uplink_table's value: this node's
// fabric-uplink next hop, the link index to redirect out plus the destination
// and source MAC needed to reach it. Resolved Go-side, the same
// resolve-at-registration, redirect-blindly-at-packet-time pattern
// egress_route_value uses and for the same reason: a live FIB lookup from this
// program's attach point unconditionally blackholes, so there is no way to
// resolve this per packet from inside usid_egress.
//
// Used by usid_egress's VIP-sourced-reply handling. Once apply_vip_xlat has
// rewritten a packet's source from a DSR backend's real address to its
// binding's VIP, a globally routable, BGP-advertised address needing no further
// translation, that packet must never reach egress_route_table's lookup: in a
// VRF with NAT66 configured, the ::/0 default would treat it as an ordinary
// ULA-sourced tenant packet and re-translate it through a shard, and the client
// discards the reply as unrecognised.
//
// It is redirected here instead, whatever its own destination. The single
// neighbor one hop off this node's fabric interface is always the correct next
// hop for a plainly routable packet, the same property a host's default gateway
// has, and ordinary routing takes over from there.
struct public_uplink_value {
	__u32 link_ifindex;
	__u8 dmac[6];
	__u8 smac[6];
};

// public_uplink_table: see struct public_uplink_value. A single-entry array
// matching node_src_addr_table's per-node lifecycle and key convention. A
// separate map rather than a field on that one, since the value shape differs
// entirely and the two are read at different points for different reasons.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct public_uplink_value);
} public_uplink_table SEC(".maps");

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

static USID_ALWAYS_INLINE void count_drop(__u32 reason)
{
	__u64 *count = bpf_map_lookup_elem(&drop_reasons, &reason);

	if (count)
		__sync_fetch_and_add(count, 1);
}

// record_value overwrites a drop_reasons slot instead of incrementing it, for
// the temporary slots documented as values rather than counts. A counter cannot
// carry an ifindex, and a second map would need its own pinning and
// control-plane wiring for a slot that exists only until this investigation
// closes.
static USID_ALWAYS_INLINE void record_value(__u32 slot, __u64 value)
{
	__u64 *cell = bpf_map_lookup_elem(&drop_reasons, &slot);

	if (cell)
		*cell = value;
}

// count_claimed_drop is count_drop plus the per-entry dropped_packets bump, for
// every drop after step 6's vrf_table match, that is, every drop of a packet
// already claimed by a specific tenant.
static USID_ALWAYS_INLINE void count_claimed_drop(__u32 reason, struct vrf_value *vrf)
{
	count_drop(reason);
	__sync_fetch_and_add(&vrf->dropped_packets, 1);
}

// read_be64 composes an 8-byte big-endian buffer into a host-native u64 byte by
// byte, rather than casting: p is not guaranteed 8-byte aligned, pointing 38
// bytes into the packet, and some architectures reject unaligned wide loads at
// verification time.
static USID_ALWAYS_INLINE __u64 read_be64(const __u8 *p)
{
	return ((__u64) p[0] << 56) | ((__u64) p[1] << 48) | ((__u64) p[2] << 40) |
	       ((__u64) p[3] << 32) | ((__u64) p[4] << 24) | ((__u64) p[5] << 16) |
	       ((__u64) p[6] << 8) | (__u64) p[7];
}

// apply_nptv6 rewrites addr's first prefix_len bits to the destination prefix,
// public if outbound and ULA otherwise, then adds or subtracts the adjustment
// in the word at byte offset 6. No checksum helper is needed: that is the point
// of the RFC 6296 construction, since the adjustment already offsets the prefix
// change's contribution to the address checksum and the packet's L4 checksum
// stays valid untouched.
static USID_ALWAYS_INLINE void apply_nptv6(__u8 *addr, const struct nptv6_value *v, int outbound)
{
	const __u8 *new_prefix = outbound ? v->public_prefix : v->ula_prefix;
	__u8 full_bytes = v->prefix_len / 8;
	__u8 rem_bits = v->prefix_len % 8;

#pragma unroll
	for (int i = 0; i < 6; i++) { // prefix_len is always <= 48 (6 bytes); see nptv6.prefixLen.
		if (i < full_bytes) {
			addr[i] = new_prefix[i];
		} else if (i == full_bytes && rem_bits != 0) {
			__u8 mask = (__u8) (0xFF << (8 - rem_bits));

			addr[i] = (__u8) ((new_prefix[i] & mask) | (addr[i] & ~mask));
		}
	}

	__be16 *word = (__be16 *) &addr[6];
	__u16 cur = __builtin_bswap16(*word);
	__u32 sum = outbound ? ((__u32) cur + v->adjustment) : ((__u32) cur + (__u16) ~v->adjustment);

	if (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	*word = __builtin_bswap16((__u16) sum);
}

// apply_vip_xlat rewrites the 16-byte address at addr_off and the 2-byte port
// at port_off to new_val's, fixing up the L4 checksum at csum_off with
// incremental replace calls: the address as pseudo-header words, the port
// directly, since a port is a real L4 header field. Unlike apply_nptv6 this is
// a genuine substitution with no checksum-neutral shortcut.
//
// is_udp preserves a zero UDP checksum, which means "no checksum", as zero
// rather than fixing it into a spurious nonzero value. TCP has no such
// convention, so that flag is only ever passed for UDP.
static USID_ALWAYS_INLINE long apply_vip_xlat(struct __sk_buff *skb, __u32 addr_off, __u32 port_off,
					       __u32 csum_off, __u8 proto, const __u8 *old_addr,
					       __be16 old_port, const struct vip_xlat_value *new_val)
{
	// The checksum helper's field-size mask accepts only 2 or 4 bytes, with no
	// 8-byte case at all, so an 8-byte-at-a-time replace fails with EINVAL. The
	// 16-byte address is updated as four 4-byte words.
	//
	// Every packet and map read this function needs happens before the first
	// helper call, into plain scalar locals, and the calls below touch only
	// those locals. Both the checksum-replace and store helpers invalidate
	// every previously derived packet pointer, old_addr included, since it
	// points into this same packet rather than being a copy. Interleaving reads
	// and calls is rejected outright by the verifier.
	__u32 from_w[4], to_w[4];
#pragma unroll
	for (int i = 0; i < 4; i++) {
		__builtin_memcpy(&from_w[i], old_addr + i * 4, 4);
		__builtin_memcpy(&to_w[i], new_val->addr + i * 4, 4);
	}
	// The ports are passed as-is, with no byte swap. Unlike apply_nptv6's
	// arithmetic on a word, which needs host order, the checksum helper's
	// from and to are a raw "what used to be there, what is there now" pair in
	// the same wire order the address words use.
	__be16 new_port = new_val->port;

	__u64 flags = USID_BPF_F_PSEUDO_HDR | 4;
	__u32 is_udp = proto == USID_IPPROTO_UDP;
	__u64 csum_flags = flags | (is_udp ? USID_BPF_F_MARK_MANGLED_0 : 0);

#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (bpf_l4_csum_replace(skb, csum_off, (__u64) from_w[i], (__u64) to_w[i], csum_flags))
			return -1;
	}
	if (bpf_l4_csum_replace(skb, csum_off, (__u64) old_port,
				 (__u64) new_port, 2 | (is_udp ? USID_BPF_F_MARK_MANGLED_0 : 0)))
		return -1;

	// Store from the locals snapshotted above rather than from new_val
	// directly. new_val is a map-value pointer, not a packet pointer, so it is
	// not subject to the same invalidation, but using the locals already in
	// hand removes any doubt.
	if (bpf_skb_store_bytes(skb, addr_off, to_w, 16, 0))
		return -1;
	if (bpf_skb_store_bytes(skb, port_off, &new_port, 2, 0))
		return -1;
	return 0;
}

// ---------------------------------------------------------------------
// Program
// ---------------------------------------------------------------------

SEC("tc")
int usid_ingress(struct __sk_buff *skb)
{
	// Defensive linearization. Every read below is a direct data pointer
	// access, so a non-linear skb would fail its bounds check and misreport as
	// a malformed inner packet instead of actually being malformed. Pulling the
	// whole packet into the linear area up front makes every read below safe
	// whatever the arriving layout.
	//
	// A failure is treated as "not applicable to us": hand off to the next tc
	// filter unmodified rather than drop traffic this program has not yet
	// determined is a uSID packet. TC_ACT_UNSPEC, not TC_ACT_OK; see the note
	// below step 2.
	count_drop(DROP_REASON_TRACE_ING_ENTRY); // TEMPORARY

	if (bpf_skb_pull_data(skb, 0)) {
		count_drop(DROP_REASON_TRACE_ING_PULL_DATA_FAILED); // TEMPORARY
		return TC_ACT_UNSPEC;
	}

	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;

	// Step 1: parse the outer Ethernet and IPv6 header, bounds-checked. Not a
	// match: hand off unmodified. See the note below step 2.
	struct usid_ethhdr *eth = data;

	if ((void *) (eth + 1) > data_end) {
		count_drop(DROP_REASON_TRACE_ING_ETH_BOUNDS_FAILED); // TEMPORARY
		return TC_ACT_UNSPEC;
	}

	if (eth->h_proto != __builtin_bswap16(USID_ETH_P_IPV6)) {
		count_drop(DROP_REASON_TRACE_ING_ETHERTYPE_MISMATCH); // TEMPORARY
		return TC_ACT_UNSPEC;
	}

	struct usid_ip6hdr *ip6 = (void *) (eth + 1);

	if ((void *) (ip6 + 1) > data_end) {
		count_drop(DROP_REASON_TRACE_ING_IP6_BOUNDS_FAILED); // TEMPORARY
		return TC_ACT_UNSPEC;
	}

	// Step 2: exact-match the destination's top 64 bits, Block and Node-ID read
	// with no shift, against locator_table. No match: hand off unmodified.
	//
	// TC_ACT_UNSPEC, not TC_ACT_OK, on every fail-open path through this point.
	// This filter attaches direct-action at a fixed priority, and a cluster CNI
	// may attach its own programs to the same hook. In direct-action mode
	// TC_ACT_OK is a final verdict that ends the filter chain, so a packet this
	// program does not claim would never reach a filter at a later priority.
	// TC_ACT_UNSPEC instead means "not matched here", letting the next filter
	// run as if this program were not attached.
	//
	// Every fail-open path is before this locator match, that is, before the
	// packet has been claimed as one of this node's Blocks. Once claimed, every
	// later failure is TC_ACT_SHOT: this program is the packet's only intended
	// handler past that point, so falling through would misdeliver it rather
	// than merely fail to accelerate it.
	__u64 locator_key = read_be64(&ip6->daddr[0]);

	struct locator_value *loc = bpf_map_lookup_elem(&locator_table, &locator_key);

	if (!loc) {
		count_drop(DROP_REASON_TRACE_ING_LOCATOR_MISS); // TEMPORARY
		return TC_ACT_UNSPEC;
	}

	__u64 block = locator_key >> 16;

	// Step 3: read Function from the unmutated packet at its fixed offset, the
	// high nibble of destination byte 8.
	__u8 fn_arg_byte = ip6->daddr[8];
	__u8 function = fn_arg_byte >> 4;

	// Step 4: exact-match (Block, Function) against function_table. No match:
	// drop, counted, since step 2 already claimed this packet and passing it
	// through would duplicate-deliver it to the normal stack.
	__u64 function_key = (block << 4) | function;

	struct function_value *fn = bpf_map_lookup_elem(&function_table, &function_key);

	if (!fn) {
		count_drop(DROP_REASON_UNKNOWN_FUNCTION);
		return TC_ACT_SHOT;
	}

		// Function 0xE and 0xF are fully independent service universes: an
		// L3 route lookup and an L2 bridge-domain lookup. This program
		// implements only the former, and a DT2 entry falling through would
		// parse an L2 frame as an inner IP packet against the wrong table
		// entirely, so it is rejected here.
	if (fn->behavior != BEHAVIOR_END_DT46) {
		count_drop(DROP_REASON_UNSUPPORTED_BEHAVIOR);
		return TC_ACT_SHOT;
	}

	// Step 5: read Argument from the unmutated packet at its fixed offset, the
	// low nibble of destination byte 8 plus byte 9.
	__u16 argument = ((__u16) (fn_arg_byte & 0x0F) << 8) | ip6->daddr[9];

	// Step 6: exact-match (Block, Argument) against vrf_table. Argument 0x000
	// is reserved and never registered, so it always misses here and needs no
	// special case.
	__u64 vrf_key = (block << 12) | argument;

	struct vrf_value *vrf = bpf_map_lookup_elem(&vrf_table, &vrf_key);

	if (!vrf) {
		count_drop(DROP_REASON_UNKNOWN_ARGUMENT);
		return TC_ACT_SHOT;
	}

	__sync_fetch_and_add(&vrf->packets, 1);
	__sync_fetch_and_add(&vrf->bytes, skb->len);
	vrf->last_seen_ns = bpf_ktime_get_ns();

	__u32 vrf_table_id = vrf->vrf_table_id;

	// The packet is claimed past this point: every failure from here is a drop,
	// never a silent pass-through.
	//
	// The outer next header must name the inner packet's family directly for
	// byte 40 to be the inner version nibble. Any other value means an
	// extension header sits between them, so byte 40 is that header's first
	// byte. Reading it as a version nibble would fold every such packet into
	// UNKNOWN_INNER_VERSION and mask a distinct, actionable failure, so it is
	// checked and counted apart before that peek. The field is already covered
	// by the bounds check above.
	if (ip6->nexthdr != USID_IPPROTO_IPIP && ip6->nexthdr != USID_IPPROTO_IPV6) {
		count_claimed_drop(DROP_REASON_UNEXPECTED_NEXTHDR, vrf);
		return TC_ACT_SHOT;
	}

	// Peek the inner version nibble now, on the still-unmutated outer header:
	// step 7 needs to know the family before it decides how to strip, not
	// after.
	if ((void *) (ip6 + 1) + 1 > data_end) {
		count_claimed_drop(DROP_REASON_MALFORMED_INNER, vrf);
		return TC_ACT_SHOT;
	}

	__u8 *inner_peek = (__u8 *) (ip6 + 1);
	__u8 inner_version = (*inner_peek) >> 4;

	if (inner_version != 4 && inner_version != 6) {
		count_claimed_drop(DROP_REASON_UNKNOWN_INNER_VERSION, vrf);
		return TC_ACT_SHOT;
	}

	// Step 7: strip the outer IPv6 header, exposing the inner IPv4 or IPv6
	// packet.
	//
	// An IPv6 inner packet is a plain 40-byte carve, since outer and inner share
	// skb->protocol.
	//
	// An IPv4 inner packet needs skb->protocol changed, and there is no direct
	// way to do that: the field is not in the context's write whitelist, and a
	// plain assignment is rejected at load. Left stale, step 9's peer redirect
	// hands the skb to the peer namespace through a path that only reassigns
	// the device and scrubs the packet, with no call to re-derive protocol from
	// the Ethernet header this function rewrites. The peer's stack then
	// dispatches an IPv4 payload to the IPv6 receive path, which drops it on
	// the version mismatch, invisibly to every counter here because the packet
	// already left through a successful redirect. The signature is a peer
	// device whose receive counters advance and whose capture shows a
	// well-formed IPv4 frame, while that namespace's IPv6 receive and header
	// error counters advance by the same amount and the pod never sees it.
	//
	// bpf_skb_change_proto is the one legal way to update the field, but it is
	// built for in-place v4/v6 header translation rather than decap. Called
	// here, before any stripping, it removes 20 bytes from the front of the
	// current L3 header, shifts everything after it up to fill the gap, and
	// sets the protocol. That leaves exactly 20 bytes of outer-header remnant
	// in front of the real inner header, which the plain carve below removes,
	// exposing it at offset 0 as in the IPv6 case. Net bytes removed is 40
	// either way; only the protocol side effect differs.
	__s32 strip_len = (__s32) sizeof(struct usid_ip6hdr);

	if (inner_version == 4) {
		if (bpf_skb_change_proto(skb, __builtin_bswap16(USID_ETH_P_IP), 0)) {
			count_claimed_drop(DROP_REASON_STRIP_FAILED, vrf);
			return TC_ACT_SHOT;
		}
		strip_len = (__s32) sizeof(struct usid_iphdr);
	}

	if (bpf_skb_adjust_room(skb, -strip_len, BPF_ADJ_ROOM_MAC, 0)) {
		count_claimed_drop(DROP_REASON_STRIP_FAILED, vrf);
		return TC_ACT_SHOT;
	}

	// Drop the outer transit VLAN, which the decapsulated inner packet must not
	// inherit.
	//
	// When the packet arrives on a VLAN whose tag the NIC strips into skb
	// metadata, the ordinary case, the tag lives in skb->vlan_tci rather than
	// packet data, so the ethertype check above sees IPv6 and the carve never
	// touches it. Stripping the outer header then leaves the tag on a packet it
	// has nothing to do with: it describes the segment the outer packet
	// crossed, while the inner packet is addressed inside a tenant VRF and
	// never belonged to that segment.
	//
	// Carrying it forward breaks step 9 two ways. A tap re-inserts a metadata
	// tag on transmit, so the guest receives a tagged frame it has no VLAN
	// interface to accept; and any other egress program on the resolved
	// interface that filters by VLAN id sees a tag from a segment that
	// interface is not on and may drop the packet, after this program has
	// already returned a redirect verdict and with no counter here to see it.
	//
	// Unconditional and idempotent: with no tag present it is a no-op returning
	// success. Placed immediately after the carve so the pointer re-read below
	// covers this helper's invalidation too.
	//
	// A failure counts as STRIP_FAILED rather than earning its own reason:
	// removing the tag is part of the same carve step, and the only way it
	// fails is the allocation the carve can equally fail on.
	if (bpf_skb_vlan_pop(skb)) {
		count_claimed_drop(DROP_REASON_STRIP_FAILED, vrf);
		return TC_ACT_SHOT;
	}

	// All three of the helpers above can change the underlying packet buffer, so
	// every previously derived pointer is invalid and must be re-read.
	data = (void *) (long) skb->data;
	data_end = (void *) (long) skb->data_end;

	struct usid_ethhdr *new_eth = data;

	if ((void *) (new_eth + 1) > data_end) {
		count_claimed_drop(DROP_REASON_MALFORMED_INNER, vrf);
		return TC_ACT_SHOT;
	}

	__u8 *inner = (__u8 *) (new_eth + 1);
	struct bpf_fib_lookup fib_params;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));

	if (inner_version == 6) {
		struct usid_ip6hdr *inner6 = (void *) inner;

		if ((void *) (inner6 + 1) > data_end) {
			count_claimed_drop(DROP_REASON_MALFORMED_INNER, vrf);
			return TC_ACT_SHOT;
		}

		// Translate the inner packet's destination before the FIB lookup
		// below, so the lookup resolves against the tenant's real, routed
		// address rather than the public or VIP address the client addressed.
		// Both lookups key on (block, argument), already resolved by steps 2
		// through 6, so no per-packet identity resolution is needed here.
		struct nptv6_value *npt = bpf_map_lookup_elem(&nptv6_table, &vrf_key);

		if (npt)
			apply_nptv6(inner6->daddr, npt, 0 /* inbound: public -> ULA */);

			// The VIP substitution needs the inner L4 destination port to key
			// vip_xlat_table, read now, before the strip-relative offsets
			// below are computed. TCP and UDP only; anything else has no port
			// to substitute on.
			//
			// This is the freshly stripped inner header's next-header field,
			// not the outer one checked above, which only ever names the encap
			// format. The outer pointer is invalid here regardless, since the
			// strip can relocate the buffer.
		if (inner6->nexthdr == USID_IPPROTO_TCP || inner6->nexthdr == USID_IPPROTO_UDP) {
			struct usid_l4ports *ports = (void *) (inner6 + 1);

			if ((void *) (ports + 1) <= data_end) {
				struct vip_xlat_key vkey = {
					.block = block, .argument = argument,
					.proto = inner6->nexthdr, .port = ports->dest,
					.direction = USID_VIP_XLAT_DIR_INGRESS,
				};
				struct vip_xlat_value *vv = bpf_map_lookup_elem(&vip_xlat_table, &vkey);

				if (vv) {
					// USID_L3_OFFSET, not a runtime pointer
					// subtraction -- see its own comment for why.
					__u32 csum_off = USID_L3_OFFSET + (inner6->nexthdr == USID_IPPROTO_TCP
									     ? sizeof(struct usid_ip6hdr) + USID_TCP_CSUM_OFFSET
									     : sizeof(struct usid_ip6hdr) + USID_UDP_CSUM_OFFSET);
					__u32 addr_off = USID_L3_OFFSET + USID_OFFSETOF(struct usid_ip6hdr, daddr);
					__u32 port_off = USID_L3_OFFSET + (__u32) sizeof(struct usid_ip6hdr) +
							  USID_OFFSETOF(struct usid_l4ports, dest);

					if (apply_vip_xlat(skb, addr_off, port_off, csum_off, inner6->nexthdr,
							    inner6->daddr, ports->dest, vv)) {
						count_claimed_drop(DROP_REASON_MALFORMED_INNER, vrf);
						return TC_ACT_SHOT;
					}
					// The store calls invalidate every previously derived
					// packet pointer, so re-read and re-derive the inner
					// header the same fixed-offset way it was originally
					// computed rather than through the stale pointer.
					data = (void *) (long) skb->data;
					data_end = (void *) (long) skb->data_end;
					new_eth = data;
					inner6 = (void *) (new_eth + 1);
					if ((void *) (inner6 + 1) > data_end) {
						count_claimed_drop(DROP_REASON_MALFORMED_INNER, vrf);
						return TC_ACT_SHOT;
					}
				}
			}
		}

		fib_params.family = USID_AF_INET6;
		__builtin_memcpy(fib_params.ipv6_src, inner6->saddr, sizeof(fib_params.ipv6_src));
		__builtin_memcpy(fib_params.ipv6_dst, inner6->daddr, sizeof(fib_params.ipv6_dst));
		new_eth->h_proto = __builtin_bswap16(USID_ETH_P_IPV6);

		// fib_params.tot_len is the L3 length the kernel's MTU check compares
		// against the route's MTU, but only when nonzero: left at zero that
		// check is skipped and a fragmentation-needed result can never fire.
		// IPv6 has no total-length field, so this is the fixed 40-byte header
		// plus payload_len, in host order.
		fib_params.tot_len = (__u16) sizeof(struct usid_ip6hdr) +
				     __builtin_bswap16(inner6->payload_len);
	} else {
		struct usid_iphdr *inner4 = (void *) inner;

		if ((void *) (inner4 + 1) > data_end) {
			count_claimed_drop(DROP_REASON_MALFORMED_INNER, vrf);
			return TC_ACT_SHOT;
		}

		fib_params.family = USID_AF_INET;
		__builtin_memcpy(&fib_params.ipv4_src, inner4->saddr, sizeof(fib_params.ipv4_src));
		__builtin_memcpy(&fib_params.ipv4_dst, inner4->daddr, sizeof(fib_params.ipv4_dst));
		new_eth->h_proto = __builtin_bswap16(USID_ETH_P_IP);

		// The same tot_len requirement as the IPv6 branch, except IPv4 carries
		// its own total-length field, in host order, so no arithmetic is
		// needed.
		fib_params.tot_len = __builtin_bswap16(inner4->tot_len);
	}

	fib_params.ifindex = skb->ingress_ifindex;
	fib_params.tbid = vrf_table_id;

	// Step 8: bpf_fib_lookup against the resolved Linux VRF table, an ordinary
	// FIB lookup scoped to that table exactly as the kernel's stock End.DT46
	// does, reached through a dynamic Argument-keyed lookup rather than a
	// static per-address route.
	long fib_rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params),
				      BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_TBID);

	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS) {
		if (fib_rc == BPF_FIB_LKUP_RET_NO_NEIGH)
			count_claimed_drop(DROP_REASON_FIB_NO_NEIGH, vrf);
		else if (fib_rc == BPF_FIB_LKUP_RET_UNREACHABLE || fib_rc == BPF_FIB_LKUP_RET_BLACKHOLE || fib_rc == BPF_FIB_LKUP_RET_PROHIBIT)
			count_claimed_drop(DROP_REASON_FIB_UNREACHABLE, vrf);
		else if (fib_rc == BPF_FIB_LKUP_RET_FRAG_NEEDED)
			// No ICMPv6 Packet Too Big is generated here, unlike the static
			// route path this replaces: an accepted PMTUD gap, recorded in
			// the CNI architecture doc's known constraints.
			count_claimed_drop(DROP_REASON_FIB_FRAG_NEEDED, vrf);
		else
			count_claimed_drop(DROP_REASON_FIB_LOOKUP_FAILED, vrf);
		return TC_ACT_SHOT;
	}

	// TEMPORARY: record the resolved redirect target before using it. A lookup
	// returning success is not required to hand back a usable ifindex, and
	// redirecting to a zero one is a silent post-return discard.
	record_value(DROP_REASON_TRACE_ING_LAST_IFINDEX, (__u64) fib_params.ifindex);

	if (fib_params.ifindex <= 0) {
		count_claimed_drop(DROP_REASON_FIB_NO_IFINDEX, vrf);
		return TC_ACT_SHOT;
	}

	__builtin_memcpy(new_eth->h_dest, fib_params.dmac, sizeof(new_eth->h_dest));
	__builtin_memcpy(new_eth->h_source, fib_params.smac, sizeof(new_eth->h_source));

	// Step 9: redirect to the resolved egress interface.
	//
	// A veth attachment's egress interface is the pod's host-side veth, whose
	// container-side peer is in another namespace, so bpf_redirect_peer is
	// required to cross into it. A tap has no peer at all, being created in this
	// namespace and never moved, so plain bpf_redirect is required instead.
	// bpf_redirect_peer against a tap always fails, which is the tap-mode
	// blackhole this per-entry egress_kind fixes.
	//
	// Unit tests cover egress_kind's control-plane wiring only. A real
	// lookup-then-redirect by egress kind needs a live route and net device
	// that a synthetic program run cannot fabricate, so that part is a
	// live-cluster concern like this file's other FIB-lookup tests.
	long redirect_rc;

	count_drop(DROP_REASON_TRACE_ING_REACHED_REDIRECT); // TEMPORARY

	if (vrf->egress_kind == EGRESS_KIND_TAP)
		redirect_rc = bpf_redirect(fib_params.ifindex, 0);
	else
		redirect_rc = bpf_redirect_peer(fib_params.ifindex, 0);

	if (redirect_rc != TC_ACT_REDIRECT) {
		count_claimed_drop(DROP_REASON_REDIRECT_FAILED, vrf);
		return TC_ACT_SHOT;
	}

	count_drop(DROP_REASON_TRACE_ING_REDIRECT_OK); // TEMPORARY

	return redirect_rc;
}

// usid_egress is usid_ingress's outbound companion. A tenant's outbound traffic
// needs the reverse NPTv6 rewrite and the reverse VIP substitution, both on the
// packet's source, and the tenant VRF's own SRv6 encapsulation, before the
// packet leaves this node.
//
// The attach point is TC ingress of the tenant's own host-side veth or tap, the
// interface usid_ingress's step 9 redirects to, which is the standard
// from-container interception point. At that point the packet is still plain,
// unencapsulated, and per-attachment, so (block, argument) resolves through
// ifindex_vrf_table keyed on skb->ifindex rather than being decoded from packet
// content.
//
// Not the shared fabric interface usid_ingress attaches to. This program's whole
// job is to run before anything has decided how to route the packet onward:
// once it reaches the uplink that decision is made and the SID resolved here
// would have to be undone and redone. There is also nothing at that shared
// point to key a per-sender-VRF lookup on without decoding the inner packet's
// own ULA source address, which can collide across tenants.
//
// This program never claims a packet for its NPTv6 and VIP responsibilities: an
// attachment with neither a mapping nor an active binding is common, so a miss
// on either lookup is not an error. The egress-routing extension is different:
// once egress_route_table has a matching entry, this program is that packet's
// only path off the node, so a failure past that point is a drop rather than a
// pass-through.
SEC("tc")
int usid_egress(struct __sk_buff *skb)
{
	count_drop(DROP_REASON_TRACE_ENTRY);

	if (bpf_skb_pull_data(skb, 0)) {
		count_drop(DROP_REASON_TRACE_PULL_DATA_FAILED);
		return TC_ACT_UNSPEC;
	}

	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;

	struct usid_ethhdr *eth = data;

	if ((void *) (eth + 1) > data_end) {
		count_drop(DROP_REASON_TRACE_ETH_BOUNDS_FAILED);
		return TC_ACT_UNSPEC;
	}

	// NPTv6 and the VIP substitution are IPv6-only by design. The
	// egress-routing extension below is not: IPv4 VPC prefixes have always
	// egressed over this IPv6-only underlay, so an IPv4 packet still reaches
	// that logic while skipping the two rewrites above. Anything that is
	// neither passes through unmodified.
	__be16 h_proto = eth->h_proto;

	if (h_proto != __builtin_bswap16(USID_ETH_P_IPV6) && h_proto != __builtin_bswap16(USID_ETH_P_IP)) {
		count_drop(DROP_REASON_TRACE_ETHERTYPE_MISMATCH);
		return TC_ACT_UNSPEC;
	}

	__u32 ifindex = skb->ifindex;
	struct ifindex_vrf_value *iv = bpf_map_lookup_elem(&ifindex_vrf_table, &ifindex);

	if (!iv) {
		count_drop(DROP_REASON_TRACE_IFINDEX_MISS);
		return TC_ACT_UNSPEC; // no attachment registered on this ifindex at all
	}
	count_drop(DROP_REASON_TRACE_IFINDEX_HIT);

	__u64 vrf_key = (iv->block << 12) | iv->argument;

	__u8 route_family;
	__u8 dst_addr[16];

	__builtin_memset(dst_addr, 0, sizeof(dst_addr));

	if (h_proto == __builtin_bswap16(USID_ETH_P_IPV6)) {
		struct usid_ip6hdr *ip6 = (void *) (eth + 1);

		if ((void *) (ip6 + 1) > data_end)
			return TC_ACT_UNSPEC;

		struct nptv6_value *npt = bpf_map_lookup_elem(&nptv6_table, &vrf_key);

		if (npt)
			apply_nptv6(ip6->saddr, npt, 1 /* outbound: ULA -> public */);

		if (ip6->nexthdr == USID_IPPROTO_TCP || ip6->nexthdr == USID_IPPROTO_UDP) {
			struct usid_l4ports *ports = (void *) (ip6 + 1);

			if ((void *) (ports + 1) <= data_end) {
				struct vip_xlat_key vkey = {
					.block = iv->block, .argument = iv->argument,
					.proto = ip6->nexthdr, .port = ports->source,
					.direction = USID_VIP_XLAT_DIR_EGRESS,
				};
				struct vip_xlat_value *vv = bpf_map_lookup_elem(&vip_xlat_table, &vkey);

				if (vv) {
					__u32 csum_off = USID_L3_OFFSET + (ip6->nexthdr == USID_IPPROTO_TCP
									     ? sizeof(struct usid_ip6hdr) + USID_TCP_CSUM_OFFSET
									     : sizeof(struct usid_ip6hdr) + USID_UDP_CSUM_OFFSET);
					__u32 addr_off = USID_L3_OFFSET + USID_OFFSETOF(struct usid_ip6hdr, saddr);
					__u32 port_off = USID_L3_OFFSET + (__u32) sizeof(struct usid_ip6hdr) +
							  USID_OFFSETOF(struct usid_l4ports, source);

					// A checksum or store failure here is not this
					// program's packet to drop. Only the rewrite is
					// abandoned; the egress-routing extension below still
					// runs.
					apply_vip_xlat(skb, addr_off, port_off, csum_off, ip6->nexthdr, ip6->saddr,
							ports->source, vv);

					// The store calls invalidate every previously derived
					// packet pointer, so re-derive before reading the
					// destination below.
					data = (void *) (long) skb->data;
					data_end = (void *) (long) skb->data_end;
					eth = data;
					if ((void *) (eth + 1) > data_end)
						return TC_ACT_SHOT;
					ip6 = (void *) (eth + 1);
					if ((void *) (ip6 + 1) > data_end)
						return TC_ACT_SHOT;

					// This packet's source is now a binding's VIP rather
					// than the backend's real address, so it must be
					// redirected out the fabric uplink immediately and
					// unconditionally, rather than reach the
					// egress_route_table lookup below. In a VRF with NAT66
					// configured, that lookup re-translates an
					// already-correctly-addressed reply through a shard and
					// the client silently discards it.
					//
					// No claimed-drop count on failure here, unlike the
					// egress route redirect path below: vrf_table's value is
					// not resolved yet at this point, and this path is
					// expected essentially never to fire.
					__u32 pu_key = 0;
					struct public_uplink_value *pu = bpf_map_lookup_elem(&public_uplink_table, &pu_key);

					if (pu && pu->link_ifindex != 0) {
						__builtin_memcpy(eth->h_dest, pu->dmac, sizeof(eth->h_dest));
						__builtin_memcpy(eth->h_source, pu->smac, sizeof(eth->h_source));

						long redirect_rc = bpf_redirect(pu->link_ifindex, 0);

						if (redirect_rc != TC_ACT_REDIRECT) {
							count_drop(DROP_REASON_PUBLIC_UPLINK_REDIRECT_FAILED);
							return TC_ACT_SHOT;
						}
						return redirect_rc;
					}
					// public_uplink_table is not configured yet, so this node
					// has not converged. Fall through rather than drop
					// outright: the NAT66 default below may still misroute
					// this reply, which is no worse than before this redirect
					// existed.
				}
			}
		}

		// Multicast and link-local destinations must never be matched against
		// egress_route_table, however broad a registered entry is, and in
		// particular not by the ::/0 default, which as a literal catch-all
		// matches them like anything else.
		//
		// Without this carve-out, a pod's Neighbor Discovery traffic for
		// resolving its own default gateway is caught by that default and
		// redirected toward a NAT66 shard instead of reaching the host-side
		// NDP handling that must answer it. The container's gateway neighbor
		// entry then goes to FAILED and every packet through it dies with a
		// locally synthesized unreachable, never sending anything this
		// program's drop counters could see.
		//
		// The kernel's own routing has an equivalent carve-out by construction,
		// link-local and multicast destinations always being handled by
		// local-scope routing rather than an application's default route. This
		// replicates it, since nothing else in this program's routing model
		// does.
		if (ip6->daddr[0] == 0xFF || (ip6->daddr[0] == 0xFE && (ip6->daddr[1] & 0xC0) == 0x80)) {
			count_drop(DROP_REASON_TRACE_MULTICAST_LL_BAIL);
			return TC_ACT_UNSPEC;
		}

		route_family = USID_EGRESS_ROUTE_FAMILY_INET6;
		__builtin_memcpy(dst_addr, ip6->daddr, 16);
	} else {
		struct usid_iphdr *ip4 = (void *) (eth + 1);

		if ((void *) (ip4 + 1) > data_end)
			return TC_ACT_UNSPEC;

		route_family = USID_EGRESS_ROUTE_FAMILY_INET4;
		__builtin_memcpy(dst_addr, ip4->daddr, sizeof(ip4->daddr));
	}

	// Resolve this attachment's Linux VRF table ID through vrf_table, populated
	// alongside ifindex_vrf_table at CNI ADD time. See struct egress_route_key
	// for why that, and not (block, argument), is egress_route_table's key.
	struct vrf_value *vrf = bpf_map_lookup_elem(&vrf_table, &vrf_key);

	if (!vrf) {
		count_drop(DROP_REASON_TRACE_MISS_VRF);
		return TC_ACT_UNSPEC; // attachment registered but its vrf_table entry isn't -- shouldn't happen; fail open
	}

	struct egress_route_key rkey;

	__builtin_memset(&rkey, 0, sizeof(rkey));
	rkey.table_id = vrf->vrf_table_id;
	rkey.family = route_family;
	__builtin_memcpy(rkey.addr, dst_addr, sizeof(rkey.addr));
	rkey.prefixlen = 8 * (sizeof(rkey.table_id) + sizeof(rkey.family)) +
			 (route_family == USID_EGRESS_ROUTE_FAMILY_INET6 ? 128 : 32);

	struct egress_route_value *rv = bpf_map_lookup_elem(&egress_route_table, &rkey);

	if (!rv) {
		count_drop(DROP_REASON_TRACE_MISS_ROUTE);
		return TC_ACT_UNSPEC; // no configured route for this destination -- defer to the kernel (still-installed netlink route during migration, or genuinely none)
	}

	// A local pass-through entry: it exists only to out-match a shorter default
	// through the trie, not to be encapsulated toward. Defer to the kernel like
	// a genuine miss, before touching node_src_addr_table or doing any encap
	// work.
	if (rv->link_ifindex == 0) {
		count_drop(DROP_REASON_TRACE_PASSTHROUGH_ENTRY);
		return TC_ACT_UNSPEC;
	}

	// node_src_addr_table is an array, not a hash: its single slot always exists
	// from map creation, pre-zeroed, so a lookup on an in-range index can never
	// signal "not configured yet" the way a hash miss can. An all-zero address
	// is never a legitimate value here, following the same unspecified-address
	// convention the Go route installers use, so it is checked explicitly below
	// as this map's not-configured signal.
	__u32 src_key = 0;
	__u8 *src = bpf_map_lookup_elem(&node_src_addr_table, &src_key);

	if (!src)
		return TC_ACT_UNSPEC; // array map, so this is unreachable in practice -- kept as a defensive null check anyway

	__u8 src_or = 0;

#pragma unroll
	for (int i = 0; i < 16; i++)
		src_or |= src[i];

	if (src_or == 0)
		return TC_ACT_UNSPEC; // this node's own source address isn't registered yet -- fail open rather than encapsulate with an all-zero source

	// Push room for a new outer IPv6 header. A positive length difference grows
	// room, the ingress strip being the same call with a negative one, and the
	// MAC-anchored mode keeps the Ethernet header at the front and opens the
	// space directly after it, where the outer header belongs.
	if (bpf_skb_adjust_room(skb, (__s32) sizeof(struct usid_ip6hdr), BPF_ADJ_ROOM_MAC, 0)) {
		count_claimed_drop(DROP_REASON_EGRESS_ROUTE_ENCAP_FAILED, vrf);
		return TC_ACT_SHOT;
	}
	count_drop(DROP_REASON_TRACE_ADJUST_ROOM_OK);

	data = (void *) (long) skb->data;
	data_end = (void *) (long) skb->data_end;

	struct usid_ethhdr *new_eth = data;

	if ((void *) (new_eth + 1) > data_end) {
		count_claimed_drop(DROP_REASON_EGRESS_ROUTE_ENCAP_FAILED, vrf);
		return TC_ACT_SHOT;
	}

	struct usid_ip6hdr *outer = (void *) (new_eth + 1);

	if ((void *) (outer + 1) > data_end) {
		count_claimed_drop(DROP_REASON_EGRESS_ROUTE_ENCAP_FAILED, vrf);
		return TC_ACT_SHOT;
	}

	__builtin_memset(outer->vtc_flow, 0, sizeof(outer->vtc_flow));
	outer->vtc_flow[0] = 0x60; // version 6, traffic class/flow label left zero
	// skb->len is now the full grown frame, Ethernet plus new outer header plus
	// the original inner packet, so the payload length this header must carry
	// is that minus the Ethernet and outer-header bytes just added.
	__u16 inner_len = (__u16) (skb->len - (__u32) sizeof(struct usid_ethhdr) - (__u32) sizeof(struct usid_ip6hdr));

	outer->payload_len = __builtin_bswap16(inner_len);
	outer->nexthdr = (route_family == USID_EGRESS_ROUTE_FAMILY_INET6) ? USID_IPPROTO_IPV6 : USID_IPPROTO_IPIP;
	outer->hop_limit = USID_EGRESS_HOP_LIMIT;
	__builtin_memcpy(outer->saddr, src, 16);
	__builtin_memcpy(outer->daddr, rv->sid, 16);
	new_eth->h_proto = __builtin_bswap16(USID_ETH_P_IPV6);

	// The L2 addresses and the egress interface come straight from the matched
	// entry, resolved once by the Go control plane at registration time rather
	// than by a FIB lookup here. That is a deliberate departure from
	// usid_ingress's step 8, which does call one per packet: from this
	// program's attach point, the tenant's VRF-enslaved veth, the lookup
	// unconditionally blackholes a main-table destination that resolves fine
	// outside BPF. Every combination of the direct and table-ID flags, and of
	// skb->ifindex against a neutral non-enslaved index, blackholes
	// identically. That is the kernel's VRF and l3mdev isolation boundary
	// asserting itself against the attaching skb's real device, not a parameter
	// bug. usid_ingress never hits it because its attach point was never
	// VRF-enslaved.
	__builtin_memcpy(new_eth->h_dest, rv->dmac, sizeof(new_eth->h_dest));
	__builtin_memcpy(new_eth->h_source, rv->smac, sizeof(new_eth->h_source));

	// Same-namespace redirect: this program's attach point and the resolved
	// uplink both live in the host namespace, unlike usid_ingress's veth branch,
	// which crosses into a different one and needs the peer helper for exactly
	// that reason.
	count_drop(DROP_REASON_TRACE_REACHED_REDIRECT);
	long redirect_rc = bpf_redirect(rv->link_ifindex, 0);

	if (redirect_rc != TC_ACT_REDIRECT) {
		count_claimed_drop(DROP_REASON_EGRESS_ROUTE_REDIRECT_FAILED, vrf);
		return TC_ACT_SHOT;
	}

	count_drop(DROP_REASON_TRACE_REDIRECT_OK);
	return redirect_rc;
}

char __license[] SEC("license") = "GPL";
