//go:build ignore

// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// usid.c implements the TC-BPF ingress datapath for the `uFMT 48+16` SRv6
// uSID carrier format described in .local/plan-ebpf-xdp-usid-datapath.md
// (design plan) §4.2/§4.4, and sequenced as Milestone 2.2 of
// .local/implementation-plan-ebpf-xdp-usid-datapath.md.
//
// Packet path (design plan §4.2, steps 1-9; every lookup here is an exact
// hash match -- R1 forbids matching anything looser than a full /64, and
// none of the three lookup maps below are BPF_MAP_TYPE_LPM_TRIE, per the
// design plan's §4.4 map inventory):
//
//  1. Parse the outer Ethernet + IPv6 header (bounds-checked). Not IPv6,
//     or too short to parse -- TC_ACT_UNSPEC (hand off to the next tc
//     filter on this device unmodified, R6).
//  2. Exact-match the destination address's top 64 bits (uSID Block(48) +
//     Node-ID(16), read with no shift) against locator_table. No match --
//     TC_ACT_UNSPEC (not one of this node's uSID Blocks, R6).
//  3. Read Function directly from the unmutated packet at its fixed
//     offset (bits 65-68) -- no shift, no mutation (R2).
//  4. Exact-match (matched Block, Function) against function_table. No
//     match -- drop, counted (DROP_REASON_UNKNOWN_FUNCTION): this packet
//     was already claimed by step 2's locator match, so silent
//     pass-through here would duplicate-deliver it to the normal stack. A
//     match whose behavior isn't BEHAVIOR_END_DT46 (i.e.
//     BEHAVIOR_END_DT2, reserved for a future L2 uEnd.DT2 path this
//     program does not implement yet) is dropped and counted separately
//     (DROP_REASON_UNSUPPORTED_BEHAVIOR) rather than falling through to
//     DT46 decap -- #740 makes 0xE and 0xF fully independent service
//     universes, so a DT2 entry reaching steps 5-9 below would parse an
//     L2 frame as an inner IP packet against the wrong table entirely.
//  5. Read Argument directly from the unmutated packet at its fixed
//     offset (bits 69-80) -- no shift, no mutation (R2, R4). Argument
//     0x000 is reserved and never registered into vrf_table (R4, design
//     plan §5.1), so it always misses step 6 -- no special-cased check
//     needed here.
//  6. Exact-match (matched Block, Argument) against vrf_table. No match --
//     drop, counted (DROP_REASON_UNKNOWN_ARGUMENT). Per-Argument hit
//     counters (packets, bytes, last_seen) are updated in vrf_table's
//     value on every match that reaches this step, supporting R8's
//     dual-key migration counters -- these count packets *claimed* by
//     this Argument, not packets successfully forwarded: a claimed packet
//     can still be dropped by any of steps 7-9 below (malformed inner,
//     strip failure, FIB failure, redirect failure), in which case it
//     also bumps that same vrf_table entry's dropped_packets counter, so
//     "packets - dropped_packets" is what actually left via step 9.
//  7. Strip the outer IPv6 header (bpf_skb_adjust_room, BPF_ADJ_ROOM_MAC),
//     exposing the inner IPv4/IPv6 packet (dual-stack, uEnd.DT46 -- R5).
//  8. bpf_fib_lookup() against the resolved Linux VRF table id
//     (vrf_table's value), using BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_TBID
//     so the lookup is scoped to that VRF's routing table exactly like the
//     kernel's own SEG6_LOCAL_ACTION_END_DT46 does today (§4.3).
//  9. Redirect to the resolved egress interface: bpf_redirect_peer() for a
//     veth attachment (the pod's host-side veth, whose container-side peer
//     lives in a different netns -- design plan §4.1), or plain
//     bpf_redirect() for a tap attachment (the tap device already sits in
//     the same netns this program runs in -- internal/cni/tap never moves
//     it -- so no netns-crossing redirect is needed or possible). Which one
//     to use is read from vrf_table's own egress_kind field, set at
//     registration time from the CNI's InterfaceType (Milestone 6.1's
//     tap-mode redirect fix).
//
// This file intentionally has no dependency on libbpf's bpf_helpers.h /
// bpf_helper_defs.h: it declares only the handful of BPF helper functions
// it actually calls (using the enum bpf_func_id constants from the
// system's own <linux/bpf.h>, not hand-picked magic numbers), and defines
// its own minimal Ethernet/IPv4/IPv6 header structs rather than pulling in
// <linux/if_ether.h>/<linux/ip.h>/<linux/ipv6.h>. This keeps the build's
// only external dependency on the kernel-headers package's <linux/bpf.h>
// (present on any distro that ships BPF/BTF support at all), and keeps the
// datapath's exact wire-format assumptions visible in one file instead of
// spread across vendored third-party headers.
//
// Compiled with CO-RE (Compile Once - Run Everywhere) via BTF: clang is
// invoked with `-g`, which emits a .BTF section into the object alongside
// the program/map definitions below (all of which already use the
// BTF-defined-map convention -- `__uint`/`__type` inside an anonymous
// struct tagged SEC(".maps") -- rather than the legacy fixed
// `struct bpf_map_def`). This program does not read any unstable
// kernel-internal struct fields (no BPF_CORE_READ of `struct sk_buff`
// internals, etc.), so it needs no `vmlinux.h`: the packet fields it reads
// are all stable, wire-format bytes accessed via direct bounds-checked
// pointer arithmetic on skb->data/skb->data_end, not BTF relocations
// against a kernel struct layout.
//
// The BPF ELF "license" section below is a kernel-required
// self-declaration for the compiled bytecode: the verifier's
// license_is_gpl_compatible() check reads it to decide whether this
// program may call a gpl_only helper -- and it already does: the VRF FIB
// lookup below calls bpf_fib_lookup(), which the kernel implements as
// gpl_only (net/core/filter.c's bpf_fib_lookup_proto). That check accepts
// only a fixed whitelist of exact strings ("GPL", "GPL v2", "GPL and
// additional rights", "Dual MIT/GPL", "Dual BSD/GPL"); this file's own
// AGPL-3.0-or-later SPDX identifier (above) is not on it, so declaring
// the ELF section as literally "AGPL-3.0-or-later" makes the program
// fail to load at all (verifier: "cannot call GPL-restricted function
// from non-GPL compatible program"), not merely a hypothetical future
// tradeoff. "GPL" is used instead (not "Dual BSD/GPL" -- this program
// isn't itself dual-licensed, so it declares plain "GPL" rather than a
// disjunction it doesn't mean), same as Cilium, Katran, and every other
// AGPL/Apache/BSD-licensed project embedding a BPF datapath: the ELF
// license section governs which helpers the verifier allows and says
// nothing about the licensing of the surrounding Go project, so this is
// independent of (and doesn't relicense) the file's own
// AGPL-3.0-or-later SPDX header.

#include <linux/bpf.h>

// __u8/__u16/__u32/__u64/__s16/__s32/__be16/__be32 all come transitively
// from <linux/bpf.h> -> <linux/types.h> -> <asm-generic/int-ll64.h>; no
// separate include or manual typedef needed.

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

// ---------------------------------------------------------------------
// BPF helper function declarations. Only the helpers this program calls
// are declared, using the enum bpf_func_id constants from the system's
// <linux/bpf.h> (BPF_FUNC_map_lookup_elem, etc.) rather than hardcoded
// helper IDs.
// ---------------------------------------------------------------------

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;

// Called once, unconditionally, at the top of usid_ingress -- see its call
// site for why a defensive linearization pass runs before any direct
// data/data_end read in this program.
static long (*bpf_skb_pull_data)(struct __sk_buff *skb, __u32 len) = (void *) BPF_FUNC_skb_pull_data;

static long (*bpf_skb_adjust_room)(struct __sk_buff *skb, __s32 len_diff, __u32 mode,
				    __u64 flags) = (void *) BPF_FUNC_skb_adjust_room;

// Only used on the IPv4-inner decap path, to retag skb->protocol -- see
// the long comment at its call site (step 7) for why a helper is needed
// here at all instead of a plain assignment.
static long (*bpf_skb_change_proto)(struct __sk_buff *skb, __be16 proto,
				     __u64 flags) = (void *) BPF_FUNC_skb_change_proto;

static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, __s32 plen,
			       __u32 flags) = (void *) BPF_FUNC_fib_lookup;

// Step 9 calls one of these two, chosen per-entry via vrf_table's
// egress_kind field: bpf_redirect_peer for a veth attachment (crosses into
// the peer's netns, per design plan §4.1), bpf_redirect for a tap
// attachment (same-netns egress -- see its call site for why).
static long (*bpf_redirect_peer)(__u32 ifindex, __u64 flags) = (void *) BPF_FUNC_redirect_peer;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *) BPF_FUNC_redirect;

static __u64 (*bpf_ktime_get_ns)(void) = (void *) BPF_FUNC_ktime_get_ns;

// ---------------------------------------------------------------------
// TC verdicts (uapi/linux/pkt_cls.h) -- reproduced as plain constants to
// avoid pulling in that header's transitive netlink dependencies for three
// integers.
// ---------------------------------------------------------------------

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_REDIRECT 7

// ---------------------------------------------------------------------
// Address-family constants (uapi asm-generic/socket.h). These values are
// fixed kernel ABI and never change.
// ---------------------------------------------------------------------

#define USID_AF_INET 2
#define USID_AF_INET6 10

#define USID_ETH_P_IP 0x0800
#define USID_ETH_P_IPV6 0x86DD

// IPv6 Next Header values (RFC 8200 §4 / IANA protocol numbers) that name
// an inner IPv4 or IPv6 packet directly -- i.e. no extension header sits
// between the outer uSID header and the real inner packet. Fixed kernel
// ABI, never change.
#define USID_IPPROTO_IPIP 4
#define USID_IPPROTO_IPV6 41

// ---------------------------------------------------------------------
// Minimal, self-contained header structs. Byte-exact to the real wire
// formats; hand-rolled (rather than <linux/if_ether.h>/<linux/ip.h>/
// <linux/ipv6.h>) so this file has exactly one external header dependency
// (<linux/bpf.h>, for the map/program/helper/fib-lookup definitions).
// ---------------------------------------------------------------------

struct usid_ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
} __attribute__((packed));

// struct usid_ip6hdr is deliberately NOT the kernel's bitfield-based
// struct ipv6hdr (whose version/traffic-class bitfield layout is
// endian-dependent) -- this program never reads version/traffic-class/flow
// label, so vtc_flow is left as an opaque 4-byte blob.
struct usid_ip6hdr {
	__u8 vtc_flow[4];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
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
// Map value types (design plan §4.4).
// ---------------------------------------------------------------------

// struct locator_value is locator_table's value: `{ generation }`.
// generation is a __u64, not __u32: userspace (Milestone 3.3's
// internal/plumbing/ebpf/usidmap) stamps it with a nanosecond-resolution
// CLOCK_MONOTONIC reading, which overflows a 32-bit field in a few
// seconds. This program never reads generation's contents itself (the
// locator_table lookup below only tests the returned pointer for a match,
// never dereferences a field of it), so widening this field has no effect
// on the packet path.
struct locator_value {
	__u64 generation;
};

// struct function_value is function_table's value: `{ behavior_enum }`.
// BEHAVIOR_END_DT46 is the only behavior this program implements (design
// plan R3); BEHAVIOR_END_DT2 is reserved for a future L2 uEnd.DT2 path.
// usid_ingress reads this field (step 4) only to reject anything that
// isn't BEHAVIOR_END_DT46 -- it does not itself implement DT2 decap.
enum function_behavior {
	BEHAVIOR_END_DT46 = 1,
	BEHAVIOR_END_DT2 = 2,
};

struct function_value {
	__u32 behavior;
};

// enum egress_kind indexes vrf_value's egress_kind field (Milestone 6.1's
// tap-mode redirect fix): which redirect helper step 9 must use for this
// entry's resolved egress interface. EGRESS_KIND_VETH (the zero value, so
// an entry registered before this field existed -- there are none, since
// nothing has shipped to production yet -- would default correctly) uses
// bpf_redirect_peer; EGRESS_KIND_TAP uses plain bpf_redirect, since a tap
// device never has a netns-crossing peer (internal/cni/tap creates it in
// the same netns this program runs in and never moves it).
enum egress_kind {
	EGRESS_KIND_VETH = 0,
	EGRESS_KIND_TAP = 1,
};

// struct vrf_value is vrf_table's value: `{ linux_vrf_table_id, packets,
// bytes, last_seen }` per the design plan's §4.4 map inventory, plus
// `generation` (design plan §4.2 step 6's earlier, value-shape description
// of this same map -- `{linux_vrf_table_id, generation, hit counter}` --
// which §4.4's table narrowed to the counter fields alone; this field
// reconciles the two by carrying generation as an actual struct member,
// same as locator_value already does) and `egress_kind` (Milestone 6.1's
// tap-mode redirect fix, above). generation is written only by userspace
// (internal/plumbing/ebpf/usidmap, Milestone 3.3) at registration time --
// this program never reads or writes it -- and lets the GC sweep
// (Milestone 7.3) distinguish "existed before this sweep's CRD-list
// snapshot was taken" from "registered after," so a Register call landing
// between the sweep's list-CRDs and delete-stale-entries steps is never
// reaped as stale (design plan §5.4's closing paragraph). egress_kind
// occupies what was previously an explicit alignment-only pad field
// between vrf_table_id and packets; generation is placed last so every
// pre-existing field keeps its original offset.
//
// `bytes` is bumped by skb->len as read at step 6, i.e. before step 7's
// strip -- it counts the whole tunneled frame (outer IPv6 header +
// Ethernet included), not just the inner payload that eventually reaches
// the egress interface.
//
// dropped_packets counts packets that matched this vrf_table entry
// (bumping `packets` above) but were then dropped by one of steps 7-9
// (malformed inner, strip failure, FIB failure, redirect failure) rather
// than actually forwarded -- so `packets` alone is a *claimed* count, not
// a *forwarded* one, and `packets - dropped_packets` is what actually left
// via step 9. Added after ecv's review of #281 pointed out that a VRF
// dropping everything still showed healthy per-Argument packets/bytes
// with no per-tenant signal in drop_reasons (which has no Block/Argument
// dimension). Placed last, like generation, so every pre-existing field
// keeps its original offset.
struct vrf_value {
	__u32 vrf_table_id;
	__u32 egress_kind;
	__u64 packets;
	__u64 bytes;
	__u64 last_seen_ns;
	__u64 generation;
	__u64 dropped_packets;
};

// enum drop_reason indexes drop_reasons (design plan §4.4's fourth map,
// observability only).
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
	// Outer ip6->nexthdr names neither IPIP(4) nor IPv6-in-IPv6(41) --
	// an extension header (Routing header/SRH, Fragment header, etc.)
	// sits between the outer header and the real inner packet, so byte
	// 40 is that extension header, not the inner packet's version
	// nibble. Counted apart from DROP_REASON_UNKNOWN_INNER_VERSION,
	// which this case would otherwise be silently folded into.
	DROP_REASON_UNEXPECTED_NEXTHDR = 10,
	// function_table matched, but the entry's behavior isn't
	// BEHAVIOR_END_DT46 (i.e. it's BEHAVIOR_END_DT2, reserved for a
	// future L2 path this program doesn't implement) -- step 4, see its
	// comment above.
	DROP_REASON_UNSUPPORTED_BEHAVIOR = 11,
	__DROP_REASON_MAX,
};

// ---------------------------------------------------------------------
// Maps (design plan §4.4). All three lookup maps are BPF_MAP_TYPE_HASH --
// no BPF_MAP_TYPE_LPM_TRIE anywhere in this program, since R1/R2 mean
// every lookup here is a fixed-width exact match, never a variable-length
// prefix match.
//
// Keys are plain u64 exact-match keys, matching
// internal/plumbing/ebpf/uformat's LocatorKey/FunctionKey composition
// (Milestone 2.1):
//   locator_key  = top 8 bytes of the destination address, as-is
//                  (Block(48) << 16 | Node-ID(16)).
//   function_key = matched Block(48) << 4 | Function(4) (52 significant
//                  bits) -- Block and Function are never adjacent in the
//                  wire address (Node-ID sits between them), so this key
//                  is always composed from two independently-read values,
//                  never read as one contiguous span.
//   vrf_key      = matched Block(48) << 12 | Argument(12) (60 significant
//                  bits), the same composition pattern as function_key.
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
	// Design plan §2: Option 2 caps each uSID Block at 4,095 usable
	// Argument values; R8 needs up to 2x that per Block during a
	// make-before-break migration. 8192 covers one Block's worst case
	// with headroom -- i.e. this map is deliberately sized for ~2 uSID
	// Blocks' worth of Argument space today, not #740's full 64-Block
	// range that locator_table/function_table already support. A third
	// concurrent Block exhausts this map at registration time (surfacing
	// as a failed CNI ADD, not a datapath drop) before R7's multi-Block
	// work revisits this map's sizing alongside theirs.
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

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

static USID_ALWAYS_INLINE void count_drop(__u32 reason)
{
	__u64 *count = bpf_map_lookup_elem(&drop_reasons, &reason);

	if (count)
		__sync_fetch_and_add(count, 1);
}

// count_claimed_drop is count_drop plus the per-vrf_table-entry
// dropped_packets bump (struct vrf_value's comment above) -- used for
// every drop that occurs after step 6's vrf_table match, i.e. every drop
// of a packet already claimed by a specific (Block, Argument) tenant.
static USID_ALWAYS_INLINE void count_claimed_drop(__u32 reason, struct vrf_value *vrf)
{
	count_drop(reason);
	__sync_fetch_and_add(&vrf->dropped_packets, 1);
}

// read_be64 composes an 8-byte big-endian (network order) buffer into a
// host-native __u64, byte by byte -- deliberately not a `*(__u64 *)p`
// cast, since p is not guaranteed to be 8-byte aligned (it points 38
// bytes into the packet, right after a 14-byte Ethernet header) and some
// architectures reject unaligned wide loads at verification time.
static USID_ALWAYS_INLINE __u64 read_be64(const __u8 *p)
{
	return ((__u64) p[0] << 56) | ((__u64) p[1] << 48) | ((__u64) p[2] << 40) |
	       ((__u64) p[3] << 32) | ((__u64) p[4] << 24) | ((__u64) p[5] << 16) |
	       ((__u64) p[6] << 8) | (__u64) p[7];
}

// ---------------------------------------------------------------------
// Program
// ---------------------------------------------------------------------

SEC("tc")
int usid_ingress(struct __sk_buff *skb)
{
	// Defensive linearization (ecv's review of #281): every read below
	// is direct data/data_end pointer access, never bpf_skb_load_bytes,
	// so a non-linear skb (fragmented linear head -- GRO normally avoids
	// this for tunnel headers, but nothing here depends on that holding)
	// would fail its bounds check and misreport as
	// DROP_REASON_MALFORMED_INNER instead of actually being malformed.
	// bpf_skb_pull_data(skb, 0) pulls the entire packet into the linear
	// area unconditionally, up front, so every direct read below is safe
	// regardless of the skb's arriving layout. A failure here is treated
	// like "not applicable to us" per R6 -- hand off to the next tc
	// filter on this device unmodified (TC_ACT_UNSPEC, not TC_ACT_OK: see
	// the note below step 2) rather than drop traffic this program hasn't
	// even determined is a uSID packet yet.
	if (bpf_skb_pull_data(skb, 0))
		return TC_ACT_UNSPEC;

	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;

	// Step 1: parse the outer Ethernet + IPv6 header (fixed 40B,
	// bounds-checked). Not a match -- TC_ACT_UNSPEC, hand off unmodified
	// (R6; see the note below step 2).
	struct usid_ethhdr *eth = data;

	if ((void *) (eth + 1) > data_end)
		return TC_ACT_UNSPEC;

	if (eth->h_proto != __builtin_bswap16(USID_ETH_P_IPV6))
		return TC_ACT_UNSPEC;

	struct usid_ip6hdr *ip6 = (void *) (eth + 1);

	if ((void *) (ip6 + 1) > data_end)
		return TC_ACT_UNSPEC;

	// Step 2: exact-match the destination address's top 64 bits
	// (Block(48) + Node-ID(16), read with no shift) against
	// locator_table. No match -- TC_ACT_UNSPEC, hand off unmodified (R6).
	//
	// TC_ACT_UNSPEC, not TC_ACT_OK, on every fail-open path through this
	// point (ecv's review of #283): this filter attaches direct-action at
	// a fixed tc priority, and Cilium attaches its own tc/bpf programs to
	// the same native-device ingress hook on these hosts. In direct-action
	// mode TC_ACT_OK is a final verdict that ends the qdisc's filter
	// chain, so a packet this program doesn't claim would never reach a
	// colocated Cilium filter at a later priority; TC_ACT_UNSPEC instead
	// tells tc "not matched here," letting the next filter run exactly as
	// if this program weren't attached at all. Every fail-open path from
	// here through the rest of the program is before step 2's
	// locator_table match, i.e. before this program has claimed the
	// packet as one of its own uSID Blocks at all -- once a packet is
	// claimed (this locator_table lookup hits), every subsequent failure
	// (unknown Function/Argument, malformed inner, FIB miss, redirect
	// failure) is still TC_ACT_SHOT: this program is the packet's only
	// intended handler past this point, so silently falling through to
	// Cilium (or the normal stack) would misdeliver it, not just fail to
	// accelerate it.
	__u64 locator_key = read_be64(&ip6->daddr[0]);

	struct locator_value *loc = bpf_map_lookup_elem(&locator_table, &locator_key);

	if (!loc)
		return TC_ACT_UNSPEC;

	__u64 block = locator_key >> 16;

	// Step 3: read Function directly from the unmutated packet at its
	// fixed offset -- bits 65-68, the high nibble of daddr byte 8. No
	// shift, no mutation (R2).
	__u8 fn_arg_byte = ip6->daddr[8];
	__u8 function = fn_arg_byte >> 4;

	// Step 4: exact-match (matched Block, Function) against
	// function_table. No match -- drop, counted: this packet was
	// already claimed by step 2, so silent pass-through here would
	// duplicate-deliver it to the normal stack.
	__u64 function_key = (block << 4) | function;

	struct function_value *fn = bpf_map_lookup_elem(&function_table, &function_key);

	if (!fn) {
		count_drop(DROP_REASON_UNKNOWN_FUNCTION);
		return TC_ACT_SHOT;
	}

	// #740 makes Function 0xE (uEnd.DT46: VRF ID, L3 route lookup) and
	// 0xF (uEnd.DT2: EVI ID, Bridge Domain MAC lookup) fully independent
	// service universes. This program only implements DT46 -- a DT2
	// entry falling through to steps 5-9 below would parse an L2 frame
	// as an inner IP packet against the wrong table entirely, not a
	// near-miss, so it's rejected here instead.
	if (fn->behavior != BEHAVIOR_END_DT46) {
		count_drop(DROP_REASON_UNSUPPORTED_BEHAVIOR);
		return TC_ACT_SHOT;
	}

	// Step 5: read Argument directly from the unmutated packet at its
	// fixed offset -- bits 69-80, the low nibble of daddr byte 8 plus
	// all of byte 9. No shift, no mutation (R2, R4).
	__u16 argument = ((__u16) (fn_arg_byte & 0x0F) << 8) | ip6->daddr[9];

	// Step 6: exact-match (matched Block, Argument) against vrf_table.
	// Argument 0x000 is reserved and never registered (R4, design plan
	// §5.1), so it always misses here -- no special-cased check.
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

	// The packet is claimed past this point: any failure from here on
	// is a drop, never a silent pass-through (the vrf_table hit already
	// committed this packet to the datapath).
	//
	// ip6->nexthdr must name the inner packet's AF directly (IPIP=4 or
	// IPv6-in-IPv6=41) for byte 40 to legitimately be the inner packet's
	// version nibble. Any other value means an extension header --
	// Routing header/SRH (43, e.g. from a peer still on full encap
	// rather than uSID reduced encap), Fragment header (44), Destination
	// Options (60), etc. -- sits between the outer header and the real
	// inner packet, so byte 40 is that extension header's own first
	// byte, not a version nibble. Reading it as one anyway would
	// silently fold every such packet into DROP_REASON_UNKNOWN_INNER_VERSION,
	// masking a distinct, actionable failure mode -- checked and counted
	// apart here, before that peek. ip6->nexthdr itself is already
	// covered by the `(void *) (ip6 + 1) > data_end` bounds check above,
	// so no further bounds check is needed to read it.
	if (ip6->nexthdr != USID_IPPROTO_IPIP && ip6->nexthdr != USID_IPPROTO_IPV6) {
		count_claimed_drop(DROP_REASON_UNEXPECTED_NEXTHDR, vrf);
		return TC_ACT_SHOT;
	}

	// Peek the inner packet's version nibble now, on the still-unmutated
	// outer header, rather than after stripping (as a prior version of
	// this function did) -- step 7 below needs to know the AF *before*
	// it decides how to strip, not after.
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

	// Step 7: strip the outer IPv6 header, exposing the inner
	// IPv4/IPv6 packet (dual-stack, per uEnd.DT46 -- R5).
	//
	// An IPv6 inner packet is a plain 40-byte carve: outer and inner
	// share the same skb->protocol (ETH_P_IPV6), so nothing else is
	// needed -- this is the path a prior version of this function
	// always took.
	//
	// An IPv4 inner packet needs skb->protocol changed from ETH_P_IPV6
	// to ETH_P_IP, and there is no direct way to do that: __sk_buff's
	// protocol field is not in tc_cls_act_is_valid_access's BPF_WRITE
	// whitelist (mark, tc_index, priority, tc_classid, cb[0..4], tstamp,
	// queue_mapping -- confirmed against upstream net/core/filter.c;
	// protocol is deliberately absent, and a direct `skb->protocol = ...`
	// here is rejected at load with "invalid bpf_context access"). Left
	// stale at ETH_P_IPV6, step 9's bpf_redirect_peer() hands the skb to
	// the peer netns via skb_do_redirect()'s BPF_F_PEER branch, which
	// only does skb->dev = dev and skb_scrub_packet() -- no
	// eth_type_trans() to re-derive skb->protocol from the Ethernet
	// header this function rewrites below (also confirmed against
	// upstream: __netif_receive_skb_core()'s "another_round" re-entry on
	// the peer device reuses skb->protocol as-is). The peer's IP stack
	// then dispatches the IPv4 payload to ipv6_rcv(), which drops it on
	// the version-nibble mismatch -- invisible to every counter in this
	// file, since the packet has already left via a *successful*
	// redirect. Confirmed live: an IPv4 uSID packet lands on the peer
	// device (its RX byte/packet counters advance, and a raw AF_PACKET
	// capture there shows a well-formed IPv4 frame) while
	// Ip6InReceives/Ip6InHdrErrors in that netns's /proc/net/snmp6 both
	// advance by exactly the same count, and the pod never sees it at
	// the socket layer -- IPv4 InMsgs/InEchos in /proc/net/snmp never
	// move.
	//
	// bpf_skb_change_proto() is the one BPF-legal way to update
	// skb->protocol, but it is built for in-place v4<->v6 header
	// translation (NAT64-style, RFC 6145), not encap/decap: called here
	// while skb->protocol is still ETH_P_IPV6 (i.e. before any stripping
	// -- exactly the point we're at), it removes
	// sizeof(usid_ip6hdr)-sizeof(usid_iphdr) (20) bytes from the *front*
	// of the current L3 header -- the first 20 bytes of our 40-byte
	// outer header -- shifts everything after (the outer header's last
	// 20 bytes, then our untouched real inner packet) up by 20 to fill
	// the gap, and sets skb->protocol = ETH_P_IP. That leaves exactly
	// sizeof(usid_iphdr) (20) bytes of outer-header leftover sitting in
	// front of our real inner IPv4 header; the plain carve below removes
	// exactly that leftover, exposing the real header at offset 0 same
	// as the IPv6 case. Net bytes removed is sizeof(usid_ip6hdr) (40)
	// either way -- change_proto's 20 plus this carve's 20 for the v4
	// case, this carve's 40 alone for the v6 case -- only the
	// skb->protocol side effect differs.
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

	// bpf_skb_change_proto/bpf_skb_adjust_room can both change the
	// underlying packet buffer: all previously derived data/data_end
	// pointers are invalidated and must be re-read.
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

		fib_params.family = USID_AF_INET6;
		__builtin_memcpy(fib_params.ipv6_src, inner6->saddr, sizeof(fib_params.ipv6_src));
		__builtin_memcpy(fib_params.ipv6_dst, inner6->daddr, sizeof(fib_params.ipv6_dst));
		new_eth->h_proto = __builtin_bswap16(USID_ETH_P_IPV6);

		// fib_params.tot_len is the L3 length the kernel's MTU check
		// (step 8, below) compares against the egress route's MTU --
		// but only if it's nonzero; left at memset's zero, that check
		// is silently skipped and BPF_FIB_LKUP_RET_FRAG_NEEDED can
		// never fire. IPv6 has no total-length field of its own, so
		// this is the fixed 40-byte header plus payload_len (host
		// order; the wire field is big-endian).
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

		// Same fib_params.tot_len requirement as the IPv6 branch
		// above, except IPv4 already carries its own total-length
		// field (host order; the wire field is big-endian) -- no
		// header-size arithmetic needed.
		fib_params.tot_len = __builtin_bswap16(inner4->tot_len);
	}

	fib_params.ifindex = skb->ingress_ifindex;
	fib_params.tbid = vrf_table_id;

	// Step 8: bpf_fib_lookup() against the resolved Linux VRF table id
	// -- a normal FIB lookup scoped to that VRF, exactly like the
	// kernel's stock End.DT46 does today, reached via a dynamic
	// Argument-keyed lookup instead of a static per-/128 route (§4.3).
	long fib_rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params),
				      BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_TBID);

	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS) {
		if (fib_rc == BPF_FIB_LKUP_RET_NO_NEIGH)
			count_claimed_drop(DROP_REASON_FIB_NO_NEIGH, vrf);
		else if (fib_rc == BPF_FIB_LKUP_RET_UNREACHABLE || fib_rc == BPF_FIB_LKUP_RET_BLACKHOLE || fib_rc == BPF_FIB_LKUP_RET_PROHIBIT)
			count_claimed_drop(DROP_REASON_FIB_UNREACHABLE, vrf);
		else if (fib_rc == BPF_FIB_LKUP_RET_FRAG_NEEDED)
			// No ICMPv6 Packet Too Big is generated here, unlike the
			// static-route SEG6 decap path this replaces -- an
			// accepted PMTUD gap for this milestone; see
			// docs/agents/ARCHITECTURE.md's Known Constraints.
			count_claimed_drop(DROP_REASON_FIB_FRAG_NEEDED, vrf);
		else
			count_claimed_drop(DROP_REASON_FIB_LOOKUP_FAILED, vrf);
		return TC_ACT_SHOT;
	}

	__builtin_memcpy(new_eth->h_dest, fib_params.dmac, sizeof(new_eth->h_dest));
	__builtin_memcpy(new_eth->h_source, fib_params.smac, sizeof(new_eth->h_source));

	// Step 9: redirect to the resolved egress interface. A veth
	// attachment's egress interface is the pod's host-side veth, whose
	// container-side peer lives in a different netns, so
	// bpf_redirect_peer is required to cross into it (§4.1). A tap
	// attachment has no peer at all -- internal/cni/tap creates a plain
	// netlink.Tuntap in this same netns and never moves it -- so plain
	// bpf_redirect (same-netns egress) is required instead;
	// bpf_redirect_peer against a tap ifindex always fails
	// (DROP_REASON_REDIRECT_FAILED), which is exactly the tap-mode
	// blackhole this per-entry egress_kind field (registered by
	// internal/cni's registerEBPFDatapath from the CNI's own
	// InterfaceType) fixes.
	//
	// Verification note: this branch is exercised by unit tests only up
	// through egress_kind's control-plane wiring (internal/cni's
	// TestEgressKindForInterfaceType) -- a real FIB-lookup-then-redirect
	// success/failure by egress kind needs a live route/interface
	// (a real net_device) that BPF_PROG_TEST_RUN cannot fabricate, so
	// that part is a live-cluster (ContainerLab/e2e) concern, same as
	// this file's other FIB-lookup tests already document.
	long redirect_rc;

	if (vrf->egress_kind == EGRESS_KIND_TAP)
		redirect_rc = bpf_redirect(fib_params.ifindex, 0);
	else
		redirect_rc = bpf_redirect_peer(fib_params.ifindex, 0);

	if (redirect_rc != TC_ACT_REDIRECT) {
		count_claimed_drop(DROP_REASON_REDIRECT_FAILED, vrf);
		return TC_ACT_SHOT;
	}

	return redirect_rc;
}

char __license[] SEC("license") = "GPL";
