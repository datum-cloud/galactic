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

// USID_OFFSETOF reproduces <stddef.h>'s offsetof -- not otherwise available,
// since this file deliberately includes no headers beyond <linux/bpf.h>
// (see the file header comment).
#define USID_OFFSETOF(type, member) ((__u32) (unsigned long) &((type *) 0)->member)

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

// vip_xlat_table's rewrite (unlike nptv6_table's, see struct
// vip_xlat_value's comment) is a genuine address+port substitution with no
// checksum-neutral shortcut, so it needs the real incremental L4 checksum
// update every stateful NAT uses -- available here because both
// usid_ingress and usid_egress are TC-BPF (a real struct __sk_buff),
// unlike edgenat.c's XDP context, which is exactly why that program needs
// the heavier bpf_csum_diff approach instead.
static long (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to,
				    __u64 flags) = (void *) BPF_FUNC_l4_csum_replace;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len,
				    __u64 flags) = (void *) BPF_FUNC_skb_store_bytes;

// BPF_F_PSEUDO_HDR/BPF_F_MARK_MANGLED_0 (uapi/linux/bpf.h) reproduced as
// plain constants for the same reason the TC_ACT_*/USID_AF_INET* constants
// above are -- avoiding a second header dependency for a couple of flags.
#define USID_BPF_F_PSEUDO_HDR (1U << 4)
#define USID_BPF_F_MARK_MANGLED_0 (1U << 5)

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

// Transport protocol numbers, needed by the DSR/Maglev redesign's
// vip_xlat_table lookup (both TCP and UDP headers place source/destination
// port at the identical offset -- struct usid_l4ports below -- so no
// separate struct is needed per protocol for the fields this file touches).
#define USID_IPPROTO_TCP 6
#define USID_IPPROTO_UDP 17

// TCP checksum field offset (bytes 16-17 of a TCP header); UDP's is at
// bytes 6-7. Used only by apply_vip_xlat's bpf_l4_csum_replace calls.
#define USID_TCP_CSUM_OFFSET 16
#define USID_UDP_CSUM_OFFSET 6

// USID_EGRESS_HOP_LIMIT is the hop limit usid_egress writes into the outer
// IPv6 header it pushes for a resolved egress route -- a fixed, reasonable
// default (matching this lab's/most Linux hosts' own default unicast hop
// limit), not read from the inner packet's own hop limit: the outer
// header's hop count only needs to survive the underlay's own hop count
// (a handful of hops in every topology this program runs on), not mirror
// whatever budget the inner packet's original sender picked.
#define USID_EGRESS_HOP_LIMIT 64

// USID_L3_OFFSET is the fixed byte offset of the L3 (IPv6) header from
// skb->data -- always sizeof(struct usid_ethhdr), a compile-time constant.
// apply_vip_xlat's csum_off/addr_off/port_off arguments must be this kind
// of compile-time-constant-derived offset, not a runtime pointer
// subtraction: bpf_skb_store_bytes (inside apply_vip_xlat) invalidates the
// verifier's tracked bounds on every previously-derived packet pointer,
// and a scalar computed by subtracting two packet pointers loses precise
// range tracking across that call boundary, which then fails the bounds
// check on the *next* direct packet dereference after the call --
// confirmed empirically via BPF_PROG_TEST_RUN (the verifier rejected the
// pointer-subtraction version with "R5 min value is outside of the
// allowed memory range"). A literal constant offset sidesteps the problem
// entirely rather than working around it.
#define USID_L3_OFFSET (sizeof(struct usid_ethhdr))

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

// struct usid_l4ports mirrors the first 4 bytes shared by a TCP and a UDP
// header (source port, destination port) -- the only L4 fields
// vip_xlat_table's rewrite touches directly; the checksum field itself is
// updated via bpf_l4_csum_replace, never read/written as a struct field
// here (its offset differs between TCP/UDP -- see USID_TCP_CSUM_OFFSET/
// USID_UDP_CSUM_OFFSET above).
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

// ---------------------------------------------------------------------
// DSR/Maglev redesign additions (design plan §0.1, §2): per-VRF stateless
// NPTv6 (RFC 6296) and the tap-backend VIP-boundary substitution. Both are
// consulted from two places: usid_ingress (this file, below -- inbound,
// after step 7's strip, before step 8's FIB lookup, using the (block,
// argument) already resolved locally by steps 2-6) and usid_egress (this
// file, below -- outbound, on a tenant's own not-yet-encapsulated reply,
// intercepted per-attachment before the kernel's SEG6 encap route ever
// runs -- see usid_egress's own header comment for why that attach point,
// not "TC egress of the shared physical uplink", is the only place that
// can resolve the sending VRF unambiguously).
// ---------------------------------------------------------------------

// struct ifindex_vrf_value is ifindex_vrf_table's value: the (Block,
// Argument) the attachment on this ifindex belongs to. usid_egress runs
// per-attachment on plain, not-yet-encapsulated tenant traffic -- it has no
// outer uSID destination to decode (block,argument) from the way
// usid_ingress does -- so this is written once per attachment (alongside
// the existing vrf_table.Register call, which already has both values) at
// CNI ADD time, keyed by the attachment's own host-side veth/tap ifindex,
// and removed at CNI DEL.
struct ifindex_vrf_value {
	__u64 block;
	__u16 argument;
};

// struct nptv6_value is nptv6_table's value: one VRF's RFC 6296 mapping,
// mirroring internal/plumbing/nptv6.Mapping/Adjustment on the control-plane
// side -- see that package's doc comment for the checksum-neutral math this
// applies. ula_prefix/public_prefix are zero-padded beyond prefix_len,
// exactly like internal/plumbing/nptv6.prefixChecksum assumes. adjustment
// is the precomputed RFC 6296 §3.6 value (Mapping.Adjustment), stored in
// ordinary host-endian layout like every other non-wire-format field in
// this file -- unlike vip_xlat_value's addr/port fields below, this value
// is never copied directly onto the wire, so no explicit byte-order
// convention is needed here.
struct nptv6_value {
	__u8 ula_prefix[16];
	__u8 public_prefix[16];
	__u8 prefix_len;
	__u16 adjustment;
};

// struct vip_xlat_key keys vip_xlat_table: (block, argument) identify the
// tenant VRF (same composition as vrf_table's own key, kept as separate
// fields here rather than pre-folded, since a struct key -- unlike
// vrf_table's plain __u64 -- has room to also carry proto/port). port's
// meaning is direction-dependent: the *ingress*-direction lookup (in
// usid_ingress) keys on the packet's own destination port, i.e. the VIP
// port a client dialed; the *egress*-direction lookup (in usid_egress)
// keys on the packet's own source port, i.e. the backend's real port --
// each ServiceVIPBinding writes one row under each key (vip_xlat.go),
// since the two directions substitute in opposite directions and are
// looked up via different fields of the same packet.
//
// direction disambiguates those two rows when their ports coincide -- a
// common, unremarkable case (e.g. a binding that keeps port 80 on both the
// VIP and the backend), not a rare one, and one this struct originally had
// no way to handle: (block, argument, proto, port) alone collapses the
// ingress row (keyed on the VIP port) and the egress row (keyed on the
// backend port) into the *same* map entry whenever those two ports match,
// so registering the second row silently overwrote the first -- found live
// in containerlab, where ns60's binding uses port 80 both ways and the
// ingress row (VIP -> backend) never survived RegisterEgress's later
// write, leaving every packet correctly matched by the edge gateway but
// silently undeliverable at the backend. usid_ingress always sets
// direction to USID_VIP_XLAT_DIR_INGRESS on the key it builds;
// usid_egress always sets USID_VIP_XLAT_DIR_EGRESS -- see vipxlatmap.go's
// mirroring register()/unregister() split for the control-plane side.
//
// The trailing pad2 exists only to eliminate the struct's own compiler-
// inserted alignment padding: block's __u64 alignment rounds this struct
// up to 16 bytes, but block+argument+proto+direction+port only account for
// 14 of them, leaving 2 bytes no initializer touches. C99 zero-initializes
// an *omitted named member* (like direction, when a caller doesn't set it)
// but says nothing about true structural padding, and clang's BPF backend
// does not zero it -- bpf_map_lookup_elem() then reads all 16 key bytes
// and the verifier rejects the two never-written ones as "invalid read
// from stack" (caught live via a real containerlab deploy). Naming the
// last 2 bytes as a real member makes them a normal omitted-member zero,
// not padding.
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

// struct vip_xlat_value is vip_xlat_table's value: unlike nptv6_value, this
// is a genuine address+port rewrite with no reserved "elsewhere" bits to
// absorb a checksum-neutral adjustment into (a real substitution, not a
// prefix-preserving one) -- applying it needs bpf_l4_csum_replace, not a
// plain word add/subtract. addr/port are stored in on-wire byte order
// (network order for port; the 16 address bytes are already wire-order by
// construction) since both are copied and diffed directly against packet
// bytes.
struct vip_xlat_value {
	__u8 addr[16];
	__be16 port;
};

// ---------------------------------------------------------------------
// TC-BPF egress-routing extension (docs/plans/tc-bpf-egress-srv6-encap.md):
// replaces internal/plumbing/srv6's kernel-native SEG6 lwtunnel route
// encapsulation (RouteEgressAdd/EgressDefaultRouteAdd) with an in-program
// header push, closing CVE-2026-31668 (seg6 lwtunnel shares one dst_cache
// per route between its input and output resolution paths, and reuses a
// stale cached result across different routing contexts -- the upstream
// fix's own writeup names VRF table separation, this codebase's own
// per-tenant-VRF architecture, as a trigger). See that plan document for
// the full mechanism and its own §3's explanation of why this is a plain
// tunnel-header prepend, not a general SRH pusher: every existing call
// site installs exactly one segment, and SEG6_IPTUN_MODE_ENCAP_RED
// already omits the SRH entirely for that case (usid_ingress's own
// decap side already requires and depends on exactly this shape).
// ---------------------------------------------------------------------

// struct egress_route_key is egress_route_table's LPM_TRIE key. Keyed on
// the Linux VRF table id (table_id), not (block, argument): every one of
// RouteEgressAdd/EgressDefaultRouteAdd/RouteMainAdd's own Go-side callers
// (internal/runtime/gobgp/monitor.go, internal/cnibgp/bgp.go) already has
// the Linux table id in hand -- that is the identity BGP path processing
// and NAT66 shard-SID resolution are already scoped by -- and none of them
// otherwise need to resolve a uSID (block, argument) identity at all. This
// program itself has no direct route from its own per-attachment identity
// (ifindex_vrf_table's block/argument) to a Linux table id either, so it
// takes one extra vrf_table lookup (already keyed by the vrf_key this
// program computes for the NPTv6/vip_xlat lookups above) to read
// vrf->vrf_table_id, rather than teaching ifindex_vrf_table or
// egress_route_table a second, redundant identity scheme.
//
// family disambiguates an IPv4 VPC prefix from an IPv6 one sharing the
// same leading bytes when addr's low bytes happen to coincide (e.g. an
// IPv4 /24 stored zero-extended into addr's first 4 bytes could otherwise
// collide with an IPv6 prefix whose own first 4 bytes are identical by
// coincidence) -- placed inside the LPM-matched region (never past
// table_id, always matched in full) specifically so this can never happen:
// two entries can only ever compare equal on their address bits once
// table_id and family already match exactly.
//
// prefixlen is bits, not bytes, per LPM_TRIE's own convention -- always at
// least 40 (the fixed table_id(32)+family(8) portion, matching
// EgressDefaultRouteAdd's own ::/0 entries) and up to 40+128=168 for a
// full IPv6 host route or 40+32=72 for a full IPv4 host route.
//
// __attribute__((packed)), unlike vrf_value/nptv6_value/vip_xlat_value
// above: an LPM_TRIE's matching semantics only ever compare the first
// prefixlen *bits*, so (unlike vip_xlat_key's HASH-map full-key-equality
// requirement, which forced that struct's own explicit pad2 field)
// trailing compiler-inserted padding here would never affect a lookup's
// correctness either way -- packed is used anyway to make the exact byte
// layout this comment's own bit-offset reasoning depends on unambiguous,
// rather than relying on it holding incidentally.
struct egress_route_key {
	__u32 prefixlen;
	__u32 table_id;
	__u8 family;
	__u8 addr[16];
} __attribute__((packed));

// USID_EGRESS_ROUTE_FAMILY_INET6/INET4 are egress_route_key.family's two
// values -- deliberately not reusing USID_AF_INET/USID_AF_INET6 (which are
// the kernel's real AF_INET/AF_INET6 values, sized and spaced for a
// different purpose, struct bpf_fib_lookup.family) for a field whose only
// job is disambiguating two prefixes within this one map, not naming a
// real address family to any kernel API.
#define USID_EGRESS_ROUTE_FAMILY_INET6 0
#define USID_EGRESS_ROUTE_FAMILY_INET4 1

// struct egress_route_value is egress_route_table's value: the resolved
// SRv6 SID (or NAT66 shard SID, for a default-route entry) to
// encapsulate toward, plus the fully precomputed link/L2 information
// needed to actually deliver that encapsulated packet.
//
// An earlier version of this struct carried only sid, on the theory that
// usid_egress could resolve link_ifindex/dmac/smac itself, fresh, via a
// per-packet bpf_fib_lookup() -- both simpler for the Go side (no
// next-hop resolution logic of its own) and self-healing (a next-hop
// change on the underlay takes effect on the very next packet). That
// theory doesn't hold: confirmed live, bpf_fib_lookup() called from
// usid_egress's own attach point (the tenant's own VRF-enslaved veth)
// unconditionally returns BPF_FIB_LKUP_RET_BLACKHOLE for a main-table
// destination that resolves just fine via `ip -6 route get` outside BPF --
// tried with/without BPF_FIB_LOOKUP_TBID, with/without BPF_FIB_LOOKUP_DIRECT,
// and with fib_params.ifindex set to both skb->ifindex and a neutral
// non-VRF-enslaved ifindex; all four combinations blackholed identically.
// This is the kernel's own VRF/l3mdev isolation boundary asserting itself
// against the *attaching* skb's real device, independent of any
// bpf_fib_lookup parameter -- not something tunable from inside this
// program at all. The Go control plane must resolve link/L2 information
// the same way the netlink-route mechanism this replaces always did
// (RouteEgressAdd's own resolveNextHop, run once at route-install time),
// and store it here -- see egressroutemap.EgressRouteTable.Register.
//
// link_ifindex == 0 is a reserved sentinel meaning "local pass-through":
// this entry exists in the trie purely to win the LPM lookup over a
// shorter, less specific entry (in practice, always a tenant VRF's own
// ::/0 NAT66 default), not to encapsulate anything -- usid_egress checks
// for it and returns TC_ACT_UNSPEC (defer to the kernel) before doing any
// of the encap work below, the same way it already special-cases
// multicast/link-local destinations. 0 is never a legitimate Linux
// ifindex (the kernel reserves it for "no interface", same convention
// netlink itself uses), so it collides with no real registration.
// Installed by egressroutemap.EgressRouteTable.RegisterPassThrough for
// every attachment's own IPAM-assigned prefix, at CNI ADD time -- see
// that function's own doc comment for why: two attachments sharing one
// VRF on the same node have a kernel connected route between them that
// this program's own ::/0 default entry would otherwise hijack, exactly
// like the multicast/link-local bug below, just for ordinary unicast
// intra-VRF peers instead of NDP.
struct egress_route_value {
	__u8 sid[16];
	__u32 link_ifindex;
	__u8 dmac[6];
	__u8 smac[6];
} __attribute__((packed));

// ---------------------------------------------------------------------

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
	// usid_egress's own egress-routing extension (docs/plans/
	// tc-bpf-egress-srv6-encap.md): egress_route_table matched (a route
	// was configured for this destination) but bpf_skb_adjust_room
	// failed to grow room for the new outer header -- essentially never
	// expected to fire (the same helper's shrink direction is
	// unconditionally trusted by usid_ingress above), kept as its own
	// reason rather than folded into an unrelated one so it's visible if
	// it ever does.
	DROP_REASON_EGRESS_ROUTE_ENCAP_FAILED = 12,
	// Unused: an earlier version of usid_egress's egress-routing
	// extension ran its own per-packet bpf_fib_lookup() to resolve the
	// matched SID's link/L2 next-hop, and this counted that call
	// failing. That approach doesn't work at all from this program's own
	// attach point (see struct egress_route_value's own comment for why
	// -- a real kernel VRF/l3mdev isolation boundary, not a parameter
	// bug) and was replaced with Go-side precomputation
	// (egressroutemap.EgressRouteTable.Register), which has nothing left
	// to fail in the same way at packet-processing time. Kept
	// undeleted rather than renumbering every index after it.
	DROP_REASON_EGRESS_ROUTE_FIB_LOOKUP_FAILED = 13,
	// The redirect out the resolved physical interface failed.
	DROP_REASON_EGRESS_ROUTE_REDIRECT_FAILED = 14,
	// usid_egress's own VIP-sourced-reply redirect (struct
	// public_uplink_value's own doc comment): public_uplink_table
	// matched (it's always populated once the node has converged, this
	// is a real registration miss or a redirect failure) but the
	// redirect to the resolved fabric-uplink interface failed.
	DROP_REASON_PUBLIC_UPLINK_REDIRECT_FAILED = 15,
	// TEMPORARY diagnostic checkpoints for an ongoing bpf_redirect
	// investigation -- not counted drops, just markers of how far
	// usid_egress's egress-routing extension got. Remove once resolved.
	DROP_REASON_TRACE_MULTICAST_LL_BAIL = 16,
	DROP_REASON_TRACE_MISS_VRF = 17,
	DROP_REASON_TRACE_MISS_ROUTE = 18,
	DROP_REASON_TRACE_PASSTHROUGH_ENTRY = 19,
	DROP_REASON_TRACE_ADJUST_ROOM_OK = 20,
	DROP_REASON_TRACE_REACHED_REDIRECT = 21,
	DROP_REASON_TRACE_REDIRECT_OK = 22,
	// bpf_trace_printk is unavailable to sched_cls programs on this
	// kernel (verifier: "program of this type cannot use helper
	// bpf_trace_printk#6", confirmed live) -- this checkpoint exists
	// because that discovery ruled out adding a print at the one
	// early-return in usid_egress that DROP_REASON_TRACE_MULTICAST_LL_BAIL
	// through DROP_REASON_TRACE_REDIRECT_OK don't cover: the
	// ifindex_vrf_table miss immediately above, in the function's own
	// entry sequence.
	DROP_REASON_TRACE_IFINDEX_MISS = 23,
	// Full entry-sequence bracketing: usid_egress's own prefix (before
	// DROP_REASON_TRACE_MULTICAST_LL_BAIL) has four more early-return
	// paths with no counter at all -- these close every remaining gap so
	// "nothing incremented" can no longer mean either "never invoked" or
	// "always took the uninstrumented path".
	DROP_REASON_TRACE_ENTRY = 24,
	DROP_REASON_TRACE_PULL_DATA_FAILED = 25,
	DROP_REASON_TRACE_ETH_BOUNDS_FAILED = 26,
	DROP_REASON_TRACE_ETHERTYPE_MISMATCH = 27,
	DROP_REASON_TRACE_IFINDEX_HIT = 28,
	// TEMPORARY diagnostic checkpoints for usid_ingress's step 8/9, the
	// mirror of DROP_REASON_TRACE_* above for usid_egress. Remove once
	// resolved.
	//
	// The ingress path has no success counter at all, so a packet that
	// is claimed at step 6 and then lost has the same signature as one
	// delivered: the per-vrf_table packets counter moves, no drop
	// counter moves, and nothing distinguishes the two. Measured on a
	// live tap attachment: packets=+5 per 5 sent, dropped_packets flat,
	// and the target tap's own tx_packets flat, so the packet is neither
	// dropped by this program nor delivered.
	//
	// Everything between step 6 and the redirect is already counted, so
	// what is left is the redirect itself and what the kernel does with
	// it after this program returns. skb_do_redirect runs post-return
	// and can discard the packet with nothing here to observe it, which
	// a zero or otherwise unusable fib_params.ifindex would cause.
	DROP_REASON_TRACE_ING_REACHED_REDIRECT = 29,
	DROP_REASON_TRACE_ING_REDIRECT_OK = 30,
	// Not a counter: SET to the ifindex bpf_fib_lookup resolved, so the
	// redirect target itself is observable rather than inferred. Read it
	// as a value, never as a count.
	DROP_REASON_TRACE_ING_LAST_IFINDEX = 31,
	// A real drop, not a trace: bpf_fib_lookup returned SUCCESS with an
	// ifindex that cannot be redirected to. Sitting in the temporary
	// block rather than with the other FIB reasons at 0-15 only to avoid
	// renumbering slots 16-30, which the Go mirror's DropReasonCount and
	// hack/returnpath-lab's name table both key off. It should graduate
	// into the real block when the temporary slots around it are
	// removed.
	DROP_REASON_FIB_NO_IFINDEX = 32,
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

// ifindex_vrf_table: see struct ifindex_vrf_value's comment above. Sized
// generously above vrf_table's own 8192 -- one row per *attachment*
// (potentially several veths/taps per VRF), not one row per VRF.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32); // ifindex
	__type(value, struct ifindex_vrf_value);
} ifindex_vrf_table SEC(".maps");

// nptv6_table: one row per VRF with NPTv6 configured, keyed identically to
// vrf_table (block<<12|argument) -- both usid_ingress (which already has
// this key locally) and usid_egress (via ifindex_vrf_table above) resolve
// it the same way.
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

// egress_route_table: see struct egress_route_key's comment above. The
// first (and, as of this writing, only) BPF_MAP_TYPE_LPM_TRIE in this
// file -- everything above is deliberately BPF_MAP_TYPE_HASH (uSID
// decode is always a fixed-width exact match, per R1/R2), but egress
// routing is inherently a longest-prefix-match problem (an intra-VPC
// peer's specific prefix must win over a tenant VRF's own ::/0 default),
// exactly what locator_table/function_table/vrf_table's own doc comment
// says this format never needs -- that reasoning is scoped to uSID
// decode, not to this unrelated map. BPF_F_NO_PREALLOC is required by the
// kernel for this map type (lpm_trie_alloc rejects any other map_flags
// value outright), not an optional tuning choice.
//
// Sized well above vrf_table's own 8192: this map holds routes, not VRFs
// -- one VRF can have several intra-VPC-peer entries (RouteEgressAdd) plus
// one default (EgressDefaultRouteAdd), so entries-per-VRF is not 1:1 the
// way locator_table/vrf_table's own sizing reasoning assumes.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 32768);
	__type(key, struct egress_route_key);
	__type(value, struct egress_route_value);
} egress_route_table SEC(".maps");

// node_src_addr_table: this node's own SRv6/underlay-facing source
// address, the single value usid_egress's egress-routing extension writes
// into the outer IPv6 header it pushes -- a per-node constant, not
// per-VRF/per-route, hence the single-entry BPF_MAP_TYPE_ARRAY rather than
// folding it into egress_route_value (which would mean every route entry
// redundantly carrying the same 16 bytes, and Go's writer needing to know
// this node's own address just to register an unrelated destination
// route). Populated once, at CNI datapath registration time (mirroring
// attachUsidEgress's own once-per-node lifecycle), not per CNI ADD/DEL.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8[16]);
} node_src_addr_table SEC(".maps");

// struct public_uplink_value is public_uplink_table's value: this node's
// own fabric-uplink interface's real, physical next hop -- the link
// index to redirect out plus the L2 (destination and source MAC)
// addressing needed to actually reach it. Resolved once, Go-side
// (egressroutemap.PublicUplink.Set), the same "resolve at registration
// time, redirect blindly at packet time" pattern egress_route_value
// itself already uses and for the identical reason: a live
// bpf_fib_lookup() from this program's own attach point (the tenant's
// own VRF-enslaved veth) unconditionally blackholes (see
// egress_route_value's own doc comment), so there is no way to resolve
// this fresh, per packet, from inside usid_egress at all.
//
// Used by usid_egress's own VIP-sourced-reply handling, below: once
// apply_vip_xlat has rewritten a packet's source address from a DSR
// backend's real address to its own ServiceVIPBinding's VIP -- a real,
// globally-routable, BGP-advertised address, needing no further
// translation -- that packet must never reach egress_route_table's own
// LPM lookup (whose only entries, in a VRF with NAT66 configured, would
// otherwise treat it as an ordinary ULA-sourced tenant packet and
// wrongly re-SNAT it through a NAT66 shard: found live, a real curl
// through a DSR-served VIP timed out because of exactly this -- the
// reply reached the client with the wrong source address and was
// silently discarded as unrecognized). Instead, it's redirected here,
// unconditionally, regardless of its own real destination: the single
// physical (or, in this lab, ContainerLab-simulated point-to-point)
// neighbor one hop off this node's own fabric interface is always the
// correct next hop for a plainly-routable packet, the same property a
// real host's own default gateway has -- from there, ordinary BGP
// routing (once a genuine external client's own reachability is wired
// up -- docs/plans/405-service-vip-route-provider.md, a separate,
// orthogonal gap) takes over exactly like it would for any other host
// on the network.
struct public_uplink_value {
	__u32 link_ifindex;
	__u8 dmac[6];
	__u8 smac[6];
};

// public_uplink_table: see struct public_uplink_value's own doc comment.
// Single-entry BPF_MAP_TYPE_ARRAY, matching node_src_addr_table's
// identical per-node-constant lifecycle and key convention (key 0,
// always present once populated) -- a separate map, not folded into
// node_src_addr_table, since the value shape is entirely different
// (link/L2 info here vs. a plain address there) and the two are read at
// different points in usid_egress for different reasons.
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

// record_value overwrites a drop_reasons slot instead of incrementing it,
// for the TEMPORARY diagnostic slots documented as values rather than
// counts (DROP_REASON_TRACE_ING_LAST_IFINDEX). A counter cannot carry an
// ifindex, and the alternative -- a second map -- would need its own
// pinning and control-plane wiring for a slot that exists only until this
// investigation closes.
static USID_ALWAYS_INLINE void record_value(__u32 slot, __u64 value)
{
	__u64 *cell = bpf_map_lookup_elem(&drop_reasons, &slot);

	if (cell)
		*cell = value;
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

// apply_nptv6 rewrites addr's first v->prefix_len bits to the destination
// prefix's own bits (public_prefix if outbound, ula_prefix otherwise), then
// adds (outbound) or subtracts (!outbound) v->adjustment into the fixed
// word at byte offset 6 (bits 48-63) -- see internal/plumbing/nptv6's
// identical algorithm and doc comment. No checksum helper call is needed:
// this is the entire point of RFC 6296's construction -- the adjustment
// already offsets the prefix change's own contribution to addr's
// 1's-complement checksum, so the packet's existing L4 checksum stays
// valid untouched.
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

// apply_vip_xlat rewrites the packet's addr_off/port_off fields (16-byte
// address, 2-byte port) to new_val's own address/port, fixing up the L4
// checksum at csum_off via three incremental bpf_l4_csum_replace calls (the
// 16-byte address in two 8-byte halves, both BPF_F_PSEUDO_HDR since address
// is a pseudo-header field; the port directly, no PSEUDO_HDR, since port is
// a real L4 header field) -- unlike apply_nptv6, this is a genuine
// substitution (see struct vip_xlat_value's comment), so there is no
// checksum-neutral shortcut available. is_udp preserves a zero UDP checksum
// (meaning "no checksum", RFC 768) as zero rather than "fixing" it into a
// spurious nonzero value (BPF_F_MARK_MANGLED_0) -- TCP has no such
// zero-means-disabled convention, so that flag is only ever passed for UDP.
//
// Validated against a real kernel via BPF_PROG_TEST_RUN
// (TestUsidIngress_VIPXlatRewritesAddrPortAndChecksum): a synthetic UDP
// packet's destination address/port are rewritten and the resulting
// checksum matches an independent full recompute, not just "the verifier
// accepted it" -- an earlier draft's 8-byte-at-a-time csum_replace calls
// failed at runtime with EINVAL (BPF_F_HDR_FIELD_MASK only supports 2/4-byte
// fields, confirmed against net/core/filter.c), and a second draft's
// interleaved packet-pointer reads between helper calls failed verification
// outright (bpf_l4_csum_replace/bpf_skb_store_bytes both invalidate
// previously-derived packet pointers) -- both fixed, see this function's own
// structure below. What remains unvalidated is real traffic through a real
// tap/VM attachment (no such containerlab fixture exists yet -- design plan
// §8); this function's own byte-level correctness is no longer speculative.
static USID_ALWAYS_INLINE long apply_vip_xlat(struct __sk_buff *skb, __u32 addr_off, __u32 port_off,
					       __u32 csum_off, __u8 proto, const __u8 *old_addr,
					       __be16 old_port, const struct vip_xlat_value *new_val)
{
	// bpf_l4_csum_replace's BPF_F_HDR_FIELD_MASK only accepts field sizes
	// 2 or 4 (net/core/filter.c's switch on flags & BPF_F_HDR_FIELD_MASK
	// has no `case 8` at all) -- an 8-byte-at-a-time replace, this
	// function's first working draft, unconditionally fails with EINVAL.
	// The 16-byte address is therefore updated as four 4-byte words, not
	// two 8-byte halves. Confirmed empirically via BPF_PROG_TEST_RUN.
	//
	// Every packet/map read this function needs happens *before* the
	// first helper call, into plain scalar locals, and every
	// bpf_l4_csum_replace/bpf_skb_store_bytes call below only ever
	// touches those locals afterward -- bpf_l4_csum_replace and
	// bpf_skb_store_bytes are both on the verifier's
	// bpf_helper_changes_pkt_data() list (same reason usid_ingress's own
	// steps re-read data/data_end after bpf_skb_adjust_room/
	// bpf_skb_change_proto): calling one invalidates every
	// previously-derived *packet* pointer -- old_addr included, since
	// it's a live pointer into this same packet, not a copy -- and a
	// later helper call's own argument evaluation dereferencing it again
	// is rejected outright ("invalid mem access"). This isn't merely
	// tidier code; interleaving reads and calls as the first draft did
	// is rejected by the verifier, confirmed empirically.
	__u32 from_w[4], to_w[4];
#pragma unroll
	for (int i = 0; i < 4; i++) {
		__builtin_memcpy(&from_w[i], old_addr + i * 4, 4);
		__builtin_memcpy(&to_w[i], new_val->addr + i * 4, 4);
	}
	// old_port/new_val->port are passed as-is (no byte-swap): unlike
	// apply_nptv6's arithmetic on a word (which needs host-order values
	// to add/subtract), bpf_l4_csum_replace's from/to are a raw
	// "what used to be there, what's there now" pair in the same
	// wire-order representation the address words above already use.
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

	// Store from the same from_w/to_w/new_port locals snapshotted above,
	// not new_val directly -- new_val is a map-value pointer, not a
	// packet pointer, so it isn't subject to the same invalidation rule,
	// but using the locals already in hand removes any doubt rather than
	// relying on that distinction holding.
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

		// DSR/Maglev redesign (design plan §2, §0.1): translate the
		// inner packet's *destination* before the FIB lookup below, so
		// the lookup resolves against the tenant's real, routed
		// address -- not the public/VIP address an external
		// client/gateway actually addressed the packet to. Both
		// lookups key on (block, argument), already resolved locally
		// by steps 2-6 above -- no new per-packet identity resolution
		// needed on this (ingress/decap) side.
		struct nptv6_value *npt = bpf_map_lookup_elem(&nptv6_table, &vrf_key);

		if (npt)
			apply_nptv6(inner6->daddr, npt, 0 /* inbound: public -> ULA */);

		// Component 0.1's tap-VIP substitution needs the inner L4
		// destination port to key vip_xlat_table -- read it now
		// (TCP/UDP only; anything else has no port to substitute on
		// and is left alone) before the strip-relative offsets below
		// are computed. This is inner6->nexthdr (the freshly-stripped
		// *inner* header's own next-header field), deliberately not
		// the outer ip6->nexthdr checked above -- that field only
		// ever names IPIP(4)/IPv6-in-IPv6(41) (the outer encap
		// format), never the inner packet's own L4 protocol; ip6 is
		// also no longer a valid pointer here regardless; the strip
		// above (bpf_skb_adjust_room/bpf_skb_change_proto) can
		// relocate the underlying buffer, invalidating every pointer
		// derived before it, and the verifier enforces this.
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
					// apply_vip_xlat's bpf_skb_store_bytes calls
					// invalidate every previously-derived packet
					// pointer -- re-read data/data_end and
					// re-derive inner6 the same fixed-offset way
					// it was originally computed (new_eth+1), not
					// via the now-stale pointer.
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
			// docs/agents/ARCHITECTURE-CNI.md's Known Constraints.
			count_claimed_drop(DROP_REASON_FIB_FRAG_NEEDED, vrf);
		else
			count_claimed_drop(DROP_REASON_FIB_LOOKUP_FAILED, vrf);
		return TC_ACT_SHOT;
	}

	// TEMPORARY (see DROP_REASON_TRACE_ING_REACHED_REDIRECT): record the
	// resolved redirect target before using it. A lookup that returns
	// SUCCESS is not required to hand back a usable ifindex, and
	// redirecting to a zero one is a silent post-return discard.
	record_value(DROP_REASON_TRACE_ING_LAST_IFINDEX, (__u64) fib_params.ifindex);

	if (fib_params.ifindex <= 0) {
		count_claimed_drop(DROP_REASON_FIB_NO_IFINDEX, vrf);
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

// usid_egress (design plan §0.1, §2) is usid_ingress's outbound companion:
// a tenant's own reply/outbound traffic needs the reverse NPTv6 rewrite
// (ULA -> public, on the packet's *source*) and/or the reverse tap-VIP
// substitution (real addr:port -> VIP addr:port, also on *source*), and
// (docs/plans/tc-bpf-egress-srv6-encap.md) the tenant VRF's own egress
// SRv6 encapsulation, before the packet leaves this node at all.
//
// Attach point, and why it is NOT the shared physical/fabric-facing
// interface usid_ingress attaches to: this program's whole job (both its
// original NPTv6/VIP-xlat responsibilities and its egress-routing
// extension below) is to run *before* anything has yet decided how to
// route this packet onward -- once a packet reaches the physical uplink,
// that decision has already been made and the SID this program itself now
// resolves would have to be un-done and re-done. There is also nothing at
// that shared attach point to key a per-sender-VRF lookup on without
// decoding the inner packet's own (potentially colliding across tenants,
// per the same reasoning usidresolver.go's tenant-ownership fix already
// closed for a different lookup) ULA source address.
//
// Correct attach point: TC *ingress* of the tenant's own host-side veth (or
// tap, for a VM), the exact interface usid_ingress's own step 9 already
// redirects packets *to* -- the standard "from-container" interception
// point (mirroring e.g. Cilium's own per-endpoint egress hook). At that
// point the packet is still a plain, unencapsulated, per-attachment
// (so VRF-unambiguous) tenant packet -- (block, argument) is resolved via
// ifindex_vrf_table (keyed on skb->ifindex, this interface's own identity),
// not decoded from packet content at all.
//
// This program never "claims" a packet the way usid_ingress does for its
// NPTv6/VIP-xlat responsibilities: an attachment with no NPTv6 mapping and
// no active ServiceVIPBinding is common and expected (most VRFs/backends
// need neither), so a miss on either lookup is not an error. The
// egress-routing extension below is different: once egress_route_table
// has a matching entry, this program *is* that packet's only path off
// this node (the kernel-native SEG6 route this extension replaces is
// being removed, not left as a fallback -- see the design plan's own §5
// migration-ordering note for why it's still safe to leave both mechanisms
// briefly installed together during rollout), so a failure past that
// point is a drop, not a pass-through.
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

	// NPTv6/VIP-xlat remain IPv6-only by design (component 2/0.1); the
	// egress-routing extension below does not share that restriction --
	// RouteEgressAdd/EgressDefaultRouteAdd have always supported IPv4 VPC
	// prefixes egressing over this IPv6-only underlay (egress.go's own
	// Via-attribute handling) -- so an IPv4 packet still needs to reach
	// that logic even though it skips the two IPv6-only rewrites above.
	// Anything that's neither passes through unmodified, same as any
	// packet this program has no mapping for.
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

					// A checksum/store failure here is not
					// this program's packet to drop --
					// only the rewrite itself is
					// abandoned; the egress-routing
					// extension below still runs.
					apply_vip_xlat(skb, addr_off, port_off, csum_off, ip6->nexthdr, ip6->saddr,
							ports->source, vv);

					// apply_vip_xlat's bpf_skb_store_bytes
					// calls invalidate every
					// previously-derived packet pointer --
					// re-derive before reading ip6->daddr
					// below.
					data = (void *) (long) skb->data;
					data_end = (void *) (long) skb->data_end;
					eth = data;
					if ((void *) (eth + 1) > data_end)
						return TC_ACT_SHOT;
					ip6 = (void *) (eth + 1);
					if ((void *) (ip6 + 1) > data_end)
						return TC_ACT_SHOT;

					// This packet's source is now a DSR backend's
					// own ServiceVIPBinding VIP, not its real address
					// -- see public_uplink_table's own doc comment for
					// why it must be redirected there immediately,
					// unconditionally, rather than ever reaching
					// egress_route_table's lookup below (found live:
					// without this, a VRF with NAT66 configured wrongly
					// re-SNATs an already-correctly-VIP-addressed reply
					// through a NAT66 shard, and the real client
					// silently discards it as unrecognized). No
					// count_claimed_drop on failure here (unlike the
					// egress_route_table redirect failure path below)
					// -- vrf_table's own per-VRF vrf_value isn't
					// resolved yet at this point in the function, and
					// this failure path is expected to essentially
					// never fire in practice, the same as that one.
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
					// public_uplink_table not configured yet (this
					// node hasn't converged) -- fall through to the
					// pre-existing behavior below rather than dropping
					// outright; egress_route_table's own NAT66 default
					// may still misroute this reply, but that's no
					// worse than before this redirect existed.
				}
			}
		}

		// Multicast (ff00::/8) and link-local (fe80::/10) destinations
		// must never be matched against egress_route_table, no matter
		// how broad a registered entry is (in particular
		// EgressDefaultRouteAdd's own ::/0 default, which -- being a
		// literal catch-all -- otherwise matches these exactly like any
		// other destination). Found live: a tenant pod's own Neighbor
		// Discovery traffic for resolving its *own default gateway's*
		// link-layer address (an NS targeting a solicited-node
		// multicast address) was being caught by the ::/0 default entry
		// and redirected toward a NAT66 shard SID instead of ever
		// reaching the normal kernel/host-side NDP handling that must
		// answer it -- the container's own gateway neighbor entry went
		// to FAILED and every packet through it silently died with a
		// locally-synthesized "Destination unreachable", never sending
		// anything at all, let alone anything usid_egress's own drop
		// counters could see. The kernel's own routing has an equivalent
		// carve-out by construction (link-local/multicast destinations
		// are always handled by dedicated local-scope routing, never an
		// application's own default route); this replicates it here,
		// since nothing else in this program's own routing model does.
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

	// Resolve this attachment's Linux VRF table id via vrf_table --
	// already populated identically to ifindex_vrf_table at CNI ADD
	// time -- see struct egress_route_key's own comment for why this,
	// not (block, argument), is egress_route_table's key.
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

	// A local pass-through entry (struct egress_route_value's own comment
	// above) -- it exists only to out-match a shorter default entry via
	// LPM, not to be encapsulated toward. Defer to the kernel exactly like
	// a genuine miss above, before touching node_src_addr_table or doing
	// any encap work below.
	if (rv->link_ifindex == 0) {
		count_drop(DROP_REASON_TRACE_PASSTHROUGH_ENTRY);
		return TC_ACT_UNSPEC;
	}

	// node_src_addr_table is BPF_MAP_TYPE_ARRAY, not BPF_MAP_TYPE_HASH:
	// every one of its (here, exactly one) slots always exists from map
	// creation onward, pre-zeroed -- bpf_map_lookup_elem on an in-range
	// array index can never itself signal "not configured yet" the way a
	// HASH map miss (a null return) can. An all-zero address is
	// otherwise never a legitimate value here (the unspecified address
	// convention internal/plumbing/srv6's own RouteEgressAdd/RouteMainAdd
	// already use for "not a usable address"), so it's checked
	// explicitly below as this map's own "not yet configured" signal.
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

	// Push room for a new outer IPv6 header. Positive len_diff grows
	// room (usid_ingress's own strip, above, is this same call with a
	// negative len_diff) -- BPF_ADJ_ROOM_MAC keeps the Ethernet header
	// at the very front and opens the new space directly after it,
	// exactly where the outer header being pushed here belongs.
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
	// skb->len is now the full grown frame (Ethernet + new outer header +
	// original inner packet); the inner payload length this header's own
	// payload_len must carry is that minus the Ethernet and outer-header
	// bytes just added.
	__u16 inner_len = (__u16) (skb->len - (__u32) sizeof(struct usid_ethhdr) - (__u32) sizeof(struct usid_ip6hdr));

	outer->payload_len = __builtin_bswap16(inner_len);
	outer->nexthdr = (route_family == USID_EGRESS_ROUTE_FAMILY_INET6) ? USID_IPPROTO_IPV6 : USID_IPPROTO_IPIP;
	outer->hop_limit = USID_EGRESS_HOP_LIMIT;
	__builtin_memcpy(outer->saddr, src, 16);
	__builtin_memcpy(outer->daddr, rv->sid, 16);
	new_eth->h_proto = __builtin_bswap16(USID_ETH_P_IPV6);

	// L2 (dmac/smac) and the real egress interface all come straight from
	// rv -- resolved once by the Go control plane at Register time, not
	// via a runtime bpf_fib_lookup() here. This is a deliberate departure
	// from usid_ingress's own step 8 (which *does* call bpf_fib_lookup()
	// per packet): confirmed live, bpf_fib_lookup() called from this
	// program's own attach point (the tenant's own VRF-enslaved veth)
	// unconditionally returns BPF_FIB_LKUP_RET_BLACKHOLE for a
	// main-table destination -- tried with BPF_FIB_LOOKUP_TBID, without
	// it, with BPF_FIB_LOOKUP_DIRECT, without it, and with fib_params.ifindex
	// set to both skb->ifindex and a neutral non-VRF-enslaved ifindex,
	// all four combinations identically blackholed a destination `ip -6
	// route get` resolves just fine outside BPF. This is the kernel's own
	// VRF/l3mdev isolation boundary asserting itself against the
	// *attaching* skb's real device (skb->dev), independent of anything
	// bpf_fib_lookup's own params can override -- not a parameter bug.
	// usid_ingress never hits this because its own attach point (the
	// physical uplink) was never VRF-enslaved to begin with.
	__builtin_memcpy(new_eth->h_dest, rv->dmac, sizeof(new_eth->h_dest));
	__builtin_memcpy(new_eth->h_source, rv->smac, sizeof(new_eth->h_source));

	// Same-netns redirect: this program's attach point (the tenant's own
	// host-side veth) and the resolved physical uplink both live in the
	// root/host netns, unlike usid_ingress's step 9 veth-mode branch
	// (which crosses into a *different* netns and needs
	// bpf_redirect_peer for exactly that reason).
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
