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
//     or too short to parse -- TC_ACT_OK (pass through unmodified, R6).
//  2. Exact-match the destination address's top 64 bits (uSID Block(48) +
//     Node-ID(16), read with no shift) against locator_table. No match --
//     TC_ACT_OK (not one of this node's uSID Blocks, R6).
//  3. Read Function directly from the unmutated packet at its fixed
//     offset (bits 65-68) -- no shift, no mutation (R2).
//  4. Exact-match (matched Block, Function) against function_table. No
//     match -- drop, counted (DROP_REASON_UNKNOWN_FUNCTION): this packet
//     was already claimed by step 2's locator match, so silent
//     pass-through here would duplicate-deliver it to the normal stack.
//  5. Read Argument directly from the unmutated packet at its fixed
//     offset (bits 69-80) -- no shift, no mutation (R2, R4). Argument
//     0x000 is reserved and never registered into vrf_table (R4, design
//     plan §5.1), so it always misses step 6 -- no special-cased check
//     needed here.
//  6. Exact-match (matched Block, Argument) against vrf_table. No match --
//     drop, counted (DROP_REASON_UNKNOWN_ARGUMENT). Per-Argument hit
//     counters (packets, bytes, last_seen) are updated in vrf_table's
//     value on every match that reaches this step, supporting R8's
//     dual-key migration counters.
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
// self-declaration for the compiled bytecode (governs which helper
// functions the verifier allows), independent of this file's own
// AGPL-3.0-or-later SPDX header above: it says nothing about the licensing
// of the surrounding Go project, exactly as Cilium, Katran, and every
// other AGPL/Apache/BSD-licensed project embedding a BPF datapath declares
// a GPL-compatible license string here for the same reason.

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

static long (*bpf_skb_adjust_room)(struct __sk_buff *skb, __s32 len_diff, __u32 mode,
				    __u64 flags) = (void *) BPF_FUNC_skb_adjust_room;

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
// BEHAVIOR_END_DT46 is the only behavior defined today (design plan R3);
// BEHAVIOR_END_DT2 is reserved for the future L2 uEnd.DT2 path and is not
// otherwise referenced by this program.
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
struct vrf_value {
	__u32 vrf_table_id;
	__u32 egress_kind;
	__u64 packets;
	__u64 bytes;
	__u64 last_seen_ns;
	__u64 generation;
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
	// with headroom; tune alongside R7 multi-Block sizing later.
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
	void *data = (void *) (long) skb->data;
	void *data_end = (void *) (long) skb->data_end;

	// Step 1: parse the outer Ethernet + IPv6 header (fixed 40B,
	// bounds-checked). Not a match -- TC_ACT_OK, pass through
	// unmodified (R6).
	struct usid_ethhdr *eth = data;

	if ((void *) (eth + 1) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto != __builtin_bswap16(USID_ETH_P_IPV6))
		return TC_ACT_OK;

	struct usid_ip6hdr *ip6 = (void *) (eth + 1);

	if ((void *) (ip6 + 1) > data_end)
		return TC_ACT_OK;

	// Step 2: exact-match the destination address's top 64 bits
	// (Block(48) + Node-ID(16), read with no shift) against
	// locator_table. No match -- TC_ACT_OK, pass through (R6).
	__u64 locator_key = read_be64(&ip6->daddr[0]);

	struct locator_value *loc = bpf_map_lookup_elem(&locator_table, &locator_key);

	if (!loc)
		return TC_ACT_OK;

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
	if ((void *) (ip6 + 1) + 1 > data_end) {
		count_drop(DROP_REASON_MALFORMED_INNER);
		return TC_ACT_SHOT;
	}

	// Step 7: strip the outer IPv6 header, exposing the inner
	// IPv4/IPv6 packet (dual-stack, per uEnd.DT46 -- R5).
	if (bpf_skb_adjust_room(skb, -(__s32) sizeof(struct usid_ip6hdr), BPF_ADJ_ROOM_MAC, 0)) {
		count_drop(DROP_REASON_STRIP_FAILED);
		return TC_ACT_SHOT;
	}

	// bpf_skb_adjust_room can change the underlying packet buffer: all
	// previously derived data/data_end pointers are invalidated and
	// must be re-read.
	data = (void *) (long) skb->data;
	data_end = (void *) (long) skb->data_end;

	struct usid_ethhdr *new_eth = data;

	if ((void *) (new_eth + 1) > data_end) {
		count_drop(DROP_REASON_MALFORMED_INNER);
		return TC_ACT_SHOT;
	}

	__u8 *inner = (__u8 *) (new_eth + 1);

	if ((void *) (inner + 1) > data_end) {
		count_drop(DROP_REASON_MALFORMED_INNER);
		return TC_ACT_SHOT;
	}

	__u8 inner_version = (*inner) >> 4;

	struct bpf_fib_lookup fib_params;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));

	if (inner_version == 6) {
		struct usid_ip6hdr *inner6 = (void *) inner;

		if ((void *) (inner6 + 1) > data_end) {
			count_drop(DROP_REASON_MALFORMED_INNER);
			return TC_ACT_SHOT;
		}

		fib_params.family = USID_AF_INET6;
		__builtin_memcpy(fib_params.ipv6_src, inner6->saddr, sizeof(fib_params.ipv6_src));
		__builtin_memcpy(fib_params.ipv6_dst, inner6->daddr, sizeof(fib_params.ipv6_dst));
		new_eth->h_proto = __builtin_bswap16(USID_ETH_P_IPV6);
	} else if (inner_version == 4) {
		struct usid_iphdr *inner4 = (void *) inner;

		if ((void *) (inner4 + 1) > data_end) {
			count_drop(DROP_REASON_MALFORMED_INNER);
			return TC_ACT_SHOT;
		}

		fib_params.family = USID_AF_INET;
		__builtin_memcpy(&fib_params.ipv4_src, inner4->saddr, sizeof(fib_params.ipv4_src));
		__builtin_memcpy(&fib_params.ipv4_dst, inner4->daddr, sizeof(fib_params.ipv4_dst));
		new_eth->h_proto = __builtin_bswap16(USID_ETH_P_IP);
	} else {
		count_drop(DROP_REASON_UNKNOWN_INNER_VERSION);
		return TC_ACT_SHOT;
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
		count_drop(DROP_REASON_FIB_LOOKUP_FAILED);
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
		count_drop(DROP_REASON_REDIRECT_FAILED);
		return TC_ACT_SHOT;
	}

	return redirect_rc;
}

char __license[] SEC("license") = "Dual BSD/GPL";
