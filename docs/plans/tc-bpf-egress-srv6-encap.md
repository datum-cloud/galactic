# Design Plan — Replace Kernel-Native SEG6 Lwtunnel Egress Encap with TC-BPF

## 0. Problem statement

Every tenant-VRF egress route this codebase installs today
(`RouteEgressAdd`, `EgressDefaultRouteAdd`, both in
`internal/plumbing/srv6/egress.go`) relies on the Linux kernel's own
native SEG6 lwtunnel route encapsulation (`netlink.SEG6Encap`, mode
`SEG6_IPTUN_MODE_ENCAP_RED`) to push the outer SRv6/tunnel header onto a
packet leaving a tenant VRF. This is a real, currently-unpatched Linux
kernel bug, confirmed live in the containerlab lab and documented in the
kitt note `projects/galactic/seg6-vrf-recursion-kernel-bug.md`:

- **CVE-2026-31668** — "seg6: separate dst_cache for input and output
  paths in seg6 lwtunnel." The seg6 lwtunnel implementation shares a
  single `dst_cache` per encap route between `seg6_input_core()` and
  `seg6_output_core()`. When those two paths resolve the post-encap SID
  lookup under **different routing contexts — the fix's own upstream
  writeup names "VRF table separation" as a trigger case** — whichever
  path runs first populates the cache, and the other reuses it blindly,
  producing a routing loop that trips the kernel's own recursion guard
  and silently drops the packet (`lwtunnel_input(): recursion limit
  reached on datapath`).
- Confirmed via direct testing on the lab's `dfw-worker`/`sjc-worker`
  nodes: `verify:ns10` and `verify:ns20` (plain inter-site tenant
  connectivity, no NAT66/DSR code involved) both fail with 100% packet
  loss, the recursion message firing in lockstep with each ping attempt,
  and `tcpdump` on the physical uplink showing the packet never leaves
  the host at all — it's dropped inside the kernel's own encapsulation
  logic before transmission.
- The fix landed upstream at **7.1.7** on the 7.1.x stable branch (the
  CVE's fixed-version list: 5.10.264, 5.15.215, 6.1.182, 6.6.150,
  6.12.102, 6.18.43, 7.1.7, mainline 7.2-rc5). As of this writing, no
  Fedora repo (stable or `updates-testing`) has shipped anything past
  7.1.4 — the fix is not available to install, not just risky to apply.

**This is not a lab-only problem.** Galactic is explicitly a *multi-cloud*
dataplane — it cannot assume uniform control over every node's kernel
version across every cloud it runs on, and even where the underlying
infrastructure is controlled, tracking and enforcing a minimum kernel
version fleet-wide is an open-ended operational burden that does nothing
for any node already running an affected kernel. A production node on an
affected kernel would silently black-hole ordinary inter-VPC tenant
traffic with no application-level error at all — exactly what `verify:
ns10`/`verify:ns20` demonstrate in the lab. Treating this as a
lab-environment quirk to document and move past was the wrong call (see
the kitt note's revision history); it needs a real fix.

## 1. Goal

Remove this codebase's dependency on kernel-native SEG6 lwtunnel route
encapsulation entirely, for every egress path that currently uses it.
Once done, no galactic-controlled datapath should touch
`seg6_output_core()`/`seg6_input_core()` at all, on any kernel version —
eliminating this entire bug class going forward rather than working
around one instance of it.

This mirrors a decision this codebase already made once, for a different
but analogous reason: `usid_ingress` (the uSID decap path,
`internal/plumbing/ebpf/prog/usid.c`) is a TC-BPF program, not a native
`seg6local` route, specifically because kernel-native SRv6 endpoint
processing was judged too fragile/under-tested a corner of the kernel
networking stack to depend on for a multi-tenant dataplane. This plan
applies the same judgment to the encapsulation (egress) side, which
today is the one remaining place native kernel SRv6 machinery is still
load-bearing.

## 2. What's in scope

Three call sites in `internal/plumbing/srv6/egress.go` currently install
a `netlink.SEG6Encap`-bearing route:

- `RouteEgressAdd` — per-destination-prefix intra-VPC peer routes (one
  segment: the peer node's own uSID address).
- `EgressDefaultRouteAdd` — the tenant VRF's `::/0` fallback, added for
  NAT66 egress (one segment: a NAT66 shard's SID).

`RouteMainAdd` is **out of scope** — it installs a plain, non-SEG6
recursive route for RT-less anycast VIP paths (see its own doc comment:
wrapping that traffic in another SRv6 header would make it
undeliverable, nothing is listening for it). It never touches
`netlink.SEG6Encap` and doesn't exercise the buggy kernel code path at
all.

## 3. Why this is smaller than "implement generic SRv6 encapsulation in
BPF" sounds

Every existing call site installs a route with **exactly one segment** —
multi-segment SRH support has never actually been used. And
`usid_ingress`'s own doc comment already establishes what today's wire
format actually looks like: `SEG6_IPTUN_MODE_ENCAP_RED` with one segment
omits the Segment Routing Header entirely (RFC 8754 Next Header 43) —
"the one segment is already fully expressed by the outer destination
address, so there is nothing left for an SRH to carry" — leaving the
outer header's Next Header set **directly** to the inner packet's own
protocol (4/IPIP or 41/IPv6-in-IPv6). `usid_ingress` already requires
and depends on exactly this shape on decap (`DROP_REASON_UNEXPECTED_NEXTHDR`
for anything else).

So what needs replacing is not a general SRH pusher — it's a plain
IPv6-in-IPv6 / IPIP-over-IPv6 tunnel header prepend, with the destination
set to the resolved SID. That's a well-trodden `bpf_skb_adjust_room`
pattern, structurally the mirror image of what `usid_ingress` already
does on strip (step 7 of its own doc comment), not new territory.

This plan explicitly does **not** add multi-segment SRH support in BPF —
if a future requirement needs it, that's new scope on top of this, not
part of closing out the kernel bug.

## 4. Proposed mechanism

### 4.1 Attachment point

Attach a new TC-BPF program at **ingress on each tenant's host-side veth
(or tap) interface** — i.e. the CNI's own per-attachment interface
(`G0...H`), not the shared physical uplink `eth1`. This is the point
where a pod's outbound packet first arrives on the host side, before any
routing decision is made, and — critically — it is **already 1:1 with
exactly one tenant VRF/routing table**, the same association
`RouteEgressAdd`/`EgressDefaultRouteAdd` are keyed on today. That means
the new program needs no VRF-table lookup of its own: which map to
consult is implicit in which interface the program is attached to,
exactly the same "attachment point carries tenant identity" property
`usid_ingress`'s own `vrf_table`/`Argument` match already relies on for
its side of the split.

This also means CNI ADD/DEL, which already attaches/detaches per-veth TC
filters today (`internal/plumbing/ebpf/attach`), is the natural place to
attach/detach this program too — no new lifecycle hook needed.

### 4.2 Map design

One `BPF_MAP_TYPE_LPM_TRIE`, pinned per veth (or keyed by the veth's own
ifindex in a single shared trie — pick whichever the implementation
phase finds cleaner; both are viable, see the "open questions" list
below), mapping destination prefix → `{segment SID, egress ifindex,
resolved L2 next-hop}`. This is a direct port of what
`RouteEgressAdd`/`EgressDefaultRouteAdd` already compute in Go today via
`resolveNextHop` (which does exactly this resolution against the
kernel's own routing table) — the *resolution* logic doesn't change, only
where the result is installed: a BPF map entry via
`ebpf.Map.Put`/`Update`, instead of a `netlink.RouteReplace` carrying
`SEG6Encap`.

A default (`::/0`) entry in the same trie replaces
`EgressDefaultRouteAdd`'s route; LPM match naturally gives specific
intra-VPC prefixes priority over it, matching today's FIB longest-prefix
semantics with no special-casing needed.

### 4.3 Datapath

1. Parse the packet (inner IPv4 or IPv6 — dual-stack, matching
   `usid_ingress`'s own DT46 handling).
2. LPM-match the inner destination against this attachment's own trie.
   No match — this shouldn't happen once the default entry exists (see
   §5's rollout-ordering note); `TC_ACT_UNSPEC` if it ever does, so an
   incompletely-configured attachment fails open to the normal stack
   rather than black-holing traffic.
3. `bpf_skb_adjust_room` to grow the packet, write the new outer IPv6
   header (destination = matched SID, Next Header = 4 or 41 per inner
   AF, matching `usid_ingress`'s own expectation on the receiving end).
4. Redirect out the matched egress interface/next-hop
   (`bpf_redirect`/`bpf_redirect_neigh`, resolved the same way
   `usid_ingress`'s step 9 already picks between `bpf_redirect_peer` and
   `bpf_redirect` depending on egress_kind — here egress is always the
   shared physical uplink, not a netns-crossing veth, so this is closer
   to `usid_ingress`'s tap-mode branch: same-netns, plain redirect).

### 4.4 Go-side changes

- `internal/plumbing/srv6/egress.go`: `RouteEgressAdd`/`RouteEgressDel`/
  `EgressDefaultRouteAdd`/`EgressDefaultRouteDel` stop calling
  `netlink.RouteReplace`/`netlink.RouteDel` with `SEG6Encap` and instead
  write/delete entries in the new BPF map for the relevant attachment.
  Keep `resolveNextHop` as-is — its job (flatten an indirect BGP
  next-hop into a concrete link+L3 hop) is unchanged.
- New file alongside `usid.c` (e.g. `usid_egress_route.c`, name TBD at
  implementation time) plus its own `attach`/pin wiring in
  `internal/plumbing/ebpf/attach`, following the exact pattern already
  established for `usid_egress` (`AttachEgress`, `UsidEgressPinName`,
  etc.) in this same package.
- `internal/cnibgp/bgp.go`'s `registerEBPFDatapath` gets a new
  attach/detach call alongside `attachUsidEgress`.

## 5. Migration / rollout ordering

Attach the new program and populate its default-route map entry
*before* removing the old netlink SEG6 route it replaces, per attachment
— never leave a window where a tenant VRF has neither. Given
`RouteEgressAdd`/`EgressDefaultRouteAdd` are idempotent
(`netlink.RouteReplace`) and the new program starts with an empty trie
that fails open (`TC_ACT_UNSPEC`) rather than dropping, the safe
sequence per existing attachment is: attach program → populate map →
delete old netlink route. New attachments (fresh CNI ADD) only ever need
the new path.

## 6. Testing plan

- Unit: `BPF_PROG_TEST_RUN`-based tests for the new program, matching
  `usid_test.go`'s/`nat66_test.go`'s existing style — construct a raw
  packet, run the program, assert the resulting header. Cover both inner
  AFs (IPv4/IPIP, IPv6/IPv6-in-IPv6), the LPM default-vs-specific
  priority case, and the fail-open (no map entries) case.
- Local integration: real netns + real veth pair (no XDP/TC live-node
  dependency), matching this session's existing `egress_test.go` style,
  to prove map population write path end-to-end without touching the
  live lab.
- Containerlab: re-run `verify:ns10`, `verify:ns20`, and
  `verify:nat66-sharding` against a lab rebuilt on this mechanism — these
  are the exact three that motivated this plan and should all pass
  without the kernel dependency once it lands.

## 7. Explicitly out of scope

- Multi-segment SRH support (§3) — no current call site needs it.
- `RouteMainAdd`'s plain recursive route (§2) — untouched, doesn't use
  SEG6 encap.
- Any change to `usid_ingress`'s own decap side — it's already TC-BPF
  and already unaffected by this bug.
- A minimum-kernel-version enforcement mechanism — considered and
  rejected as the primary fix (§0: doesn't hold up across genuinely
  heterogeneous multi-cloud node kernels, and does nothing for
  already-affected nodes), though nothing here prevents adding one later
  as defense in depth once this lands.

## 8. Open questions

- Per-veth pinned map vs. one shared trie keyed by ifindex: the former
  matches `usid_ingress`'s existing per-value (not per-interface) map
  layout less closely but avoids any cross-tenant key collision by
  construction; the latter is one map to manage instead of N. Decide at
  implementation time once the attach/pin plumbing is actually being
  written.
- Exact redirect helper (`bpf_redirect` vs `bpf_redirect_neigh`) depends
  on whether the physical uplink's L2 next-hop resolution needs to be
  precomputed (as `resolveNextHop` does today) or can be left to the
  kernel's neighbor table at redirect time — a real implementation-time
  tradeoff, not a design blocker.
- Whether this new program and `usid_egress` (the existing DSR
  reply-path VIP-translation program) should be merged into one program
  attached at the same point, or stay separate — they run at different
  conceptual stages (VIP translation vs. VRF-egress routing) but may end
  up on the same interface. Decide once both are concretely in hand.
