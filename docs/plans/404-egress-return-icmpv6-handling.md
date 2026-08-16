# Implementation Plan — Translate ICMPv6 Egress Replies Instead of Dropping Them

- **Issue:** [datum-cloud/galactic#404](https://github.com/datum-cloud/galactic/issues/404) — "Egress
  replies that are not TCP or UDP are dropped, including path MTU discovery."
- **Applies to:** `internal/plumbing/ebpf/edgeprog/edgenat.c`'s egress (masquerade) datapath, added by
  the still-open, still-unmerged `feat/865-egress-phase-b` branch (galactic#381) — **not yet on
  `main`**. See §7 for why this changes where the fix should land.
- **Status:** planning only — no implementation started.

## 1. Issue recap

`handle_egress_return` (the branch that handles internet-originated replies addressed to a gateway
node's public `masq_addr`) claims that address and drops anything that isn't TCP or UDP:

```c
if (ip6->nexthdr != EDGE_IPPROTO_TCP && ip6->nexthdr != EDGE_IPPROTO_UDP) {
	count_drop(DROP_REASON_MALFORMED_EGRESS_RETURN);
	return XDP_DROP;
}
```

`masq_addr` is reachable from the entire internet, and the internet routinely sends ICMPv6 to it:
Destination Unreachable, Packet Too Big (the PMTUD message), Time Exceeded, and Echo Reply all arrive
this way, and all of them are dropped today. Per the issue and the author's own review comment (#381),
this was a known, called-out deferral — `handle_egress_forward` (the tenant-outbound side) has the
identical restriction and the same review comment flags it as "the tenant-outbound side of the same
restriction" — but nothing tracked closing either half.

Two consequences called out as the reason this matters:

- **Packet Too Big being dropped breaks PMTUD.** A tenant connection crossing a smaller-MTU link
  anywhere on the path stalls instead of adapting, on large transfers only, intermittently — one of the
  hardest failure classes to attribute back to its actual cause.
- **Echo Reply being dropped breaks the simplest reachability check a tenant can run** (`ping` from
  inside their own workload), which reads as "the network is broken" long before ansyone suspects the
  gateway.

The review comment also flags two smaller items to fold in: `DROP_REASON_MALFORMED_EGRESS_RETURN` is
the wrong reason name for a well-formed ICMPv6 packet (it's a protocol-policy decision, not a parse
failure), and translating ICMP errors back to the originating tenant requires parsing the embedded
original datagram to recover the masqueraded port, since ICMPv6 has no ports of its own to key
`egress_conn_table` on.

## 2. Current behavior (read from `feat/865-egress-phase-b`)

`handle_egress_return` (`edgenat.c`, currently ~line 1227) unconditionally requires
`ip6->nexthdr == EDGE_IPPROTO_TCP || EDGE_IPPROTO_UDP` before doing anything else, counting
`DROP_REASON_MALFORMED_EGRESS_RETURN` and dropping otherwise. `handle_egress_forward` (currently
~line 1074) has the mirrored restriction on the inner (post-decap) packet, counting
`DROP_REASON_MALFORMED_EGRESS_FORWARD`. Both reach the top-level `edge_nat()` dispatcher unconditionally
for their respective claimed addresses (`masq_addr`, `egress_sid`) — there is no protocol filtering
before either function is called, only inside them.

`egress_conn_table`'s existing reverse-direction key — `(proto, dest_addr:dest_port →
masq_addr:masq_port)` — is exactly what a TCP/UDP reply is looked up by (§3.2/§3.3 of
`docs/plans/865-edge-gateway-nat66-egress.md`). This plan's core insight is that both new ICMPv6 cases
can reuse that same key shape without any map or struct change:

- An **ICMPv6 error message** (Destination Unreachable/Packet Too Big/Time Exceeded/Parameter Problem)
  embeds the IPv6 header and (per RFC 4443) at least the first 8 bytes of the transport header of the
  packet that triggered it — which, for a packet this program itself SNAT'd on the way out, is
  `masq_addr:masq_port → dest_addr:dest_port`, read one layer deeper than a direct TCP/UDP reply.
- An **ICMPv6 Echo Reply** has no ports at all, but its Identifier field plays the same role a
  port does for every other conntrack implementation (Linux's `nf_conntrack` ICMP tracker does the
  same) — so `handle_egress_forward` needs a matching change on the way out: mask the Identifier the
  same way it already masks the source port for TCP/UDP.

## 3. Fix

### 3.1 New wire constants and header structs (`edgenat.c`)

Alongside `EDGE_IPPROTO_TCP`/`EDGE_IPPROTO_UDP`:

```c
#define EDGE_IPPROTO_ICMPV6 58

#define EDGE_ICMPV6_DEST_UNREACH   1
#define EDGE_ICMPV6_PACKET_TOO_BIG 2
#define EDGE_ICMPV6_TIME_EXCEEDED  3
#define EDGE_ICMPV6_PARAM_PROBLEM  4
#define EDGE_ICMPV6_ECHO_REQUEST   128
#define EDGE_ICMPV6_ECHO_REPLY     129
```

Alongside `edge_tcphdr`/`edge_udphdr` (packet-parsing structs, never map key/values — no `bpf2go
-type` exposure needed, same as the existing two):

```c
// Common 4-byte prefix shared by every ICMPv6 message type this program
// reads (RFC 4443 §2.1).
struct edge_icmp6hdr {
	__u8 type;
	__u8 code;
	__be16 check;
} __attribute__((packed));

// Destination Unreachable/Packet Too Big/Time Exceeded/Parameter Problem
// (RFC 4443 §3) share this 8-byte header shape -- the 4 bytes after
// checksum vary by type (unused for 1/3, MTU for 2, pointer for 4) and
// this program never reads them. What follows is "as much of the
// invoking packet as possible," guaranteed to include at least the
// embedded IPv6 header's first 48 bytes (RFC 4443 §2.4(c)) -- the full
// 40-byte IPv6 header plus the first 8 bytes of whatever transport
// header follows, which is where both TCP and UDP keep their two 16-bit
// port fields.
struct edge_icmp6_error_hdr {
	__u8 type;
	__u8 code;
	__be16 check;
	__u8 unused[4];
} __attribute__((packed));

// Echo Request/Reply (RFC 4443 §4). identifier stands in for the port
// egress_conn_table is keyed by, for both this program's PAT-style
// re-mapping and the tenant's own kernel matching a reply back to the
// socket that sent the request -- see handle_egress_forward_icmp6 and
// handle_egress_return_icmp6_echo.
struct edge_icmp6_echo_hdr {
	__u8 type;
	__u8 code;
	__be16 check;
	__be16 identifier;
	__be16 sequence;
} __attribute__((packed));
```

### 3.2 New drop reasons, appended (safe — nothing on this branch has shipped)

```c
enum edge_drop_reason {
	...                                    // unchanged, 0-14
	DROP_REASON_MALFORMED_EGRESS_ICMP = 15,
	DROP_REASON_NO_EGRESS_ICMP_CONN   = 16,
	DROP_REASON_COUNT                 = 17,
};
```

This directly answers the review comment's "a distinct reason would pay for itself" note: an operator
reading drop counters can now tell a genuinely malformed ICMPv6 message (`MALFORMED_EGRESS_ICMP`) apart
from a well-formed one with no matching flow (`NO_EGRESS_ICMP_CONN`) apart from the pre-existing
TCP/UDP-specific `MALFORMED_EGRESS_RETURN`/`NO_EGRESS_RETURN_CONN`. No reuse of
`DROP_REASON_NO_EGRESS_CONN_NOT_SYN` for the ICMP forward-allocation path — every Echo Request may
start a new flow the same way "any UDP packet may start a new flow" already does, so that check never
applies to ICMP and no new reason is needed there. `DROP_REASON_EGRESS_PAT_EXHAUSTED` is reused as-is
for identifier-claim exhaustion (§3.4) — it's the same exhausted-probe condition regardless of which
field is being re-mapped.

Mirror in `internal/plumbing/ebpf/edgeprog/dropreason.go` (hand-kept in sync, per that file's own doc
comment): add `DropReasonMalformedEgressICMP uint32 = 15`, `DropReasonNoEgressICMPConn uint32 = 16`,
bump `DropReasonCount` to `17`, and add both to `DropReasonNames` (`"malformed_egress_icmp"`,
`"no_egress_icmp_conn"`).

No `go:generate`/`bpf2go -type` change needed — `edge_icmp6hdr`/`edge_icmp6_error_hdr`/
`edge_icmp6_echo_hdr` are packet-parsing structs, not map key/value types, the same category
`edge_tcphdr`/`edge_udphdr` already fall into. Re-run `task ebpf:generate` after editing `edgenat.c` so
the compiled object picks up the widened `drop_reasons` `PERCPU_ARRAY` (`DROP_REASON_COUNT` grew).

### 3.3 `handle_egress_return`: dispatch on protocol instead of gating on it

```c
static EDGE_ALWAYS_INLINE int handle_egress_return(struct xdp_md *ctx, struct edge_ip6hdr *ip6, void *data_end)
{
	if (ip6->nexthdr == EDGE_IPPROTO_ICMPV6)
		return handle_egress_return_icmp6(ctx, ip6, data_end);

	if (ip6->nexthdr != EDGE_IPPROTO_TCP && ip6->nexthdr != EDGE_IPPROTO_UDP)
		// Some other protocol addressed to masq_addr -- e.g. Neighbor
		// Discovery, or an Echo Request targeting this node's own
		// public address directly rather than replying to a tenant
		// flow. Not this program's to translate; hand it to the
		// normal kernel stack instead of dropping it (mirrors step 1's
		// "can't fully parse/match -> XDP_PASS", just decided
		// per-protocol here since this address is otherwise claimed).
		return XDP_PASS;

	/* ... existing TCP/UDP body, unchanged ... */
}
```

`handle_egress_return_icmp6` reads just the shared 4-byte prefix, bounds-checks it, and dispatches
again by ICMPv6 type:

```c
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

	// Router Advertisement, Neighbor Solicitation/Advertisement, an Echo
	// Request targeting masq_addr directly, ... -- not a reply to any
	// tenant flow this program tracks. XDP_PASS, not XDP_DROP.
	return XDP_PASS;
}
```

### 3.4 Echo Reply: identifier as the pseudo-port, both directions

**Forward (tenant → internet), `handle_egress_forward`:** currently the inner (post-decap) packet is
rejected outright unless `nexthdr` is TCP/UDP. Split the existing TCP/UDP body into
`handle_egress_forward_l4` (unchanged logic, just factored out) and add a sibling
`handle_egress_forward_icmp6`, dispatched the same way `handle_egress_return` now is:

```c
if (inner->nexthdr == EDGE_IPPROTO_ICMPV6)
	return handle_egress_forward_icmp6(ctx, eth, inner, tenant_arg, backend_usid, data_end);
if (inner->nexthdr != EDGE_IPPROTO_TCP && inner->nexthdr != EDGE_IPPROTO_UDP) {
	count_drop(DROP_REASON_MALFORMED_EGRESS_FORWARD);
	return XDP_DROP;
}
return handle_egress_forward_l4(ctx, eth, inner, tenant_arg, backend_usid, data_end);
```

`handle_egress_forward_icmp6` accepts only `EDGE_ICMPV6_ECHO_REQUEST` (anything else from a tenant
backend — Echo Reply, Router Solicitation, Neighbor Discovery — has no defined masquerade behavior and
is dropped, `DROP_REASON_MALFORMED_EGRESS_ICMP`, same "this address is claimed" reasoning as everywhere
else in this file). On a miss, it allocates exactly like `handle_egress_forward_l4`'s SNAT-port claim,
just keyed by `identifier` in both the forward key's `sport`/`dport` slots and the reverse key's, with
the same bounded linear-probe/`BPF_NOEXIST` claim over `egress_conn_table` — no new map, no new probe
technique, just the field being re-mapped is an identifier instead of a port.
`egress_conn_value.backend_port`/`dest_port`/`masq_port` are reused to hold the identifier for
`proto == EDGE_IPPROTO_ICMPV6` flows rather than adding dedicated fields — call this out with an
explicit comment on `struct egress_conn_value` (same reasoning the file already applies elsewhere:
"passing the same old/new value ... contributes zero diff," `fix_l4_checksum` doesn't care what a field
means, just that old/new pairs line up).

The rewrite masquerades **both** the source address and the identifier (mirroring the SNAT-port
rewrite exactly, with identifier standing in for port), fixing the ICMPv6 checksum via the same
`fix_l4_checksum` helper (an address+word-pair checksum-diff, not a Full-NAT-specific one — any field
held equal old/new contributes zero delta, so passing `0` for the unused word-slot is safe, same
technique `handle_egress_forward_l4`'s own SNAT-only rewrite already uses).

**Return (internet → tenant), `handle_egress_return_icmp6_echo`:** looks up `egress_conn_table` by the
reverse key built from `ip6->saddr`/`ip6->daddr`/`echo->identifier` (identifier in both the `sport` and
`dport` slots, matching what the forward allocation wrote) — a miss counts
`DROP_REASON_NO_EGRESS_ICMP_CONN` and drops. A hit un-masquerades **both** fields DNAT-style: rewrite
`ip6->daddr` from `masq_addr` to `cv->backend_addr`, and rewrite `echo->identifier` from the masqueraded
value back to `cv->backend_port` (the tenant's own original identifier, captured at allocation time,
before masquerading) — this is the piece easy to get wrong: leaving the identifier untouched would let
the destination-address rewrite succeed while the tenant's own ping process still doesn't recognize the
reply, because the identifier it sees would be the masqueraded one, not the one it originally sent. Fix
the checksum with the same `fix_l4_checksum` reuse, then `push_outer_header` toward
`cv->backend_usid` exactly like the existing TCP/UDP return path — no different tail shape.

### 3.5 ICMPv6 errors: recover the flow from the embedded datagram

`handle_egress_return_icmp6_error` is the piece with actual teeth (PMTUD). It must **not** reuse
`parse_l4` against the embedded transport header — `parse_l4` bounds-checks a full `struct edge_tcphdr`
(20 bytes), but RFC 4443 only guarantees the first 8 bytes of the invoking packet's transport header, and
a minimally-sized ICMPv6 error message legitimately won't have the rest. Both TCP's and UDP's source/dest
port fields sit in the first 4 bytes of either header shape, well within that guaranteed minimum, so add
a narrower helper that reads only those two fields:

```c
// parse_embedded_ports reads the two 16-bit port fields both edge_tcphdr
// and edge_udphdr start with, bounds-checking only those 4 bytes --
// deliberately not parse_l4, whose full-struct bounds check would reject
// a validly-minimal ICMPv6 error message's embedded TCP header (RFC 4443
// guarantees only the first 8 bytes of the invoking transport header).
static EDGE_ALWAYS_INLINE int parse_embedded_ports(void *l4, void *data_end, __be16 *sport, __be16 *dport)
{
	__be16 *ports = l4;
	if ((void *) (ports + 2) > data_end)
		return -1;
	*sport = ports[0];
	*dport = ports[1];
	return 0;
}
```

Then:

```c
static EDGE_ALWAYS_INLINE int handle_egress_return_icmp6_error(struct xdp_md *ctx, struct edge_ip6hdr *ip6, void *data_end)
{
	struct edge_icmp6_error_hdr *err = (void *) (ip6 + 1);
	struct edge_ip6hdr *embedded = (void *) (err + 1);
	if ((void *) (embedded + 1) > data_end) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_ICMP);
		return XDP_DROP;
	}
	if (embedded->nexthdr != EDGE_IPPROTO_TCP && embedded->nexthdr != EDGE_IPPROTO_UDP) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_ICMP);
		return XDP_DROP;
	}

	__be16 embedded_sport, embedded_dport;
	if (parse_embedded_ports((void *) (embedded + 1), data_end, &embedded_sport, &embedded_dport) != 0) {
		count_drop(DROP_REASON_MALFORMED_EGRESS_ICMP);
		return XDP_DROP;
	}

	// The embedded packet is masq_addr:masq_port -> dest_addr:dest_port
	// -- exactly the packet handle_egress_forward last sent -- so this
	// is the *same reverse key* a direct TCP/UDP reply is looked up by,
	// just read one layer deeper.
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

	// Two rewrites land on the *same* checksum (ICMPv6's own, which
	// covers the whole message including the embedded bytes verbatim --
	// the embedded packet's own stale L4 checksum is untouched and never
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
	// new values, diffed together" (same generic reuse its own doc
	// comment already licenses).
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
```

Note this reuses `struct egress_conn_key`/`egress_conn_value` and `egress_conn_table` completely
unmodified — no new map, matching the review comment's own framing ("that is the standard NAT
approach"). `Parameter Problem` (type 4) is folded into the same generic handler as the other three
error types even though the issue text only names Destination Unreachable/PTB/Time Exceeded by name —
it carries an embedded datagram the identical way and costs nothing extra to cover.

## 4. Explicitly out of scope

- **The FIB-lookup PMTUD gap** (`count_fib_drop`'s `DROP_REASON_FIB_FRAG_NEEDED` case, documented in
  `docs/agents/ARCHITECTURE-GATEWAY.md`'s Known Constraints and shared with
  `internal/plumbing/ebpf/prog/usid.c`) is a different problem — *generating* a fresh ICMPv6 Packet Too
  Big when this gateway's own uplink route can't carry a packet, rather than *translating* one some
  other router already generated. This plan only does the latter. Not touched here.
- **Anti-spoofing on the embedded datagram.** `handle_egress_return_icmp6_error` trusts the embedded
  original packet's addresses/ports unconditionally once `egress_conn_table` confirms a matching flow
  exists — consistent with this datapath's existing trust model (design plan §7 item 4 already flags a
  dedicated security review of the broader trust boundary as a prerequisite before any gateway node runs
  this against real traffic; this plan doesn't reopen that review, just doesn't make it any wider).
- **ICMPv6 arriving at `gw_addr`** (the ingress return address) is unchanged and intentionally so —
  `gw_addr` is fabric-internal and only ever sees traffic this gateway itself sourced (design plan §3.1),
  a materially different risk/reward trade than an internet-facing address.

## 5. Testing

`internal/plumbing/ebpf/edgeprog/edgenat_test.go`, root-required, `BPF_PROG_TEST_RUN`-based (mirroring
the existing `TestEdgeNat_ReturnPacketUnNATsEndToEnd`/`TestEdgeNat_ReturnWithNoConnDrops` shape). Note
`feat/865-egress-phase-b` currently has **no** egress-specific tests at all yet (`grep -n "Egress"
edgenat_test.go` on that branch is empty) — design plan §6 calls for base coverage
(`TestEdgeNat_EgressForward...`/`TestEdgeNat_EgressReturn...`) that hasn't landed yet either. This plan's
tests assume that base coverage exists (add it first if it still doesn't by the time this is picked up)
and add these on top:

- `TestEdgeNat_EgressReturnICMPDestUnreachableTranslatesToTenant` — pre-seed `egress_conn_table`'s
  reverse row via a real forward-direction packet (or a direct map write mirroring one), then send an
  ICMPv6 Destination Unreachable with an embedded `masq_addr:masq_port → dest_addr:dest_port` TCP
  segment; assert `XDP_TX`, outer daddr rewritten to `backend_addr`, embedded saddr/sport rewritten to
  `backend_addr:backend_port`, valid ICMPv6 checksum, SRv6 push toward `backend_usid`.
- `TestEdgeNat_EgressReturnICMPPacketTooBigTranslatesToTenant` — same shape, type 2 — this is the PMTUD
  case the issue calls "the one with teeth."
- `TestEdgeNat_EgressReturnICMPTimeExceededTranslatesToTenant` — type 3, same assertions.
- `TestEdgeNat_EgressReturnICMPUnknownConnDrops` — an ICMPv6 error whose embedded tuple matches no
  `egress_conn_table` row; assert `XDP_DROP` and `DROP_REASON_NO_EGRESS_ICMP_CONN` (not
  `MALFORMED_EGRESS_ICMP` — the naming distinction the review comment asked for).
- `TestEdgeNat_EgressPingRoundTrip` — send an Echo Request through `handle_egress_forward`, assert
  identifier masqueraded and SNAT applied; feed the resulting masqueraded identifier back through
  `handle_egress_return` as an Echo Reply, assert the identifier and destination address are restored to
  the tenant's original values and the packet reaches the right `backend_usid`.
- `TestEdgeNat_EgressForwardICMPNonEchoRequestDrops` — an Echo Reply or other ICMPv6 type arriving from
  a tenant backend via `egress_sid`; assert `XDP_DROP`/`MALFORMED_EGRESS_ICMP`, not silently accepted.
- `TestEdgeNat_EgressReturnUnhandledICMPPassesThrough` — an ICMPv6 type that is none of the handled
  cases (e.g. a Router Advertisement, if constructible in the test harness, or any other type value)
  arriving addressed to `masq_addr`; assert `XDP_PASS`, not `XDP_DROP` — the actual behavior change this
  issue asks for on the "pass or handle the rest" half of its desired outcome.

`internal/plumbing/ebpf/edgeprog/dropreason_test.go` (if one exists on this branch) or an inline check:
`DropReasonNames` has an entry for every index up to `DropReasonCount - 1`, so the two new reasons don't
silently fall back to a blank Prometheus label.

## 6. Documentation

- `edgenat.c`'s own file-header comment (point 5, "EGRESS RETURN BRANCH") currently says: "this includes
  any non-TCP/UDP protocol arriving addressed to masq_addr, e.g. ICMPv6, which this program does not
  special-case and drops rather than XDP_PASS." Rewrite to describe the new ICMPv6 dispatch (error
  translation, Echo Reply translation, XDP_PASS for anything else) instead of the old blanket-drop
  behavior. Point 4 ("EGRESS FORWARD BRANCH") needs the equivalent update for Echo Request.
- `docs/agents/ARCHITECTURE-GATEWAY.md`'s Known Constraints section currently still describes egress as
  "planned, not implemented" (stale relative to `feat/865-egress-phase-b`'s actual code — a pre-existing
  gap in that stack, not something this plan should try to fix in isolation). Whichever phase finally
  updates that section to describe the real, implemented egress datapath should fold in a line noting
  the ICMPv6 handling decision this plan makes (translate errors + Echo Reply, pass through everything
  else), so the doc doesn't ship describing the pre-fix blanket-drop behavior as current.

## 7. Rollout: this belongs on `feat/865-egress-phase-b`, not a follow-up PR

Per [[project_865_egress_implementation_stack]], the entire egress feature (galactic#380/381/383/385/386)
is still open and unmerged as of this writing — `handle_egress_forward`/`handle_egress_return` have
never shipped. That makes this the right moment to fold the fix directly into **galactic#381** (the PR
that owns `edgenat.c`'s egress datapath) before it merges, rather than shipping the known-bad blanket-drop
behavior first and filing a separate fix afterward. Concretely: rebase/amend commits on
`feat/865-egress-phase-b` rather than branching from `main` (main doesn't have this code at all yet).
The three PRs stacked on top (383/385/386) rebase automatically when 381 gains commits, the same as any
other change to a stacked branch — no separate coordination needed beyond the review already in
progress. No `config/`/CRD/rollout changes of any kind — this is exclusively a datapath + drop-reason
change, entirely internal to `edgenat.c`'s own claimed addresses.

## 8. Open questions for review

- Should `handle_egress_forward_icmp6`'s identifier-claim probe share `EDGE_PAT_PORT_BASE`/
  `EDGE_PAT_PORT_RANGE` with the TCP/UDP port-claim probe (as sketched above, since both draw from the
  same `masq_addr` and the same `egress_conn_table`), or does sharing the numeric range risk a
  higher-than-expected collision rate between real SNAT ports and masqueraded ICMP identifiers under
  heavy ping traffic? Leaning toward sharing (simplicity, and `BPF_NOEXIST` already makes any collision
  self-resolving via the next probe attempt) but flagging since it's a capacity trade-off, not a
  correctness one.
- Is folding `Parameter Problem` (type 4) into the same generic error handler as the three issue-named
  types the right call, or should it stay unhandled (`XDP_PASS`) until a concrete need for it surfaces?
  This plan includes it since the marginal cost is effectively zero, but it's not explicitly requested by
  the issue.
