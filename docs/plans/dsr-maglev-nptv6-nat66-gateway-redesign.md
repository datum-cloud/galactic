# Implementation Plan — DSR/Maglev Gateway + Per-VRF NPTv6 + Sharded NAT66

- **Issue:** none yet — this redesign was scoped and implemented directly
  (branch `feat/dsr-maglev-gateway` here, `feat/dsr-maglev-crds` in
  `go.datum.net/network`) without opening a tracking issue first, per an
  explicit instruction to leave GitHub untouched while this work was in
  flight. File one before merging, and rename this doc to the conventional
  `docs/plans/NNN-*.md` at that point (matching `405`/`408`/`865` and
  friends) rather than carrying the unnumbered filename forward.
- **Supersedes:** [`865-edge-gateway-nat66-egress.md`](865-edge-gateway-nat66-egress.md)
  (`datum-cloud/enhancements#865`) — see §6 for the disposition of that
  stack's branches/PRs. **Not closed or deleted as part of this work** —
  same "don't touch GitHub" instruction above applies to the old PRs
  (`galactic#380`/`381`/`383`/`385`/`386`) and branches
  (`feat/865-egress-phase-a` through `-phase-e`); do that as an explicit,
  separate, outward-facing step later.
- **Status:** **implementation complete, committed locally, not yet a
  PR.** All three components below are implemented, integrated, and
  verified (`go build`/`go vet`/`golangci-lint`/`go test`, including the
  kernel-required suite via `sudo -n go test`, all clean across the whole
  repo). Originally a kitt notebook design doc
  (`~/.vaults/notebook/projects/galactic/dsr-maglev-nptv6-nat66-design.md`);
  promoted here per this repo's own `docs/plans/NNN-*.md` convention once
  implementation was done, per the note in that doc's own §8.

## 0. Core architectural constraint

`galactic-gateway` is a true Maglev-style consistent-hash L4 LB operating
in DSR (Direct Server Return) mode:

- The LB does **no address rewriting**. It picks a backend via consistent
  hashing on the 5-tuple, encapsulates the untouched original packet
  (SRv6) toward the backend's worker node. No DNAT, no port translation,
  no connection table on the LB path at all.
- The backend node binds the VIP on loopback (component 1) and replies
  **directly to the client** — reply traffic never re-enters
  `galactic-gateway`.
- Consequence: nothing stateful (conntrack, PAT) can live on the
  consistent-hash selection stage, because DSR guarantees that stage never
  sees return traffic. NPTv6 (stateless, checksum-neutral, per-tenant) can
  live there; stateful NAT66 cannot and gets its own tier (component 3).

This is a significant *simplification* over the Full-NAT datapath it
replaces: the old `edgenat.c` had a whole ingress-return branch
(`handle_return`) that existed solely to route Full-NAT replies back to
the SNAT'ing node. DSR deletes that branch outright — the gateway's XDP
program (`edgedsr.c`) only ever needs a forward path.

**Anycast, not primary/secondary.** Every gateway node the datapath is
loaded on advertises every VIP identically via BGP — no
`LocalPreference`, no primary-node election
(`AssignPrimaryNode`/`LocalPreference`/`placement.go`/`localpref.go` are
deleted outright). Maglev's consistent-hash ring, not BGP local-pref,
decides which node's backend set actually answers a given flow.

**Go/no-go spike run 2026-08-17 — anycast premise confirmed, GO.** The
rejected predecessor design avoided colocating a gateway in a tenant VRF
specifically to dodge two named GoBGP issues (`monitor.go`'s
`processEVPNPath` skipping local paths before RT match; `rtIndex` being
1:1 not fan-out). Both are scoped to advertisements carrying a
VRFID/Function (tenant-VRF SEG6 kernel-route install) — a VIP/self-address
advertisement carries neither, so it never reaches that code path. What
actually governs anycast survival is `paths.go`'s `deriveRD`: a
VRFID-less advertisement's RD falls back to `routerID:0`, distinct per
node — and per RFC 4364 §4.3.2/EVPN's identical convention, routes with
different RDs are never best-path competitors, full stop. Proved
empirically against gobgp v4.8.0 as actually driven by this codebase's
own `buildEVPNPaths` — `internal/runtime/gobgp/anycast_spike_test.go`:
two advertisements with the identical VIP prefix and two router IDs
produce two independent, both-`Best=true`, independently-withdrawable
paths; the same-router-ID negative control collapses to one, proving the
positive result isn't a methodology false-positive.

**Remaining, still-open gap this spike does not cover:** how the VIP gets
announced to the actual external border/internet at all — this design
(like the Full-NAT gateway it replaces) never specified that mechanism.
Whatever bridges it (FRR redistribution, a `fabric-vip`-style component,
or something else) must propagate *every* qualifying gateway node's
route, not collapse to "the best one" the way the old local-pref
primary/secondary model deliberately did. Flagged in §5, not resolved
here.

## 0.1 Hard requirement — must work for both veth and tap backends

**Non-negotiable, cutting across every component below:** a backend can
be a container (`galactic-veth`/`internal/cni`) or a VM
(`galactic-tap`/`internal/cnitap` — the actual VPC/SRv6-dataplane VM
attach plugin, **not** `vmtap-cni`/`internal/vmtap`, an unrelated
Unikraft/kraftlet mechanism that is unused in any deployment and
scheduled for removal from this repo) — this design must work for both.
The existing SRv6 uSID ingress decap program
(`internal/plumbing/ebpf/prog/usid.c`) already forks on this at its final
delivery step for a real kernel-level reason: a veth attachment's egress
interface has a peer living in a *different* netns (`bpf_redirect_peer`);
a tap attachment never moves its interface out of the node's own netns,
so it needs plain `bpf_redirect` instead.

**Where this needed no new work:** backend resolution (`usidresolver.go`)
is purely address+VRF based; final local delivery is the existing
`usid_ingress` step 9 redirect, already correct for both kinds; NAT66's
forward leg receives already-encapsulated traffic via the tenant VRF's
ordinary default route, agnostic to originating workload kind.

**Where this was a real fork, resolved by a new mechanism (component
1):** binding a VIP on the node's own `galactic-vip0` doesn't get the
address in front of whatever actually has to answer on it. For a veth/pod
backend, the answering process lives in the pod's own netns, reached
across the veth pair — `internal/cni`'s `cmdAdd` already reaches into
that netns, so extending it to also assign the VIP there is plausible,
buildable work. For a tap/VM backend, there is categorically **no
guest-side configuration capability anywhere in this repo**, by design —
`internal/cnitap`'s own `cmdAdd` doc comment states the boundary
explicitly: "no host-device delegation, no guest interface, no netns IP
configuration. The VM manages its own interface entirely."

**Resolution: don't bind anything in the guest at all; make the VIP
invisible to it instead.** The guest doesn't need to know about the VIP
if the host transparently substitutes addresses (and, when a VM backs
more than one rule/port, the port too) at the tap boundary — a genuine
NAT-style address/port rewrite with a real (if cheap) checksum fixup via
`bpf_l4_csum_replace` (available because both `usid_ingress`/`usid_egress`
are TC-BPF, with a real `struct __sk_buff` — unlike `edgedsr.c`'s XDP
context). This is **not** literally NPTv6-at-/128: RFC 6296's
checksum-neutral trick needs an untouched Interface Identifier and an
"elsewhere in the address" to fold the checksum delta into, and at a full
/128 substitution (with the port possibly changing too) there is no
"elsewhere" left — so this is a variant of "the same table/attach-point
infrastructure" as NPTv6, not "the same math."

Concretely, this needed one genuinely new piece of eBPF plumbing shared
with component 2: **`usid_egress`, a new TC-BPF program attached at TC
*ingress* of the tenant's own host-side veth (or tap device)** — the same
interface `usid_ingress`'s own step 9 already redirects *to*, matching
the standard "from-container" interception pattern. This attach point,
not a shared physical uplink, is correct because by the time a tenant's
outbound packet reaches the shared uplink, `RouteEgressAdd`'s own SEG6
encap route has already pushed an outer header whose destination encodes
the **remote** peer's identity, not the local sending VRF's — nothing to
key a per-sender-VRF lookup on there without decoding the tenant's own
(ambiguous, possibly-colliding) inner ULA source address. At the
per-attachment ingress point instead, VRF identity is resolved via a new
`ifindex_vrf_table` (key = `skb->ifindex` → `{block, argument}`),
registered once per attachment at CNI ADD time and unregistered at DEL
time — decoupled from the actual translation tables (`nptv6_table`,
`vip_xlat_table`, both keyed by the same `(block, argument)` `vrf_table`
already uses). `usid_egress` translates the packet's *source* (ULA→public
outbound, or VIP-substitution outbound); `usid_ingress` gains the
mirrored lookup after its own step 7 (strip) and before step 8 (FIB
lookup), translating the packet's *destination* (public→ULA inbound, or
VIP-substitution inbound) using the `(block, argument)` already resolved
locally from steps 2–6.

**Honest limitation, not oversold:** the guest application itself has no
way to *learn* its own VIP at the socket/API level (no `getsockname()`
visibility) unless told out-of-band (DNS, cloud-init metadata). A
container backend that explicitly binds the VIP on its own loopback
doesn't have this gap.

## 1. Component 1 — Loopback VIP binding automation (backend nodes)

**Package:** `internal/plumbing/vip`. Mirrors `internal/plumbing/vrf`'s
shape (idempotent create/delete over netlink) and reuses `loaddr`'s
detection precedent for what already lives on `lo`.

```go
package vip

// Bind idempotently assigns vip to the node's dedicated VIP interface
// (galactic-vip0, a dummy link this package owns exclusively — not lo,
// since lo already carries the SRv6 locator address loaddr.Detect reads).
func Bind(vip net.IP) error

// Unbind idempotently removes vip. No-op (not an error) if already absent.
func Unbind(vip net.IP) error

// Verify confirms vip is actually live: present in the interface's address
// list AND resolvable as a local (RTN_LOCAL) route via the kernel's own
// route table — not just "AddrAdd returned nil".
func Verify(vip net.IP) error
```

`galactic-vip0` is created lazily the first time `Bind` runs on a node.
Binding/unbinding is driven by `ServiceVIPBinding` (namespaced, one per
`(nodeName, vip)` pair), reconciled by `ServiceVIPBindingReconciler`
inside `galactic-router`'s tenant role (not a new binary — this only
needs `NET_ADMIN` + netlink, which tenant-mode `galactic-router` already
has). `EgressKindTap` bindings take a different path — no loopback bind at
all, instead a `vip_xlat_table` registration for the transparent tap-VIP
substitution described in §0.1. `cmd/galactic-router` also gains a `vip
bind|unbind|verify <addr>` CLI subcommand for manual/debug use, backed
directly by the `vip` package.

## 2. Component 2 — Per-VRF NPTv6 (RFC 6296)

**Package:** `internal/plumbing/nptv6` (pure Go, no kernel dependency —
mirrors `internal/plumbing/srv6`'s split between pure computation and the
netlink/eBPF wiring that consumes it).

```go
package nptv6

// Mapping is one tenant VRF's stateless prefix translation.
type Mapping struct {
	ULAPrefix    *net.IPNet
	PublicPrefix *net.IPNet // same prefix length as ULAPrefix
}

// Adjustment precomputes the RFC 6296 §3.6 checksum-neutral adjustment
// value for a Mapping, control-plane side, once.
func (m Mapping) Adjustment() (uint16, error)

// Translate applies m to addr (either direction — RFC 6296 translation is
// symmetric).
func Translate(m Mapping, addr net.IP, outbound bool) (net.IP, error)
```

Test vectors are pinned against RFC 6296 §3.6's own published worked
example.

**Scoping is the whole point:** the eBPF-side table
(`internal/plumbing/ebpf/nptv6map`, mirroring `edgemap`'s
Register/Reconcile/Generation crash-safety convention) is keyed **by
VRFID**, never by address — resolved by the existing SRv6 uSID decap
program before a packet is delivered into a tenant's VRF. Two tenants
with colliding ULA prefixes get two independent `nptv6map` rows, never a
single shared/global table.

**Lifecycle:** `BGPVRFInstance.Spec` gains an optional `NPTv6
*NPTv6Spec{ULAPrefix, PublicPrefix}`. `BGPRouterReconciler`'s
`updateVRFInstanceStatuses` reports `ConditionNPTv6Configured`,
validating spec (parseable CIDRs, matching prefix lengths,
`nptv6.Mapping`'s own supported-length rules) — config validity only,
since that reconciler has no access back to `nptv6_table`'s live kernel
state from a different container. `gc.SweepEBPFNPTv6Table` is
`nptv6_table`'s *only* writer, run from `internal/installer.Run` inside
the CNI "run" container (the only container with `/sys/fs/bpf` +
`CAP_BPF`): it both registers every currently-live NPTv6 mapping from
`BGPVRFInstance` specs and reconciles stale entries away on every GC
tick.

## 3. Component 3 — Sharded stateful NAT66 tier

**New, standalone component**, deliberately not folded into
`galactic-gateway`'s XDP program, since its whole reason to exist is
*not* sharing state or a hash ring with the backend-selection LB tier.
`cmd/galactic-nat66` (new binary, own DaemonSet, own eBPF program/maps:
`internal/plumbing/ebpf/nat66prog` + `nat66map`, mirroring the
`edgeprog`/`edgemap`/`edgeattach` three-way split).

### 3.1 Generic consistent-hash ring (shared with the LB tier's own use)

`internal/maglev` (pure Go, no kernel/CRD dependency) implements Google's
Maglev consistent-hash table (`New(backends, tableSize)`,
`(*Table).Lookup(key)`), unit-tested including the paper's own
disruption-bound property. Used by **both** `galactic-gateway`'s
backend-selection ring (replacing a naive `hash % backend_count`, which
reshuffles ~100% of flows on any backend-list change — Maglev bounds
that to ~1/N, which is also what makes multi-node anycast-safe: every
gateway node computes the identical table from the identical backend
list) and component 3's shard-placement ring — a **separate `Table`
instance**, never sharing a ring with the LB's own.

### 3.2 Shard placement (outbound / translation leg)

A new flow's shard assignment is chosen via a `maglev.Table` built over
`(tenant VRFID, backend addr:port, dest addr:port)` — load-distributed,
minimally disrupted when a shard node is added/removed.

### 3.3 Return-leg routing — self-routing by construction

Rather than requiring every node to hash a reply packet against a
replicated shard-placement table, **each shard owns a dedicated,
BGP-advertised public IPv6 address** (a `/128` advertisement, no
VRFID/Function). A flow's allocated public port lives within *that*
shard's own address, so ordinary unicast SRv6/BGP routing delivers a
reply to the correct shard with **zero hashing on the return path** — the
destination address already names the owner, satisfying the same
property (any node can determine the owning shard from the tuple alone)
more simply than recomputing a hash per reply packet.

*Scale note:* this spends one public /128 per shard — cheap on this
fabric's IPv6 addressing, would not generalize to a scarce-public-IPv4
deployment; revisit with a shared-pool-plus-hash design if/when IPv4
egress is ever in scope.

### 3.4 Per-shard state

`nat66map`'s `conn_table`: `BPF_MAP_TYPE_LRU_HASH`, self-evicting, no
separate GC. Forward key `(proto, tenant_arg, backend_addr:port →
dest_addr:port)`; reverse key `(proto, dest_addr:port →
shard_addr:masq_port)`. `tenant_arg` (a VRFID) guards against two tenants
presenting the same backend ULA colliding on the forward key. **Each
shard owns its table exclusively** — no shared state, no cross-shard
lookup, by construction.

### 3.5 Minimal-disruption test under shard-set changes

Synthesize N flows, hash each against a `maglev.Table` built from shard
set S, record assignments; build a second table from S ± one node;
re-hash the same N flows; assert the reassigned fraction is bounded
(~1/|S|, allow some slack — the classic Maglev disruption-bound test).
Separately: a reply packet keyed only by `(dest_addr:port,
shard_addr:masq_port)` resolves to the exact shard that allocated it,
purely from already-in-place-by-construction routing (§3.3) — this half
needs no re-test under shard changes at all, since it was never
hash-dependent.

## 4. Ties between components

- Component 1 (VIP binding) is what makes DSR possible at all — without
  it, a backend has nothing to source replies from.
- Component 2 (NPTv6) can sit in the same forward path as the LB's
  consistent-hash selection because it's stateless — applied per-packet,
  after VRF/tenant identity is already resolved, no conflict with DSR.
- Component 3 (NAT66) is deliberately kept off that path entirely — a
  tenant's *egress* traffic never touches the ingress LB's hash ring; a
  different traffic pattern needing its own ring, its own state, its own
  tier.

## 5. Explicitly out of scope / open

- **Closed during implementation — the gateway's backend-address→SID
  resolver's missing tenant-identity check.** `usidresolver.go`'s
  `buildBackendSIDIndex`/`resolveUSID` used to match a rule's backend
  address against advertised prefixes by containment only — two tenants
  with a backend at the identical ULA address, both configured on
  different rules, resolved ambiguously. Fixed with zero CRD schema
  changes: `resolveUSID` now takes the calling rule's `VPCRef` and
  cross-checks each candidate advertisement's `(RouterRef, VRFID)` against
  the specific `BGPVRFInstance` that VPC actually owns on that node,
  named deterministically via `crdnames.BGPVRFInstanceName(vpc,
  nodeName)`. A candidate whose owning VRF instance doesn't exist or
  whose VRFID doesn't match is never trusted, regardless of prefix
  containment.
- `galactic-router` transit-mode interaction — unscoped, not assumed.
- **External VIP announcement mechanism.** Nothing in this repo (old
  design or this one) specifies how a VIP prefix reaches the actual
  internet-facing border. Whatever does (FRR redistribution, a
  `fabric-vip`-style component, or something else) must forward every
  gateway node's independent route for a VIP, not pick "the best one."
  Needs its own design pass before this redesign can be considered
  complete end-to-end.
- IPv4 for component 3 (see §3.3 scale note).
- Anti-spoofing / trust boundary for egress traffic entering
  `galactic-nat66` — deserves its own security pass before real traffic.
- Public IPv6 prefix provisioning/allocation for component 3's per-shard
  addresses — operator-supplied for phase 1, no in-cluster derivation yet
  (matches this repo's existing precedent for gateway `SRv6Address`-style
  values elsewhere).

## 6. Removal scope — dead stateful-NAT code superseded by this design

The `#865` stack built stateful egress NAT66 as a *second personality
bolted onto the old Full-NAT `edgenat.c`* (`egress_config_table`/
`egress_conn_table`, `handle_egress_forward`/`handle_egress_return`,
`tenant_arg` = `BGPVRFInstance.Spec.VRFID` reused directly in the
datapath key). None of that host program exists in this design —
`galactic-gateway`'s XDP program is forward-only DSR (§0), with no
egress personality of its own at all, and stateful NAT66 lives in its own
standalone tier (component 3) with its own hash ring, own maps, own
per-shard state, and self-routing return path (§3.3) instead of a
per-gateway-node `tenant_arg`-keyed conn table. **Verdict: abandon, not
salvage.**

Concretely dead: branches `feat/865-egress-phase-a` through `-phase-e`
(local and `origin`); PRs `galactic#380`/`381`/`383`/`385`/`386` (should
be closed as superseded, not merged); `network#15`'s
`NetworkEgressPolicy`/`NetworkGatewayStatus.EgressAddress`/`EgressSID`
CRD additions (worth a second look for a simple per-VPC "egress enabled"
toggle CRD, but their shape was designed around the old
personality-on-the-gateway model — needs redesign, not reuse, when
component 3's control-plane CRD is actually scoped).

**Explicitly not done as part of this implementation:** deleting pushed
branches and closing PRs that may have active reviewers is a distinct,
outward-facing action from the code/design work above, and per explicit
instruction was left alone — do it as its own deliberate step, with its
own go-ahead, separately from this plan.

## 7. Phased delivery (all phases below are done)

0. ~~Remove the dead `#865` stack~~ — **left untouched on GitHub, on
   purpose** (see §6's last paragraph); the local code superseding it is
   in place regardless.
1. **Component 1** (VIP bind/unbind/verify + CLI) — done.
2. **`internal/maglev`** — done.
3. **Component 2** (NPTv6) — done.
4. **`galactic-gateway` DSR rewrite** — done: Full-NAT forward/return
   logic replaced with DNAT-free consistent-hash forward-only,
   `internal/maglev` wired in for backend selection,
   `AssignPrimaryNode`/`LocalPreference`/self-address-advertisement
   deleted (anycast makes them unnecessary).
5. **Component 3** (`galactic-nat66`) — done: new binary, depends on
   `internal/maglev` and the shard-address-advertisement mechanism from
   step 4.

## 8. Containerlab validation

`deploy/containerlab/` has real, reusable scaffolding for every component
here (the `ns10`/`ns20`/`ns30`/`ns40`/`ns60` tenant fixtures, the
`iad-gateway1`/`iad-gateway2` gateway-role nodes) — this section is
grounded in what actually exists, not a green-field lab design. **Not yet
done** — the two items below are the concrete remaining work before this
redesign can claim containerlab validation beyond manifests:

**Known blocker, root-caused during implementation — two stacked
issues, not one.** The lab's own `README.md` used to describe "real
end-to-end ingress traffic through the datapath still doesn't reach a
backend in this topology — it currently stops on a veth-specific
`XDP_TX` behavior," attributed to the lab environment generically.
Live-kernel investigation found it is actually two separate, stacked
issues:

1. **IPv6 forwarding sysctls not enabled** — `bpf_fib_lookup()` (used
   identically by `edgedsr.c`'s and `nat66.c`'s `push_outer_header`)
   returned `BPF_FIB_LKUP_RET_NOT_FWDED` for every lookup, since the
   kernel correctly refuses to resolve a route on an interface not
   configured as a router. **Fixed:**
   `sysctl.ConfigureFIBLookupUplinkSysctls` now sets both
   `net.ipv6.conf.<iface>.forwarding` and `net.ipv6.conf.all.forwarding`
   (empirically confirmed both are required together) from both
   `cmd/galactic-gateway` and `cmd/galactic-nat66` startup.
2. **veth's native `XDP_TX` fast path is invisible to normal observation
   unless the peer also runs an XDP program.** A frame `XDP_TX`'d on one
   veth leg is only promoted into the peer's normal receive stack
   (visible to tcpdump/AF_PACKET) if the peer interface *also* has an
   XDP program attached — otherwise delivery uses a raw fast-path queue
   nothing but another XDP program on that peer can see. **Not fixable
   in this datapath's own code** — a genuine veth/kernel characteristic
   that doesn't apply to a real physical NIC uplink in production, only
   to this lab's veth-pair simulation of one. Document as a lab-only
   caveat when this section's live-traffic validation is actually run,
   not carried forward as an unexplained blocker.

**Bonus find while chasing the above with a strict external observer
(tcpdump) instead of just `BPF_PROG_TEST_RUN`:** two real,
previously-undiscovered wire-format bugs in `push_outer_header`,
inherited unchanged from the removed `edgenat.c` into both `edgedsr.c`
and `nat66.c` — the pushed outer IPv6 header's version nibble was left
zeroed instead of set to 6, and `payload_len` undercounted the outer
header's declared length by the inner IPv6 header's own 40 bytes. Both
fixed in both C programs, with regression-guard test assertions added.

**Second known gap: no tap/VM fixture exists in this lab at all.** Every
tenant fixture is a plain k8s `Deployment` (container/veth backend);
§0.1's veth-vs-tap requirement can only be validated for the veth half in
this lab as it stands. The tap half needs a new fixture built on
`galactic-tap`/`internal/cnitap`'s existing attach path before it's
testable at all.

### Per-component validation, reusing real lab fixtures (not yet run)

- **Component 1 (VIP binding).** veth case: validate against `ns60`'s
  existing backend pod. tap/VM case: per §0.1's resolution, this is the
  transparent `usid_ingress`/`usid_egress` translation, proven against a
  real VM once a tap fixture exists.
- **Component 2 (NPTv6).** `ns10` (`fd20` ULA, already 3-site) is the
  ready-made base case; add a second tenant on the same ULA range (a new
  `ns70`-style fixture) to prove overlapping-prefix disambiguation live.
- **Phase 4 (`galactic-gateway` DSR rewrite).** Reuses
  `resources/galactic-gateway/{base,iad,iad-gateway1,iad-gateway2}`
  unchanged and the `ns60` fixture unchanged. Two things to prove, now
  that the sysctl blocker is fixed: (1) a real client → VIP → backend →
  direct-reply round-trip, asserting the reply's source address; (2) the
  anycast spike's finding against real BGP — both `iad-gateway1`/
  `iad-gateway2` routes reaching a third site independently.
- **Component 3 / phase 5 (`galactic-nat66` shard tier).** Reuse the
  three existing site workers as a 3-shard DaemonSet. Validate the
  minimal-disruption property (§3.5) against real node removal:
  drain/cordon one worker, confirm only that worker's own flows
  reassign, confirm the reply-routing self-addressing (§3.3) survives the
  shard-set change unchanged.

### New verification tasks (naming matches existing `verify:*` convention)

`verify:vip-binding`, `verify:nptv6`, `verify:dsr-gateway` (extends
`verify:gateway` past "CRDs exist" now that the sysctl blocker is fixed),
`verify:nat66-sharding`. Each should be addable to `task verify`'s
existing aggregate the same way `verify:ns10`..`verify:ns40` already are.
