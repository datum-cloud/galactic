# Implementation Plan — NAT Masquerade (Egress) for the Edge Gateway

- **Issue:** none yet — recommend filing one against `datum-cloud/enhancements` before implementation starts (this plan can seed its body).
- **Builds on:** the edge XDP NAT+LB gateway's existing ingress design (`internal/gateway/doc.go`, `internal/plumbing/ebpf/edgeprog/doc.go`, the design plan those two doc comments cite).
- **Status:** planning only — no implementation started.

## 0. Terminology

The existing gateway already does SNAT, but only as a side effect of Full-NAT ingress load-balancing: an external client's connection to a VIP gets DNAT'd to a backend Pod *and* SNAT'd to the gateway node's own SRv6 address, purely so the reply routes back through the same node. That is not what "NAT masquerade" means here. This plan is about the other direction: a VPC backend Pod *originating* a connection toward an arbitrary internet destination, with its private source address masqueraded to a public one — classic egress SNAT/PAT, with no VIP and no pre-configured backend list, because the destination is arbitrary and not known in advance.

## 1. Problem statement / scope

Today's gateway (`internal/gateway`, `internal/plumbing/ebpf/edgeprog/edgenat.c`) only handles one traffic direction: external client → VIP → tenant backend. `NetworkRule` is inbound-only, keyed by VIP+port+protocol, and the XDP program's SNAT-to-self behavior exists solely to make ingress return traffic routable, not to give tenants outbound connectivity. There is currently no path anywhere in this codebase for a VPC-attached workload to reach the general internet: nothing translates its private address, and nothing routes its outbound traffic toward a gateway node at all.

This plan adds a second personality to the same XDP program and the same control-plane process: masquerade traffic *from* backend Pods addressed to arbitrary internet destinations, SNAT'd to a per-gateway-node publicly-routable address, reusing the ingress path's Full-NAT/PAT machinery rather than building a parallel subsystem.

## 2. What already exists that this reuses unmodified

- `fix_l4_checksum`, `push_outer_header`, `strip_outer_header` (edgenat.c) — the Full-NAT rewrite and outer-SRv6-header push/strip helpers are direction-agnostic already.
- The SNAT-port claim technique in `handle_forward` (hash-seeded linear probe, atomic claim via `BPF_MAP_TYPE_HASH` `BPF_NOEXIST` insert of the reverse row) — protocol- and direction-agnostic, reusable as-is for masquerade-port allocation.
- `conn_table`'s `BPF_MAP_TYPE_LRU_HASH` self-eviction as the sole port-reclaim mechanism, no separate GC pass — same convention applies to a new egress connection table.
- `edgemap.RuleTable`'s Register/Reconcile/Generation crash-safety pattern (`internal/plumbing/ebpf/edgemap`) — the shape a new egress policy table should mirror if §3.2 decides it needs one.
- Argument-based uSID reservation: Argument 0 is already reserved as "this uSID means the gateway's own self-address" (`NetworkGatewayStatus.SRv6Address`, uformat's `ArgumentMin`/`ArgumentMax`). This plan reserves a second Argument value with a different, equally special meaning.
- `gateway.Engine`'s converge-everything-in-`desired` reconcile loop and `NetworkGatewayReconciler`'s BGPAdvertisement plumbing for `status.SRv6Address` — the same mechanism advertises the new public egress address into BGP.

## 3. Datapath design (`edgenat.c`)

### 3.1 Direction disambiguation

`edge_nat()` currently branches only on whether the outer destination equals `gw_addr` (ingress return) versus everything else (ingress forward, matched against `rule_table`). A fresh egress request also arrives SRv6-encapsulated and addressed to *something* resolving to this gateway node, so a third address is needed to tell "reply to a flow I originated" apart from "a tenant backend's first packet of a new outbound flow."

Three distinct addresses are needed per gateway node, not two:

| Address      | Kind                                       | Meaning                                                                                  |
|--------------|--------------------------------------------|------------------------------------------------------------------------------------------|
| `gw_addr`    | SRv6 uSID, Argument 0 (existing)           | Ingress Full-NAT SNAT source / return-branch match. Unchanged.                           |
| `egress_sid` | SRv6 uSID, a newly reserved Argument value | Where a tenant VRF's default route points. Decap match for a *fresh* outbound flow.      |
| `masq_addr`  | Plain, publicly-routable IPv6 (no uSID)    | The masquerade SNAT source visible to the internet, and the return-branch match address. |

`masq_addr` cannot be a uSID: it must be a real, internet-routable address on the gateway node's uplink, outside the SRv6 fabric's locator block entirely — the internet has no concept of SRv6. `egress_sid` cannot double as `masq_addr` for the same reason in the other direction: a tenant VRF's default route can only encapsulate toward an SRv6 uSID, not toward an arbitrary public IP.

Updated top-level dispatch:

```
edge_nat(ctx):
  parse eth + ip6                                   (unchanged)
  if daddr == gw_addr:      handle_return(...)        # existing ingress return
  if daddr == egress_sid:   handle_egress_forward(...)  # NEW
  if daddr == masq_addr:    handle_egress_return(...)   # NEW
  if nexthdr not tcp/udp:   XDP_PASS                  (unchanged)
  else:                     handle_forward(...)        # existing ingress forward
```

Four-way branch on three configured addresses, read once per packet from two maps — same O(1) shape as today's two-way branch; no regression to existing ingress performance.

### 3.2 New maps

- `egress_config_table` (`BPF_MAP_TYPE_ARRAY`, 1 entry): `{ egress_sid[16], masq_addr[16] }`. A sibling of `gw_config_table`, not a repurposed field on it — a schema change to the ingress `gw_config` wire format should never force a review of egress logic, and vice versa (same one-map-one-purpose convention `struct backend`/`struct rule_value` already follow).
- `egress_conn_table` (`BPF_MAP_TYPE_LRU_HASH`, self-evicting): a **new** struct, not a repurposed `conn_table`/`conn_value`. `conn_value`'s fields (`client_addr`, `vip_addr`, `backend_addr`, `gw_addr`) are named for the ingress direction and don't map cleanly onto an egress flow's shape (there is no "client" or "VIP" in an egress flow — there's a backend's own address, an arbitrary internet destination, and the masquerade address). A new `egress_conn_value{ backend_addr, backend_port, backend_usid, dest_addr, dest_port, masq_addr, masq_port, proto }` keeps every map's field names honest instead of overloading a shared struct with two meanings — the same reasoning `edgeprog`'s own `doc.go` gives for being a separate package from `internal/plumbing/ebpf/prog` rather than a second program folded into it.
- **No new per-tenant policy table is proposed for the datapath itself** — see the decision in §7.2. Enablement is enforced by whether a tenant VRF's default route toward `egress_sid` exists at all (a routing-layer decision, made once per tenant by the control plane), not by a per-packet map lookup keyed by tenant. This generalizes decision #1 of the existing ingress design ("a VIP is globally unique by construction, no tenant dimension needed in the datapath") to egress: reaching `egress_sid` at all is itself the enablement signal.

### 3.3 New packet paths

**`handle_egress_forward`** — triggered when the outer destination matches `egress_sid` and outer `nexthdr == 41` (the same plain IPv6-in-IPv6 wire format every other cross-node SRv6 packet in this codebase uses, so a tenant VRF's default route needs zero new encap format). Strip the outer header (reuse `strip_outer_header` verbatim), parse the inner IPv6 + L4 header, look up `egress_conn_table` by the forward key `(proto, backend_addr:backend_port → dest_addr:dest_port)`. A miss on a SYN or UDP packet allocates: pick a `masq_port` via the existing linear-probe technique, claim the reverse row `(proto, dest_addr:dest_port → masq_addr:masq_port)` with `BPF_NOEXIST`, remember `backend_addr`/`backend_usid` in the `conn_value` (needed to route the eventual reply back to the originating worker node). SNAT `saddr` to `masq_addr:masq_port`, fix the L4 checksum, `XDP_TX` back out `ctx->ingress_ifindex` as a **plain IPv6 packet — no outer header pushed**. This is the one genuinely new tail shape in the file: `handle_forward` ends by pushing an outer header, `handle_return` ends by having already stripped one; this path ends by stripping one and sending the *inner* packet on, unwrapped, toward the real internet.

**`handle_egress_return`** — triggered when the destination matches `masq_addr` (a plain address match, no `nexthdr == 41` requirement — this arrives as an ordinary internet-originated IPv6 packet, not an SRv6-encapsulated one, mirroring `handle_forward`'s "match a plain destination address" shape rather than `handle_return`'s "must be an SRv6-encapsulated reply" shape). Parse L4, look up `egress_conn_table` by the reverse key `(proto, dest_addr:dest_port → masq_addr:masq_port)`. A miss drops (claimed address, no pass-through, same fail-closed convention every other claimed-address branch in this file already uses). A hit DNATs `daddr` to `backend_addr:backend_port`, fixes the checksum, and pushes a fresh 40-byte outer SRv6 header addressed to `backend_usid` (reuse `push_outer_header` verbatim — this is exactly the return-trip mirror of `handle_egress_forward`), then `XDP_TX`.

### 3.4 IPv4 is explicitly out of scope for Phase 1

`edge_nat()` unconditionally rejects any non-`ETH_P_IPV6` frame at its very first check (`XDP_PASS`), matching `edgenat.c`'s documented "IPv6-only, phase 1 scope." Most real internet destinations are IPv4-only or dual-stack, so this plan's Phase 1 only masquerades traffic toward IPv6-reachable destinations — a real but narrower slice of "give tenants internet egress" than the phrase usually implies. IPv4 egress needs its own header parser, its own (different) checksum-fixup path (an IPv4 header checksum in addition to the L4 one), and a materially different PAT-density design, since public IPv4 addresses are scarce enough that many tenants sharing a handful of public IPv4s at high PAT density is the realistic deployment shape — nothing like the "roughly one public IPv6 per gateway node" assumption this plan makes. Treat as a separate, larger follow-on plan; see §7.3.

## 4. Control-plane changes (Go)

### 4.1 CRD (`go.datum.net/network` — external repo, consumed here as a Go module dependency)

The natural new type is a companion to `NetworkRule`: e.g. `NetworkEgressPolicy`, namespaced and tenant-writable, gated by the same ownership-verification admission webhook `NetworkRule` already requires. Unlike `NetworkRule` it carries no VIP/backend/port at all — egress is on or off for a `(vpcRef, vpcAttachmentRef)` pair, not a per-flow rule — so `spec` may need nothing beyond those two ref strings (existence-implies-enabled, mirroring how sparse `NetworkRuleSpec` already keeps `vpcRef`/`vpcAttachmentRef` as opaque, unvalidated-by-this-API identifiers).

`NetworkGatewayStatus` needs a new field, `EgressAddress` — the publicly-routable masquerade source IP, populated and advertised the same way `SRv6Address` already is.

**This is a cross-repo dependency**: the type must land and be tagged in `datum-cloud/network` before this repo's `go.mod` can be bumped to consume it, the same sequencing `docs/plans/855-ingress-sidecar-vpc-backend-connectivity.md` already flags for its own upstream-schema dependency on `datum-cloud/galactic#854`.

### 4.2 `internal/gateway`

- `types.go`: a new `DesiredEgressPolicy{ VPCRef, VPCAttachmentRef string }` (no backend/port fields, per §4.1), and an `EgressPolicies` map added to `EngineState` — needed only if §7.2 resolves toward per-tenant datapath enforcement; if it resolves toward routing-only enforcement (this plan's recommendation), this type may end up used solely for BGP-advertisement bookkeeping in `NetworkGatewayReconciler`, not passed to `Datapath` at all.
- `datapath.go`/`kerneldatapath.go`: `NewKernelDatapath` gains a second one-time write, `egress_sid`/`masq_addr` into `egress_config_table`, alongside the existing `gwAddr` → `gw_config_table` write. No new per-call `Datapath` methods are proposed for Phase 1 under the routing-only enforcement model.

### 4.3 `NetworkGatewayReconciler` (`internal/controller/networkgateway_controller.go`)

- Extend `publishSelfAddress`'s pattern to also publish `status.EgressAddress` (operator-supplied via a new config field, same "not yet computed, no in-cluster derivation mechanism" caveat `SRv6Address`'s own doc comment already carries) and advertise it as a `/128` L2VPN/EVPN Type-5 IP-Prefix route, the same shape `publishSelfAddress` already builds for `SRv6Address`. Unlike `SRv6Address` (learned by every other Galactic node over the internal iBGP/EVPN mesh), `EgressAddress` additionally needs to be reachable from the actual internet — an eBGP/uplink-peering concern entirely outside this repo (likely `config/fabric`'s FRR underlay, or a dedicated transit peer), called out here as an infra dependency this plan does not solve.
- A new watch/reconcile input on `NetworkEgressPolicy`, structurally mirroring the existing `NetworkRule` list-and-assemble loop, resolving this node's own `egress_sid` the same way `SRv6Address` is resolved today: supplied via operator config (`GALACTIC_GATEWAY_EGRESS_SID`), not computed in-cluster — the same deferral `publishSelfAddress`'s doc comment already documents for Argument 0, now needed for a second reserved Argument value too.

### 4.4 Default-route plumbing — the piece with no current owner

For a tenant backend's outbound packet to ever reach `egress_sid` at all, its VRF needs a `::/0` (or public-internet-covering aggregate) route encapsulating toward `egress_sid`, installed via the exact same `internal/plumbing/srv6.RouteEgressAdd` function every other tenant-VRF SRv6 route in this codebase already uses. Nothing in this repo triggers that today: `galactic-cni`'s per-pod attach path installs only specific, known-destination routes, and the ingress-sidecar design (`docs/plans/855`) is scoped to per-`EndpointSlice` routes, not a tenant-wide default route.

Two candidate owners, neither committed to yet:

1. `galactic-cni`'s `cmdAdd` installs the default route at pod-attach time if the pod's `NetworkEgressPolicy` is enabled — requires the CNI to gain a new CRD read dependency it doesn't have today.
2. A new, lightweight per-node controller watching `NetworkEgressPolicy` + `VPCAttachment` and reconciling the default route directly against every tenant VRF present on its node — closer in shape to `gc_controller.go`'s node-scoped kernel-state reconciliation than to CNI-attach-time logic.

This is the single largest open question in this plan (§7.1): everything in §3 and §4.1–4.3 is buildable and testable in isolation without resolving it, but no egress packet reaches a gateway node in a real cluster until it is.

### 4.5 Gateway node assignment

Ingress uses `AssignPrimaryNode` (`hash(vpcRef) % gateway-node-count`) under an Active-Active model — every gateway node serves every rule, just at different BGP local-preference. A VRF default route has exactly one next-hop, so egress has no equivalent secondary path to fail over to. Recommend reusing `AssignPrimaryNode` unmodified for the default route's single next-hop (so a tenant's egress node and its primary ingress node are the same, simplifying operational reasoning even though nothing datapath-level requires it), while explicitly accepting that Phase 1 has no failover story: if the assigned node's XDP program or the node itself goes down, that tenant's egress blackholes until something recomputes the route against a different node. See §7.6.

## 5. Config / manifest changes

- `internal/config/gateway.go`: new fields/env vars `GALACTIC_GATEWAY_EGRESS_ADDRESS` (masquerade public source IP) and `GALACTIC_GATEWAY_EGRESS_SID`. Both optional — unlike `PublicInterface`/`SRv6Address`, a gateway node not offering egress is a valid deployment, so `Validate` should only require the pair together, not unconditionally.
- `config/gateway/base/daemonset.yaml`: extend the existing "these two values are deployment-specific, the per-node overlay must set them" comment block to cover the two new ones; still left unset at the base level.
- `deploy/containerlab/resources/galactic-router-gateway/`: extend the `iad-gateway1`/`iad-gateway2` worked example with real values once picked, for local dev/e2e proof.

## 6. Testing

- `internal/plumbing/ebpf/edgeprog/edgenat_test.go`: new root-required cases mirroring the existing ingress ones — an SRv6-encapsulated packet addressed to `egress_sid` through `BPF_PROG_TEST_RUN`, asserting SNAT + plain-IPv6 `XDP_TX`; a plain-IPv6 reply addressed to `masq_addr` asserting DNAT + SRv6-push `XDP_TX`. Cover PAT exhaustion and no-conn-table-hit drops with the same rigor the existing ingress tests apply.
- `internal/gateway`: unit tests for whatever `EngineState`/`Datapath` surface §4.2 lands on, Noop-backed, no kernel required.
- `internal/controller`: extend the `NetworkGatewayReconciler` suite for `NetworkEgressPolicy` watch → `status.EgressAddress` publication → BGPAdvertisement.
- e2e: extend `deploy/containerlab/`'s gateway canary (`iad-gateway1`/`iad-gateway2`, added on this branch) with a real or simulated outbound-to-internet destination. This is the only way to exercise §4.4's default-route plumbing end-to-end and, per this repo's own precedent (`docs/plans/855` §7), should be a **required pre-merge check**, not deferred to generic follow-up e2e work.

## 7. Open decisions / risks, ranked by how much each blocks starting real implementation

1. **Default-route ownership (§4.4) blocks everything downstream of "packets actually arrive at the gateway."** Needs a decision before eBPF/control-plane code is worth running against a real cluster — unit and kernel-level tests in isolation don't need it resolved first.
2. **Per-tenant enforcement in the datapath vs. enforcement-by-routing-existence-only (§3.2).** Recommend routing-only for Phase 1, matching this codebase's existing "no tenant dimension in the datapath" philosophy; revisit only if a real abuse/quota need surfaces later.
3. **IPv4 egress is out of scope for Phase 1 (§3.4).** May make Phase 1 alone insufficient for "give tenants internet egress" depending on how much expected traffic is IPv6-only vs. IPv4/dual-stack — needs an explicit product-level call on whether IPv6-only is shippable on its own.
4. **Anti-spoofing / cross-tenant trust boundary.** This plan trusts the inner source address unconditionally once a packet has arrived via a tenant VRF's own SRv6-encapsulated default route, consistent with this design's existing trust model elsewhere — but an internet-facing masquerade path raises the stakes of that decision well above an internal load-balancing path. Recommend a dedicated security review of this specific decision before any gateway node runs it against real traffic, not folded into general pre-release review.
5. **Public IPv6 prefix provisioning for `EgressAddress`.** The same "no in-cluster derivation mechanism yet" gap `SRv6Address` already has, now needed for a value that is a real external allocation rather than an internally-derived uSID — likely harder to eventually automate, not easier.
6. **No egress failover (§4.5).** A Phase 1 gap, not silently accepted: a gateway node holding a tenant's egress default route going down blackholes that tenant's egress traffic until something recomputes the route.

## 8. Phased delivery

Mirrors this repo's own Phase A–E convention from the ingress build-out (`internal/gateway/datapath.go`'s `QuotaEnforcer`/`TelemetryEmitter` doc comments).

- **Phase A** — CRD: `NetworkEgressPolicy` + `NetworkGatewayStatus.EgressAddress` in `go.datum.net/network`, consumed here once merged and tagged.
- **Phase B** — eBPF: `egress_config_table`, `egress_conn_table`, `handle_egress_forward`/`handle_egress_return`, updated top-level dispatch, kernel-required unit tests (§6).
- **Phase C** — Control plane: `internal/gateway` datapath wiring, `NetworkGatewayReconciler` extension, config plumbing (§5).
- **Phase D** — Default-route plumbing (§4.4/§7.1) — needs its own design decision before it can be scoped further than the two candidates above.
- **Phase E** — ContainerLab e2e proof (§6) + telemetry/quota, reusing the existing Noop-stubbed `QuotaEnforcer`/`TelemetryEmitter` seam under the same Phase E deferral the ingress build already established.

## Non-goals for Phase 1

- IPv4 egress masquerade (§3.4, §7.3).
- Per-tenant datapath-level quota/rate-limiting beyond the existing coarse admission-cap seam.
- Automatic public-IPv6-prefix allocation for `EgressAddress` — operator-supplied, same as `SRv6Address` today.
- Failover for a gateway node holding a tenant's egress default route (§7.6).
