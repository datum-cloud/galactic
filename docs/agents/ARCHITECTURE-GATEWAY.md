# Architecture — galactic-gateway

> The edge XDP Maglev/DSR (Direct Server Return) load-balancing gateway
> control plane: a controller-runtime process that loads and attaches an
> anycast consistent-hash L4 load-balancing program to a dedicated gateway
> node's public uplink and drives it from `NetworkGateway`/`NetworkRule`
> CRDs. Every gateway node advertises every VIP identically over the
> existing tenant EVPN mesh — there is no primary/secondary node, no BGP
> local-preference split, and no address rewriting anywhere in the datapath.

_Last updated: 2026-10-06_

This document covers `galactic-gateway` and the `NetworkGateway`/
`NetworkRule` reconcilers only. See
[ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md) for the tenant-BGP core
(`galactic-router`, its own separate DaemonSet co-located on gateway-role
nodes — not the same pod) and
[ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md) for the CNI attach chain that
produces the `BGPAdvertisement`/`BGPRouter` CRDs this binary's own
uSID-resolution code reads. A third, separate `galactic-nat` binary (out
of this document's scope) provides sharded stateful NAT66 egress for
VPC-attached workloads reaching the internet — see `cmd/galactic-nat`,
`internal/plumbing/ebpf/natprog`, and the `EgressShard` reconciler
(`internal/controller/egressshard_controller.go`, which registers with
`galactic-nat`'s own manager (`cmd/galactic-nat/root.go`) — a separate
binary from both this one and `galactic-router`) rather than this file for
egress. It can run on the same edge nodes as this binary, each from its own
slot of the node's shared XDP dispatcher; see
[Sharing the XDP hook](#sharing-the-xdp-hook-xdpdispatch) below for the part
of that contract this binary owns. This file,
together with the other two architecture docs, supersedes the former
monolithic `ARCHITECTURE.md` — see [AGENTS.md](../../AGENTS.md) for which
document to start from for a given task.

---

## Overview

`galactic-gateway` gives external clients a stable VIP:port that
load-balances into a tenant VPC's backend Pods, without a VRF or tunnel
dependency and without a per-tenant Geneve device. It is a **separate
binary from `galactic-router`**, deployed as its own single-container,
`hostNetwork: true` DaemonSet on `galactic.datumapis.com/node: edge` nodes
an operator has labeled `galactic.datumapis.com/gateway: enabled` (opt-in,
never automatic; it shares those nodes with `galactic-vrf`), so a crash on either side — tenant
BGP vs. the XDP-holding gateway engine — no longer takes the other down
with it. `galactic-router` used to run as a second container in this same
pod; it's now a fully independent DaemonSet instead, opted in via
`galactic.datumapis.com/galactic: router` (the identical flag `compute`
nodes use), which a gateway node may carry too, not co-located here at all. Tenant BGP
itself (the embedded GoBGP server, the
`BGPRouter`/`BGPPeer`/`BGPAdvertisement`/`BGPPolicy`/`BGPVRFInstance`
reconcilers) still runs unmodified in that separate `galactic-router`
pod — see [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md).

The load-balancing design itself is **DSR (Direct Server Return) over a
Maglev consistent-hash ring**. The defining simplification: this datapath does
**no address or port rewriting at all**. A client's packet travels inside
the SRv6 encapsulation byte-for-byte unmodified all the way to the backend;
the backend replies to the client *directly*, never re-entering the
load-balancing decision, which is DSR's whole premise. That is a statement
about *flow state*, not about topology: where the compute tier routes
through an edge node, the reply still crosses that node as ordinary
forwarded traffic, and the `edge_return` program below is what carries it. Every gateway node
the datapath is loaded on advertises every VIP **identically** via BGP —
anycast, not primary/secondary — and Maglev's consistent-hash ring (not BGP
local-preference) decides which node's backend set actually answers a given
flow, and which specific backend within that node's set. Because every
gateway node builds the byte-identical Maglev table from the byte-identical
`(VIP, backend list)` input, a flow's packets landing on a different gateway
node mid-connection (ECMP, BGP reconvergence) still resolve to the same
backend.

Consequences that follow directly from dropping rewriting:

- No `conn_table`/flow state of any kind, and nothing to garbage-collect
  beyond the eBPF verifier's own bookkeeping — DSR is fully stateless.
  Maglev re-derives the same backend from the same input on every packet.
- No reply-translation branch — a reply carries the client's own addressing
  already, so the return program forwards it rather than translating it,
  and needs no flow state to do so.
- No L3/L4 checksum touch anywhere in the datapath — the packet's own
  checksum is already correct for its own, completely unmodified content.
- No BGP local preference, no primary/secondary node election, and no
  per-node self-address to publish — every gateway node's
  route is equally preferred by construction (a distinct Route
  Distinguisher per originating node keeps every node's identical-prefix
  advertisement alive as an independent, non-competing route rather than
  one silently replacing another — see the go/no-go anycast spike,
  `internal/runtime/gobgp/anycast_spike_test.go`).

This design is also a deliberate pivot away from a still-earlier, rejected
approach (internally called `gwprog`) that tunneled tenant traffic to
gateway nodes over Geneve and drove a TC-BPF program keyed by `(VNI,
5-tuple)`. That design was abandoned after live testing ruled out driving
LoxiLB directly and found native XDP unavailable specifically on Geneve
tunnel devices. The current design instead attaches XDP directly to the
gateway node's public interface: no tunnel, no per-tenant Geneve
provisioning, and — because the outer SRv6 header is pushed straight from
the program's own `vip_table` rather than a kernel VRF route — no VRF
dependency and no exposure to the GoBGP bugs that forced every earlier
per-VPC gateway design to colocate with the workload's own VRF.

### The two CRDs

| CRD              | Scope                                                                | Written by                                                                                                                                    | Purpose                                                                                                                                                                                                                                                                                  |
| ---------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NetworkGateway` | Namespaced, one per gateway node (`spec.targetRef.name` = node name) | Operator, once per gateway node (see [worked example](#worked-containerlab-example) below)                                                    | Node-scoped root object, mirroring `BGPRouter`'s pattern. Identifies which nodes participate in the anycast mesh and surfaces each node's engine health via `status.conditions`. Carries **no** self-address field — DSR rewrites nothing, so there is no translation source to publish. |
| `NetworkRule`    | Namespaced, internal                                                 | The platform API that serves tenants, after it verifies the tenant owns `vpcRef` (galactic does not repeat the check — see Known Constraints) | Ingress load-balancing spec: `vpcRef` (opaque tenant identifier), `vipAddresses` (1–8, IPv4/IPv6), `protocol` (`tcp`/`udp`), `port`, `backendSelector` (the VPCAttachments in `vpcRef` that serve it), `backendPort`. Served by every `NetworkGateway` in the namespace identically.     |

Both are defined in `go.datum.net/network`'s `api/v1alpha1` package
(`gateway_types.go`, `rule_types.go`) — the same external CRD module the
BGP-family types live in. Both types' own doc comments describe this
DSR/anycast model directly.

---

## Repository Layout

```
galactic/
├── cmd/
│   └── galactic-gateway/    # Gateway control-plane binary (controller-runtime)
├── internal/
│   ├── controller/          # NetworkGatewayReconciler, NetworkRuleReconciler,
│   │                        #   usidresolver.go (backend-address → SRv6 uSID
│   │                        #   resolution) — shares the internal/controller
│   │                        #   package with the BGP-family reconcilers (see
│   │                        #   ARCHITECTURE-ROUTER.md) but registers only with
│   │                        #   galactic-gateway's own manager
│   ├── config/              # GatewayConfig (internal/config/gateway.go):
│   │                        #   node name, ports, public interface, SRv6
│   │                        #   encap-source address
│   ├── gateway/              # Engine, Datapath/QuotaEnforcer/TelemetryEmitter
│   │                        #   interfaces + real implementations, crash
│   │                        #   recovery — no VRF/Geneve state
│   ├── maglev/               # Pure-Go Maglev consistent-hash lookup table
│   │                        #   (internal/maglev/table.go) — this binary's
│   │                        #   only importer; galactic-nat has no
│   │                        #   analogous ring today (see Known Constraints)
│   └── plumbing/ebpf/
│       ├── edgeprog/         # Compiled XDP program (edgedsr.c, program
│       │                     #   edge_lb) + bpf2go bindings
│       ├── edgemap/          # vip_table/vip_stats_table/vip_addr_table/encap_config_table
│       │                     #   read/write API (viptable.go)
│       ├── edgeattach/       # Load + XDP-attach the compiled program to one
│       │                     #   interface
│       ├── edgemetrics/      # Pull-based Prometheus collector reading
│       │                     #   vip_table/vip_stats_table/drop_reasons live
│       ├── edgepreflight/    # Startup kernel-capability check for this
│       │                     #   datapath's own requirement list
│       └── xdpattach/        # Bond-safe native XDP attach, shared with
│                             #   natattach (support check + slave wait)
├── config/
│   ├── galactic-gateway/
│   │   ├── serviceaccount.yaml  # Applied cluster-wide, idempotent
│   │   ├── rbac.yaml            # Applied cluster-wide, idempotent
│   │   ├── kustomization.yaml   # Covers only the two files above — deliberately
│   │   │                        #   excludes base/, see that dir's own note
│   │   └── base/
│   │       ├── daemonset.yaml   # Single-container pod: galactic-gateway only
│   │       └── kustomization.yaml
│   └── fabric-router/        # (not gateway-specific, but fabric-router must also
│                              #   run on gateway-role nodes — see ARCHITECTURE-CNI.md
│                              #   and root CLAUDE.md's config/fabric-router/ note)
└── containers/
    └── galactic-gateway/    # galactic-gateway production image
```

`config/galactic-gateway/base/` is **not** included in
`config/galactic-gateway/`'s own kustomization and is **not** applied
as-is — the same exemption `config/fabric-router/` documents in root
`CLAUDE.md`, for the same reason: `GALACTIC_GATEWAY_PUBLIC_INTERFACE` is
deployment-specific and has no generic default. It's designed to be
instantiated once per gateway node by a further overlay that pins it to one
node (`kubernetes.io/hostname`) and sets that node's own public interface.
The SRv6 encapsulation source needs no per-node value: it is derived from
the node's `BGPRouter` (see [SRv6 encap-source
address](#srv6-encap-source-address) below).

### Worked ContainerLab example

`deploy/containerlab/resources/galactic-gateway/` runs this role on all four
lab edge nodes: `dfw-worker2`/`dfw-worker3`, `sjc-worker2`, and
`iad-worker2`. Each node shares its uplinks with that node's egress shard
through the XDP dispatcher (the shard runs with
`GALACTIC_NAT_XDP_ATTACH=dispatch`). Each node's overlay directory, named for
the node itself, carries:

- `node-patch.yaml` — sets `GALACTIC_GATEWAY_PUBLIC_INTERFACE` (`bond0`, the
  transit-facing bond) and `GALACTIC_GATEWAY_INTERNAL_INTERFACES` (`bond1`, the
  compute-facing bond). It leaves `GALACTIC_GATEWAY_SRV6_ADDRESS` unset, so
  the lab exercises the derivation from the node's `BGPRouter`
  (`2001:db8:ff01:1002::` on `dfw-worker2`). The overlay's `kustomization.yaml`
  pins the DaemonSet to the node via `kubernetes.io/hostname` and renames it
  `galactic-gateway-<node>`.
- `networkgateway.yaml` — the `NetworkGateway` object itself (just
  `spec.targetRef.name`, see the [samples](#the-two-crds) above).

The node's `BGPRouter`/`BGPPeer` live with the separate `galactic-router`
DaemonSet's config, in `resources/galactic-router/<site>/`.

Each site directory (`dfw/`, `sjc/`, `iad/`) adds the site's
`networkrules.yaml` (`ns60-tcp` and `ns60-udp`, port 80) and
`servicevipbindings.yaml`. Each site has its own VIP, in a `/64` only that
site's edge nodes originate into the underlay (`2001:db8:6060:1::/64` for
dfw, `:2::` for sjc, `:3::` for iad), and one `ns60` backend on its compute
node. `task verify:gateway-ingress` drives TCP and UDP through each gateway
node in turn; see [Testing](#testing).

---

## Data Flow

See [docs/architecture/](../architecture/) for C4 context/container diagrams covering all four Galactic applications, including how `galactic-gateway` and `galactic-router` run as separate, co-located DaemonSets on gateway-role nodes.

### Control-plane reconcile flow (per gateway node, per `NetworkGateway` reconcile)

`NetworkGatewayReconciler.Reconcile` runs the aggregate, List-driven pass
that converges this node's whole gateway engine:

1. **Assemble desired state.** Lists every accepted, non-deleting
   `NetworkRule` in the namespace — under the DSR anycast model every
   gateway node in a PoP serves every accepted rule identically, so there
   is no primary/secondary subset to filter on — expands each rule's
   `backendSelector` into backends, the IPv6 interface addresses of the
   `VPCAttachment`s it selects in the rule's VPC (`rulebackends.go`'s
   `selectRuleBackends`, over one cluster-wide attachment list per pass
   grouped by VPC), leaves out each backend an older rule serves on
   the same backend port and protocol (`ruleBackendOwners`: a backend node
   translates a backend's replies back to only one VIP, so the newer rule's
   flows would be dropped there), resolves each to the SRv6 uSID of the node its
   attachment reports via `usidresolver.go`'s `buildBackendSIDIndex`, writes
   the backend's slot (`srv6.BackendSlot`, a hash of its address and port)
   into bits 81–96 of that uSID so a node hosting several of the rule's
   backends can tell which one Maglev chose (#799), and converges
   `gateway.Engine` toward the result. The reconciler watches
   `VPCAttachment`s cluster-wide, so a backend appearing, moving node or
   changing address reconverges every gateway without a rule edit. Its
   predicate (`vpcAttachmentBackendChanged`) drops updates that change
   none of the fields `selectRuleBackends` reads (labels, `status.vpc`,
   `status.node`, `spec.interface.addresses`, `spec.interface.mode`), so a
   conditions-only status write triggers no pass. The router's
   `NetworkRuleBindingReconciler` uses the same predicate and re-queues
   only the rules in the attachment's VPC. A deleting rule stays in that state,
   as *draining*, while it still carries the teardown finalizer and any
   `BGPAdvertisement` labelled with its name exists: it is not advertised
   and its `<node>/Programmed` condition is left alone, but the datapath
   keeps serving it. Once the last labelled advertisement is gone, the node
   keeps it loaded for a further `ruleDrainDelay` (5s, tracked in memory by
   `networkgateway_drain.go`'s `ruleDrainTracker`, even after the object
   itself is gone) so the BGP withdrawal can reach every peer, then drops it
   (issue #715). The `BGPAdvertisement` watch wakes the pass when the
   advertisements are deleted, and a `RequeueAfter` wakes the one that ends
   the delay. A restarted process remembers nothing, so it drops a rule
   whose advertisements are already gone on its first pass.
2. **Wire BGP.** Reconciles one `BGPAdvertisement` per loaded rule per
   non-empty VIP address family, name-qualified by node
   (`<rule>-<node>-<hash>-v4`/`-v6` — required, not cosmetic, since every
   gateway node computes the same rule independently), and deletes any other
   advertisement this node made for the rule. This reuses the existing `l2vpn/evpn` Type-5 IP-Prefix
   advertisement path end-to-end unmodified. `VRFID`/`Function` are left
   unset (these routes need no SRv6 decap behavior of their own — a
   different Route Distinguisher per originating node, not a decap
   Function, is what keeps every node's route alive as an independent,
   non-competing path). **No `LocalPreference` is set** — every gateway
   node's route is equally preferred by construction. A rule that fails to
   build (no backend uSID resolves, or an address is malformed) or that the
   engine refuses (over quota, or a VIP the datapath rejects) is not
   advertised, and any route an earlier pass published for it is withdrawn,
   so the fabric never sends a VIP's traffic to a node with nothing loaded
   for it. A rule where only some backends resolve is loaded and advertised
   with the rest (#713). Each node records the result on the rule as its
   own `<node>/Programmed` condition (`Programmed`, `BackendsUnresolved`,
   `LoadFailed`, or `InvalidRule`, with the error or the unresolved
   backends in the message). The type is node-scoped because
   `NetworkRule` status is shared by every gateway node while loading
   is per node; a node writes it only when it changes, and a
   departing, deleted, or disabled node's condition is removed with its
   advertisements. The `NetworkGateway`'s `EngineDegraded` message
   lists every failed rule. Every rule
   advertisement carries a `networkRuleLabel` label and a plain (not
   controller, no `blockOwnerDeletion`) owner reference to its
   `NetworkRule`, both backfilled on existing objects, and nothing is
   created or updated for a rule that is being deleted. A pass whose cache
   has not yet seen that deletion can still create one after teardown has
   finished. Each pass therefore withdraws this node's advertisements for
   rules missing from its list once an uncached read confirms the rule is
   gone (`sweepOrphanedAdvertisements`, #763). The owner reference lets
   Kubernetes garbage collection delete any that remain.
3. **Crash recovery.** Runs `Engine.ReconcileOrphans` (see
   [Crash recovery](#crash-recovery) below).

`NetworkRuleReconciler.Reconcile` separately owns two **per-object**
lifecycle pieces the aggregate pass above is the wrong place for:
`status.conditions`'s `Accepted` condition (`updateAcceptedCondition` — set
once gateway nodes exist for the namespace) and the
finalizer-guarded teardown ordering on deletion (`reconcileDelete`: delete
every `BGPAdvertisement` labelled with the rule's name, on any node,
*before* releasing quota/reservation state, then list them again through
the manager's uncached API reader and, if another node created one the
cache missed, delete it and requeue instead of removing the finalizer).
Each gateway node removes the rule's `vip_table` rows only after those
deletes and its drain delay (step 1 above), which is what the
`Datapath.RemoveRule` contract requires: withdraw the route first, or
traffic the fabric still sends to the VIP is dropped. The finalizer does
not wait for every node to finish draining; that would need a cross-node
protocol that does not exist.

Every gateway node's own process runs both reconcilers, unconditionally, on
every `NetworkGateway`/`NetworkRule` in the namespace, with no leader
election anywhere in this codebase — safe because the reconcile logic is
either idempotent (finalizer add/remove, `BGPAdvertisement` create/delete)
or a pure function of inputs every gateway node observes identically
(`vip_table` registration, the Maglev table itself). A rule carries no
`gatewayRef`, so both reconcilers watch the *other* CRD type and broadcast
to every object in the namespace on change (`ruleToGatewayRequests`,
`gatewayToRuleRequests`) rather than targeting a specific object.

### Packet path (`internal/plumbing/ebpf/edgeprog/edgedsr.c`, program `edge_lb`)

IPv6-only, phase 1 scope (plain TCP/UDP, no extension headers). Attached to
the node's public/underlay-facing uplink. There is no "is this a reply to me"
direction check: a reply never reaches this program, which sees only the
forward half, so it has exactly one branch, not two. Replies are
`edge_return`'s, on a different attach point — see below.

1. **Parse** the outer Ethernet + IPv6 header, then the L4 header (TCP or
   UDP only). Not IPv6, unparseable, or not TCP/UDP — unclaimed: handed to
   the dispatcher's later slots, in practice the egress shard's, if the
   interface carries their role (see
   [below](#sharing-the-xdp-hook-xdpdispatch)), otherwise `XDP_PASS` to the
   kernel stack, e.g. BGP/SSH to the node itself. Only the
   source/destination port are ever read; nothing is rewritten.
2. **Match** `(proto, dst port, dst addr)` against `vip_table` (a VIP is
   globally unique by construction, so the key has no tenant dimension). No
   match — unclaimed, as above (not one of this gateway's VIPs).
3. **Claimed past this point** — every subsequent failure is a drop, not a
   pass-through (this gateway owns this VIP+port+protocol). Bump
   `vip_stats_table`'s hit counters (packets/bytes/last-seen), lazily
   creating the row on first match. An empty backend list drops
   (`DROP_REASON_EMPTY_BACKEND_LIST`).
4. **Maglev lookup.** Hash the client's own `(address, port)` and look up
   the precomputed Maglev table (`vip_table`'s own `maglev_table` field,
   populated by the Go control plane's `internal/maglev.Table` — see
   `edgemap`'s doc comment) to get a backend index, deterministically and
   statelessly: every gateway node computes the identical index for the
   identical flow from the identical `(VIP, backend list)` input, which is
   what makes this design safe under anycast/ECMP — a flow's packets
   landing on a different gateway node mid-connection still resolve to the
   same backend.
5. **Push** a fresh 40-byte outer IPv6 header addressed to the chosen
   backend's own worker-node SRv6 uSID (`vip_table`'s per-backend field,
   resolved by the Go control plane the same way any other cross-node SRv6
   destination is — see [uSID resolution](#usid-resolution-for-backends)
   below), sourced from this node's own `encap_config_table` entry (this
   node's plain SRv6-reachable address — never compared against anything on a
   receive path, since no reply ever re-enters this program). Resolve the L2
   next-hop via `bpf_fib_lookup`, then leave over the interface that lookup
   selected: `XDP_TX` where the route egresses the interface the client's
   packet arrived on, `bpf_redirect` + `XDP_REDIRECT` where it does not. Those
   differ on every gateway that reaches its clients and its compute nodes over
   separate links, which is this role's normal shape — see [Known
   Constraints](#known-constraints) for the bug that came from returning
   `XDP_TX` unconditionally. The inner packet travels completely unmodified —
   this is DSR's entire premise: no address or port rewriting and no checksum
   touch anywhere.

See `edgedsr.c`'s own header comment for the full byte-level walkthrough,
including the `EDGE_BARRIER_VAR` eBPF-verifier bounds-narrowing workaround
and two wire-format bugs found and fixed in `push_outer_header`: the pushed
outer IPv6 header's version nibble was left zeroed instead of set to `6`,
and the outer header's `payload_len` undercounted the inner IPv6 header's
own 40 bytes (a call site passed `ip6->payload_len` directly instead of
`sizeof(ip6hdr) + payload_len`). Both were invisible on the SRv6 uSID
decap path (`usid.c`'s decap reads fixed offsets unconditionally, without
validating either field) but would have caused any version- or
length-validating intermediate hop or receiver to reject every packet this
datapath ever pushed — found via live-kernel investigation, not
`BPF_PROG_TEST_RUN`, and covered by regression tests in `edgedsr_test.go`.

### Sharing the XDP hook (`xdpdispatch`)

An interface takes one native XDP program, and `galactic-nat`'s egress shard
can run on the same edge nodes, needing the same interfaces: tenant egress
arrives on the compute-facing bond (`edge_return`'s) and its replies on the
public uplink (`edge_lb`'s). Neither binary owns the hook. The node's shared
XDP dispatcher (`internal/plumbing/ebpf/xdpdispatch`) holds it, and each
datapath runs from its own slot.

- `GALACTIC_GATEWAY_XDP_ATTACH=dispatch`, the default, opens the dispatcher,
  loads `edgedsr.c` against its maps (`edgeattach.Load` with
  `CollectionOptions.MapReplacements`), fills slot 0 with `edge_lb` and slot
  1 with `edge_return`, and renews both slots' leases. `xdpattach.DispatchSet`
  puts the dispatcher on the public targets with the public role and on the
  internal targets with the return role. The links are pinned under
  `/sys/fs/bpf/galactic-xdp`, so a gateway restart swaps its programs into
  the slots without detaching anything.
- Every unclaimed exit in `edge_lb` and `edge_return`, including the
  non-IPv6 early returns that carry NAT64's IPv4 replies, goes through
  `dispatch_next` (`dispatch.h`), which tail-calls the later slots the
  interface's roles allow. A claimed packet never reaches them.
- The return slot never runs on an interface that also carries the public
  role: the dispatcher's root and `SetRole` both refuse it, and
  `setupGatewayDatapath` refuses an internal interface that resolves to a
  public one at startup.
- `GALACTIC_GATEWAY_XDP_ATTACH=direct` attaches the programs themselves,
  unpinned. It first detaches an idle dispatcher from the targets and
  refuses to start while another datapath's slot is live there.
  Attached directly, the programs hold their own empty copies of the
  dispatcher maps, so every unclaimed packet passes to the kernel.
- `GALACTIC_GATEWAY_DATAPATH_ENABLED=false` loads nothing, empties the
  gateway's slots, and makes `NetworkGatewayReconciler` withdraw this
  node's VIP advertisements and report `DatapathDisabled`.
- The two datapaths claim disjoint traffic, a VIP destination or source here
  and a shard SID or masquerade-address destination there, so the slot
  order changes no verdict.
- The kernel ties a program array to its first user's program type, JIT
  state, frags support and expected attach type, and rejects any other
  program with a bare `EINVAL`. The root, `edge_lb`/`edge_return` and the
  shard's `nat_ingress` are all ELF `SEC("xdp")` programs (`AttachXDP`), so
  they match; a hand-built program needs `AttachType: ebpf.AttachXDP` to be
  accepted (see `edgedsr_chain_test.go`).

### Return path (`edgedsr.c`, program `edge_return`)

Where the compute tier routes through this node — the shape the
containerlab topology models, compute nodes holding links only to their
site's edge nodes — a backend's reply to a VIP crosses this node on its way
to the fabric. The kernel will not forward it: the forward half reached the
backend inside an SRv6 packet through XDP, which netfilter never saw, so
connection tracking holds no entry, marks the reply `INVALID`, and
kube-proxy's `KUBE-FORWARD` chain drops it on its first rule. No forward
packet will ever create the entry the reply is judged against, so this is
structural rather than a misconfiguration to exempt.

`edge_return` forwards the reply itself, in XDP, before netfilter runs, so
the node keeps its stock forwarding rules and needs no rule of ours ahead
of kube-proxy's. It matches on the **source address alone**
(`vip_addr_table`, keyed by VIP with no port or protocol dimension), which
also covers the ICMPv6 errors a port-keyed match would miss; decrements the
hop limit, the kernel no longer being there to do it; resolves the next hop
through the same `bpf_fib_lookup`; and leaves over the interface that
lookup selected. It is as stateless as the forward path and has no
relationship to the forward half's backend choice, so a site whose two edge
nodes take the request and the reply respectively still works — both hold
the same `vip_addr_table` rows.

Attached only to `GALACTIC_GATEWAY_INTERNAL_INTERFACES`, never the public
uplink: on the uplink an external client could source a packet from a VIP
address and have it forwarded unexamined. A node with no compute tier
behind it sets nothing, attaches no return program, and its packet path is
unchanged.

`vip_addr_table` is maintained by `edgemap.VIPTable` alongside `vip_table`
itself, an address present exactly while some rule still uses it, with its
own generation for the same crash-safe reconcile cutoff. Its counters live
in `vip_return_stats_table` and surface as `galactic_edge_return_*`,
labeled by `vip` and `vpc`.

---

## Entry Points

### `cmd/galactic-gateway/main.go` / `root.go` — Gateway daemon

`main.go` holds `checkWatchPermissions` (RBAC pre-flight, mirroring
`cmd/galactic-router/main.go`'s identically-named function, scoped to this
binary's own resource set: `networkgateways`, `networkrules`,
`bgpadvertisements`, and — even though this binary has no BGP client of its
own — `bgprouters`, since `usidresolver.go` reads `BGPRouter` CRDs directly
to resolve backend uSIDs). The scheme also registers `cloud.datumapis.com`,
since a rule's backends are `VPCAttachment`s.

`root.go`'s `runCmd`:

1. Build a controller-runtime manager (`HealthProbeBindAddress: "0"` — no
   built-in HTTP health, same as `galactic-router`; metrics on
   `cfg.MetricsPort`).
2. Start a gRPC health server, explicitly forced to `NOT_SERVING` at
   startup rather than the default-`SERVING` `grpchealth.NewServer()`
   behavior — flipped to `SERVING` only once the datapath is attached and
   the vip table reachable (see [#360](#known-constraints) below for why
   this ordering was fixed deliberately).
3. RBAC pre-flight (`checkWatchPermissions`).
4. `resolveEncapSource` (`cmd/galactic-gateway/encapsource.go`) — use
   `SRv6Address` when set; otherwise list `BGPRouter`s through the uncached
   API reader (the manager has not started) and derive the node's locator
   address from the one targeting this node, waiting with backoff until one
   carries a locator and node ID. A failed list is retried on the same
   backoff and logged as a warning each time (#797). See
   [SRv6 encap-source address](#srv6-encap-source-address).
5. `setupGatewayDatapath` (`cmd/galactic-gateway/gateway.go`) — configure
   the required IPv6-forwarding sysctls on the public interface (see
   [Configuration](#configuration) below), load and attach the XDP program,
   register the Prometheus metrics collector. `PublicInterface` is required,
   with no `NoopDatapath{}` fallback — the config validator already rejected
   it being empty before `runCmd` was ever reached.
6. Construct real (not stubbed) `gateway.NodeQuotaEnforcer` and
   `gateway.PrometheusTelemetryEmitter`, wire `gateway.NewEngine`.
7. Register `NetworkGatewayReconciler` and `NetworkRuleReconciler`.
8. `mgr.Start(ctx)`.

### `cmd/galactic-gateway/gateway.go` — datapath setup

`setupGatewayDatapath` first resolves `PublicInterface` via
`edgeattach.ResolveTargets`: usually that's just `[PublicInterface]`
unchanged, but if `PublicInterface` names a Linux bonding master, it
resolves to that bond's slave interfaces instead — native-mode XDP against
a bonding master is not reliable (see [Known Constraints](#known-constraints)
below for the confirmed failure and why it isn't simply "bonding never
implements `ndo_bpf`"), unlike `internal/plumbing/ebpf/attach`'s TC-BPF
path, which attaches to both the master and its slaves (see
[ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md) for that side). It then calls
`sysctl.ConfigureFIBLookupUplinkSysctls` once per resolved target —
required for `bpf_fib_lookup()` (`edgedsr.c`'s `push_outer_header`) to
ever succeed on the interface the XDP program actually runs on: without it
the kernel returns `BPF_FIB_LKUP_RET_NOT_FWDED` for every lookup,
correctly refusing to resolve a forwarding route on an interface not
configured as a router. This was found via live-kernel investigation of a
pre-existing containerlab veth/XDP_TX blocker — the sysctl gap, not
`XDP_TX` itself, was what actually prevented every gateway node's
`bpf_fib_lookup` from ever succeeding in that lab (see
[Known Constraints](#known-constraints) below for the related, lab-only
`XDP_TX` observability quirk this investigation also turned up, and for
why the sysctl targets the resolved bond slave rather than
`PublicInterface` itself when the two differ). The helper reads each
sysctl back and returns an error unless it reads `1`, which fails startup:
before #586 it logged the write failure and returned `nil`, so a pod with
a read-only `/proc/sys` ran a datapath that dropped every packet. The
DaemonSet mounts the host's `/proc/sys/net` at `/host/proc/sys/net` and
points `GALACTIC_GATEWAY_PROC_SYS_PATH` at `/host/proc/sys` so the write
can succeed without `privileged`. It then loads `edgeprog.EdgedsrObjects`
(`edgeattach.Load`), attaches it to every
resolved target (`edgeattach.Attach` — native XDP driver mode only, no
generic/SKB-mode fallback, one `link.Link` per target), and constructs a
`gateway.KernelDatapath` over it, writing this node's SRv6 encap-source
address into `encap_config_table` once at construction time.

The loaded objects and every returned `link.Link` are stashed in a
package-level `gatewayDatapathKeepAlive` var rather than ever being
`Close`d — see that var's doc comment for a concrete, previously-live
incident: `cilium/ebpf`'s program/map/link types register a runtime
finalizer that silently closes the underlying fd once nothing reachable
points at it, and the first time this path ran against a real interface
with nothing pinning `objs`/the link, the XDP attachment was silently GC'd
and detached mid-run — every control-plane signal (pod healthy, `ApplyRule`
succeeding, `vip_stats_table` metrics populated) still looked completely
normal while ingress traffic quietly stopped being intercepted at all.

---

## Configuration

### GatewayConfig environment variables (`internal/config/gateway.go`)

| Variable                            | Required | Default | Description                                                                                                                                                                                                                         |
| ----------------------------------- | -------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GALACTIC_GATEWAY_NODE_NAME`        | Yes      | —       | Kubernetes node name                                                                                                                                                                                                                |
| `GALACTIC_GATEWAY_PUBLIC_INTERFACE` | Yes      | —       | Public/underlay-facing uplink interface the XDP program attaches to. May name a Linux bonding master (`edgeattach.ResolveTargets` expands it to that bond's slaves — see [Known Constraints](#known-constraints))                   |
| `GALACTIC_GATEWAY_SRV6_ADDRESS`     | No       | Derived | This node's own plain SRv6-reachable IPv6 address, used as the DSR outer-header encap source (`encap_config_table`) — never compared against anything on a receive path; must be a native IPv6 address (rejected if IPv4 or 4-in-6) |
| `GALACTIC_GATEWAY_METRICS_PORT`     | No       | `8081`  | Prometheus metrics port                                                                                                                                                                                                             |
| `GALACTIC_GATEWAY_GRPC_HEALTH_PORT` | No       | `5181`  | gRPC health check port                                                                                                                                                                                                              |

Both required fields are enforced by `GatewayConfig.Validate` at
startup, not deferred to a later, less obvious kernel-datapath error — a
node deployed without them crash-loops immediately rather than running
degraded.

The metrics/gRPC-health port defaults (`8081`/`5181`) deliberately differ
from every other `galactic-*` process's own defaults
(`galactic-router`'s `9179`/`5179`; `galactic-cni`'s credential-refresh
health port `5180`, metrics port `9180`) because every `edge` node runs
`galactic-gateway`, `galactic-router`, and `galactic-cni` as separate
`hostNetwork: true` DaemonSet pods, all sharing that one node's network
namespace regardless of pod boundaries — every port any of them binds must
not collide with any of the others':

| Component          | Metrics                                             | gRPC health |
| ------------------ | --------------------------------------------------- | ----------- |
| `galactic-router`  | `9179`                                              | `5179`      |
| `galactic-gateway` | `8081`                                              | `5181`      |
| `fabric-router`    | `9342` (frr-exporter), `9343` (fabric-config-agent) | none        |

### SRv6 encap-source address

`GALACTIC_GATEWAY_SRV6_ADDRESS` is this gateway node's own plain
SRv6-reachable address, used purely as the source of every outer header
this node's `edge_lb` program pushes (`edge_return` pushes no header at
all, so it never reads this). It is never an address-translation source,
never has return-path significance (DSR has no return path through this node at
all), and is never published to any CRD status (`NetworkGatewayStatus`
carries no self-address field — see [The two CRDs](#the-two-crds) above).

Left unset, it is derived at startup (#707) from the `BGPRouter` whose
`targetRef.name` is this node, searched across every namespace:
`srv6.NodeLocatorAddress` returns the node's locator address, the
`srv6Locator` Block and the `nodeID` with the Function and Argument fields
zero (`2001:db8:ff01::/48` with `nodeID: 4098` gives
`2001:db8:ff01:1002::`). That is the value deployments used to set by hand.
It shares bits 1-64 with the CNI's `srv6.NodeSIDBase`, so both name the same
node, but carries no End.DT46 function. The gateway waits, not ready, until
such a router exists, and refuses to start if two routers for the node
derive different addresses. The wait counts against the startupProbe, which
allows 10 minutes before the kubelet restarts the container and the wait
starts over (#796). A set value always wins, for a node that needs
an override.

### Deployment (`config/galactic-gateway/base/daemonset.yaml`)

Single-container pod: `galactic-gateway` only, with its own
`ServiceAccount` (`galactic-gateway`) and `ClusterRoleBinding` (see
[RBAC](#rbac) below). `galactic-router` used to run as a second container
in this same pod; it now runs on the same gateway-role node as its own,
separate DaemonSet and pod (`config/galactic-router/overlays/router/`).

| Capability | Why                                                                                                                                                                                                                                                                                                                          |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NET_ADMIN` | netlink XDP attach                                                                                                                                                                                                                                                                                                          |
| `BPF`       | the `bpf()` syscalls themselves (program/map creation)                                                                                                                                                                                                                                                                      |
| `PERFMON`   | the verifier only allows pointer+scalar arithmetic on packet data/data_end when the loading process is `perfmon_capable()` — without it, even a `root` container gets "pointer arithmetic ... prohibited for !root"                                                                                                       |

Mounts `/sys/fs/bpf` (must already be a real bpffs — `type: Directory`,
not `DirectoryOrCreate`, so a missing mount fails loudly instead of
silently pinning to a plain directory) for `edgeattach.PinDir`
(`/sys/fs/bpf/galactic-edge`). See [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md)
for the co-located `galactic-router` pod's own capabilities (`NET_ADMIN`
only) and its `/var/run/netns` mount (GC's netns-liveness check) — a
separate pod spec entirely, not part of this manifest.

### RBAC

`config/galactic-gateway/rbac.yaml`'s `ClusterRole` covers exactly what
`NetworkGatewayReconciler`/`NetworkRuleReconciler` touch:
`networkgateways`/`networkrules` (+ `/status`) read-write,
`bgpadvertisements` full CRUD, and read-only `get`/`list`/`watch` on both
`bgprouters` (for `usidresolver.go` — see above), `vpcattachments` in
`cloud.datumapis.com` (a rule's backends, selected and watched
cluster-wide) and `bgpvrfinstances`
(`NetworkGatewayReconciler.SetupWithManager` also watches `BGPVRFInstance`
to re-trigger reconciliation once a backend's owning VRF/advertisement data
actually exists; omitting this rule left the manager's informer cache never
finishing `WaitForCacheSync`, silently, behind a `bgpvrfinstances ...
is forbidden` reflector error loop). This was split out of
`config/galactic-router/rbac.yaml`'s single `ClusterRole`, which used to grant one
`galactic-router` identity both the BGP-family CRD verbs and
`networkgateways`/`networkrules` verbs when both reconciler sets lived in
the same binary — every *other* (non-gateway) node's `galactic-router`
ServiceAccount now loses that access entirely, rather than every
`galactic-router` pod in the cluster carrying it as before.

`galactic-gateway` has its own self-contained `ServiceAccount`/`ClusterRole`
— it carries none of `galactic-router`'s RBAC, and none is bound to it. A
gateway node still needs `config/galactic-router/` (its RBAC included)
applied too, since the co-located `galactic-router` **pod** — not a
container in this one — is what actually advertises the node's tenant BGP
session: a bare `galactic-gateway` pod with no co-located `galactic-router`
pod on that node is not a supported configuration.

---

## Module / Package Reference

| Package                                                 | Binary           | Responsibility                                                                                                                                                                                                                                                  | Owns state                           |
| ------------------------------------------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `internal/config` (`gateway.go`)                        | galactic-gateway | `GatewayConfig`: node name, ports, public interface, SRv6 encap-source address; three-tier CLI/env/default precedence via viper                                                                                                                                 | No                                   |
| `internal/controller` (`networkgateway_controller.go`)  | galactic-gateway | `NetworkGatewayReconciler`: desired-state assembly (with the deleted-rule drain in `networkgateway_drain.go`), BGP wiring, orphan-crash recovery                                                                                                                | No                                   |
| `internal/controller` (`networkrule_controller.go`)     | galactic-gateway | `NetworkRuleReconciler`: finalizer-guarded teardown ordering, `Accepted`-condition maintenance (`updateAcceptedCondition`)                                                                                                                                      | No                                   |
| `internal/controller` (`usidresolver.go`)               | galactic-gateway | `backendSIDIndex`: resolves a `NetworkRule` backend address to the SRv6 uSID of the node its `VPCAttachment` reports by matching against `BGPAdvertisement`/`BGPRouter`/`BGPVRFInstance` CRDs, verifying tenant ownership; `backendSID` adds the backend's slot | No                                   |
| `internal/gateway` (`engine.go`)                        | galactic-gateway | `Engine`: mutex-guarded convergence loop ("apply everything in desired, remove everything not in desired"), mirroring `GoBGPRuntime`'s shape                                                                                                                    | Yes (active-rule map)                |
| `internal/gateway` (`types.go`)                         | galactic-gateway | `DesiredRule`/`DesiredBackend`/`EngineState`/`EngineStatus`/`RuleStatus` — the engine's own representation, assembled by the controllers above; `DesiredBackend` implements `internal/maglev.Backend`                                                           | No                                   |
| `internal/gateway` (`datapath.go`, `kerneldatapath.go`) | galactic-gateway | `Datapath`/`QuotaEnforcer`/`TelemetryEmitter` interfaces; `KernelDatapath`, the real `Datapath` backed by `edgemap.VIPTable` over a loaded `edgeprog.EdgedsrObjects`, building a `internal/maglev.Table` per rule; `NoopDatapath` for tests                     | Yes (`vipKeysByName` bookkeeping)    |
| `internal/gateway` (`quota.go`)                         | galactic-gateway | `NodeQuotaEnforcer` — real, coarse node-level admission caps (max rules/tenant, max total `vip_table` entries); `NoopQuotaEnforcer` for tests                                                                                                                   | Yes (in-memory reservation counters) |
| `internal/gateway` (`telemetry.go`)                     | galactic-gateway | `PrometheusTelemetryEmitter` — control-plane-drop counter only; `NoopTelemetryEmitter` for tests                                                                                                                                                                | Yes (Prometheus metric state)        |
| `internal/gateway` (`recovery.go`, `diff.go`)           | galactic-gateway | `Engine.ReconcileOrphans` (crash recovery) and `diffRuleKeys` (the pure key-set diff both `Reconcile`/`ReconcileOrphans` build on)                                                                                                                              | No                                   |
| `internal/maglev` (`table.go`)                          | galactic-gateway | Pure-Go Maglev consistent-hash lookup table (`New`/`Lookup`/`Backends`) — one `*Table` built per ring; this binary's only importer today (`galactic-nat` has no analogous shard-placement ring — see Known Constraints)                                         | No                                   |
| `internal/plumbing/ebpf/edgeprog`                       | galactic-gateway | Compiled XDP program (`edgedsr.c`, program `edge_lb`) + bpf2go-generated Go bindings (`EdgedsrObjects`)                                                                                                                                                         | No                                   |
| `internal/plumbing/ebpf/edgemap`                        | galactic-gateway | `VIPTable`: `vip_table`/`vip_stats_table`/`vip_addr_table` read/write API, `Generation`/`Reconcile` crash-safety mechanism                                                                                                                                      | Yes (via `KernelTable`)              |
| `internal/plumbing/ebpf/edgeattach`                     | galactic-gateway | Load + native-XDP-only attach of the compiled program to one interface                                                                                                                                                                                          | Yes (pinned maps, held link)         |
| `internal/plumbing/ebpf/edgemetrics`                    | galactic-gateway | Pull-based `prometheus.Collector` reading `vip_table`/`vip_stats_table`/`drop_reasons` live at every scrape                                                                                                                                                     | No                                   |
| `internal/plumbing/ebpf/edgepreflight`                  | galactic-gateway | Startup kernel-capability check (`BPF_PROG_TYPE_XDP`, `BPF_MAP_TYPE_HASH`, kernel BTF, `bpf_xdp_adjust_head`) — no partial pass, no degraded fallback                                                                                                           | No                                   |
| `internal/plumbing/ebpf/xdpattach`                      | gateway, nat     | Native-XDP attach across a target list, shared with `natattach`: per-NIC support check before any attach, each bond slave waited back into its aggregate before the next                                                                                        | No                                   |

---

## External Dependencies

| Dependency                            | Version           | Purpose                                                                                                                                                                                                                                                                                             |
| -------------------------------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `github.com/cilium/ebpf`              | v0.22.0           | XDP program load/attach/map bindings (`edgeprog`/`edgemap`/`edgeattach`) — the same library version `internal/plumbing/ebpf` (the CNI chain's TC-BPF uSID datapath, see [ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md)) uses, but a fully separate program/map/attach surface with no shared map layout |
| `go.datum.net/network`                | bumped frequently | `NetworkGateway`/`NetworkRule` CRD API types, plus the BGP-family types this binary reads (`BGPAdvertisement`, `BGPRouter`, `BGPVRFInstance`)                                                                                                                                                       |
| `go.datum.net/cloud`                  | pseudo-version    | `VPCAttachment` types a rule's `backendSelector` picks from. Galactic only reads them. datum-cloud/cloud's controllers write `status.vpc` and `status.node`, which backend selection waits on (#821)                                                                                                |
| `sigs.k8s.io/controller-runtime`      | v0.24.1           | Full manager + reconciler framework — like `galactic-router`, not a bare client like the CNI chain                                                                                                                                                                                                  |
| `github.com/prometheus/client_golang` | v1.24.1           | `PrometheusTelemetryEmitter`'s control-plane-drop counter, plus `edgemetrics`'s pull-based `vip_table`/`vip_stats_table`/`drop_reasons` collector                                                                                                                                                   |
| `github.com/spf13/cobra`              | v1.10.2           | CLI command/flag handling                                                                                                                                                                                                                                                                            |
| `google.golang.org/grpc`              | v1.83.2           | gRPC health server (default `:5181`)                                                                                                                                                                                                                                                                 |
| `k8s.io/api`, `k8s.io/client-go`      | v0.36.3           | Kubernetes client, `SelfSubjectAccessReview` (RBAC pre-flight)                                                                                                                                                                                                                                       |

---

## Key Design Decisions

- **DSR (Direct Server Return).** The datapath does no address/port
  rewriting at all: a client's packet is pushed inside an SRv6 outer header
  toward the chosen backend's worker node completely unmodified, and the
  backend replies to the client directly. Everything else in this section
  follows from that one choice.
- **Anycast VIP advertisement.** Every gateway node in a PoP advertises
  every accepted rule's VIPs at equal BGP preference; nothing in this
  codebase sets a local preference or picks a primary node. A distinct
  Route Distinguisher per originating node (RFC 4364 §4.3.2,
  `internal/runtime/gobgp/paths.go`'s `deriveRD`) is what keeps
  every node's identical-prefix advertisement alive as an independent,
  non-competing route instead of BGP collapsing them to one best path — see
  the go/no-go anycast spike, `internal/runtime/gobgp/anycast_spike_test.go`.
- **Maglev, not `hash(client) % backend_count`.** `internal/maglev.Table`
  gives every gateway node the byte-identical lookup table for the
  byte-identical `(VIP, backend list)` input, with no coordination or RPC
  between nodes — this is what makes it safe for ECMP/BGP reconvergence to
  move a flow's packets to a different gateway node mid-connection and
  still land on the same backend. It also bounds backend-set-change
  disruption to roughly `1/N` of flows (N = backend count) rather than
  reshuffling everything, unlike a plain modulo scheme.
- **No VRF/Geneve dependency.** The outer SRv6 header is pushed straight
  from `vip_table` (resolved via `edgemap`) rather than a kernel VRF route,
  so this datapath has no VRF dependency and no exposure to the GoBGP
  EVPN-decode bugs that forced every earlier per-VPC gateway design to
  colocate with the workload's own VRF. `Engine`/`KernelDatapath` hold no
  VRF/Geneve state at all.
- **No tenant dimension in the datapath.** `vip_table` is keyed by `(proto,
  VIP port, VIP address)` only — a VIP is globally unique by construction,
  so no tenant/VPC field is needed to disambiguate ingress traffic.
  `DesiredRule.VPCRef` is carried through only for the per-tenant rule
  quota, never consulted by the datapath itself.
- **uSID resolution for backends.** There is no exported "IP → uSID" query
  anywhere else in this codebase (`internal/runtime/gobgp/monitor.go`
  decodes EVPN Prefix-SID attributes purely internally, for local kernel
  route installation only). `usidresolver.go`'s `backendSIDIndex` mirrors
  `internal/reconcile/reconcile.go`'s `resolveSRv6SID` instead of embedding
  a second GoBGP speaker: list `BGPRouter`/`BGPAdvertisement`/
  `BGPVRFInstance` CRDs once per reconcile, match a backend's address
  against advertised prefixes, and — unlike an earlier version of this
  resolver — **verify tenant ownership** of the match
  (`verifyTenantOwnership`) via the calling rule's own `VPCRef` and the
  deterministic `BGPVRFInstance` name `galactic-bgp` writes
  (`crdnames.BGPVRFInstanceName`), before trusting it: two tenants
  advertising overlapping (e.g. colliding ULA) address space would
  otherwise resolve ambiguously, silently routing a packet into the wrong
  tenant's VRF rather than merely picking an ambiguous-but-harmless match.
  A backend that does not resolve is left out of the rule rather than
  failing it (`buildDesiredRule`), since a backend pod being recreated
  removes its `BGPAdvertisement` until the new pod attaches. Nodes stay
  consistent because each resolves from the same API objects and the
  Maglev table depends only on the backend set. A per-node cache of the
  last resolved uSID was rejected: a restarted gateway starts with an
  empty cache, so nodes would disagree for longer, and traffic would keep
  going to a pod that no longer exists. Dropping a backend because it is
  unhealthy is #704.
- **SRv6 encap-source address is derived, not published.**
  `GALACTIC_GATEWAY_SRV6_ADDRESS` defaults to the node's locator address,
  derived once at startup from its own `BGPRouter` (#707), rather than a
  per-node operator value. A later change to that router's locator or node
  ID takes effect on the next gateway restart. The value is never published
  to any CRD status: DSR rewrites nothing, so there is no translation source
  that needs advertising as a node-reachability route.
- **Quota/telemetry are real but deliberately coarse.** `NodeQuotaEnforcer`
  enforces two node-level admission caps entirely from control-plane state
  already held by `Engine` (no eBPF map read required): max `NetworkRule`s
  per tenant, and total `vip_table` rows across every tenant vs. the map's
  fixed capacity. It deliberately does **not** do per-flow rate limiting —
  `vip_table`'s key carries no tenant dimension (by design, see above), and
  a meaningful bandwidth/packet-rate quota needs a time-windowed rate
  rather than `vip_stats_table`'s cumulative, never-reset packet/byte
  counters. `PrometheusTelemetryEmitter` similarly covers only what
  `Engine`'s own call sites uniquely know (control-plane-level rejections
  before a rule ever reaches the datapath) — `vip_table`/`vip_stats_table`'s
  own per-packet counters are exposed separately by `edgemetrics`'s
  pull-based collector.
- **Per-VIP hit counters live in their own map (`vip_stats_table`), not
  `vip_table`.** A control-plane `Register` read-modify-write racing the
  datapath's own per-packet increments would silently discard whichever
  landed second (issue #361). So `Register` is a blind
  overwrite of `vip_table` alone and never touches `vip_stats_table`, which
  `edgedsr.c` alone populates, lazily, on a VIP's first matching packet —
  so re-registering a VIP (e.g. every controller reconcile pass) can never
  race, and therefore never lose, the datapath's own increments.
- **Per-VIP series carry the owning VPC from process memory, not a map
  (#709).** Every `galactic_edge_rule_*` and `galactic_edge_return_*` series
  has a `vpc` label holding the rule's `spec.vpcRef`, the same opaque
  identifier the CNI-side `galactic_usid_vrf_*` series carry in their own
  `vpc` label (#672). `KernelDatapath` records it per `vip_table` key as it
  applies each rule, and the collector reads that record at every scrape.
  The CNI needed a pinned `vpc_attribution_table` because it is a separate
  process from its collector; the gateway is not, so no new map, and no map
  schema change, is involved. There is no `vpc_attachment` label: a rule's
  backends come from a selector that can span many VPCAttachments, so none
  owns a VIP. What follows from that:
  - After a restart the counters survive in their pinned maps, but the
    record starts empty, so the series read `vpc=""` until the first
    reconcile re-applies every rule.
  - Deleting a rule deletes its `vip_stats_table` rows, so its series
    disappear rather than freeze. A return-path series disappears once no
    rule uses its address.
  - Two VPCs' rules sharing one VIP address on different ports each keep
    their own `vpc` on the rule series, but that address's return series
    reads `vpc=""`, since `edge_return` counts per address and cannot split
    the traffic.
- **Generation-based crash recovery, not a Geneve-interface scan.**
  `Engine.ReconcileOrphans` delegates to `edgemap.VIPTable.Reconcile`'s
  `Generation`-cutoff mechanism: a caller must capture
  `Engine.DatapathGeneration()` *before* listing the `NetworkRule` CRDs
  that become the live set, so a rule created between the snapshot and the
  list is never mistaken for an orphan. `vip_table` state (not a kernel
  interface) is the only thing this design can leak on a crash — DSR keeps
  no flow/conntrack state at all to garbage-collect beyond that.
- **Native XDP only, no generic-mode fallback.** `edgeattach.Attach` always
  requests `link.XDPDriverMode` and errors rather than silently retrying in
  `link.XDPGenericMode` (SKB mode) if the interface's driver doesn't
  support it — accepting generic mode silently would defeat the reason
  this design chose XDP over TC-BPF in the first place.
- **`galactic-router` carries no gateway-role code anymore.** Splitting the
  edge gateway out of `galactic-router` into its own binary means a crash
  in the XDP-loading, BPF/PERFMON-capable container never takes down the
  tenant BGP session on the same node, and vice versa. See
  [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md) for what's left in that
  binary.

### History

The gateway first shipped as a Full-NAT datapath (`edgenat.c`) with
primary/secondary BGP local-preference placement (`AssignPrimaryNode`,
`internal/gateway/placement.go`, `localpref.go`) and a per-node
self-address route (`publishSelfAddress`).
[#427](https://github.com/datum-cloud/galactic/pull/427) replaced it with
the DSR/anycast design described here, with no migration path, and deleted
that code.

---

## Testing

| Layer           | Command                               | Framework                       | Scope                                                                                                                                                                                                                                                                                                                                    |
| --------------- | -------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unit            | `task test:unit`                      | `go test -race`                 | `internal/config` (`gateway_test.go`), `internal/controller` (`networkgateway_controller_test.go`, `networkrule_controller_test.go`, `usidresolver_test.go`), `internal/gateway` (`engine_test.go`, `diff_test.go`, `kerneldatapath_test.go`, `quota_test.go`, `recovery_test.go`, `telemetry_test.go`), `internal/maglev` (`table_test.go`), `internal/plumbing/bond` (`bond_test.go`, faked `netlink.Link`s, no kernel required — shared bond-master/slave detection used by both this package's `edgeattach.ResolveTargets` and `internal/plumbing/ebpf/attach`'s CNI TC-BPF path), `internal/plumbing/ebpf/edgemap` (`viptable_test.go`, in-memory fake `Table`, no kernel required), `internal/plumbing/ebpf/edgemetrics` (`collector_test.go`), `internal/plumbing/ebpf/edgepreflight` (`preflight_test.go`, `kernel_prober_test.go`); `edgeattach.ResolveTargets` also has its own faked-netlink `TestResolveTargets` (non-bond passthrough, bond-expands-to-slaves-only, no-slaves error) |
| Kernel-required | `task test:unit` (root/CAP_BPF gated) | `go test` + `BPF_PROG_TEST_RUN` | `internal/plumbing/ebpf/edgeprog/edgedsr_test.go` — exercises the compiled program directly, including the version-nibble/payload_len regression tests; `internal/plumbing/ebpf/edgeattach/attach_test.go`                                                                                                                                |
| E2E             | `task verify:gateway-ingress` (in `deploy/containerlab/`) | bash, live containerlab lab | Real TCP and UDP from the off-fabric host to each site's VIP, pinned through each gateway node in turn by a temporary `/128` on the transit router. Asserts the pinned node's `galactic_edge_rule_packets_total` rises, `edge_return` counts the replies, no gateway counts a drop or a `ctstate INVALID` drop, and the backend sees the client's own address. `verify:gateway-restart` restarts a node's gateway and its egress shard in turn while the other carries traffic (#710). `verify:gateway-detach`, outside `task verify`, turns one node's datapath off and confirms the ingress check fails. The lab's uplinks are LACP bonds of veths, which accept a native XDP attach and so do not reproduce the real igb/tg3 bond failure; the root-gated `TestResolveTargetsAndAttach_RealBondDevice` above covers that. |

---

## CI/CD

**Pipeline:** `.github/workflows/ci.yaml` — see
[ARCHITECTURE-ROUTER.md#cicd](ARCHITECTURE-ROUTER.md#cicd) for the shared
tier structure.

**Publish pipeline:** `.github/workflows/publish.yaml`'s
`publish-galactic-gateway-image` job builds and pushes
`ghcr.io/datum-cloud/galactic-gateway`; `publish-kustomize-bundles` stamps
that tag into `config/galactic-gateway/base`.

**Container image:**
- `containers/galactic-gateway/Dockerfile` — golang builder →
  `gcr.io/distroless/static:nonroot`, `ENTRYPOINT ["/galactic-gateway"]`.
  The builder stage additionally installs `clang`/`llvm`/`linux-libc-dev`
  and runs `go generate` for **both** `internal/plumbing/ebpf/prog` (the
  SRv6 uSID TC-BPF program, transitively imported via
  `internal/plumbing/ebpf/edgepreflight`) and
  `internal/plumbing/ebpf/edgeprog` (this binary's own XDP program) —
  neither package's `bpf2go` output (`*_bpfel.go/.o`, `*_bpfeb.go/.o`) is
  committed to git. No shell or CLI tools in the final image:
  `galactic-gateway` drives its eBPF/XDP and `BGPAdvertisement` CRD state
  entirely through the `cilium/ebpf` and controller-runtime Go libraries.

---

## Known Constraints

- **E2E coverage is lab-only.** `task verify:gateway-ingress` in `deploy/containerlab/` sends real traffic through every lab gateway node (see [Testing](#testing)). Before it, the `gatewayDatapathKeepAlive` incident described in [Entry Points](#cmd-galactic-gatewaygateway-go--datapath-setup) above was only discovered because ingress traffic silently stopped being intercepted. Nothing runs that check in CI, since it needs the containerlab lab.
- **Galactic does not check VPC ownership on `NetworkRule`.** `NetworkRule` is internal: the platform API that serves tenants verifies the tenant owns `vpcRef` before it writes the rule, and RBAC on `galactic-system` decides who else can write one. `updateAcceptedCondition` sets `Accepted=True` once gateway nodes exist for the namespace; it is not an ownership result. galactic-router used to carry an allow-all admission webhook for this, never deployed, removed in #366. The `go.datum.net/network` API's doc comments still call the CRD tenant-writable and define `OwnershipVerified`/`OwnershipDenied` reasons nothing sets.
- **The uSID backend resolver's tenant-ownership check depends on `BGPVRFInstance` naming staying deterministic.** `verifyTenantOwnership` closes the ambiguous-match gap an earlier version of this resolver had, but it is only as strong as `crdnames.BGPVRFInstanceName(vpc, nodeName)` staying the exact name `galactic-bgp` writes — a divergence between the two would fail closed (a real backend never resolving) rather than open (a wrong-tenant resolve), which is the safer failure direction but still worth knowing about when either side of that naming contract changes.
- **The derived SRv6 encap source is read once, at startup.** Changing a gateway node's `BGPRouter` locator or node ID does not move its encapsulation source until `galactic-gateway` restarts. See [SRv6 encap-source address](#srv6-encap-source-address) above.
- **The uSID TC-BPF/XDP FIB-lookup PMTUD gap applies here too.** When `bpf_fib_lookup()` returns `BPF_FIB_LKUP_RET_FRAG_NEEDED`, `edgedsr.c` counts `DROP_REASON_FIB_FRAG_NEEDED` and drops rather than emitting an ICMPv6 Packet Too Big — the same gap `internal/plumbing/ebpf/prog/usid.c`'s `usid_ingress` has for its FIB lookup (see [ARCHITECTURE-CNI.md#known-constraints](ARCHITECTURE-CNI.md#known-constraints)). `usid_egress` and the egress shard both send Packet Too Big now; closing it here is #700.
- **`bpf_fib_lookup()` requires IPv6 forwarding sysctls on the public uplink, not just XDP driver support.** `setupGatewayDatapath` calls `sysctl.ConfigureFIBLookupUplinkSysctls` before attaching the datapath — without `net.ipv6.conf.<iface>.forwarding` and `net.ipv6.conf.all.forwarding` both set, the kernel returns `BPF_FIB_LKUP_RET_NOT_FWDED` for every lookup regardless of anything this program does, which `edgedsr.c`'s own drop-reason accounting cannot distinguish from a generic FIB lookup failure. Found via live-kernel investigation of a pre-existing containerlab veth/XDP_TX blocker: the sysctl gap, not `XDP_TX` itself, was the actual cause. A related, lab-only characteristic the same investigation turned up: native `XDP_TX` on a veth pair only promotes a frame into the peer's normal receive stack (visible to `tcpdump`) if the peer *also* runs an XDP program — otherwise delivery uses a raw fast-path invisible to normal tools. This does not apply to a real physical NIC uplink in production, where there is no "peer's own XDP program" question to begin with.
- **A bonded public uplink attaches per-slave, with per-slave FIB-lookup sysctls to match.** Native-mode XDP against a Linux bonding master is not reliable: confirmed failing outright with "operation not supported" on a real gateway node (802.3ad over an igb/tg3 slave pair). Not every kernel's bonding driver categorically lacks `ndo_bpf` — some do implement it by forwarding the attach to every slave — but that still requires each slave's own driver to support native XDP itself, which not every NIC driver does (tg3 is a commonly cited example that doesn't), so this codebase never relies on attaching to the master working, on any kernel. `edgeattach.ResolveTargets` expands a bonding-master `GALACTIC_GATEWAY_PUBLIC_INTERFACE` to its slave interfaces (never the master itself — see `internal/plumbing/bond`, shared with `internal/plumbing/ebpf/attach`'s TC-BPF path, which attaches to the master *and* its slaves instead), and `setupGatewayDatapath` attaches to and configures FIB-lookup sysctls on every one of them. This is not cosmetic: `edgedsr.c`'s `push_outer_header` calls `bpf_fib_lookup()` with `ctx->ingress_ifindex` — confirmed against the source, not assumed — which for a native XDP program attached to a bond slave is that slave's own ifindex, not the bond master's, so `net.ipv6.conf.<slave>.forwarding` (not `net.ipv6.conf.<bond-master>.forwarding`) is what the kernel actually checks. A bonding master with no resolvable slaves is a hard startup error, not a silent fallback to attaching the master (which would only risk repeating the same failure). `edgeattach.Attach` is all-or-nothing across every resolved slave in one call — if any single slave's driver can't accept a native XDP attach (a real possibility per the tg3 note above, not independently confirmed against that node specifically), the whole datapath startup fails rather than running in a degraded, missing-that-slave's-traffic state. The attach step itself lives in `internal/plumbing/ebpf/xdpattach`, shared with `natattach`: every target is checked for native XDP support through the netdev generic netlink family before any is touched, and each bond slave is waited back into its aggregate (MII up, plus LACP collecting|distributing on an 802.3ad bond) before the next is attached (#583); this has not been exercised against real igb/tg3 hardware, only veth in tests, so whether all of a real bonded pair's slaves actually accept native XDP on the affected class of hardware is still open. Attaching per-slave rather than to the bond as a whole means the slave set has to be kept current after startup: `watchTargets` (`cmd/galactic-gateway/gateway.go`) re-runs `ResolveTargets` on every netlink link or route change, and every 30s with none, and hands the result to an `xdpattach.Set` per program (#647). The set attaches a member enslaved or replaced (new ifindex under the same name) since startup through the same gate, one at a time, and skips one whose bounce would leave its bond with no member carrying traffic; it never detaches a member that still exists, since detaching bounces the link as attaching does. Unlike the startup attach, one member failing there does not undo the rest: it is retried on the next pass, and while any resolved target lacks the program the gateway's `readiness` gRPC health service (`config.GRPCReadinessService`, the readinessProbe's `service`) reports NOT_SERVING, without failing liveness.
- **`XDP_REDIRECT` into a veth needs NAPI enabled on the *peer*, which is a lab-only concern.** `edgedsr.c` returns `XDP_REDIRECT` whenever the route to the backend egresses an interface other than the ingress one. In native mode that calls the egress device's `ndo_xdp_xmit`, and veth's implementation silently discards the frame unless the peer end has NAPI enabled — which for a veth means the peer runs its own XDP program or has GRO turned on. A containerlab peer inside an FRR/transit container has neither by default, so a redirect there can fail exactly the way this datapath's original bug did: no drop counter moves, because `bpf_redirect()` itself succeeded and the discard happens later in `xdp_do_redirect`. Both programs are affected, and `edge_return` more so: it attaches to compute-facing links, which are veth pairs in the lab and may be veth or a plain NIC in production. `bpftool prog tracelog` and the `xdp:xdp_redirect_err` tracepoint are the diagnostics; `ethtool -K <peer> gro on` is the lab fix. A production uplink (physical NIC, or a bond slave per the bullet above) implements `ndo_xdp_xmit` natively and has no peer to ask about. This is the redirect-side analogue of the `XDP_TX`-on-veth observability quirk noted above.
- **The return path is opt-in per node and fails closed at startup, not silently.** `edge_return` attaches only where `GALACTIC_GATEWAY_INTERNAL_INTERFACES` names an interface; a node that needs it and does not set it drops every reply in `KUBE-FORWARD` with nothing to say why, exactly as before this program existed. Where it *is* set, an attach failure is fatal to `setupGatewayDatapath` and the pod crash-loops rather than running with the forward half working and replies dying — the same all-or-nothing choice `edgeattach.Attach` already makes across a bond's slaves.
- **A backend in another site replies through that site's edge node.** The gateway can pick a backend anywhere its `NetworkRule` reaches, and the reply then leaves through the edge node in front of *that* backend, whose own `vip_addr_table` must hold the same anycast VIP or the reply meets the unmodified kernel path and dies. Within one cluster the reconciler guarantees this; across clusters it depends on the same `NetworkRule` existing on both sides, which nothing in this repo enforces.
- **Backends depend on an attachment controller outside this repo.** `selectRuleBackends` skips a `VPCAttachment` whose `status.vpc` is not the rule's VPC, and keeps a selected one pending until its `status.node` is set. Galactic writes neither field; controllers in datum-cloud/cloud do, `status.node` from the attachment's `BGPAdvertisement`. Without them an attachment with no `status.vpc` is silently unselected, one with `status.vpc` but no `status.node` is pending with `status.node not set by datum-cloud/cloud`, and a rule with no other backend never loads; the containerlab lab patches the status by hand (`deploy/containerlab/scripts/publish-ns60-attachments.sh`). See #821.
- **`vip_table` has no active GC beyond crash-recovery reconcile.** By design (see Key Design Decisions above) — DSR keeps no flow state to leak in the first place.
- **Egress is out of this binary's scope, not unimplemented.** Egress translation is a separate, sharded tier (`galactic-nat`, its own binary — see `cmd/galactic-nat` and `internal/controller/egressshard_controller.go`). `NetworkRule`/this datapath remain ingress-only: external client → VIP → tenant backend.

---

## For Claude

**Where to start for each concern:**

| Concern                                                                              | Start here                                                                                              |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| Node-scoped aggregate reconcile (desired-state assembly, BGP wiring, crash recovery) | `internal/controller/networkgateway_controller.go:Reconcile`                                            |
| Per-object lifecycle (finalizer teardown ordering, `Accepted`-condition maintenance) | `internal/controller/networkrule_controller.go:Reconcile`, `updateAcceptedCondition`, `reconcileDelete` |
| Backend address → SRv6 uSID resolution (with tenant-ownership verification)          | `internal/controller/usidresolver.go:buildBackendSIDIndex`, `resolveUSID`, `verifyTenantOwnership`      |
| Backend selection from `backendSelector` (shared with the binding writer)            | `internal/controller/rulebackends.go:selectRuleBackends`, `ruleBackendOwners`                           |
| Backend-side `ServiceVIPBinding`s, generated per node                                | `internal/controller/networkrule_binding_controller.go` (runs in `galactic-router`)                     |
| SRv6 encap source (configured, or derived from this node's `BGPRouter`)              | `cmd/galactic-gateway/encapsource.go:resolveEncapSource`, `srv6.NodeLocatorAddress`                     |
| Engine convergence loop                                                              | `internal/gateway/engine.go:Reconcile`, `applyRuleLocked`, `removeRuleLocked`                           |
| Real datapath implementation (vip_table read/write, Maglev table construction)       | `internal/gateway/kerneldatapath.go:ApplyRule`, `RemoveRule`, `buildMaglevTable`                        |
| Maglev consistent-hash ring                                                          | `internal/maglev/table.go:New`, `Lookup`, `Backends`                                                    |
| Crash recovery (orphaned vip_table state)                                            | `internal/gateway/recovery.go`, `internal/plumbing/ebpf/edgemap/viptable.go`'s `Generation`/`Reconcile` |
| Quota enforcement                                                                    | `internal/gateway/quota.go:NodeQuotaEnforcer.CheckAndReserve`                                           |
| XDP packet path                                                                      | `internal/plumbing/ebpf/edgeprog/edgedsr.c` (start with its own header comment)                         |
| Datapath load/attach lifecycle                                                       | `internal/plumbing/ebpf/edgeattach/attach.go`, `cmd/galactic-gateway/gateway.go:setupGatewayDatapath`   |
| Sharing the XDP hook with the egress shard                                           | `edgedsr.c`'s `pass_unclaimed_*`, `internal/plumbing/ebpf/xdpdispatch`, `xdpattach/dispatchset.go`      |
| Startup sequencing / gRPC health ordering                                            | `cmd/galactic-gateway/root.go:runCmd`                                                                   |

**Stable vs. frequently changed:**
- Stable: `internal/maglev/table.go` (a settled, well-tested algorithm — Google's published Maglev construction), `internal/plumbing/ebpf/edgemap` (mirrors `usidmap`'s already-settled crash-safety pattern)
- Active: `internal/gateway/quota.go`/`telemetry.go` (real but coarse — see Key Design Decisions; likely to grow richer enforcement)
- Out of scope here, but related and evolving: `galactic-nat`'s sharded stateful egress translation tier (`cmd/galactic-nat`, a separate binary; unlike this gateway, it has no consistent-hash ring for shard selection today — `EgressDefaultRouteAdd` installs only the first resolvable shard SID, every other configured shard sitting as cold standby)

**Non-obvious patterns:**
- `gatewayDatapathKeepAlive` (`cmd/galactic-gateway/gateway.go`) intentionally never calls `Close` on the loaded eBPF objects or the XDP `link.Link` — see that var's doc comment for the live incident this guards against (silent GC-triggered detach with every control-plane signal still looking healthy).
- Every gateway node reconciles every `NetworkGateway`/`NetworkRule` in the namespace — there is no leader election and no per-node filtering predicate on the watch itself; filtering happens inside `Reconcile` (`gw.Spec.TargetRef.Name != r.NodeName` early-return) and via `isGatewayNode`/broadcast watch mappers, not via `SetupWithManager` predicates.
- `BGPAdvertisement` names for gateway-originated routes are node-qualified (`<rule>-<node>-<hash>-v4`/`-v6`, built by `ruleAdvertisementName`) specifically because the anycast model means every gateway node computes the same rule independently — omitting the node qualifier caused two nodes to race to create/update one shared object, which would leave the second node failing with `AlreadyExists` forever and only the first node's route ever advertised. The hash is a 10-hex-character SHA-256 of `<rule>/<node>`. Without it, rule `a-b` on node `c` and rule `a` on node `b-c` shared the name `a-b-c-v4`, so the two nodes overwrote one object and withdrawing either rule deleted the other's route (issue #762). Nothing rebuilds a name to find an advertisement: withdrawal and cleanup select by the `galactic.datum.net/network-rule` label and then check the name. Releases up to v0.5.3 used `<rule>-<node>-v4`/`-v6` and labelled those objects with the rule label alone. `applyBGPAdvertisements` deletes this node's old-named objects once their replacements exist (`pruneRuleAdvertisements`).
- A deleted `NetworkGateway` reconcile can't just call `Engine.Stop()` unconditionally — every gateway node's process reconciles every `NetworkGateway` in the namespace, so a *sibling* node's deletion reaches this reconciler too. `isGatewayNode` re-checks whether *this* node still has its own `NetworkGateway` before stopping the engine (issue #364).
- Advertisement failures during `Reconcile` are collected, not returned immediately — one bad rule's BGP-wiring failure must not stop the rest of the pass, but a node that converged its engine while failing to publish any route must still report `AdvertisementFailed`, not `EngineHealthy` (issue #365) — see `readyConditionFor`.
- `withdrawNodeAdvertisements` selects a node's routes by the `galactic.datum.net/gateway-node` label `applyBGPAdvertisements` sets (and backfills) on every advertisement — the node name, or for a name over a label value's 63 characters a truncated prefix plus a short hash (`gatewayNodeLabelValue`) — then deletes only those named by `ruleAdvertisementName` (or the pre-#762 `<rule>-<node>-v4`/`-v6`) for their `galactic.datum.net/network-rule` label; the anycast model publishes no other per-node route (see the package doc comment in `networkgateway_controller.go`). It never matches by name suffix, which once let removing node `edge-1` withdraw node `east-edge-1`'s routes and CNI-written advertisements ending in `-edge-1-v4` (issue #714). An unlabelled advertisement left by a node that departed before running a release that backfills the label is not withdrawn automatically and needs deleting by hand.
- A deleting `NetworkRule` is not dropped from the engine on the pass that first sees its deletion timestamp. Doing so ran `Datapath.RemoveRule` before `reconcileDelete` had withdrawn the route, breaking the withdraw-first contract on `Datapath.RemoveRule` (issue #715). It drains instead: kept loaded while any labelled advertisement exists, then for `ruleDrainDelay` more.
