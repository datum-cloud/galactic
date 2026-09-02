# Architecture — galactic-gateway

> The edge XDP Maglev/DSR (Direct Server Return) load-balancing gateway
> control plane: a controller-runtime process that loads and attaches an
> anycast consistent-hash L4 load-balancing program to a dedicated gateway
> node's public uplink and drives it from `NetworkGateway`/`NetworkRule`
> CRDs. Every gateway node advertises every VIP identically over the
> existing tenant EVPN mesh — there is no primary/secondary node, no BGP
> local-preference split, and no address rewriting anywhere in the datapath.

_Last updated: 2026-08-17_

This document covers `galactic-gateway` and the `NetworkGateway`/
`NetworkRule` reconcilers only. See
[ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md) for the tenant-BGP core
(`galactic-router`, co-located in the same pod on gateway-role nodes) and
[ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md) for the CNI attach chain that
produces the `BGPAdvertisement`/`BGPRouter` CRDs this binary's own
uSID-resolution code reads. A third, separate `galactic-nat66` binary (out
of this document's scope) provides sharded stateful NAT66 egress for
VPC-attached workloads reaching the internet — see `cmd/galactic-nat66`,
`internal/plumbing/ebpf/nat66prog`, and the `NAT66Shard` reconciler
(`internal/controller/nat66shard_controller.go`, which registers with
`galactic-router`'s manager, not this binary's) rather than this file for
egress. This file,
together with the other two architecture docs, supersedes the former
monolithic `ARCHITECTURE.md` — see [AGENTS.md](../../AGENTS.md) for which
document to start from for a given task.

---

## Overview

`galactic-gateway` gives external clients a stable VIP:port that
load-balances into a tenant VPC's backend Pods, without a VRF or tunnel
dependency and without a per-tenant Geneve device. It is a **separate
binary from `galactic-router`**, deployed as its own single-container,
`hostNetwork: true` DaemonSet on dedicated gateway-role nodes only
(`galactic.datumapis.com/node: edge`), so a crash on either side — tenant
BGP vs. the XDP-holding gateway engine — no longer takes the other down
with it. `galactic-router` used to run as a second container in this same
pod; it's now a fully independent DaemonSet instead, opted in via
`galactic.datumapis.com/galactic: router` on the same `edge` nodes (the
identical flag `compute` nodes use), not co-located here at all. Tenant BGP
itself (the embedded GoBGP server, the
`BGPRouter`/`BGPPeer`/`BGPAdvertisement`/`BGPPolicy`/`BGPVRFInstance`
reconcilers) still runs unmodified in that separate `galactic-router`
pod — see [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md).

The load-balancing design itself is **DSR (Direct Server Return) over a
Maglev consistent-hash ring**, replacing an earlier Full-NAT (DNAT+SNAT)
design entirely — a breaking change with no migration path, not a second
mode alongside the old one. The defining simplification: this datapath does
**no address or port rewriting at all**. A client's packet travels inside
the SRv6 encapsulation byte-for-byte unmodified all the way to the backend;
the backend replies to the client *directly* (bypassing the gateway node on
the return path entirely), which is DSR's whole premise. Every gateway node
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
  Full-NAT needed a flow table to remember which backend/SNAT port a flow
  was assigned; Maglev/DSR re-derives the same answer from the same input
  on every packet.
- No return/decap branch in the XDP program — DSR never sees reply
  traffic through this node at all, so there is nothing to un-DNAT/un-SNAT.
- No L3/L4 checksum touch anywhere in the datapath — the packet's own
  checksum is already correct for its own, completely unmodified content.
- No Active-Active BGP local-preference model, no primary/secondary node
  election, and no per-node self-address to publish — every gateway node's
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

| CRD              | Scope                                                                | Written by                                                                                                                                     | Purpose                                                                                                                                                                                                                                        |
| ---------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NetworkGateway` | Namespaced, one per gateway node (`spec.targetRef.name` = node name) | Operator, once per gateway node (see [worked example](#worked-containerlab-example) below)                                                     | Node-scoped root object, mirroring `BGPRouter`'s pattern. Identifies which nodes participate in the anycast mesh and surfaces each node's engine health via `status.conditions`. Carries **no** self-address field — DSR rewrites nothing, so there is no SNAT source to publish. |
| `NetworkRule`    | Namespaced, tenant-writable                                          | Tenant, via an admission webhook that verifies VPC/VPCAttachment ownership (**webhook not yet deployed in this repo** — see Known Constraints) | Ingress load-balancing spec: `vpcRef`/`vpcAttachmentRef` (opaque tenant identifiers), `vipAddresses` (1–8, IPv4/IPv6), `protocol` (`tcp`/`udp`), `port`, `backends` (1–64 `address:port` pairs). Served by every `NetworkGateway` in the namespace identically — there is **no** `status.primaryNode` field. |

Both are defined in `go.datum.net/network`'s `api/v1alpha1` package
(`gateway_types.go`, `rule_types.go`) — the same external CRD module the
BGP-family types live in. Both types' own doc comments describe this
DSR/anycast model directly (they were rewritten alongside this redesign,
not left describing the old Full-NAT behavior).

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
│   │                        #   recovery — no VRF/Geneve state, no
│   │                        #   primary/secondary placement
│   ├── maglev/               # Pure-Go Maglev consistent-hash lookup table
│   │                        #   (internal/maglev/table.go), shared in spirit
│   │                        #   (not by import) with galactic-nat66's own
│   │                        #   independent shard-placement ring
│   └── plumbing/ebpf/
│       ├── edgeprog/         # Compiled XDP program (edgedsr.c, program
│       │                     #   edge_lb) + bpf2go bindings
│       ├── edgemap/          # vip_table/vip_stats_table/encap_config_table
│       │                     #   read/write API (viptable.go)
│       ├── edgeattach/       # Load + XDP-attach the compiled program to one
│       │                     #   interface
│       ├── edgemetrics/      # Pull-based Prometheus collector reading
│       │                     #   vip_table/vip_stats_table/drop_reasons live
│       └── edgepreflight/    # Startup kernel-capability check for this
│                             #   datapath's own requirement list
├── config/
│   ├── galactic-gateway/
│   │   ├── serviceaccount.yaml  # Applied cluster-wide, idempotent
│   │   ├── rbac.yaml            # Applied cluster-wide, idempotent
│   │   ├── kustomization.yaml   # Covers only the two files above — deliberately
│   │   │                        #   excludes base/, see that dir's own note
│   │   └── base/
│   │       ├── daemonset.yaml   # Two-container pod: galactic-router + galactic-gateway
│   │       └── kustomization.yaml
│   └── fabric-router/        # (not gateway-specific, but fabric-router must also
│                              #   run on gateway-role nodes — see ARCHITECTURE-CNI.md
│                              #   and root CLAUDE.md's config/fabric-router/ note)
├── deploy/containerlab/resources/
│   └── galactic-gateway/   # Worked two-node example — see below
└── containers/
    └── galactic-gateway/    # galactic-gateway production image
```

`config/galactic-gateway/base/` is **not** included in
`config/galactic-gateway/`'s own kustomization and is **not** applied
as-is — the same exemption `config/fabric-router/` documents in root
`CLAUDE.md`, for the same reason: `GALACTIC_GATEWAY_SRV6_ADDRESS` must be
unique per gateway node and has no generic default (see [SRv6 encap-source
address](#srv6-encap-source-address) below). It's designed to be
instantiated once per gateway node by a further overlay that pins it to one
node (`kubernetes.io/hostname`) and sets that node's own
public-interface/SRv6-address values.

### Worked ContainerLab example

`deploy/containerlab/resources/galactic-gateway/` has two gateway
nodes (`iad-gateway1`/`iad-gateway2`) as a canary for this gateway role in
the `iad` cluster. Each node's overlay directory (`iad-gateway1/`,
`iad-gateway2/`) carries:

- `node-patch.yaml` — pins the DaemonSet to one node via
  `kubernetes.io/hostname` and sets `GALACTIC_GATEWAY_PUBLIC_INTERFACE`
  (`eth1` in this lab) and `GALACTIC_GATEWAY_SRV6_ADDRESS` (a distinct uFMT
  48+16 uSID per node).
- `bgprouter.yaml`/`bgppeer.yaml` — this node's tenant `BGPRouter`/`BGPPeer`
  (the separate `galactic-router` DaemonSet's own config, running
  independently on this same node).
- `networkgateway.yaml` — the `NetworkGateway` object itself (just
  `spec.targetRef.name`, see the [samples](#the-two-crds) above).

`iad/kustomization.yaml` additionally carries a `networkrule-ns60.yaml`
sample rule.

---

## Data Flow

See [docs/architecture/](../architecture/) for C4 context/container diagrams covering all three Galactic applications, including how `galactic-gateway` co-locates with `galactic-router` on gateway-role nodes.

### Control-plane reconcile flow (per gateway node, per `NetworkGateway` reconcile)

`NetworkGatewayReconciler.Reconcile` runs the aggregate, List-driven pass
that converges this node's whole gateway engine:

1. **Assemble desired state.** Lists every accepted, non-deleting
   `NetworkRule` in the namespace — under the DSR anycast model every
   gateway node in a PoP serves every accepted rule identically, so there
   is no primary/secondary subset to filter on — resolves each backend's
   SRv6 uSID via `usidresolver.go`'s `buildBackendSIDIndex`, and converges
   `gateway.Engine` toward the result.
2. **Wire BGP.** Reconciles one `BGPAdvertisement` per rule per non-empty
   VIP address family, name-qualified by node (`<rule>-<node>-v4`/`-v6` —
   required, not cosmetic, since every gateway node computes the same rule
   independently). This reuses the existing `l2vpn/evpn` Type-5 IP-Prefix
   advertisement path end-to-end unmodified. `VRFID`/`Function` are left
   unset (these routes need no SRv6 decap behavior of their own — a
   different Route Distinguisher per originating node, not a decap
   Function, is what keeps every node's route alive as an independent,
   non-competing path). **No `LocalPreference` is set** — every gateway
   node's route is equally preferred by construction, unlike the removed
   Full-NAT design's primary/secondary local-pref split.
3. **Crash recovery.** Runs `Engine.ReconcileOrphans` (see
   [Crash recovery](#crash-recovery) below).

`NetworkRuleReconciler.Reconcile` separately owns two **per-object**
lifecycle pieces the aggregate pass above is the wrong place for:
`status.conditions`'s `Accepted` condition (`updateAcceptedCondition` — set
once gateway nodes exist for the namespace; no `primary_node`-style
assignment exists anymore, since DSR has no primary node to assign) and the
finalizer-guarded teardown ordering on deletion (withdraw the rule's
`BGPAdvertisement`s *before* releasing quota/reservation state, so an
in-flight flow is never blackholed through a route that has already
disappeared while the datapath still thinks it owns it).

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

IPv6-only, phase 1 scope (plain TCP/UDP, no extension headers). One XDP
program, one attach point per gateway node — the node's single public/
underlay-facing uplink interface. Unlike the removed Full-NAT `edgenat.c`,
there is no "is this a reply to me" direction check at all — DSR never
sees reply traffic through this node, so the program has exactly one
branch, not two.

1. **Parse** the outer Ethernet + IPv6 header, then the L4 header (TCP or
   UDP only). Not IPv6, unparseable, or not TCP/UDP — `XDP_PASS` (falls
   through to the kernel stack, e.g. BGP/SSH to the node itself). Only the
   source/destination port are ever read; nothing is rewritten, so there is
   no pointer-to-field resolution the way a rewrite would need.
2. **Match** `(proto, dst port, dst addr)` against `vip_table` (keyed
   identically to the removed `rule_table` — a VIP is globally unique by
   construction, no tenant dimension). No match — `XDP_PASS` (not one of
   this gateway's VIPs).
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
   resolved by the Go control plane the same way any other cross-node
   SRv6 destination is — see
   [uSID resolution](#usid-resolution-for-backends) below), sourced from
   this node's own `encap_config_table` entry (this node's plain
   SRv6-reachable address — never a NAT/SNAT source and never compared
   against anything on a receive path, since there is no return path
   through this node at all). Resolve the L2 next-hop via
   `bpf_fib_lookup` and `XDP_TX` back out this same interface. The inner
   packet travels completely unmodified — this is DSR's entire premise:
   no DNAT, no SNAT, no checksum touch anywhere.

See `edgedsr.c`'s own header comment for the full byte-level walkthrough,
including the `EDGE_BARRIER_VAR` eBPF-verifier bounds-narrowing gotcha
carried over unchanged from the removed `edgenat.c`, and two real
wire-format bugs found and fixed in `push_outer_header` (inherited
unchanged from `edgenat.c`, not introduced by this rewrite): the pushed
outer IPv6 header's version nibble was left zeroed instead of set to `6`,
and the outer header's `payload_len` undercounted the inner IPv6 header's
own 40 bytes (a call site passed `ip6->payload_len` directly instead of
`sizeof(ip6hdr) + payload_len`). Both were invisible on the SRv6 uSID
decap path (`usid.c`'s decap reads fixed offsets unconditionally, without
validating either field) but would have caused any version- or
length-validating intermediate hop or receiver to reject every packet this
datapath ever pushed — found via live-kernel investigation, not
`BPF_PROG_TEST_RUN`, and covered by regression tests in `edgedsr_test.go`.

---

## Entry Points

### `cmd/galactic-gateway/main.go` / `root.go` — Gateway daemon

`main.go` holds `checkWatchPermissions` (RBAC pre-flight, mirroring
`cmd/galactic-router/main.go`'s identically-named function, scoped to this
binary's own resource set: `networkgateways`, `networkrules`,
`bgpadvertisements`, and — even though this binary has no BGP client of its
own — `bgprouters`, since `usidresolver.go` reads `BGPRouter` CRDs directly
to resolve backend uSIDs).

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
4. `setupGatewayDatapath` (`cmd/galactic-gateway/gateway.go`) — configure
   the required IPv6-forwarding sysctls on the public interface (see
   [Configuration](#configuration) below), load and attach the XDP program,
   register the Prometheus metrics collector. `PublicInterface`/
   `SRv6Address` are both required, not a jointly-optional pair with a
   `NoopDatapath{}` fallback — the config validator already rejected either
   being empty before `runCmd` was ever reached.
5. Construct real (not stubbed) `gateway.NodeQuotaEnforcer` and
   `gateway.PrometheusTelemetryEmitter`, wire `gateway.NewEngine`.
6. Register `NetworkGatewayReconciler` and `NetworkRuleReconciler`.
7. `mgr.Start(ctx)`.

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
`PublicInterface` itself when the two differ). It then loads
`edgeprog.EdgedsrObjects` (`edgeattach.Load`), attaches it to every
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

| Variable                            | Required | Default | Description                                                                                                                                        |
| ----------------------------------- | -------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GALACTIC_GATEWAY_NODE_NAME`        | Yes      | —       | Kubernetes node name                                                                                                                                |
| `GALACTIC_GATEWAY_PUBLIC_INTERFACE` | Yes      | —       | Public/underlay-facing uplink interface the XDP program attaches to. May name a Linux bonding master (`edgeattach.ResolveTargets` expands it to that bond's slaves — see [Known Constraints](#known-constraints)) |
| `GALACTIC_GATEWAY_SRV6_ADDRESS`     | Yes      | —       | This node's own plain SRv6-reachable IPv6 address, used as the DSR outer-header encap source (`encap_config_table`) — never a NAT/SNAT source and never compared against anything on a receive path; must be a native IPv6 address (rejected if IPv4 or 4-in-6) |
| `GALACTIC_GATEWAY_METRICS_PORT`     | No       | `8081`  | Prometheus metrics port                                                                                                                             |
| `GALACTIC_GATEWAY_GRPC_HEALTH_PORT` | No       | `5181`  | gRPC health check port                                                                                                                              |

All three required fields are enforced by `GatewayConfig.Validate` at
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

| Component           | Metrics | gRPC health |
| -------------------- | ------- | ----------- |
| `galactic-router`   | `9179`  | `5179`      |
| `galactic-gateway`  | `8081`  | `5181`      |

### SRv6 encap-source address

`GALACTIC_GATEWAY_SRV6_ADDRESS` is this gateway node's own plain
SRv6-reachable address, used purely as the source of every outer header
this node's `edge_lb` program pushes — unlike the removed Full-NAT design's
identically-named field, it is never a NAT/SNAT source, never has
return-path significance (DSR has no return path through this node at
all), and is never published to any CRD status (`NetworkGatewayStatus`
carries no self-address field — see [The two CRDs](#the-two-crds) above).
It is operator-supplied per gateway node today, with no in-cluster
mechanism deriving it automatically from a node's own `BGPRouter`
locator/node-ID; see the [worked example](#worked-containerlab-example) for
how a real deployment picks this value.

### Two-container pod (`config/galactic-gateway/base/daemonset.yaml`)

One `ServiceAccount` (`galactic-gateway`) for both containers — a
Kubernetes Pod has exactly one ServiceAccount identity, not a design
choice; its `ClusterRoleBinding`s grant the union of what each container
needs (the trimmed BGP-only `galactic-router` ClusterRole *plus* this
binary's own, see [RBAC](#rbac) below).

| Container          | Capabilities                  | Why                                                                                                                                                                                                                                                                                                                          |
| ------------------ | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic-router`  | `NET_ADMIN`                   | Same as the plain `default`/`rr` roles — no BPF/PERFMON, since gateway-specific eBPF is confined to the other container now                                                                                                                                                                                       |
| `galactic-gateway` | `NET_ADMIN`, `BPF`, `PERFMON` | `BPF` for the `bpf()` syscalls (program/map creation); `PERFMON` because the verifier only allows pointer+scalar arithmetic on packet data/data_end when the loading process is `perfmon_capable()` — without it, even a `root` container gets "pointer arithmetic ... prohibited for !root" |

Both containers mount host paths: `galactic-router` mounts
`/var/run/netns` read-only (GC's netns-liveness check, see
[ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md)); `galactic-gateway`
mounts `/sys/fs/bpf` (must already be a real bpffs — `type: Directory`,
not `DirectoryOrCreate`, so a missing mount fails loudly instead of
silently pinning to a plain directory) for `edgeattach.PinDir`
(`/sys/fs/bpf/galactic-edge`).

### RBAC

`config/galactic-gateway/rbac.yaml`'s `ClusterRole` covers exactly what
`NetworkGatewayReconciler`/`NetworkRuleReconciler` touch:
`networkgateways`/`networkrules` (+ `/status`) read-write,
`bgpadvertisements` full CRUD, `bgprouters` read-only (for
`usidresolver.go` — see above). This was split out of
`config/galactic-router/rbac.yaml`'s single `ClusterRole`, which used to grant one
`galactic-router` identity both the BGP-family CRD verbs and
`networkgateways`/`networkrules` verbs when both reconciler sets lived in
the same binary — every *other* (non-gateway) node's `galactic-router`
ServiceAccount now loses that access entirely, rather than every
`galactic-router` pod in the cluster carrying it as before.

Because one Pod has one ServiceAccount, the `galactic-gateway`
ServiceAccount is bound to *both* this `ClusterRole` and the (trimmed,
BGP-only) `galactic-router` `ClusterRole` from `config/galactic-router/rbac.yaml` —
the smallest deviation from a literal per-container RBAC split Kubernetes
allows. `config/galactic-router/rbac.yaml` must be applied for any gateway node
deployment (a bare `galactic-gateway` container with no co-located
`galactic-router` container advertising the node's tenant BGP session is
not a supported configuration).

---

## Module / Package Reference

| Package                                                 | Binary           | Responsibility                                                                                                                                                                                  | Owns state                           |
| ------------------------------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `internal/config` (`gateway.go`)                        | galactic-gateway | `GatewayConfig`: node name, ports, public interface, SRv6 encap-source address; three-tier CLI/env/default precedence via viper                                                                 | No                                   |
| `internal/controller` (`networkgateway_controller.go`)  | galactic-gateway | `NetworkGatewayReconciler`: desired-state assembly, BGP wiring, orphan-crash recovery                                                                                                            | No                                   |
| `internal/controller` (`networkrule_controller.go`)     | galactic-gateway | `NetworkRuleReconciler`: finalizer-guarded teardown ordering, `Accepted`-condition maintenance (`updateAcceptedCondition`)                                                                       | No                                   |
| `internal/controller` (`usidresolver.go`)               | galactic-gateway | `backendSIDIndex`: resolves a `NetworkRule` backend address to the worker node's SRv6 uSID by matching against `BGPAdvertisement`/`BGPRouter`/`BGPVRFInstance` CRDs, verifying tenant ownership  | No                                   |
| `internal/gateway` (`engine.go`)                        | galactic-gateway | `Engine`: mutex-guarded convergence loop ("apply everything in desired, remove everything not in desired"), mirroring `GoBGPRuntime`'s shape                                                    | Yes (active-rule map)                |
| `internal/gateway` (`types.go`)                         | galactic-gateway | `DesiredRule`/`DesiredBackend`/`EngineState`/`EngineStatus`/`RuleStatus` — the engine's own representation, assembled by the controllers above; `DesiredBackend` implements `internal/maglev.Backend` | No                              |
| `internal/gateway` (`datapath.go`, `kerneldatapath.go`) | galactic-gateway | `Datapath`/`QuotaEnforcer`/`TelemetryEmitter` interfaces; `KernelDatapath`, the real `Datapath` backed by `edgemap.VIPTable` over a loaded `edgeprog.EdgedsrObjects`, building a `internal/maglev.Table` per rule; `NoopDatapath` for tests | Yes (`vipKeysByName` bookkeeping) |
| `internal/gateway` (`quota.go`)                         | galactic-gateway | `NodeQuotaEnforcer` — real, coarse node-level admission caps (max rules/tenant, max total `vip_table` entries); `NoopQuotaEnforcer` for tests                                                    | Yes (in-memory reservation counters) |
| `internal/gateway` (`telemetry.go`)                     | galactic-gateway | `PrometheusTelemetryEmitter` — control-plane-drop counter only (no primary/secondary placement gauge — see Key Design Decisions); `NoopTelemetryEmitter` for tests                               | Yes (Prometheus metric state)        |
| `internal/gateway` (`recovery.go`, `diff.go`)           | galactic-gateway | `Engine.ReconcileOrphans` (crash recovery) and `diffRuleKeys` (the pure key-set diff both `Reconcile`/`ReconcileOrphans` build on)                                                               | No                                   |
| `internal/maglev` (`table.go`)                          | galactic-gateway, galactic-nat66 | Pure-Go Maglev consistent-hash lookup table (`New`/`Lookup`/`Backends`) — one `*Table` built per ring; shared in design, not by import, with `galactic-nat66`'s independent shard-placement ring | No                        |
| `internal/plumbing/ebpf/edgeprog`                       | galactic-gateway | Compiled XDP program (`edgedsr.c`, program `edge_lb`) + bpf2go-generated Go bindings (`EdgedsrObjects`)                                                                                          | No                                   |
| `internal/plumbing/ebpf/edgemap`                        | galactic-gateway | `VIPTable`: `vip_table`/`vip_stats_table` read/write API, `Generation`/`Reconcile` crash-safety mechanism                                                                                        | Yes (via `KernelTable`)              |
| `internal/plumbing/ebpf/edgeattach`                     | galactic-gateway | Load + native-XDP-only attach of the compiled program to one interface                                                                                                                          | Yes (pinned maps, held link)         |
| `internal/plumbing/ebpf/edgemetrics`                    | galactic-gateway | Pull-based `prometheus.Collector` reading `vip_table`/`vip_stats_table`/`drop_reasons` live at every scrape                                                                                      | No                                   |
| `internal/plumbing/ebpf/edgepreflight`                  | galactic-gateway | Startup kernel-capability check (`BPF_PROG_TYPE_XDP`, `BPF_MAP_TYPE_HASH`, kernel BTF, `bpf_xdp_adjust_head`) — no partial pass, no degraded fallback                                            | No                                   |

---

## External Dependencies

| Dependency                            | Version           | Purpose                                                                                                                                                                                                                                                                                             |
| -------------------------------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `github.com/cilium/ebpf`              | v0.22.0           | XDP program load/attach/map bindings (`edgeprog`/`edgemap`/`edgeattach`) — the same library version `internal/plumbing/ebpf` (the CNI chain's TC-BPF uSID datapath, see [ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md)) uses, but a fully separate program/map/attach surface with no shared map layout |
| `go.datum.net/network`                | bumped frequently | `NetworkGateway`/`NetworkRule` CRD API types, plus the BGP-family types this binary reads (`BGPAdvertisement`, `BGPRouter`, `BGPVRFInstance`)                                                                                                                                                       |
| `sigs.k8s.io/controller-runtime`      | v0.24.1           | Full manager + reconciler framework — like `galactic-router`, not a bare client like the CNI chain                                                                                                                                                                                                  |
| `github.com/prometheus/client_golang` | v1.24.1           | `PrometheusTelemetryEmitter`'s control-plane-drop counter, plus `edgemetrics`'s pull-based `vip_table`/`vip_stats_table`/`drop_reasons` collector                                                                                                                                                   |
| `github.com/spf13/cobra`              | v1.10.2           | CLI command/flag handling                                                                                                                                                                                                                                                                            |
| `google.golang.org/grpc`              | v1.83.0           | gRPC health server (default `:5181`)                                                                                                                                                                                                                                                                 |
| `k8s.io/api`, `k8s.io/client-go`      | v0.36.3           | Kubernetes client, `SelfSubjectAccessReview` (RBAC pre-flight)                                                                                                                                                                                                                                       |

---

## Key Design Decisions

- **DSR (Direct Server Return), not Full-NAT.** The datapath does no
  address/port rewriting at all: a client's packet is pushed inside an SRv6
  outer header toward the chosen backend's worker node completely
  unmodified, and the backend replies to the client directly. This is a
  breaking replacement of the earlier Full-NAT (DNAT+SNAT) design, not a
  second mode alongside it — no migration path, per the redesign's
  explicit decision to drop Full-NAT rather than grow a second personality.
  Everything else in this section follows from that one choice.
- **Anycast, not Active-Active BGP local-preference.** Every gateway node
  in a PoP advertises every accepted rule's VIPs at equal BGP preference —
  there is no `AssignPrimaryNode`/`LocalPreference` primitive anywhere in
  this codebase anymore (`internal/gateway/placement.go` and
  `localpref.go`, and their tests, were deleted outright as part of this
  rewrite). A distinct Route Distinguisher per originating node (RFC 4364
  §4.3.2, `internal/runtime/gobgp/paths.go`'s `deriveRD`) is what keeps
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
  `DesiredRule.VPCRef`/`VPCAttachmentRef` are carried through purely for
  telemetry labeling and admission-webhook auditing, never consulted by the
  datapath itself.
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
- **SRv6 encap-source address has no in-cluster derivation mechanism.**
  `GALACTIC_GATEWAY_SRV6_ADDRESS` is operator-supplied per gateway node
  today; nothing in this repo yet computes it automatically from a node's
  own `BGPRouter` locator/node-ID. Unlike the removed Full-NAT design, this
  value is never published to any CRD status — there is no reconcile step
  analogous to the old `publishSelfAddress` at all, since DSR rewrites
  nothing and so has no SNAT source that needs advertising as a
  node-reachability route.
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
  `vip_table`.** The removed Full-NAT predecessor's `rule_table`/
  `rule_stats_table` split already established this convention (issue
  #361: a control-plane `Register` read-modify-write racing the datapath's
  own per-packet increments silently discarded whichever landed second).
  `vip_table`/`vip_stats_table` keep the same split: `Register` is a blind
  overwrite of `vip_table` alone and never touches `vip_stats_table`, which
  `edgedsr.c` alone populates, lazily, on a VIP's first matching packet —
  so re-registering a VIP (e.g. every controller reconcile pass) can never
  race, and therefore never lose, the datapath's own increments.
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

---

## Testing

| Layer           | Command                               | Framework                       | Scope                                                                                                                                                                                                                                                                                                                                    |
| --------------- | -------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unit            | `task test:unit`                      | `go test -race`                 | `internal/config` (`gateway_test.go`), `internal/controller` (`networkgateway_controller_test.go`, `networkrule_controller_test.go`, `usidresolver_test.go`), `internal/gateway` (`engine_test.go`, `diff_test.go`, `kerneldatapath_test.go`, `quota_test.go`, `recovery_test.go`, `telemetry_test.go`), `internal/maglev` (`table_test.go`), `internal/plumbing/bond` (`bond_test.go`, faked `netlink.Link`s, no kernel required — shared bond-master/slave detection used by both this package's `edgeattach.ResolveTargets` and `internal/plumbing/ebpf/attach`'s CNI TC-BPF path), `internal/plumbing/ebpf/edgemap` (`viptable_test.go`, in-memory fake `Table`, no kernel required), `internal/plumbing/ebpf/edgemetrics` (`collector_test.go`), `internal/plumbing/ebpf/edgepreflight` (`preflight_test.go`, `kernel_prober_test.go`); `edgeattach.ResolveTargets` also has its own faked-netlink `TestResolveTargets` (non-bond passthrough, bond-expands-to-slaves-only, no-slaves error) |
| Kernel-required | `task test:unit` (root/CAP_BPF gated) | `go test` + `BPF_PROG_TEST_RUN` | `internal/plumbing/ebpf/edgeprog/edgedsr_test.go` — exercises the compiled program directly, including the version-nibble/payload_len regression tests; `internal/plumbing/ebpf/edgeattach/attach_test.go`                                                                                                                                |
| E2E             | —                                     | —                                | **Not yet covered.** `deploy/containerlab/`'s `iad-gateway1`/`iad-gateway2` nodes are a manifests-and-live-pod canary, not a scripted e2e test — see Known Constraints. No bonded-uplink scenario exists there either, deliberately: `iad-gateway1`/`iad-gateway2`'s uplinks are veth pairs, and (confirmed while adding `TestResolveTargetsAndAttach_RealBondDevice` above) veth slaves accept a native XDP attach on a real bond master directly on at least some kernels, since veth itself supports native XDP and some kernels' bonding driver forwards the attach through to slaves that do — the opposite of the real igb/tg3 failure this whole feature exists for. A containerlab veth-bond scenario would not exercise the bug it would be built to guard against; the root-gated real-bond-device unit test does, without that false sense of coverage. |

---

## CI/CD

**Pipeline:** `.github/workflows/ci.yaml` — see
[ARCHITECTURE-ROUTER.md#cicd](ARCHITECTURE-ROUTER.md#cicd) for the shared
tier structure.

**Publish pipeline:** `.github/workflows/publish.yaml`'s
`publish-galactic-gateway-image` job builds and pushes
`ghcr.io/datum-cloud/galactic-gateway`; `publish-kustomize-bundles` stamps
that tag (alongside the `galactic-router` tag) into `config/galactic-gateway/base`,
since that base's DaemonSet runs both images in one pod.

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

- **No e2e coverage yet.** The gateway canary in `deploy/containerlab/` validates manifests and a live pod/eBPF attach, but predates any live underlay BGP peering that would deliver real traffic through it — see the `gatewayDatapathKeepAlive` incident described in [Entry Points](#cmd-galactic-gatewaygateway-go--datapath-setup) above, which was only discovered because ingress traffic silently stopped being intercepted, not caught by any test.
- **No `NetworkRule` admission webhook is deployed in this repo.** The CRD's own doc comment and `NetworkRuleReconciler`'s doc comment both describe an admission webhook that verifies VPC/VPCAttachment ownership before setting the `Accepted` condition — no `ValidatingWebhookConfiguration` exists in `config/` yet (`config/webhook/` doesn't exist). `updateAcceptedCondition` currently sets `Accepted=True` unconditionally once gateway nodes exist for the namespace, not gated on any ownership check.
- **The uSID backend resolver's tenant-ownership check depends on `BGPVRFInstance` naming staying deterministic.** `verifyTenantOwnership` closes the ambiguous-match gap an earlier version of this resolver had, but it is only as strong as `crdnames.BGPVRFInstanceName(vpc, nodeName)` staying the exact name `galactic-bgp` writes — a divergence between the two would fail closed (a real backend never resolving) rather than open (a wrong-tenant resolve), which is the safer failure direction but still worth knowing about when either side of that naming contract changes.
- **`GALACTIC_GATEWAY_SRV6_ADDRESS` has no in-cluster derivation mechanism.** It is operator-supplied per gateway node today; nothing in this repo yet computes it automatically from a node's own `BGPRouter` locator/node-ID. See [SRv6 encap-source address](#srv6-encap-source-address) above.
- **The uSID TC-BPF/XDP FIB-lookup PMTUD gap applies here too.** When `bpf_fib_lookup()` returns `BPF_FIB_LKUP_RET_FRAG_NEEDED`, `edgedsr.c` counts `DROP_REASON_FIB_FRAG_NEEDED` and drops rather than emitting an ICMPv6 Packet Too Big — the same accepted gap `internal/plumbing/ebpf/prog/usid.c` has for the SRv6 uSID datapath (see [ARCHITECTURE-CNI.md#known-constraints](ARCHITECTURE-CNI.md#known-constraints)), not yet scheduled to be closed on either side.
- **`bpf_fib_lookup()` requires IPv6 forwarding sysctls on the public uplink, not just XDP driver support.** `setupGatewayDatapath` calls `sysctl.ConfigureFIBLookupUplinkSysctls` before attaching the datapath — without `net.ipv6.conf.<iface>.forwarding` and `net.ipv6.conf.all.forwarding` both set, the kernel returns `BPF_FIB_LKUP_RET_NOT_FWDED` for every lookup regardless of anything this program does, which `edgedsr.c`'s own drop-reason accounting cannot distinguish from a generic FIB lookup failure. Found via live-kernel investigation of a pre-existing containerlab veth/XDP_TX blocker: the sysctl gap, not `XDP_TX` itself, was the actual cause. A related, lab-only characteristic the same investigation turned up: native `XDP_TX` on a veth pair only promotes a frame into the peer's normal receive stack (visible to `tcpdump`) if the peer *also* runs an XDP program — otherwise delivery uses a raw fast-path invisible to normal tools. This does not apply to a real physical NIC uplink in production, where there is no "peer's own XDP program" question to begin with.
- **A bonded public uplink attaches per-slave, with per-slave FIB-lookup sysctls to match.** Native-mode XDP against a Linux bonding master is not reliable: confirmed failing outright with "operation not supported" on a real gateway node (802.3ad over an igb/tg3 slave pair). Not every kernel's bonding driver categorically lacks `ndo_bpf` — some do implement it by forwarding the attach to every slave — but that still requires each slave's own driver to support native XDP itself, which not every NIC driver does (tg3 is a commonly cited example that doesn't), so this codebase never relies on attaching to the master working, on any kernel. `edgeattach.ResolveTargets` expands a bonding-master `GALACTIC_GATEWAY_PUBLIC_INTERFACE` to its slave interfaces (never the master itself — see `internal/plumbing/bond`, shared with `internal/plumbing/ebpf/attach`'s TC-BPF path, which attaches to the master *and* its slaves instead), and `setupGatewayDatapath` attaches to and configures FIB-lookup sysctls on every one of them. This is not cosmetic: `edgedsr.c`'s `push_outer_header` calls `bpf_fib_lookup()` with `ctx->ingress_ifindex` — confirmed against the source, not assumed — which for a native XDP program attached to a bond slave is that slave's own ifindex, not the bond master's, so `net.ipv6.conf.<slave>.forwarding` (not `net.ipv6.conf.<bond-master>.forwarding`) is what the kernel actually checks. A bonding master with no resolvable slaves is a hard startup error, not a silent fallback to attaching the master (which would only risk repeating the same failure). `edgeattach.Attach` is all-or-nothing across every resolved slave in one call — if any single slave's driver can't accept a native XDP attach (a real possibility per the tg3 note above, not independently confirmed against that node specifically), the whole datapath startup fails rather than running in a degraded, missing-that-slave's-traffic state; this has not been exercised against real igb/tg3 hardware, only veth in tests, so whether all of a real bonded pair's slaves actually accept native XDP on the affected class of hardware is still open. One further accepted tradeoff: attaching per-slave rather than to the bond as a whole means a slave failing over (LACP renegotiation, a link flap) is not automatically picked up — there is no Watch-style re-resolution here, matching the rest of this package's "resolved once at startup" design (see `edgeattach`'s package doc comment).
- **`vip_table` has no active GC beyond crash-recovery reconcile.** By design (see Key Design Decisions above) — DSR keeps no flow state to leak in the first place, unlike the removed Full-NAT predecessor's `conn_table`, which relied on `BPF_MAP_TYPE_LRU_HASH` self-eviction for the same purpose.
- **Egress is out of this binary's scope, not unimplemented.** An earlier plan (`docs/plans/865-edge-gateway-nat66-egress.md`) proposed adding a second, egress-masquerading XDP personality to this same program and process; that approach was superseded by a separate, sharded stateful NAT66 tier (`galactic-nat66`, its own binary — see `cmd/galactic-nat66` and `internal/controller/nat66shard_controller.go`) rather than built here. `NetworkRule`/this datapath remain ingress-only: external client → VIP → tenant backend.

---

## For Claude

**Where to start for each concern:**

| Concern                                                                                            | Start here                                                                                               |
| --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Node-scoped aggregate reconcile (desired-state assembly, BGP wiring, crash recovery)               | `internal/controller/networkgateway_controller.go:Reconcile`                                             |
| Per-object lifecycle (finalizer teardown ordering, `Accepted`-condition maintenance)                 | `internal/controller/networkrule_controller.go:Reconcile`, `updateAcceptedCondition`, `reconcileDelete`  |
| Backend address → SRv6 uSID resolution (with tenant-ownership verification)                        | `internal/controller/usidresolver.go:buildBackendSIDIndex`, `resolveUSID`, `verifyTenantOwnership`       |
| Engine convergence loop                                                                             | `internal/gateway/engine.go:Reconcile`, `applyRuleLocked`, `removeRuleLocked`                            |
| Real datapath implementation (vip_table read/write, Maglev table construction)                      | `internal/gateway/kerneldatapath.go:ApplyRule`, `RemoveRule`, `buildMaglevTable`                          |
| Maglev consistent-hash ring                                                                          | `internal/maglev/table.go:New`, `Lookup`, `Backends`                                                      |
| Crash recovery (orphaned vip_table state)                                                           | `internal/gateway/recovery.go`, `internal/plumbing/ebpf/edgemap/viptable.go`'s `Generation`/`Reconcile`  |
| Quota enforcement                                                                                    | `internal/gateway/quota.go:NodeQuotaEnforcer.CheckAndReserve`                                             |
| XDP packet path                                                                                      | `internal/plumbing/ebpf/edgeprog/edgedsr.c` (start with its own header comment)                          |
| Datapath load/attach lifecycle                                                                       | `internal/plumbing/ebpf/edgeattach/attach.go`, `cmd/galactic-gateway/gateway.go:setupGatewayDatapath`    |
| Startup sequencing / gRPC health ordering                                                            | `cmd/galactic-gateway/root.go:runCmd`                                                                    |

**Stable vs. frequently changed:**
- Stable: `internal/maglev/table.go` (a settled, well-tested algorithm — Google's published Maglev construction), `internal/plumbing/ebpf/edgemap` (mirrors `usidmap`'s already-settled crash-safety pattern)
- Active: `internal/gateway/quota.go`/`telemetry.go` (real but coarse — see Key Design Decisions; likely to grow richer enforcement)
- Out of scope here, but related and evolving: `galactic-nat66`'s sharded stateful NAT66 egress tier (`cmd/galactic-nat66`, a separate binary, its own Maglev ring built from this same `internal/maglev` package for shard placement rather than backend selection), the `NetworkRule` admission webhook

**Non-obvious patterns:**
- `gatewayDatapathKeepAlive` (`cmd/galactic-gateway/gateway.go`) intentionally never calls `Close` on the loaded eBPF objects or the XDP `link.Link` — see that var's doc comment for the live incident this guards against (silent GC-triggered detach with every control-plane signal still looking healthy).
- Every gateway node reconciles every `NetworkGateway`/`NetworkRule` in the namespace — there is no leader election and no per-node filtering predicate on the watch itself; filtering happens inside `Reconcile` (`gw.Spec.TargetRef.Name != r.NodeName` early-return) and via `isGatewayNode`/broadcast watch mappers, not via `SetupWithManager` predicates.
- `BGPAdvertisement` names for gateway-originated routes are node-qualified (`<rule>-<node>-v4`/`-v6`) specifically because the anycast model means every gateway node computes the same rule independently — omitting the node qualifier caused two nodes to race to create/update one shared object, confirmed live (`AlreadyExists` forever on the second node, only the first node's route ever advertised) under the earlier Full-NAT design and never reintroduced here.
- A deleted `NetworkGateway` reconcile can't just call `Engine.Stop()` unconditionally — every gateway node's process reconciles every `NetworkGateway` in the namespace, so a *sibling* node's deletion reaches this reconciler too. `isGatewayNode` re-checks whether *this* node still has its own `NetworkGateway` before stopping the engine (issue #364).
- Advertisement failures during `Reconcile` are collected, not returned immediately — one bad rule's BGP-wiring failure must not stop the rest of the pass, but a node that converged its engine while failing to publish any route must still report `AdvertisementFailed`, not `EngineHealthy` (issue #365) — see `readyConditionFor`.
- `withdrawNodeAdvertisements` matches only the `-v4`/`-v6` rule-advertisement name suffixes now — an earlier, Full-NAT-era version of this function also withdrew a `-selfaddr` self-address route; DSR's anycast model has no self-address to publish at all, so that name pattern no longer applies (see this file's package doc comment in `networkgateway_controller.go`).
