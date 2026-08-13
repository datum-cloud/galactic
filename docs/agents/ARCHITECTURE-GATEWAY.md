# Architecture — galactic-gateway

> The edge XDP NAT+LB gateway control plane: a controller-runtime process
> that loads and attaches an XDP Full-NAT (DNAT+SNAT) load-balancing
> program to a dedicated gateway node's public uplink and drives it from
> `NetworkGateway`/`NetworkRule` CRDs, publishing an Active-Active BGP
> local-preference model over the existing tenant EVPN mesh.

_Last updated: 2026-08-13_

This document covers `galactic-gateway` and the `NetworkGateway`/
`NetworkRule` reconcilers only. See
[ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md) for the tenant-BGP core
(`galactic-router`, co-located in the same pod on gateway-role nodes) and
[ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md) for the CNI attach chain that
produces the `BGPAdvertisement`/`BGPRouter` CRDs this binary's own
uSID-resolution code reads. This file, together with those two, supersedes
the former monolithic `ARCHITECTURE.md` — see [AGENTS.md](../../AGENTS.md)
for which document to start from for a given task.

---

## Overview

`galactic-gateway` gives external clients a stable VIP:port that
load-balances into a tenant VPC's backend Pods, without a VRF or tunnel
dependency and without a per-tenant Geneve device. It is a **separate
binary from `galactic-router`**, deployed as a second container in the same
`hostNetwork: true` pod on dedicated gateway-role nodes only
(`galactic.datumapis.com/node: gateway`), specifically so a crash on either
side — tenant BGP vs. the XDP-holding gateway engine — no longer takes the
other down with it. Tenant BGP itself (the embedded GoBGP server, the
`BGPRouter`/`BGPPeer`/`BGPAdvertisement`/`BGPPolicy`/`BGPVRFInstance`
reconcilers) still runs in the co-located `galactic-router` container,
unmodified — see [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md).

This design is a deliberate pivot away from an earlier, rejected approach
(internally called `gwprog`) that tunneled tenant traffic to gateway nodes
over Geneve and drove a TC-BPF program keyed by `(VNI, 5-tuple)`. That
design was abandoned after live testing ruled out driving LoxiLB directly
and found native XDP unavailable specifically on Geneve tunnel devices. The
current design instead attaches XDP directly to the gateway node's public
interface: no tunnel, no per-tenant Geneve provisioning, and — because the
outer SRv6 header is pushed straight from the program's own `rule_table`
rather than a kernel VRF route — no VRF dependency and no exposure to the
GoBGP bugs that forced every earlier per-VPC gateway design to colocate
with the workload's own VRF.

### The two CRDs

| CRD              | Scope                                                                | Written by                                                                                                                                     | Purpose                                                                                                                                                                                                                                                      |
| ---------------- | -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `NetworkGateway` | Namespaced, one per gateway node (`spec.targetRef.name` = node name) | Operator, once per gateway node (see [worked example](#worked-containerlab-example) below)                                                     | Node-scoped root object, mirroring `BGPRouter`'s pattern. `status.sRv6Address` is this node's Full-NAT SNAT source, published by `NetworkGatewayReconciler`.                                                                                                 |
| `NetworkRule`    | Namespaced, tenant-writable                                          | Tenant, via an admission webhook that verifies VPC/VPCAttachment ownership (**webhook not yet deployed in this repo** — see Known Constraints) | Ingress load-balancing spec: `vpcRef`/`vpcAttachmentRef` (opaque tenant identifiers), `vipAddresses` (1–8, IPv4/IPv6), `protocol` (`tcp`/`udp`), `port`, `backends` (1–64 `address:port` pairs). `status.primaryNode` is assigned exactly once, at creation. |

Both are defined in `go.datum.net/network`'s `api/v1alpha1` package
(`gateway_types.go`, `rule_types.go`) — the same external CRD module the
BGP-family types live in.

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
│   │                        #   node name, ports, public interface, SRv6 address
│   ├── gateway/              # Engine, Datapath/QuotaEnforcer/TelemetryEmitter
│   │                        #   interfaces + real implementations, Active-Active
│   │                        #   placement/local-pref, crash recovery
│   └── plumbing/ebpf/
│       ├── edgeprog/         # Compiled XDP program (edgenat.c) + bpf2go bindings
│       ├── edgemap/          # rule_table/gw_config_table read/write API
│       └── edgeattach/       # Load + XDP-attach the compiled program to one interface
├── config/
│   ├── gateway/
│   │   ├── serviceaccount.yaml  # Applied cluster-wide, idempotent
│   │   ├── rbac.yaml            # Applied cluster-wide, idempotent
│   │   ├── kustomization.yaml   # Covers only the two files above — deliberately
│   │   │                        #   excludes base/, see that dir's own note
│   │   └── base/
│   │       ├── daemonset.yaml   # Two-container pod: galactic-router + galactic-gateway
│   │       └── kustomization.yaml
│   └── fabric/               # (not gateway-specific, but fabric-router must also
│                              #   run on gateway-role nodes — see ARCHITECTURE-CNI.md
│                              #   and root CLAUDE.md's config/fabric/ note)
├── deploy/containerlab/resources/
│   └── galactic-gateway/   # Worked two-node example — see below
└── containers/
    └── galactic-gateway/    # galactic-gateway production image
```

`config/gateway/base/` is **not** included in `config/gateway/`'s own
kustomization and is **not** applied as-is — the same exemption
`config/fabric/` documents in root `AGENTS.md`, for the same reason:
`GALACTIC_GATEWAY_SRV6_ADDRESS` must be unique per gateway node and has no
generic default (see [publishSelfAddress](#status-and-self-address-publish)
below). It's designed to be instantiated once per gateway node by a further
overlay that pins it to one node (`kubernetes.io/hostname`) and sets that
node's own public-interface/SRv6-address values.

### Worked ContainerLab example

`deploy/containerlab/resources/galactic-gateway/` has two gateway
nodes (`iad-gateway1`/`iad-gateway2`) as a canary for this gateway role in
the `iad` cluster. Each node's overlay directory (`iad-gateway1/`,
`iad-gateway2/`) carries:

- `node-patch.yaml` — pins the DaemonSet to one node via
  `kubernetes.io/hostname` and sets `GALACTIC_GATEWAY_PUBLIC_INTERFACE`
  (`eth1` in this lab) and `GALACTIC_GATEWAY_SRV6_ADDRESS` (a distinct uFMT
  48+16 uSID per node, computed at Argument 0 — see
  [Argument-0 reservation](#argument-0-reservation) below).
- `bgprouter.yaml`/`bgppeer.yaml` — this node's tenant `BGPRouter`/`BGPPeer`
  (the co-located `galactic-router` container's own config).
- `networkgateway.yaml` — the `NetworkGateway` object itself (just
  `spec.targetRef.name`, see the [samples](#the-two-crds) above).

`iad/kustomization.yaml` additionally carries a `networkrule-ns60.yaml`
sample rule.

---

## Data Flow

### Control-plane reconcile flow (per gateway node, per `NetworkGateway` reconcile)

`NetworkGatewayReconciler.Reconcile` runs the aggregate, List-driven pass
that converges this node's whole gateway engine:

1. **Publish self-address.** `publishSelfAddress` writes `status.sRv6Address`
   (operator-supplied via `GALACTIC_GATEWAY_SRV6_ADDRESS`, already the value
   the running datapath was configured with at startup) and ensures a
   `/128` `l2vpn/evpn` `BGPAdvertisement` exists distributing it — a plain
   node-reachability route, no VRFID/Function.
2. **Assemble desired state.** Lists every accepted, non-deleting
   `NetworkRule` in the namespace (both primary- and secondary-assigned —
   Active-Active means every gateway node serves every rule), resolves each
   backend's SRv6 uSID via `usidresolver.go`'s `buildBackendSIDIndex`, and
   converges `gateway.Engine` toward the result.
3. **Wire BGP.** Reconciles one `BGPAdvertisement` per rule per non-empty
   VIP address family, name-qualified by node (`<rule>-<node>-v4`/`-v6` —
   required, not cosmetic, since every gateway node computes the same rule
   independently), with `Spec.LocalPreference` from
   `gateway.LocalPreference`. This reuses the existing `l2vpn/evpn` Type-5
   IP-Prefix advertisement path end-to-end unmodified — no changes were
   needed in `internal/reconcile` or `internal/runtime/gobgp` to support it.
4. **Crash recovery.** Runs `Engine.ReconcileOrphans` (see
   [Crash recovery](#crash-recovery) below).

`NetworkRuleReconciler.Reconcile` separately owns two **per-object**
lifecycle pieces the aggregate pass above is the wrong place for:
`status.primaryNode` assignment (exactly once, at creation — see
[Placement](#placement-and-local-preference) below) and the finalizer-guarded
teardown ordering on deletion (withdraw the rule's `BGPAdvertisement`s
*before* releasing NAT/conntrack state, so an in-flight flow is never
blackholed through a translation whose route has already disappeared).

Every gateway node's own process runs both reconcilers, unconditionally, on
every `NetworkGateway`/`NetworkRule` in the namespace, with no leader
election anywhere in this codebase — safe because the reconcile logic is
either idempotent (finalizer add/remove, `BGPAdvertisement` create/delete)
or a pure function of inputs every gateway node observes identically
(`AssignPrimaryNode`, `LocalPreference`). A rule carries no
`gatewayRef`, so both reconcilers watch the *other* CRD type and broadcast
to every object in the namespace on change (`ruleToGatewayRequests`,
`gatewayToRuleRequests`) rather than targeting a specific object.

### Packet path (`internal/plumbing/ebpf/edgeprog/edgenat.c`)

IPv6-only, phase 1 scope (plain TCP/UDP, no extension headers). One XDP
program, one attach point per gateway node — the node's single public/
underlay-facing uplink interface. Direction is decided by matching the
packet's outer IPv6 destination against this node's own configured
`gw_addr` (`gw_config_table`), the same "is this mine" pattern
`internal/plumbing/ebpf/prog/usid.c` uses for the SRv6 uSID datapath (see
[ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md)), just against a single address
instead of a locator/function/argument hierarchy.

1. **Parse** the outer Ethernet + IPv6 header. Not IPv6, or unparseable —
   `XDP_PASS` (falls through to the kernel stack, e.g. BGP/SSH to the node
   itself).
2. **Return branch** (`daddr == gw_addr`, outer `nexthdr == 41`, plain
   IPv6-in-IPv6, no SRH): this is a reply this node SNAT'd on the way out.
   Strip the outer header, look up `conn_table` by the revealed inner
   packet's reverse 5-tuple, un-SNAT/un-DNAT back to the client's original
   view, fix the L4 checksum via `bpf_csum_diff` (XDP has no
   `__sk_buff`-based checksum helpers), resolve the L2 next-hop via
   `bpf_fib_lookup`, `XDP_TX`. No `conn_table` hit — drop, not pass-through
   (this address is claimed).
3. **Forward branch** (everything else, TCP/UDP only — anything else
   `XDP_PASS`): match `(proto, dst port, dst addr)` against `rule_table`
   (keyed by VIP+port only, no tenant dimension — a VIP is globally unique
   by construction). No match — `XDP_PASS`. A `conn_table` hit on the
   forward key reuses the already-assigned backend/SNAT port (a flow's
   translation never changes mid-connection even if the rule's backend list
   changes later). A miss on a TCP SYN or any UDP packet allocates: pick a
   backend by `hash(client_addr,client_port) % backend_count`, claim a SNAT
   port by probing candidate ports and inserting the *reverse* `conn_table`
   row with `BPF_NOEXIST` (the atomic claim and the sole liveness/reuse
   mechanism — `conn_table` is `BPF_MAP_TYPE_LRU_HASH`, self-evicting, no
   separate GC). DNAT to the backend, SNAT to `gw_addr:allocated-port`, fix
   the checksum, push a fresh 40-byte outer IPv6 header addressed to the
   backend's own worker-node SRv6 uSID (`rule_table`'s per-backend field,
   resolved by the Go control plane — see
   [uSID resolution](#usid-resolution-for-backends) below), resolve the L2
   next-hop, `XDP_TX`.

See `edgenat.c`'s own header comment for the full byte-level walkthrough,
including the `EDGE_BARRIER_VAR` eBPF-verifier bounds-narrowing gotcha
carried over from `gwprog`.

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
   the rule table reachable (see [#360](#known-constraints) below for why
   this ordering was fixed deliberately).
3. RBAC pre-flight (`checkWatchPermissions`).
4. `setupGatewayDatapath` (`cmd/galactic-gateway/gateway.go`) — load and
   attach the XDP program, register the Prometheus metrics collector.
   Unlike the pre-split `cmd/galactic-router`'s identically-named function
   (now removed), `PublicInterface`/`SRv6Address` are both required, not a
   jointly-optional pair with a `NoopDatapath{}` fallback — the config
   validator already rejected either being empty before `runCmd` was ever
   reached.
5. Construct real (not stubbed) `gateway.NodeQuotaEnforcer` and
   `gateway.PrometheusTelemetryEmitter`, wire `gateway.NewEngine`.
6. Register `NetworkGatewayReconciler` and `NetworkRuleReconciler`.
7. `mgr.Start(ctx)`.

### `cmd/galactic-gateway/gateway.go` — datapath setup

`setupGatewayDatapath` loads `edgeprog.EdgenatObjects`
(`edgeattach.Load`), attaches it to `PublicInterface`
(`edgeattach.Attach` — native XDP driver mode only, no generic/SKB-mode
fallback), and constructs a `gateway.KernelDatapath` over it.

The loaded objects and the returned `link.Link` are stashed in a
package-level `gatewayDatapathKeepAlive` var rather than ever being
`Close`d — see that var's doc comment for a concrete, previously-live
incident: `cilium/ebpf`'s program/map/link types register a runtime
finalizer that silently closes the underlying fd once nothing reachable
points at it, and the first time this path ran against a real interface
with nothing pinning `objs`/the link, the XDP attachment was silently GC'd
and detached mid-run — every control-plane signal (pod healthy, `ApplyRule`
succeeding, `rule_table` metrics populated) still looked completely normal
while ingress traffic quietly stopped being intercepted at all.

---

## Configuration

### GatewayConfig environment variables (`internal/config/gateway.go`)

| Variable                            | Required | Default | Description                                                                                                                               |
| ----------------------------------- | -------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `GALACTIC_GATEWAY_NODE_NAME`        | Yes      | —       | Kubernetes node name                                                                                                                      |
| `GALACTIC_GATEWAY_PUBLIC_INTERFACE` | Yes      | —       | Public/underlay-facing uplink interface the XDP program attaches to                                                                       |
| `GALACTIC_GATEWAY_SRV6_ADDRESS`     | Yes      | —       | This node's own SRv6-reachable IPv6 address, used as the Full-NAT SNAT source; must be a native IPv6 address (rejected if IPv4 or 4-in-6) |
| `GALACTIC_GATEWAY_METRICS_PORT`     | No       | `8081`  | Prometheus metrics port                                                                                                                   |
| `GALACTIC_GATEWAY_GRPC_HEALTH_PORT` | No       | `5181`  | gRPC health check port                                                                                                                    |

All three required fields are enforced by `GatewayConfig.Validate` at
startup, not deferred to a later, less obvious kernel-datapath error — a
node deployed without them crash-loops immediately rather than running
degraded.

The metrics/gRPC-health port defaults (`8081`/`5181`) deliberately differ
from every other `galactic-*` process's own defaults
(`galactic-router`'s `8080`/`5000`, overridden to `5179` on gateway nodes;
`galactic-cni`'s credential-refresh health port `5180`) because
`galactic-gateway` runs as a second container in the same
`hostNetwork: true` pod as `galactic-router` — every port it binds shares
that node's network namespace with every other `galactic-*` process already
running there and must not collide with any of them. See the two-container
pod's port table:

| Container                                      | Metrics | gRPC health |
| ---------------------------------------------- | ------- | ----------- |
| `galactic-router` (this pod's tenant-BGP side) | `8080`  | `5179`      |
| `galactic-gateway`                             | `8081`  | `5181`      |

### Two-container pod (`config/gateway/base/daemonset.yaml`)

One `ServiceAccount` (`galactic-gateway`) for both containers — a
Kubernetes Pod has exactly one ServiceAccount identity, not a design
choice; its `ClusterRoleBinding`s grant the union of what each container
needs (the trimmed BGP-only `galactic-router` ClusterRole *plus* this
binary's own, see [RBAC](#rbac) below).

| Container          | Capabilities                  | Why                                                                                                                                                                                                                                                                                                                          |
| ------------------ | ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic-router`  | `NET_ADMIN`                   | Same as the plain `tenant`/`tenant-control` roles — no BPF/PERFMON, since gateway-specific eBPF is confined to the other container now                                                                                                                                                                                       |
| `galactic-gateway` | `NET_ADMIN`, `BPF`, `PERFMON` | `BPF` for the `bpf()` syscalls (program/map creation); `PERFMON` because the verifier only allows pointer+scalar arithmetic on packet data/data_end (the DNAT/SNAT header rewrites) when the loading process is `perfmon_capable()` — without it, even a `root` container gets "pointer arithmetic ... prohibited for !root" |

Both containers mount host paths: `galactic-router` mounts
`/var/run/netns` read-only (GC's netns-liveness check, see
[ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md)); `galactic-gateway`
mounts `/sys/fs/bpf` (must already be a real bpffs — `type: Directory`,
not `DirectoryOrCreate`, so a missing mount fails loudly instead of
silently pinning to a plain directory) for `edgeattach.PinDir`
(`/sys/fs/bpf/galactic-edge`).

### RBAC

`config/gateway/rbac.yaml`'s `ClusterRole` covers exactly what
`NetworkGatewayReconciler`/`NetworkRuleReconciler` touch:
`networkgateways`/`networkrules` (+ `/status`) read-write,
`bgpadvertisements` full CRUD, `bgprouters` read-only (for
`usidresolver.go` — see above). This was split out of
`config/router/rbac.yaml`'s single `ClusterRole`, which used to grant one
`galactic-router` identity both the BGP-family CRD verbs and
`networkgateways`/`networkrules` verbs when both reconciler sets lived in
the same binary — every *other* (non-gateway) node's `galactic-router`
ServiceAccount now loses that access entirely, rather than every
`galactic-router` pod in the cluster carrying it as before.

Because one Pod has one ServiceAccount, the `galactic-gateway`
ServiceAccount is bound to *both* this `ClusterRole` and the (trimmed,
BGP-only) `galactic-router` `ClusterRole` from `config/router/rbac.yaml` —
the smallest deviation from a literal per-container RBAC split Kubernetes
allows. `config/router/rbac.yaml` must be applied for any gateway node
deployment (a bare `galactic-gateway` container with no co-located
`galactic-router` container advertising the node's tenant BGP session is
not a supported configuration).

---

## Module / Package Reference

| Package                                                 | Binary           | Responsibility                                                                                                                                                                                  | Owns state                           |
| ------------------------------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `internal/config` (`gateway.go`)                        | galactic-gateway | `GatewayConfig`: node name, ports, public interface, SRv6 address; three-tier CLI/env/default precedence via viper                                                                              | No                                   |
| `internal/controller` (`networkgateway_controller.go`)  | galactic-gateway | `NetworkGatewayReconciler`: self-address publish, desired-state assembly, BGP wiring, orphan-crash recovery                                                                                     | No                                   |
| `internal/controller` (`networkrule_controller.go`)     | galactic-gateway | `NetworkRuleReconciler`: finalizer-guarded teardown ordering, one-time `primary_node` assignment                                                                                                | No                                   |
| `internal/controller` (`usidresolver.go`)               | galactic-gateway | `backendSIDIndex`: resolves a `NetworkRule` backend address to the worker node's SRv6 uSID by matching against `BGPAdvertisement`/`BGPRouter` CRDs                                              | No                                   |
| `internal/gateway` (`engine.go`)                        | galactic-gateway | `Engine`: mutex-guarded convergence loop ("apply everything in desired, remove everything not in desired"), mirroring `GoBGPRuntime`'s shape                                                    | Yes (active-rule map)                |
| `internal/gateway` (`types.go`)                         | galactic-gateway | `DesiredRule`/`DesiredBackend`/`EngineState`/`EngineStatus`/`RuleStatus` — the engine's own representation, assembled by the controllers above                                                  | No                                   |
| `internal/gateway` (`datapath.go`, `kerneldatapath.go`) | galactic-gateway | `Datapath`/`QuotaEnforcer`/`TelemetryEmitter` interfaces; `KernelDatapath`, the real `Datapath` backed by `edgemap.RuleTable` over a loaded `edgeprog.EdgenatObjects`; `NoopDatapath` for tests | Yes (`ruleKeysByName` bookkeeping)   |
| `internal/gateway` (`quota.go`)                         | galactic-gateway | `NodeQuotaEnforcer` — real, coarse node-level admission caps (max rules/tenant, max total `rule_table` entries); `NoopQuotaEnforcer` for tests                                                  | Yes (in-memory reservation counters) |
| `internal/gateway` (`telemetry.go`)                     | galactic-gateway | `PrometheusTelemetryEmitter` — primary/secondary placement gauge + control-plane-drop counter; `NoopTelemetryEmitter` for tests                                                                 | Yes (Prometheus metric state)        |
| `internal/gateway` (`placement.go`, `localpref.go`)     | galactic-gateway | `AssignPrimaryNode` (`hash(vpcRef) % gateway-node-count`), `LocalPreference` (pure lookup) — the Active-Active BGP model's primitives                                                           | No                                   |
| `internal/gateway` (`recovery.go`, `diff.go`)           | galactic-gateway | `Engine.ReconcileOrphans` (crash recovery) and `diffRuleKeys` (the pure key-set diff both `Reconcile`/`ReconcileOrphans` build on)                                                              | No                                   |
| `internal/plumbing/ebpf/edgeprog`                       | galactic-gateway | Compiled XDP program (`edgenat.c`) + bpf2go-generated Go bindings (`EdgenatObjects`)                                                                                                            | No                                   |
| `internal/plumbing/ebpf/edgemap`                        | galactic-gateway | `RuleTable`: `rule_table`/`gw_config_table` read/write API, `Generation`/`Reconcile` crash-safety mechanism                                                                                     | Yes (via `KernelTable`)              |
| `internal/plumbing/ebpf/edgeattach`                     | galactic-gateway | Load + native-XDP-only attach of the compiled program to one interface                                                                                                                          | Yes (pinned maps, held link)         |

---

## External Dependencies

| Dependency                            | Version           | Purpose                                                                                                                                                                                                                                                                                             |
| ------------------------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `github.com/cilium/ebpf`              | v0.22.0           | XDP program load/attach/map bindings (`edgeprog`/`edgemap`/`edgeattach`) — the same library version `internal/plumbing/ebpf` (the CNI chain's TC-BPF uSID datapath, see [ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md)) uses, but a fully separate program/map/attach surface with no shared map layout |
| `go.datum.net/network`                | bumped frequently | `NetworkGateway`/`NetworkRule` CRD API types, plus the BGP-family types this binary reads (`BGPAdvertisement`, `BGPRouter`)                                                                                                                                                                         |
| `sigs.k8s.io/controller-runtime`      | v0.24.1           | Full manager + reconciler framework — like `galactic-router`, not a bare client like the CNI chain                                                                                                                                                                                                  |
| `github.com/prometheus/client_golang` | v1.24.1           | `PrometheusTelemetryEmitter`'s gauge/counter metrics, plus `edgemetrics`'s pull-based `rule_table`/`conn_table`/`drop_reasons` collector                                                                                                                                                            |
| `github.com/spf13/cobra`              | v1.10.2           | CLI command/flag handling                                                                                                                                                                                                                                                                           |
| `google.golang.org/grpc`              | v1.82.0           | gRPC health server (default `:5181`)                                                                                                                                                                                                                                                                |
| `k8s.io/api`, `k8s.io/client-go`      | v0.36.0           | Kubernetes client, `SelfSubjectAccessReview` (RBAC pre-flight)                                                                                                                                                                                                                                      |

---

## Key Design Decisions

- **No VRF/Geneve dependency.** The outer SRv6 header is pushed straight from `rule_table` (resolved via `edgemap`) rather than a kernel VRF route, so this datapath has no VRF dependency and no exposure to the GoBGP EVPN-decode bugs that forced every earlier per-VPC gateway design to colocate with the workload's own VRF. `Engine`/`KernelDatapath` hold no VRF/Geneve state at all — no `vrfLinkNames` map, no `SetVRFLink` method, unlike the rejected `gwprog` predecessor.
- **Active-Active BGP model, not active-passive failover.** Both gateway nodes in a PoP always advertise every rule they hold; `AssignPrimaryNode` (`hash(vpcRef) % gateway-node-count`, sorted node list for determinism) only decides which node advertises at the higher local-preference (`PrimaryLocalPref = 100` vs. `SecondaryLocalPref = 50`). Failover is ordinary BGP reconvergence, not a controller-driven health check — the secondary path is always live, just less preferred.
- **`primary_node` is assigned exactly once, never recomputed.** `NetworkRuleReconciler.assignPrimaryNode` explicitly skips re-assignment once `status.primaryNode` is set. Recomputing it on a later reconcile (e.g. after a gateway node is added/removed) would generally produce a different assignment for the same `vpcRef` and flip which node is primary for a live VIP — an avoidable traffic flap.
- **No tenant dimension in the datapath.** `rule_table` is keyed by `(proto, VIP port, VIP address)` only — a VIP is globally unique by construction, so no tenant/VPC field is needed to disambiguate ingress traffic. `DesiredRule.VPCRef`/`VPCAttachmentRef` are carried through purely for telemetry labeling and admission-webhook auditing, never consulted by the datapath itself.
- **uSID resolution for backends.** There is no exported "IP → uSID" query anywhere else in this codebase (`internal/runtime/gobgp/monitor.go` decodes EVPN Prefix-SID attributes purely internally, for local kernel route installation only). `usidresolver.go`'s `backendSIDIndex` mirrors `internal/reconcile/reconcile.go`'s `resolveSRv6SID` instead of embedding a second GoBGP speaker: list `BGPRouter`/`BGPAdvertisement` CRDs once per reconcile, match a backend's address against advertised prefixes, combine the matching advertisement's VRFID/Function with its router's SRv6Locator/NodeID via `srv6.ComputeSID`. **Known limitation:** matching is by address containment only, with no tenant-identity check (`BGPAdvertisement` carries no VPCRef/VPCAttachmentRef to disambiguate against) — two tenants advertising overlapping private address space would resolve ambiguously. A pre-existing gap in the address model, not introduced by this resolver, and out of scope to close here.
- **Argument-0 reservation.** A gateway node's own `SRv6Address` is a uFMT 48+16 uSID at the reserved Argument value `0` (`uformat.go`'s `ArgumentMin`) — reserved specifically so it is never registered into any tenant's `vrf_table`. `srv6.ComputeSID` unconditionally rejects `argument==0` (that guard exists for tenant-VRF SID derivation, where 0 must never be assigned), so deriving this value needs a second, narrower encode path bypassing that guard — genuinely new work this phase does not build. Today `SRv6Address` is supplied via operator config (`GALACTIC_GATEWAY_SRV6_ADDRESS`) instead of computed in-cluster; `publishSelfAddress`'s only job is to publish that already-authoritative value into the CRD and into BGP, so there is exactly one source of truth rather than two that could drift. See the [worked example](#worked-containerlab-example) for how a real deployment picks this value today.
- **Quota/telemetry are real but deliberately coarse.** `NodeQuotaEnforcer` enforces two node-level admission caps entirely from control-plane state already held by `Engine` (no eBPF map read required): max `NetworkRule`s per tenant, and total `rule_table` rows across every tenant vs. the map's fixed capacity. It deliberately does **not** do per-flow/conntrack rate limiting — `conn_table`'s key carries no tenant dimension (by design, see above), and a meaningful bandwidth/packet-rate quota needs a time-windowed rate rather than `rule_table`'s cumulative, never-reset packet/byte counters. Real rate-based enforcement needs live traffic data this repo does not have yet. `PrometheusTelemetryEmitter` similarly covers only what `Engine`'s own call sites uniquely know (primary/secondary placement, control-plane-level rejections before a rule ever reaches the datapath) — `rule_table`/`conn_table`'s own per-packet counters are exposed separately by `edgemetrics`'s pull-based collector.
- **Generation-based crash recovery, not a Geneve-interface scan.** `Engine.ReconcileOrphans` delegates to `edgemap.RuleTable.Reconcile`'s `Generation`-cutoff mechanism: a caller must capture `Engine.DatapathGeneration()` *before* listing the `NetworkRule` CRDs that become the live set, so a rule created between the snapshot and the list is never mistaken for an orphan. `rule_table` state (not a kernel interface) is the only thing this design can leak on a crash — unlike the rejected Geneve-based predecessor, which had to scan interfaces.
- **Native XDP only, no generic-mode fallback.** `edgeattach.Attach` always requests `link.XDPDriverMode` and errors rather than silently retrying in `link.XDPGenericMode` (SKB mode) if the interface's driver doesn't support it — accepting generic mode silently would defeat the reason this design chose XDP over TC-BPF in the first place.
- **`galactic-router` carries no gateway-role code anymore.** Splitting the edge gateway out of `galactic-router` into its own binary means a crash in the XDP-loading, BPF/PERFMON-capable container never takes down the tenant BGP session on the same node, and vice versa. See [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md) for what's left in that binary.

---

## Testing

| Layer           | Command                               | Framework                       | Scope                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| --------------- | ------------------------------------- | ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unit            | `task test:unit`                      | `go test -race`                 | `internal/config` (`gateway_test.go`), `internal/controller` (`networkgateway_controller_test.go`, `networkrule_controller_test.go`, `usidresolver_test.go`), `internal/gateway` (`engine_test.go`, `diff_test.go`, `kerneldatapath_test.go`, `localpref_test.go`, `placement_test.go`, `quota_test.go`, `recovery_test.go`, `telemetry_test.go`), `internal/plumbing/ebpf/edgemap` (`ruletable_test.go`, in-memory fake `Table`, no kernel required) |
| Kernel-required | `task test:unit` (root/CAP_BPF gated) | `go test` + `BPF_PROG_TEST_RUN` | `internal/plumbing/ebpf/edgeprog/edgenat_test.go` — exercises the compiled program directly; `internal/plumbing/ebpf/edgeattach/attach_test.go`                                                                                                                                                                                                                                                                                                       |
| E2E             | —                                     | —                               | **Not yet covered.** `deploy/containerlab/`'s `iad-gateway1`/`iad-gateway2` nodes are a manifests-and-live-pod canary, not a scripted e2e test — see Known Constraints.                                                                                                                                                                                                                                                                               |

---

## CI/CD

**Pipeline:** `.github/workflows/ci.yaml` — see
[ARCHITECTURE-ROUTER.md#cicd](ARCHITECTURE-ROUTER.md#cicd) for the shared
tier structure.

**Publish pipeline:** `.github/workflows/publish.yaml`'s
`publish-galactic-gateway-image` job builds and pushes
`ghcr.io/datum-cloud/galactic-gateway`; `publish-kustomize-bundles` stamps
that tag (alongside the `galactic-router` tag) into `config/gateway/base`,
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

- **No e2e coverage yet.** The gateway canary in `deploy/containerlab/` validates manifests and a live pod/eBPF attach, but predates any live underlay BGP peering that would deliver real traffic through it — see the `gatewayDatapathKeepAlive` incident described in [Entry Points](#cmd-galactic-gateway-gateway-go--datapath-setup) above, which was only discovered because ingress traffic silently stopped being intercepted, not caught by any test.
- **No `NetworkRule` admission webhook is deployed in this repo.** The CRD's own doc comment and `NetworkRuleReconciler`'s doc comment both describe an admission webhook that verifies VPC/VPCAttachment ownership before setting the `Accepted` condition — no `ValidatingWebhookConfiguration` exists in `config/` yet (`config/webhook/` doesn't exist). `assignPrimaryNode` currently sets `Accepted=True` unconditionally once gateway nodes exist for the namespace, not gated on any ownership check.
- **The uSID backend resolver has no tenant-identity check** (see [uSID resolution](#usid-resolution-for-backends) above) — two tenants advertising overlapping private address space resolve ambiguously. Pre-existing gap in the address model, not unique to this resolver.
- **`SRv6Address` (and, per the design plan, a second reserved Argument value for future egress use) has no in-cluster derivation mechanism.** Both are operator-supplied per gateway node today; nothing in this repo yet computes them automatically from a node's own `BGPRouter` locator/node-ID at the reserved Argument value. See [Argument-0 reservation](#argument-0-reservation) above.
- **The uSID TC-BPF/XDP FIB-lookup PMTUD gap applies here too.** When `bpf_fib_lookup()` returns `BPF_FIB_LKUP_RET_FRAG_NEEDED`, `edgenat.c` counts `DROP_REASON_FIB_FRAG_NEEDED` and drops rather than emitting an ICMPv6 Packet Too Big — the same accepted gap `internal/plumbing/ebpf/prog/usid.c` has for the SRv6 uSID datapath (see [ARCHITECTURE-CNI.md#known-constraints](ARCHITECTURE-CNI.md#known-constraints)), not yet scheduled to be closed on either side.
- **Egress (NAT masquerade for outbound tenant traffic) is planned, not implemented.** Today's gateway only handles ingress (external client → VIP → tenant backend); there is no path for a VPC-attached workload to reach the general internet. See `docs/plans/edge-gateway-nat-masquerade-egress.md` for the design-in-progress (status: planning only, no implementation started) — it proposes a second XDP personality (`handle_egress_forward`/`handle_egress_return`), a new `NetworkEgressPolicy` CRD, and flags the open questions (default-route ownership, IPv4 scope, anti-spoofing trust boundary) that block starting real implementation.
- **conn_table/rule_table have no active GC beyond LRU self-eviction.** By design (see Key Design Decisions above) — this is a deliberate, not accidental, scope boundary carried over from the rejected `gwprog` predecessor's identical choice.

---

## For Claude

**Where to start for each concern:**

| Concern                                                                                            | Start here                                                                                               |
| -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Node-scoped aggregate reconcile (self-address, desired-state assembly, BGP wiring, crash recovery) | `internal/controller/networkgateway_controller.go:Reconcile`                                             |
| Per-object lifecycle (finalizer teardown ordering, one-time primary_node assignment)               | `internal/controller/networkrule_controller.go:Reconcile`, `assignPrimaryNode`, `reconcileDelete`        |
| Backend address → SRv6 uSID resolution                                                             | `internal/controller/usidresolver.go:buildBackendSIDIndex`, `resolveUSID`                                |
| Engine convergence loop                                                                            | `internal/gateway/engine.go:Reconcile`, `applyRuleLocked`, `removeRuleLocked`                            |
| Real datapath implementation (rule_table read/write)                                               | `internal/gateway/kerneldatapath.go:ApplyRule`, `RemoveRule`                                             |
| Active-Active placement                                                                            | `internal/gateway/placement.go:AssignPrimaryNode`, `internal/gateway/localpref.go:LocalPreference`       |
| Crash recovery (orphaned rule_table state)                                                         | `internal/gateway/recovery.go`, `internal/plumbing/ebpf/edgemap/ruletable.go`'s `Generation`/`Reconcile` |
| Quota enforcement                                                                                  | `internal/gateway/quota.go:NodeQuotaEnforcer.CheckAndReserve`                                            |
| XDP packet path                                                                                    | `internal/plumbing/ebpf/edgeprog/edgenat.c` (start with its own header comment)                          |
| Datapath load/attach lifecycle                                                                     | `internal/plumbing/ebpf/edgeattach/attach.go`, `cmd/galactic-gateway/gateway.go:setupGatewayDatapath`    |
| Startup sequencing / gRPC health ordering                                                          | `cmd/galactic-gateway/root.go:runCmd`                                                                    |

**Stable vs. frequently changed:**
- Stable: `internal/gateway/placement.go`, `localpref.go` (pure functions, unaffected by any datapath change), `internal/plumbing/ebpf/edgemap` (mirrors `usidmap`'s already-settled crash-safety pattern)
- Active: `internal/gateway/quota.go`/`telemetry.go` (real but coarse — see Key Design Decisions; likely to grow richer enforcement), `internal/plumbing/ebpf/edgeprog/edgenat.c` (the egress masquerade plan below would add a second personality here)
- Planning only, not yet built: egress/NAT-masquerade (`docs/plans/edge-gateway-nat-masquerade-egress.md`), the `NetworkRule` admission webhook

**Non-obvious patterns:**
- `gatewayDatapathKeepAlive` (`cmd/galactic-gateway/gateway.go`) intentionally never calls `Close` on the loaded eBPF objects or the XDP `link.Link` — see that var's doc comment for the live incident this guards against (silent GC-triggered detach with every control-plane signal still looking healthy).
- Every gateway node reconciles every `NetworkGateway`/`NetworkRule` in the namespace — there is no leader election and no per-node filtering predicate on the watch itself; filtering happens inside `Reconcile` (`gw.Spec.TargetRef.Name != r.NodeName` early-return) and via `isGatewayNode`/broadcast watch mappers, not via `SetupWithManager` predicates.
- `BGPAdvertisement` names for gateway-originated routes are node-qualified (`<rule>-<node>-v4`/`-v6`, or `<gateway>-selfaddr`) specifically because Active-Active means every gateway node computes the same rule independently — omitting the node qualifier caused two nodes to race to create/update one shared object, confirmed live (`AlreadyExists` forever on the second node, only the first node's route ever advertised).
- A deleted `NetworkGateway` reconcile can't just call `Engine.Stop()` unconditionally — every gateway node's process reconciles every `NetworkGateway` in the namespace, so a *sibling* node's deletion reaches this reconciler too. `isGatewayNode` re-checks whether *this* node still has its own `NetworkGateway` before stopping the engine (issue #364).
- Advertisement failures during `Reconcile` are collected, not returned immediately — one bad rule's BGP-wiring failure must not stop the rest of the pass, but a node that converged its engine while failing to publish any route must still report `AdvertisementFailed`, not `EngineHealthy` (issue #365) — see `readyConditionFor`.
