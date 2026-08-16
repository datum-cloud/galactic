# Architecture — galactic-router

> The BGP/EVPN control plane: a controller-runtime reconciler that watches
> BGP CRDs (`BGPRouter`/`BGPPeer`/`BGPAdvertisement`/`BGPPolicy`/
> `BGPVRFInstance`) and drives an embedded GoBGP server per node to
> distribute EVPN (L2VPN/EVPN AFI/SAFI) paths between nodes.

_Last updated: 2026-08-13_

This document covers `galactic-router`'s tenant-BGP core only. See
[ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md) for the CNI attach chain that
writes the CRDs this binary reconciles, and
[ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md) for the edge XDP NAT+LB
gateway (`galactic-gateway`, which co-locates a `galactic-router` container
in the same pod on gateway-role nodes but adds no gateway-specific code to
this binary — see that doc for the `NetworkGateway`/`NetworkRule`
reconcilers, which run in `galactic-gateway`, not here, despite living in
the same `internal/controller` package). This file, together with those
two, supersedes the former monolithic `ARCHITECTURE.md` — see
[AGENTS.md](../../AGENTS.md) for which document to start from for a given
task.

---

## Overview

`galactic-router` watches BGP CRDs directly via controller-runtime — no gRPC
sidecar, no provider CRD lifecycle. When `galactic-veth`/`galactic-tap`
attaches a pod/VM and `galactic-bgp` writes a `BGPAdvertisement` CRD (see
[ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md)), `galactic-router` reconciles
that CRD and injects the EVPN path into the node-local GoBGP server. GoBGP
distributes the path to a BGP route reflector, enabling pods/VMs on
different nodes or clusters to reach each other via SRv6-encapsulated
traffic.

### SRv6 SID encoding (control-plane side)

`galactic-router`'s own reconciler derives the SID value for the BGP
control-plane side: advertising it in a BGP Prefix-SID path attribute (RFC
9252 SRv6 L3 Service TLV, `internal/runtime/gobgp/paths.go`'s
`prefixSIDAttr`) — not the EVPN Type 5 route's own Gateway IP field, which
RFC 9136 requires to share the prefix's own address family and so cannot
carry an IPv6 SID for an IPv4 VPC prefix. This SID is computed via
`srv6.ComputeSID` (`internal/plumbing/srv6/usid.go`, called from
`internal/reconcile/reconcile.go`) from the same inputs
(`BGPRouter.spec.srv6Locator` + `nodeID` + the attachment's VRFID) that
`galactic-bgp`'s `registerEBPFDatapath` independently derives for the CNI
side's eBPF datapath registration — see
[ARCHITECTURE-CNI.md#srv6-sid-encoding](ARCHITECTURE-CNI.md#srv6-sid-encoding).
The CNI side and the router side compute the same bit layout via separate
code paths (`uformat` is the single source of truth both build on), by
design — see `internal/plumbing/ebpf/doc.go`.

All nodes in the same VPC derive the same BGP Route Target by truncating the
48-bit hex VPC identifier to its low 32 bits (`uint32(v)`), formatted as
`ASN:NN`, enabling automatic cross-node path import without explicit RT
configuration. The RT is also used as the `BGPVRFInstance`'s Route
Distinguisher and import/export Route Target.

---

## Repository Layout

```
galactic/
├── cmd/
│   └── galactic-router/     # Router binary (controller-runtime reconciler)
├── internal/
│   ├── controller/          # controller-runtime reconcilers (BGPRouter, BGPPeer,
│   │                        #   BGPAdvertisement, BGPVRFInstance, BGPPolicy, Secret,
│   │                        #   Node, GC); field index registration; status helpers.
│   │                        #   (NetworkGatewayReconciler/NetworkRuleReconciler also
│   │                        #   live in this package but run in galactic-gateway, not
│   │                        #   galactic-router — see ARCHITECTURE-GATEWAY.md.)
│   ├── reconcile/           # CRD → DesiredRouter translation (node/role checks,
│   │                        #   secret resolution, IPv6 next-hop from Node)
│   ├── runtime/             # RouterRuntime interface + RuntimeManager
│   │   ├── gobgp/           # GoBGP RouterRuntime (tenant mode)
│   │   └── frr/             # FRR RouterRuntime stub (fabric mode)
│   ├── model/               # DesiredRouter and family; re-exports BGP API enums
│   ├── hash/                # SHA-256 change detection over DesiredRouter
│   ├── metadata/            # Build-time version info (Version, GitCommit, etc.)
│   ├── gc/                  # Orphaned BGPAdvertisement/BGPVRFInstance CRD, stale
│   │                        #   kernel VRF, and eBPF vrf_table entry cleanup,
│   │                        #   driven by the GC controller
│   └── plumbing/            # Low-level kernel and network primitives (shared with
│       ├── intf/            #   the CNI chain — see ARCHITECTURE-CNI.md's own copy
│       ├── srv6/             #   of this tree for the CNI-side entries)
│       ├── ebpf/             # GC's stale vrf_table entry sweep only, here
│       └── vrf/
├── config/
│   └── router/              # Shared RBAC/ServiceAccount, plus:
│       ├── base/             #   common DaemonSet spec
│       ├── tenant/            #   per-node role: base + node affinity excluding control-plane
│       │                     #     and tenant-control nodes
│       └── tenant-control/    #   route-reflector role: base + GALACTIC_ROUTER_REFLECTOR=true,
│                              #     opt-in via the galactic.datumapis.com/node=control node label
└── containers/
    └── galactic-router/     # galactic-router production image
```

Production images are published by `.github/workflows/publish.yaml` — see CI/CD below.

---

## Data Flow

See [docs/agent-startup.md](../agent-startup.md) for the router startup sequence diagram, and [docs/architecture/](../architecture/) for C4 context/container diagrams covering all three Galactic applications.

---

## Components

| Component                | Binary                                     | Role                                                                                                                                                                                                                  |
| ------------------------ | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `internal/controller`    | `galactic-router`                          | controller-runtime reconcilers (BGPRouter, BGPPeer, BGPAdvertisement, BGPVRFInstance, BGPPolicy, Secret, Node, GC — not NetworkGateway/NetworkRule, see the note above); field index registration; CRD status helpers |
| `internal/reconcile`     | `galactic-router`                          | CRD → DesiredRouter translation                                                                                                                                                                                       |
| `internal/runtime/gobgp` | `galactic-router`                          | Embedded GoBGP server (`--mode=tenant`)                                                                                                                                                                               |
| `internal/runtime/frr`   | `galactic-router`                          | FRR stub (`--mode=fabric`) — returns "not implemented" for every method                                                                                                                                               |
| `internal/model`         | `galactic-router`                          | Internal BGP model types                                                                                                                                                                                              |
| `internal/hash`          | `galactic-router`                          | Change detection                                                                                                                                                                                                      |
| `internal/metadata`      | every binary in the repo                   | Build-time version info stamped via `-ldflags`                                                                                                                                                                        |
| `internal/gc`            | `galactic-router`                          | Orphaned CRD/VRF/eBPF-entry cleanup, driven by the GC controller's ticker                                                                                                                                             |
| `internal/plumbing/srv6` | `galactic-router`                          | SID computation (`ComputeSID`) for the BGP Prefix-SID path attribute                                                                                                                                                  |
| `internal/plumbing/intf` | `galactic-router` + every CNI-chain binary | Interface naming, base62↔hex encoding                                                                                                                                                                                 |
| `internal/plumbing/vrf`  | `galactic-router` + every CNI-chain binary | Linux VRF create/delete/lookup                                                                                                                                                                                        |

---

## Entry Points

### `cmd/galactic-router/main.go` / `root.go` — Router daemon

`main.go` is a 3-line wrapper around `newRootCommand().Execute()`; all startup logic
lives in `root.go`'s `runCmd`:

1. Validate config (`--node-name` and `--mode` required; `--mode` must be `transit`,
   `fabric`, or `tenant`). Env vars: `GALACTIC_ROUTER_NODE_NAME`,
   `GALACTIC_ROUTER_ROUTER_MODE`, plus optional `GALACTIC_ROUTER_BGP_LISTEN_PORT`,
   `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS`, `GALACTIC_ROUTER_METRICS_PORT`,
   `GALACTIC_ROUTER_GRPC_HEALTH_PORT`, `GALACTIC_ROUTER_GC_NAMESPACE`,
   `GALACTIC_ROUTER_GC_INTERVAL`, `GALACTIC_ROUTER_REFLECTOR`.
2. Select `RuntimeFactory`: `tenant` → GoBGP, `fabric` → FRR stub, `transit` → returns
   an error ("not yet supported").
3. Build controller-runtime manager (metrics on configurable port, default `:9179`;
   no HTTP health endpoint).
4. Start gRPC health server on a configurable port (default `:5179`).
5. RBAC pre-flight: `checkWatchPermissions` (in `main.go`) issues a
   `SelfSubjectAccessReview` for every watched resource type and logs an actionable
   error if watch RBAC is missing (informer caches would otherwise silently never sync).
6. Register field indexes: BGPPeer→secret, BGPPeer→router, BGPPolicy→router,
   BGPAdvertisement→router, BGPVRFInstance→router, BGPRouter→node.
7. Register eight controllers: BGPRouter, BGPPeer, BGPAdvertisement, BGPVRFInstance,
   BGPPolicy, Secret, Node, and GC (the GC controller also starts a ticker goroutine
   that waits for cache sync, then runs on `--gc-interval`, default 5m).
8. `mgr.Start(ctx)` — blocks until the signal-handler context is cancelled.

This is identical whether the pod is running in the plain `tenant` role
(`config/router/tenant/`), the route-reflector role
(`config/router/tenant-control/`), or as the tenant-BGP container co-located
with `galactic-gateway` on a gateway-role node
(`config/gateway/base/daemonset.yaml`) — `galactic-router` carries no
gateway-role code path of its own at all; see
[ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md) for what runs in the
sibling container instead.

---

## Configuration

### galactic-router environment variables

| Variable                            | Required | Default           | Description                                                             |
| ----------------------------------- | -------- | ----------------- | ----------------------------------------------------------------------- |
| `GALACTIC_ROUTER_NODE_NAME`         | Yes      | —                 | Kubernetes node name; filters which BGPRouter CRDs this instance owns   |
| `GALACTIC_ROUTER_ROUTER_MODE`       | Yes      | —                 | `transit` (unsupported stub), `fabric` (FRR stub), or `tenant` (GoBGP)  |
| `GALACTIC_ROUTER_REFLECTOR`         | No       | `false`           | Enable route reflector mode; only valid for `fabric`/`tenant`           |
| `GALACTIC_ROUTER_BGP_LISTEN_PORT`   | No       | `179`             | BGP TCP listen port; `-1` disables inbound connections (outbound-only)  |
| `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS` | No       | —                 | Source address for outgoing BGP TCP connections (numbered underlay use) |
| `GALACTIC_ROUTER_METRICS_PORT`      | No       | `9179`            | controller-runtime Prometheus metrics port                              |
| `GALACTIC_ROUTER_GRPC_HEALTH_PORT`  | No       | `5179`            | gRPC health check port (liveness/readiness probes)                      |
| `GALACTIC_ROUTER_GC_NAMESPACE`      | No       | `galactic-system` | Namespace the GC controller scans for orphaned CRDs                     |
| `GALACTIC_ROUTER_GC_INTERVAL`       | No       | `5m`              | GC controller sweep interval                                            |

See [docs/router/configuration.md](../router/configuration.md) for the full reference, including CLI flags and precedence.

On a gateway-role node, `GALACTIC_ROUTER_BGP_LISTEN_PORT=-1` is set by
`config/gateway/base/daemonset.yaml` — the tenant-BGP container only dials
out to iBGP peers there, same as the plain tenant role.
`GALACTIC_ROUTER_GRPC_HEALTH_PORT=5179` is set explicitly too, matching
the binary's own default, so it can't silently start colliding with the
co-located `galactic-gateway` container's own health port on the same
`hostNetwork: true` pod if either default ever changes — see
[ARCHITECTURE-GATEWAY.md#configuration](ARCHITECTURE-GATEWAY.md#configuration).

---

## Module / Package Reference

| Package                  | Binary                                   | Responsibility                                                                                                                                                   | Owns state        |
| ------------------------ | ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| `internal/controller`    | galactic-router                          | controller-runtime reconcilers (BGPRouter, BGPPeer, BGPAdvertisement, BGPVRFInstance, BGPPolicy, Node, Secret, GC); field index registration; CRD status helpers | No                |
| `internal/reconcile`     | galactic-router                          | Translates BGPRouter + related CRDs into `model.DesiredRouter`; enforces node/role filtering, timer validation, AFI validation                                   | No                |
| `internal/runtime`       | galactic-router                          | `RouterRuntime` interface; `RuntimeManager` (keyed map of live runtimes, double-checked lock create)                                                             | Yes (runtime map) |
| `internal/runtime/gobgp` | galactic-router                          | Embeds GoBGP v4; lazy-starts on first Apply; handles peer/VRF/EVPN-path/policy add/update/delete; tracks established timestamps                                  | Yes (per-router)  |
| `internal/runtime/frr`   | galactic-router                          | FRR stub — returns "not implemented" for every method                                                                                                            | No                |
| `internal/model`         | galactic-router                          | `DesiredRouter`, `DesiredPeer`, `DesiredAdvertisement`, `DesiredPolicy`, `DesiredVRFInstance`, `RuntimeStatus`; re-exports BGP API enums                         | No                |
| `internal/hash`          | galactic-router                          | SHA-256 fingerprint of `DesiredRouter` for no-op suppression                                                                                                     | No                |
| `internal/metadata`      | every binary                             | Build-time vars (`Version`, `GitCommit`, `GitTreeState`, `BuildDate`) stamped via `-ldflags`                                                                     | No                |
| `internal/gc`            | galactic-router                          | Collects orphaned `BGPAdvertisement`/`BGPVRFInstance` CRDs, stale kernel VRFs, and stale eBPF `vrf_table` entries; invoked by the GC controller's ticker         | No                |
| `internal/plumbing/srv6` | galactic-router                          | SID computation (`ComputeSID`) for the router's own BGP Prefix-SID path attribute                                                                                | No                |
| `internal/plumbing/intf` | galactic-router + every CNI-chain binary | Deterministic interface naming (`G{vpc9}{att3}V/H/G`); base62↔hex encoding                                                                                       | No                |
| `internal/plumbing/vrf`  | galactic-router + every CNI-chain binary | Linux VRF create/delete/lookup via netlink                                                                                                                       | No                |

---

## External Dependencies

| Dependency                       | Version               | Purpose                                                                                                                                                                         |
| -------------------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `github.com/osrg/gobgp/v4`       | v4.7.0                | Embedded BGP server (tenant mode)                                                                                                                                               |
| `go.datum.net/network`           | bumped frequently     | BGP CRD API types (BGPRouter, BGPPeer, BGPAdvertisement, BGPPolicy, BGPVRFInstance)                                                                                             |
| `sigs.k8s.io/controller-runtime` | v0.24.1               | Full manager + reconciler framework: manager, field indexes, eight registered controllers (see Entry Points)                                                                    |
| `github.com/spf13/cobra`         | v1.10.2               | CLI command/flag handling                                                                                                                                                       |
| `github.com/spf13/viper`         | v1.21.0               | Config resolution (flags/env/defaults) — unlike the CNI-chain binaries (see [ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md)), which resolve config themselves and don't import viper |
| `github.com/vishvananda/netlink` | pinned pseudo-version | Linux netlink: VRF, SRv6 routes (GC's kernel-state sweep)                                                                                                                       |
| `google.golang.org/grpc`         | v1.82.0               | gRPC health server (default `:5179`)                                                                                                                                            |
| `k8s.io/api`, `k8s.io/client-go` | v0.36.0               | Kubernetes client, Node/Secret API types                                                                                                                                        |

---

## Key Design Decisions

- **GoBGP embedded, lazy-started.** GoBGP runs in-process (`--mode=tenant` only) and starts only when the first `BGPRouter` is reconciled for that router; `Apply` re-runs on every subsequent reconcile too (subject to hash-based no-op suppression), re-applying peers/VRFs/EVPN/policies each time. `listenPort` defaults to `179`; `-1` (outbound-only) is an operator choice for specific deployments, not the codebase default. ASN or RouterID changes trigger a full `Reconfigure` (fresh `BgpServer` — `StopBgp` is not called because it permanently terminates the v4 Serve loop).
- **Overlay BGP port.** galactic-router peers connect outbound on port `1790` by default (configurable per-peer via `BGPPeer.spec.remotePort`). Port `179` is occupied by the underlay FRR `bgpd` on every node, so the overlay uses a non-conflicting port. The `BGPPeer` CRD defaults `remotePort` to `179` (the IANA BGP port); galactic-router overrides this to `1790` when the field is unset, so existing CRDs without an explicit value continue to work. Set `remotePort: 179` explicitly when peering with external BGP speakers that listen on the standard port.
- **VRF/route-target model via BGPVRFInstance.** `galactic-bgp` (the CNI chain, see [ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md)) creates a `BGPVRFInstance` (RouteDistinguisher + import/export Route Targets, all set to the derived RT) before the `BGPAdvertisement`; `galactic-router`'s GoBGP runtime applies VRFs (`applyVRFs`) before originating EVPN paths (`applyEVPN`). `galactic-gateway`'s own `BGPAdvertisement`s (VIP/self-address routes, see [ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md)) leave VRFID/Function unset entirely — they carry no SRv6 decap behavior of their own.
- **CRD-driven config, no sidecar gRPC.** `galactic-router` watches BGP CRDs directly via controller-runtime. `galactic-bgp` writes `BGPVRFInstance`/`BGPAdvertisement` CRDs; the router reconciler picks them up. No in-node gRPC calls between any of the CNI-chain binaries and `galactic-router`.
- **Hash-based no-op suppression.** SHA-256 over the sorted `DesiredRouter` prevents redundant GoBGP Apply calls on every CRD event.
- **RuntimeFactory pattern.** `--mode=tenant` (`GALACTIC_ROUTER_ROUTER_MODE=tenant`) selects GoBGP; `--mode=fabric` selects the FRR stub; `--mode=transit` is accepted by validation but returns an error at startup (not yet implemented). The mode is selected at startup; no controller changes are needed to add a new mode.
- **DEL is intentionally minimal everywhere in the CNI chain; GC reclaims shared state asynchronously.** See [ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md#key-design-decisions) for the CNI-side half of this decision. `galactic-router`'s GC controller (ticker-driven, default every 5m) reclaims orphaned CRDs, stale kernel VRFs, and stale eBPF entries once no live container still references them.
- **gRPC health, configurable port.** Liveness and readiness probes use the gRPC health protocol (`google.golang.org/grpc/health`) on a configurable port (default `5179`). No HTTP health endpoint. `galactic-gateway` follows the identical convention on its own port — see [ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md).
- **`galactic-router` carries no gateway-role code.** The edge XDP NAT+LB gateway used to be a `galactic-router` mode; it was split into its own `galactic-gateway` binary specifically so a crash on either side no longer takes the other down with it — see [ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md) for the full rationale and design.

---

## Testing

| Layer   | Command          | Framework        | Scope                                                                                                                                                                                                                    |
| ------- | ---------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Unit    | `task test:unit` | `go test -race`  | `internal/plumbing/srv6`, `internal/gc`, `internal/reconcile`, `internal/controller` (BGP-family reconcilers), `internal/plumbing/intf`, `internal/metadata`, `internal/runtime/gobgp` (partial), `internal/runtime/frr` |
| E2E     | `task test:e2e`  | Kind + `go test` | Full BGPRouter lifecycle coverage for `galactic-router` comes from this Kind cluster's separate reconciler tests, run alongside the CNI e2e suite described in [ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md#testing).       |
| CI full | `task ci`        | all of the above | lint → build → test:unit → test:e2e                                                                                                                                                                                      |

---

## CI/CD

**Pipeline:** `.github/workflows/ci.yaml`

Runs on every PR and push to `main`. Two tiers:

- **Tier 1 (parallel):** `lint` (golangci-lint v2.12.2 + yamlfmt), `test-unit` (race detector + codecov upload), `build`
- **Tier 2 (sequential):** `test-e2e` — blocked on all Tier 1 jobs passing

This same pipeline covers every binary in the repo (CNI chain, router,
gateway) — it is not duplicated per architecture doc; see
[ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md#cicd) and
[ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md#cicd) for each binary's
own publish/image details.

**Publish pipeline:** `.github/workflows/publish.yaml`, modeled on the `compute` repo's. Runs on every push and on published releases, via reusable `datum-cloud/actions` workflows: `publish-galactic-cni-image`, `publish-galactic-router-image`, and `publish-galactic-gateway-image` each build and push their own image (`ghcr.io/datum-cloud/galactic-cni`, `ghcr.io/datum-cloud/galactic-router`, `ghcr.io/datum-cloud/galactic-gateway`), and `publish-kustomize-bundles` (which `needs` all three image jobs) pushes `config/` as an OCI Kustomize bundle (`ghcr.io/datum-cloud/galactic-kustomize`), using the `images` input (`datum-cloud/actions` v1.20.0+) to stamp each job's real published tag into `config/cni`, `config/router/base`, and `config/gateway/base` respectively (the last of these getting both the router and gateway tags, since that base runs both images in one pod) — the bundle ships with matching versioned image references, not `:latest`. This replaced the old single-image `.github/workflows/release.yaml` (removed — see history below) with per-binary images, matching the split `deploy/containerlab/` already used for local dev.

**Container image:**
- `containers/galactic-router/Dockerfile` — golang builder → `gcr.io/distroless/static:nonroot`, `ENTRYPOINT ["/galactic-router"]`. No shell or CLI tools: `galactic-router` drives VRF/SRv6/route/BGP state entirely through the netlink and GoBGP Go libraries, never shells out. Pushed by `publish.yaml` as `ghcr.io/datum-cloud/galactic-router`.

**History:** the original `.github/workflows/release.yaml` built and pushed a single `ghcr.io/datum-cloud/galactic:{version,major.minor,major,sha}` image from a shared `containers/galactic/Dockerfile`, but that image only ever built `galactic-cni` while `config/router/base/daemonset.yaml` ran `command: [/galactic-router]` against it — the image advertised a binary it never built. Both were removed. `publish.yaml` and the per-binary Dockerfiles fix this by building each binary into its own image, so `config/cni/daemonset.yaml` and `config/router/base/daemonset.yaml` now reference `ghcr.io/datum-cloud/galactic-cni:latest` and `ghcr.io/datum-cloud/galactic-router:latest` respectively — matching images, matching binaries. `galactic-gateway` (see [ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md)) was split out of `galactic-router` later still, following the same one-binary-one-image precedent.

---

## Known Constraints

- **GoBGP RIB is ephemeral.** All BGP state is in-process memory. On restart, sessions and paths must be re-established from CRD state; controller-runtime's reconcile loop handles this automatically.
- **EVPN Type 5 is implemented, not deferred.** `internal/runtime/gobgp/paths.go`'s `buildEVPNPaths` builds real `EVPNIPPrefixRoute` NLRIs, deriving the Route Distinguisher from `routerID + ":0"` (not from the CRD). The `BGPVRFInstance` CRD carries its own explicit `RouteDistinguisher` and import/export Route Targets (see Key Design Decisions above), applied via `internal/runtime/gobgp/runtime.go`'s `applyVRFs`. There is no `ErrMissingRouteDistinguisher` or similar rejection path in the current code.
- **`--mode=transit` is unimplemented.** Accepted by CLI/env validation, but `runCmd` returns an error at startup ("mode=transit is not yet supported").
- **No binary's `cmdDel` tears down shared kernel/CRD state.** See [ARCHITECTURE-CNI.md#known-constraints](ARCHITECTURE-CNI.md#known-constraints) for the CNI-side half; this reconciler's GC controller (`internal/gc`) is the asynchronous cleanup path for all of it.

---

## For Claude

**Where to start for each concern:**

| Concern                                      | Start here                                                                               |
| -------------------------------------------- | ---------------------------------------------------------------------------------------- |
| CRD → BGP translation                        | `internal/reconcile/reconcile.go:BuildDesiredRouter`                                     |
| BGP runtime application (GoBGP)              | `internal/runtime/gobgp/runtime.go:Apply`                                                |
| BGP peer / VRF / advertisement / policy CRUD | `internal/runtime/gobgp/peers.go`, `runtime.go` (`applyVRFs`), `paths.go`, `policies.go` |
| Controller watch graph                       | `internal/controller/bgprouter_controller.go:SetupWithManager`                           |
| CRD status update logic                      | `internal/controller/status.go`, `bgprouter_controller.go:updateRouterStatus`            |
| Orphaned CRD/VRF garbage collection          | `internal/controller/gc_controller.go`, `internal/gc/gc.go`                              |
| RBAC pre-flight self-check                   | `cmd/galactic-router/main.go:checkWatchPermissions`                                      |
| Hash-based no-op suppression                 | `internal/hash/hash.go`; annotation `galactic.datum.net/config-hash` on BGPRouter        |
| GoBGP server lifecycle (start/reconfigure)   | `internal/runtime/gobgp/server.go`                                                       |
| SRv6 SID computation for BGP Prefix-SID      | `internal/plumbing/srv6/usid.go:ComputeSID`                                              |

**Stable vs. frequently changed:**
- Stable: `internal/plumbing/` (pure kernel primitives), `internal/model/types.go`, `internal/runtime/runtime.go` (interface)
- Active: `internal/controller/` (status conditions, watch graph), `internal/runtime/gobgp/` (EVPN path construction), `internal/reconcile/` (validation rules), `internal/gc/` (GC rules)
- Stub / incomplete: `internal/runtime/frr/` (returns "not implemented" everywhere), `--mode=transit` (rejected at startup)

**Non-obvious patterns:**
- `BGPPeer` and `BGPPolicy` reconcilers do not call Apply themselves — they enqueue their owning `BGPRouter`, which is the only reconciler that calls `RuntimeManager.Apply`. This means touching any associated resource triggers a full router reconcile.
- `SecretReconciler.Reconcile()` is a no-op body — it exists only to register the watch; the real work is done by `secretToRouterRequests` mapping changes to BGPRouter reconcile requests.
- Same for `NodeReconciler` — the reconcile body is empty; the watch mapper `nodeToRouterRequests` does the work.
- `peerStatusRequeue = 30s` periodic requeue keeps BGPPeer session state current because BGP FSM transitions are not Kubernetes events.
- `annotationConfigHash` is persisted on the BGPRouter object (not just in memory) so no-op detection survives pod restarts without re-applying GoBGP config.
- GoBGP `Reconfigure()` calls `old.Stop()` then creates a fresh `BgpServer` — it does NOT call the BGP-level `StopBgp`/`StartBgp` on the old server, avoiding the v4 "Serve loop permanently dead" problem.
- No binary's `cmdDel` deletes the VRF, veth/tap, routes, the eBPF `vrf_table` entry, or `BGPAdvertisement`/`BGPVRFInstance` CRDs — each CNI-chain binary's own DEL only handles its own per-container bookkeeping. Shared-resource cleanup is entirely this GC controller's job (`internal/gc`), to avoid racing a concurrent ADD during pod restarts.
- Production images are published by `.github/workflows/publish.yaml` as separate per-binary images (`galactic-cni`, `galactic-router`, `galactic-gateway`), not one shared image — see CI/CD above.
- `internal/controller` also hosts `NetworkGatewayReconciler`/`NetworkRuleReconciler`/`usidresolver.go` — these register with `galactic-gateway`'s manager, not `galactic-router`'s (compare `cmd/galactic-router/root.go`'s controller registration list in Entry Points above against `cmd/galactic-gateway/root.go`'s — see [ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md)). Don't assume every reconciler type in this package runs in this binary.
