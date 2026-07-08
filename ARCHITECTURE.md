# Architecture

> Galactic is the SRv6 data plane for multi-cloud VPC networking, deployed as two
> binaries on each Kubernetes node: a CNI plugin that attaches containers to VPC
> networks, and a router that reconciles Cosmos BGP CRDs and drives an embedded
> GoBGP server to distribute EVPN (L2VPN/EVPN AFI/SAFI) paths between nodes.

_Last updated: 2026-06-23_

---

## Overview

Galactic implements VPC isolation and cross-cluster reachability using Linux SRv6.
When a pod is attached to a VPC, the CNI plugin creates the required kernel state
(VRF, veth pair, SRv6 ingress route) and writes a `BGPAdvertisement` CRD.
`galactic-router` watches that CRD and injects the EVPN path into the node-local
GoBGP server. GoBGP distributes the path to a BGP route reflector, enabling pods
on different nodes or clusters to reach each other via SRv6-encapsulated traffic.

VPC and VPCAttachment CRDs are owned by a separate companion operator
(`go.miloapis.com/cosmos`). Galactic receives pre-populated identifiers through the
CNI config and acts on them. `galactic-router` reconciles BGP CRDs from the same
cosmos API group directly — no gRPC sidecar, no provider CRD lifecycle.

### SRv6 SID encoding

Each container endpoint is assigned a /128 USID (Unique Local SID, RFC 8986 Section 3.2).
The companion operator allocates a unique /128 per (VPC, VPCAttachment) pair and injects
it into the NAD as `srv6_sid`. The CNI installs an END.DT46 decap route for that exact
/128 and advertises it as the EVPN Type 5 GWIPAddress.

All nodes in the same VPC derive the same BGP Route Target via `fnv32a(vpcHex)`,
enabling automatic cross-node path import without explicit RT configuration.

---

## Repository Layout

```
galactic/
├── cmd/
│   ├── galactic-cni/        # CNI binary
│   └── galactic-router/     # Router binary (controller-runtime reconciler)
├── internal/
│   ├── controller/          # controller-runtime reconcilers (BGPRouter, BGPPeer,
│   │                        #   BGPAdvertisement, BGPPolicy, Secret, Node)
│   ├── reconcile/           # CRD → DesiredRouter translation (node/role checks,
│   │                        #   secret resolution, IPv6 next-hop from Node)
│   ├── runtime/             # RouterRuntime interface + RuntimeManager
│   │   ├── gobgp/           # GoBGP RouterRuntime (tenant role)
│   │   └── frr/             # FRR RouterRuntime stub (fabric role, Phase 2)
│   ├── model/               # DesiredRouter and family; re-exports cosmos enums
│   ├── hash/                # SHA-256 change detection over DesiredRouter
│   ├── metadata/            # Build-time version info (Version, GitCommit, etc.)
│   ├── cni/                 # CNI cmdAdd / cmdDel
│   │   ├── route/           # Host-side static routes via netlink
│   │   └── veth/            # veth pair management
│   └── plumbing/            # Low-level kernel and network primitives
│       ├── intf/            # Interface naming, base62↔hex encoding
│       ├── srv6/            # SRv6 ingress route add/del (END.DT46)
│       ├── sysctl/          # Interface sysctl helpers
│       └── vrf/             # Linux VRF create/delete/lookup
├── deploy/
│   ├── galactic-router/     # DaemonSet, RBAC, ServiceAccount
│   ├── galactic-cni/        # DaemonSet installing galactic-cni onto /opt/cni/bin via hostPath
│   └── containerlab/        # ContainerLab lab topology and scripts
└── containers/
    └── galactic/            # Production Dockerfile
```

---

## Data Flow

See [docs/cni-sequence.md](docs/cni-sequence.md) for the full CNI ADD/DEL sequence diagram.

See [docs/agent-startup.md](docs/agent-startup.md) for the router startup sequence diagram.

---

## Components

| Component | Binary | Role |
|-----------|--------|------|
| `internal/controller` | `galactic-router` | controller-runtime reconcilers; field index registration; CRD status helpers |
| `internal/reconcile` | `galactic-router` | CRD → DesiredRouter translation |
| `internal/runtime/gobgp` | `galactic-router` | Embedded GoBGP server (tenant role) |
| `internal/runtime/frr` | `galactic-router` | FRR stub (fabric role, Phase 2) |
| `internal/model` | `galactic-router` | Internal BGP model types |
| `internal/hash` | `galactic-router` | Change detection |
| `internal/metadata` | both | Build-time version info stamped via `-ldflags` |
| `internal/cni` | `galactic-cni` | CNI cmdAdd / cmdDel |
| `internal/plumbing/intf` | both | Interface naming, base62↔hex encoding |
| `internal/plumbing/srv6` | both | SRv6 ingress route add/del (END.DT46) |
| `internal/plumbing/vrf` | both | Linux VRF create/delete/lookup |
| `internal/plumbing/sysctl` | both | Interface sysctl helpers |

---

## Entry Points

### `cmd/galactic-cni/main.go` — CNI plugin

Calls `cni.RunPlugin()` which hands control to `skel.PluginMainFuncs`. Reads config from stdin (CNI spec). Requires `GALACTIC_CNI_NODE_NAME` env var at runtime. See [docs/cni-sequence.md](docs/cni-sequence.md) for the full ADD/DEL sequence.

### `cmd/galactic-router/main.go` — Router daemon

1. Read `GALACTIC_ROUTER_NODE_NAME`, `GALACTIC_ROUTER_ROUTER_ROLE`, optionally `GALACTIC_ROUTER_BGP_LISTEN_PORT` and `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS`
2. Select `RuntimeFactory`: `tenant` → GoBGP, `fabric` → FRR stub
3. Build controller-runtime manager (Prometheus on `:8080`, no HTTP health)
4. Start gRPC health server on `:5000`
5. Register field indexes (BGPPeer→router, BGPRouter→node, BGPPeer→secret)
6. Register six controllers: BGPRouter, BGPPeer, BGPAdvertisement, BGPPolicy, Secret, Node
7. `mgr.Start(ctx)` — blocks until signal

---

## Configuration

### galactic-router environment variables

| Variable                        | Required | Default | Description                                                             |
|---------------------------------|----------|---------|-------------------------------------------------------------------------|
| `GALACTIC_ROUTER_NODE_NAME`     | Yes      | —       | Kubernetes node name; filters which BGPRouter CRDs this instance owns   |
| `GALACTIC_ROUTER_ROUTER_ROLE`   | Yes      | —       | `tenant` (GoBGP) or `fabric` (FRR stub, not yet implemented)            |
| `GALACTIC_ROUTER_BGP_LISTEN_PORT` | No     | `179`   | BGP TCP listen port; `-1` disables inbound connections (outbound-only)  |
| `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS` | No   | —       | Source address for outgoing BGP TCP connections (numbered underlay use) |

### galactic-cni CNI config fields (`PluginConf`)

| Field           | Type     | Description                                                             |
|-----------------|----------|-------------------------------------------------------------------------|
| `vpc`           | string   | Base62-encoded 48-bit VPC identifier                                    |
| `vpcattachment` | string   | Base62-encoded 16-bit VPCAttachment identifier                          |
| `interface_type`| string   | `veth` (default) or `tap`; tap mode omits IPAM and guest-side config   |
| `srv6_sid`      | string   | USID (/128) for this endpoint; bare IPv6 or CIDR form                       |
| `namespace`     | string   | Kubernetes namespace for BGP CRDs; defaults to `default`               |
| `mtu`           | int      | MTU for the veth pair; 0 uses kernel default                            |
| `terminations`  | array    | Static routes to install on the host-side veth (`network`, `via`)      |
| `ipam`          | object   | Passed through to the IPAM plugin (ignored in tap mode)                |

### galactic-cni environment variables

| Variable                  | Required | Description                                                |
|---------------------------|----------|------------------------------------------------------------|
| `GALACTIC_CNI_NODE_NAME`  | Yes      | Kubernetes node name; used to look up the owning BGPRouter |

### galactic-cni ADD result

On a successful ADD, the plugin returns a CNI spec v1.0.0 result with the following structure:

```json
{
  "cniVersion": "1.0.0",
  "interfaces": [
    { "name": "G<09-vpc><03-att>H", "mac": "aa:bb:cc:dd:ee:ff", "mtu": 1500, "sandbox": "" },
    { "name": "eth0", "mac": "aa:bb:cc:dd:ee:11", "mtu": 1500, "sandbox": "/proc/<pid>/ns/net" }
  ],
  "ips": [
    { "address": "fd00:10:ff01::1234/80", "gateway": "fd00:10:ff01::1", "interface": 1 }
  ],
  "routes": [
    { "dst": "::/0" }
  ]
}
```

| Field | Description |
|-------|-------------|
| `interfaces[0]` | Host-side veth endpoint (`G{vpc}{att}H`); sandbox is empty (host network namespace) |
| `interfaces[1]` | Guest-side veth endpoint (`args.IfName`, typically `eth0`); sandbox is the container netns path |
| `ips[0].interface` | Index `1` into `interfaces` — the guest veth carries the pod IP |
| `routes` | Default route via IPAM gateway (when IPAM is configured) |

The VRF dummy interface (`G{vpc}{att}V`) is **not** reported — it is pre-existing infrastructure created by the `vrf.Add()` plumbing function, not by the CNI attachment itself.

On DEL, the result contains only `cniVersion` (empty result is correct since the guest interface no longer exists at DEL time).

---

## Module / Package Reference

| Package                       | Binary          | Responsibility                                                                                      | Owns state |
|-------------------------------|-----------------|-----------------------------------------------------------------------------------------------------|------------|
| `internal/controller`         | galactic-router | controller-runtime reconcilers (BGPRouter, BGPPeer, BGPAdvertisement, BGPPolicy, Node, Secret); field index registration; CRD status helpers | No         |
| `internal/reconcile`          | galactic-router | Translates BGPRouter + related CRDs into `model.DesiredRouter`; enforces node/role filtering, timer validation, AFI validation | No         |
| `internal/runtime`            | galactic-router | `RouterRuntime` interface; `RuntimeManager` (keyed map of live runtimes, double-checked lock create) | Yes (runtime map) |
| `internal/runtime/gobgp`      | galactic-router | Embeds GoBGP v4; lazy-starts on first Apply; handles peer add/update/delete, EVPN paths, policies; tracks established timestamps | Yes (per-router) |
| `internal/runtime/frr`        | galactic-router | FRR stub — returns `errNotImplemented` for every method                                             | No         |
| `internal/model`              | both            | `DesiredRouter`, `DesiredPeer`, `DesiredAdvertisement`, `DesiredPolicy`, `RuntimeStatus`; re-exports cosmos enums | No         |
| `internal/hash`               | galactic-router | SHA-256 fingerprint of `DesiredRouter` for no-op suppression                                        | No         |
| `internal/metadata`           | both            | Build-time vars (`Version`, `GitCommit`, `GitTreeState`, `BuildDate`) stamped via `-ldflags`         | No         |
| `internal/cni`                | galactic-cni    | `cmdAdd` / `cmdDel`; CNI PluginConf parsing; BGPAdvertisement lifecycle; delegates kernel work to plumbing | No         |
| `internal/cni/route`          | galactic-cni    | Host-side static route add/delete via netlink                                                        | No         |
| `internal/cni/veth`           | galactic-cni    | veth pair create/delete                                                                               | No         |
| `internal/plumbing/intf`      | both            | Deterministic interface naming (`G{vpc9}{att3}V/H/G`); base62↔hex encoding | No |
| `internal/plumbing/srv6`      | galactic-cni    | SRv6 END.DT46 ingress route add/delete via netlink                                                   | No         |
| `internal/plumbing/vrf`       | galactic-cni    | Linux VRF create/delete/lookup via netlink                                                           | No         |
| `internal/plumbing/sysctl`    | galactic-cni    | Per-interface sysctl helpers                                                                          | No         |

---

## External Dependencies

| Dependency                              | Version  | Purpose                                                  |
|-----------------------------------------|----------|----------------------------------------------------------|
| `github.com/osrg/gobgp/v4`             | v4.6.0   | Embedded BGP server (tenant role)                        |
| `go.miloapis.com/cosmos`               | pinned   | Cosmos BGP CRD API types (BGPRouter, BGPPeer, etc.)      |
| `sigs.k8s.io/controller-runtime`       | v0.24.1  | Reconciler framework, manager, field indexes             |
| `github.com/containernetworking/cni`   | v1.3.0   | CNI plugin spec, skel, invoke                            |
| `github.com/vishvananda/netlink`        | pinned   | Linux netlink: VRF, veth, SRv6 routes                   |
| `github.com/kenshaw/baseconv`           | v0.1.1   | Base62↔hex conversion for interface names               |
| `github.com/lorenzosaino/go-sysctl`    | v0.3.1   | Interface sysctl helpers                                 |
| `github.com/coreos/go-iptables`         | v0.8.0   | iptables manipulation (CNI path)                         |
| `google.golang.org/grpc`               | v1.81.1  | gRPC health server on :5000                              |
| `k8s.io/api`, `k8s.io/client-go`       | v0.36.x  | Kubernetes client, Node/Secret API types                 |

---

## Key Design Decisions

- **USID per endpoint.** Each (VPC, VPCAttachment) pair is assigned a unique /128 USID by the companion operator. The CNI installs an END.DT46 decap route for that /128 and advertises it as the EVPN GWIPAddress. VPC identity is not encoded in the SID.
- **Base62 interface names.** Kernel interface names use the format `G{9-char-vpc-base62}{3-char-att-base62}{suffix}` (suffix: `V` = VRF, `H` = host veth, `G` = guest veth), fitting in the 14-character kernel limit. The hex form is used for BGP and SRv6; base62 for kernel interfaces.
- **GoBGP embedded, lazy-started.** GoBGP runs in-process and starts only when the first `BGPRouter` is reconciled (`listenPort=-1`, outbound-only). ASN or RouterID changes trigger a full `Reconfigure` (fresh `BgpServer` — `StopBgp` is not called because it permanently terminates the v4 Serve loop).
- **CRD-driven config, no sidecar gRPC.** `galactic-router` watches cosmos BGP CRDs directly via controller-runtime. The CNI writes a `BGPAdvertisement` CRD; the router reconciler picks it up. No in-node gRPC calls.
- **Hash-based no-op suppression.** SHA-256 over the sorted `DesiredRouter` prevents redundant GoBGP Apply calls on every CRD event.
- **RuntimeFactory pattern.** `GALACTIC_ROUTER_ROUTER_MODE=tenant` selects GoBGP; `GALACTIC_ROUTER_ROUTER_MODE=fabric` selects FRR (Phase 2 stub). The binary is selected at startup; no controller changes are needed for Phase 2.
- **gRPC health on :5000.** Liveness and readiness probes use the gRPC health protocol (`google.golang.org/grpc/health`) on port 5000. No HTTP health endpoint.

---

## Testing

| Layer      | Command          | Framework           | Scope                                                                |
|------------|------------------|---------------------|----------------------------------------------------------------------|
| Unit       | `task test:unit` | `go test -race`     | `internal/cni` (`buildResult`, `parseConf`, `routeTarget`, `lookupBGPRouter`), `internal/reconcile`, `internal/controller`, `internal/plumbing/intf`, `internal/runtime/gobgp` (partial), `internal/runtime/frr` |
| E2E        | `task test:e2e`  | Kind + `go test`    | Full BGPRouter lifecycle in a Kind cluster; builds and loads image    |
| CI full    | `task ci`        | all of the above    | lint → build → test:unit → test:e2e                                  |

Kernel-path packages (`internal/cni`, `internal/plumbing/srv6`, `internal/plumbing/vrf`) have no unit tests — they require `CAP_NET_ADMIN`. New code in those paths should use e2e tests. `internal/plumbing/intf` is pure-function and fully unit-testable.

---

## CI/CD

**Pipeline:** `.github/workflows/ci.yaml`

Runs on every PR and push to `main`. Two tiers:

- **Tier 1 (parallel):** `lint` (golangci-lint v2.12.2 + yamlfmt), `test-unit` (race detector + codecov upload), `build`
- **Tier 2 (sequential):** `test-e2e` — blocked on all Tier 1 jobs passing

**Release pipeline:** `.github/workflows/release.yaml`

Triggered by `v*` tags. Builds and pushes `ghcr.io/datum-cloud/galactic:{version,major.minor,major,sha}` for `linux/amd64` and `linux/arm64`. Uses GHA layer cache. Creates a GitHub Release with generated release notes.

**Container image:** `containers/galactic/Dockerfile` — multi-stage distroless build. Both `galactic-cni` and `galactic-router` binaries are in the same image (ENTRYPOINT defaults to `galactic-cni`; DaemonSet overrides to `galactic-router`). Build args: `VERSION`, `GIT_COMMIT`, `GIT_TREE_STATE`, `BUILD_DATE` — stamped into binary via `-ldflags`.

---

## Known Constraints

- **GoBGP RIB is ephemeral.** All BGP state is in-process memory. On restart, sessions and paths must be re-established from CRD state; controller-runtime's reconcile loop handles this automatically.
- **EVPN Type 5 deferred.** `BGPAdvertisement` does not carry a Route Distinguisher field in the current cosmos API. `galactic-router` returns `ErrMissingRouteDistinguisher` for l2vpn/evpn advertisements and sets `Accepted=False` on the CRD.
- **No kernel-path unit tests.** `internal/cni`, `internal/plumbing/srv6`, and `internal/plumbing/vrf` require `CAP_NET_ADMIN` and a real kernel. `internal/plumbing/intf` is fully unit-testable (pure functions only). Coverage comes from the e2e suite (`task test:e2e`).

---

## For Claude

**Where to start for each concern:**

| Concern                                    | Start here                                                   |
|--------------------------------------------|--------------------------------------------------------------|
| CNI attach/detach flow                     | `internal/cni/cni.go:cmdAdd` / `cmdDel`                     |
| CRD → BGP translation                      | `internal/reconcile/reconcile.go:BuildDesiredRouter`         |
| BGP runtime application (GoBGP)            | `internal/runtime/gobgp/runtime.go:Apply`                   |
| BGP peer / advertisement / policy CRUD     | `internal/runtime/gobgp/peers.go`, `paths.go`, `policies.go`|
| Controller watch graph                     | `internal/controller/bgprouter_controller.go:SetupWithManager` |
| CRD status update logic                    | `internal/controller/status.go`, `bgprouter_controller.go:updateRouterStatus` |
| Interface naming / base62 encoding         | `internal/plumbing/intf/intf.go`                             |
| Hash-based no-op suppression               | `internal/hash/hash.go`; annotation `galactic.datum.net/config-hash` on BGPRouter |
| GoBGP server lifecycle (start/reconfigure) | `internal/runtime/gobgp/server.go`                          |

**Stable vs. frequently changed:**
- Stable: `internal/plumbing/` (pure kernel primitives), `internal/model/types.go`, `internal/runtime/runtime.go` (interface)
- Active: `internal/controller/` (status conditions, watch graph), `internal/runtime/gobgp/` (EVPN path construction), `internal/reconcile/` (validation rules)
- Stub / incomplete: `internal/runtime/frr/` (returns `errNotImplemented` everywhere)

**Non-obvious patterns:**
- `BGPPeer` and `BGPPolicy` reconcilers do not call Apply themselves — they enqueue their owning `BGPRouter`, which is the only reconciler that calls `RuntimeManager.Apply`. This means touching any associated resource triggers a full router reconcile.
- `SecretReconciler.Reconcile()` is a no-op body — it exists only to register the watch; the real work is done by `secretToRouterRequests` mapping changes to BGPRouter reconcile requests.
- Same for `NodeReconciler` — the reconcile body is empty; the watch mapper `nodeToRouterRequests` does the work.
- `peerStatusRequeue = 30s` periodic requeue keeps BGPPeer session state current because BGP FSM transitions are not Kubernetes events.
- `annotationConfigHash` is persisted on the BGPRouter object (not just in memory) so no-op detection survives pod restarts without re-applying GoBGP config.
- GoBGP `Reconfigure()` calls `old.Stop()` then creates a fresh `BgpServer` — it does NOT call the BGP-level `StopBgp`/`StartBgp` on the old server, avoiding the v4 "Serve loop permanently dead" problem.
- Both binaries are in the same container image. The DaemonSet for `galactic-router` overrides the entrypoint in its spec; `galactic-cni` uses the default entrypoint and is installed by a CNI installer init container pattern.
