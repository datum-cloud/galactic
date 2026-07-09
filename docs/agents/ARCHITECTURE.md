# Architecture

> Galactic is the SRv6 data plane for multi-cloud VPC networking, deployed as two
> binaries on each Kubernetes node: a CNI plugin that attaches containers to VPC
> networks, and a router that reconciles BGP CRDs and drives an embedded
> GoBGP server to distribute EVPN (L2VPN/EVPN AFI/SAFI) paths between nodes.

_Last updated: 2026-07-08_

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
CNI config and acts on them. `galactic-router` reconciles BGP CRDs
(`go.datum.net/network`) directly — no gRPC sidecar, no provider CRD lifecycle.

### SRv6 SID encoding

Each container endpoint is assigned a /128 USID (Unique Local SID, RFC 8986 Section 3.2).
The companion operator allocates a unique /128 per (VPC, VPCAttachment) pair and injects
it into the NAD as `srv6_sid`. The CNI installs an END.DT46 decap route for that exact
/128 and advertises it as the EVPN Type 5 GWIPAddress.

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
│   ├── galactic-cni/        # CNI binary
│   └── galactic-router/     # Router binary (controller-runtime reconciler)
├── internal/
│   ├── controller/          # controller-runtime reconcilers (BGPRouter, BGPPeer,
│   │                        #   BGPAdvertisement, BGPVRFInstance, BGPPolicy, Secret,
│   │                        #   Node, GC); field index registration; status helpers
│   ├── reconcile/           # CRD → DesiredRouter translation (node/role checks,
│   │                        #   secret resolution, IPv6 next-hop from Node)
│   ├── runtime/             # RouterRuntime interface + RuntimeManager
│   │   ├── gobgp/           # GoBGP RouterRuntime (tenant mode)
│   │   └── frr/             # FRR RouterRuntime stub (fabric mode)
│   ├── model/               # DesiredRouter and family; re-exports BGP API enums
│   ├── hash/                # SHA-256 change detection over DesiredRouter
│   ├── metadata/            # Build-time version info (Version, GitCommit, etc.)
│   ├── gc/                  # Orphaned BGPAdvertisement/BGPVRFInstance CRD and
│   │                        #   stale kernel VRF cleanup, driven by the GC controller
│   ├── cni/                 # CNI cmdAdd / cmdDel / cmdCheck, PluginConf parsing,
│   │                        #   BGP CRD publish, built-in IPAM wiring
│   │   ├── ipam/            # Built-in IPv6 pool + static IP allocators
│   │   ├── route/           # Host-side static routes via netlink
│   │   ├── tap/             # Tap interface management (VM workloads)
│   │   └── veth/            # veth pair management
│   └── plumbing/            # Low-level kernel and network primitives
│       ├── intf/            # Interface naming, base62↔hex encoding
│       ├── srv6/            # SRv6 ingress route add/del (END.DT46)
│       ├── sysctl/          # Interface sysctl helpers
│       └── vrf/             # Linux VRF create/delete/lookup
├── config/                  # Kustomize-composed; `kubectl apply -k config/` deploys everything
│   ├── system/              # galactic-system namespace (shared by both components)
│   ├── router/              # Shared RBAC/ServiceAccount, plus:
│   │   ├── base/            #   common DaemonSet spec
│   │   ├── tenant/          #   per-node role: base + node affinity excluding control-plane
│   │   │                    #     and tenant-control nodes
│   │   └── tenant-control/  #   route-reflector role: base + GALACTIC_ROUTER_REFLECTOR=true,
│   │                        #     opt-in via the galactic.datum.net/node=control node label
│   └── cni/                 # DaemonSet installing galactic-cni onto /opt/cni/bin via hostPath
├── deploy/
│   └── containerlab/        # ContainerLab lab topology and scripts
└── containers/
    └── galactic-cni/        # e2e-test image build (galactic-cni + host-device only)
```

There is no production release Dockerfile/pipeline in the repo — see Known Constraints below.

---

## Data Flow

See [docs/cni-sequence.md](../cni-sequence.md) for the full CNI ADD/DEL sequence diagram.

See [docs/agent-startup.md](../agent-startup.md) for the router startup sequence diagram.

---

## Components

| Component | Binary | Role |
|-----------|--------|------|
| `internal/controller` | `galactic-router` | controller-runtime reconcilers; field index registration; CRD status helpers |
| `internal/reconcile` | `galactic-router` | CRD → DesiredRouter translation |
| `internal/runtime/gobgp` | `galactic-router` | Embedded GoBGP server (`--mode=tenant`) |
| `internal/runtime/frr` | `galactic-router` | FRR stub (`--mode=fabric`) — returns "not implemented" for every method |
| `internal/model` | `galactic-router` | Internal BGP model types |
| `internal/hash` | `galactic-router` | Change detection |
| `internal/metadata` | both | Build-time version info stamped via `-ldflags` |
| `internal/gc` | `galactic-router` | Orphaned CRD/VRF cleanup, driven by the GC controller's ticker |
| `internal/cni` | `galactic-cni` | CNI cmdAdd / cmdDel / cmdCheck; BGP CRD publish |
| `internal/cni/ipam` | `galactic-cni` | Built-in IPv6 pool + static allocators |
| `internal/cni/tap` | `galactic-cni` | Tap interface create/delete (VM workloads) |
| `internal/plumbing/intf` | both | Interface naming, base62↔hex encoding |
| `internal/plumbing/srv6` | both | SRv6 ingress route add/del (END.DT46) |
| `internal/plumbing/vrf` | both | Linux VRF create/delete/lookup |
| `internal/plumbing/sysctl` | both | Interface sysctl helpers |

---

## Entry Points

### `cmd/galactic-cni/main.go` — CNI plugin

A cobra/viper command, not a bare `skel.PluginMain` call. `newRootCommand()` builds
a root command with `--node-name`/`-n` and `--enable-local-ipam` flags (bound to
`GALACTIC_CNI_NODE_NAME` or `NODE_NAME`, and `GALACTIC_CNI_ENABLE_LOCAL_IPAM`), plus
`--build-info` and `--version`/`-V` utility flags. On `RunE`:

1. Handle `--build-info`/`--version` and return early if set.
2. If `CNI_COMMAND=VERSION`, encode supported CNI spec versions and return — this
   bypasses config validation since `--node-name` isn't needed for a VERSION query.
3. Validate config (`--node-name` required).
4. Re-export the resolved node name into `NODE_NAME` (the `internal/cni` package
   reads `os.Getenv("NODE_NAME")` directly).
5. Call `cni.SetEnableLocalIPAM(...)`, then `cni.RunPlugin()`, which hands control
   to `skel.PluginMainFuncs` (ADD/DEL/CHECK read from stdin per the CNI spec).

See [docs/cni-sequence.md](../cni-sequence.md) for the full ADD/DEL sequence.

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
3. Build controller-runtime manager (metrics on configurable port, default `:8080`;
   no HTTP health endpoint).
4. Start gRPC health server on a configurable port (default `:5000`).
5. RBAC pre-flight: `checkWatchPermissions` (in `main.go`) issues a
   `SelfSubjectAccessReview` for every watched resource type and logs an actionable
   error if watch RBAC is missing (informer caches would otherwise silently never sync).
6. Register field indexes: BGPPeer→secret, BGPPeer→router, BGPPolicy→router,
   BGPAdvertisement→router, BGPVRFInstance→router, BGPRouter→node.
7. Register eight controllers: BGPRouter, BGPPeer, BGPAdvertisement, BGPVRFInstance,
   BGPPolicy, Secret, Node, and GC (the GC controller also starts a ticker goroutine
   that waits for cache sync, then runs on `--gc-interval`, default 5m).
8. `mgr.Start(ctx)` — blocks until the signal-handler context is cancelled.

---

## Configuration

### galactic-router environment variables

| Variable                            | Required | Default            | Description                                                             |
|-------------------------------------|----------|--------------------|--------------------------------------------------------------------------|
| `GALACTIC_ROUTER_NODE_NAME`         | Yes      | —                  | Kubernetes node name; filters which BGPRouter CRDs this instance owns   |
| `GALACTIC_ROUTER_ROUTER_MODE`       | Yes      | —                  | `transit` (unsupported stub), `fabric` (FRR stub), or `tenant` (GoBGP)  |
| `GALACTIC_ROUTER_REFLECTOR`         | No       | `false`            | Enable route reflector mode; only valid for `fabric`/`tenant`          |
| `GALACTIC_ROUTER_BGP_LISTEN_PORT`   | No       | `179`              | BGP TCP listen port; `-1` disables inbound connections (outbound-only)  |
| `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS` | No       | —                  | Source address for outgoing BGP TCP connections (numbered underlay use) |
| `GALACTIC_ROUTER_METRICS_PORT`      | No       | `8080`             | controller-runtime Prometheus metrics port                             |
| `GALACTIC_ROUTER_GRPC_HEALTH_PORT`  | No       | `5000`             | gRPC health check port (liveness/readiness probes)                     |
| `GALACTIC_ROUTER_GC_NAMESPACE`      | No       | `galactic-system`  | Namespace the GC controller scans for orphaned CRDs                    |
| `GALACTIC_ROUTER_GC_INTERVAL`       | No       | `5m`               | GC controller sweep interval                                           |

See [docs/router/configuration.md](../router/configuration.md) for the full reference, including CLI flags and precedence.

### galactic-cni CNI config fields (`PluginConf`)

| Field           | Type     | Description                                                             |
|-----------------|----------|-------------------------------------------------------------------------|
| `vpc`           | string   | Base62-encoded 48-bit VPC identifier                                    |
| `vpcattachment` | string   | Base62-encoded 16-bit VPCAttachment identifier                          |
| `interface_type`| string   | `veth` (default) or `tap`; tap mode omits IPAM and guest-side config   |
| `srv6_sid`      | string   | Optional pre-computed USID (/128) for this endpoint, bare IPv6 or `/128` CIDR; SRv6 ingress setup is skipped when empty or in tap mode |
| `namespace`     | string   | Kubernetes namespace for BGP CRDs; defaults to `default`               |
| `mtu`           | int      | MTU for the veth pair; 0 uses kernel default                            |
| `terminations`  | array    | Static routes to install on the host-side veth (`network`, `via`)      |
| `ipam`          | object   | Built-in IPv6 pool/static allocator config (Galactic has no external IPAM delegation); ignored in tap mode. See [docs/cni/configuration.md](../cni/configuration.md). |

### galactic-cni environment variables

| Variable                          | Required | Description                                                       |
|------------------------------------|----------|--------------------------------------------------------------------|
| `GALACTIC_CNI_NODE_NAME`          | Yes*     | Kubernetes node name; used to look up the owning BGPRouter         |
| `NODE_NAME`                        | Yes*     | Accepted fallback for node name; also what `internal/cni` reads directly at runtime (the CLI layer re-exports the resolved value into this var) |
| `GALACTIC_CNI_ENABLE_LOCAL_IPAM`  | No       | Enables the built-in IPv6 pool allocator when no explicit `ipam` block is configured (default `false`) |

\* One of `GALACTIC_CNI_NODE_NAME`/`NODE_NAME` or `--node-name` is required.

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

This is the `veth`-mode result. In `tap` mode the result has a single interface (the
host-side tap, empty sandbox) with no `ips`/`routes` — no guest endpoint is reported
since the fd is handed off to the VM hypervisor, not moved into a container netns.

The result is printed to Multus **before** SRv6 ingress setup and BGP CRD publish run
(see [docs/cni-sequence.md](../cni-sequence.md)) — a successful ADD response does not
guarantee the BGPAdvertisement/BGPVRFInstance CRDs exist yet.

On DEL, the result contains only `cniVersion` (empty result; DEL only deallocates the
pod's IPAM bookkeeping and does not attempt to unwind kernel/CRD state — see the
`cmdDel` note in [docs/cni-sequence.md](../cni-sequence.md) and Known Constraints below).

---

## Module / Package Reference

| Package                       | Binary          | Responsibility                                                                                      | Owns state |
|-------------------------------|-----------------|-----------------------------------------------------------------------------------------------------|------------|
| `internal/controller`         | galactic-router | controller-runtime reconcilers (BGPRouter, BGPPeer, BGPAdvertisement, BGPVRFInstance, BGPPolicy, Node, Secret, GC); field index registration; CRD status helpers | No         |
| `internal/reconcile`          | galactic-router | Translates BGPRouter + related CRDs into `model.DesiredRouter`; enforces node/role filtering, timer validation, AFI validation | No         |
| `internal/runtime`            | galactic-router | `RouterRuntime` interface; `RuntimeManager` (keyed map of live runtimes, double-checked lock create) | Yes (runtime map) |
| `internal/runtime/gobgp`      | galactic-router | Embeds GoBGP v4; lazy-starts on first Apply; handles peer/VRF/EVPN-path/policy add/update/delete; tracks established timestamps | Yes (per-router) |
| `internal/runtime/frr`        | galactic-router | FRR stub — returns "not implemented" for every method                                               | No         |
| `internal/model`              | both            | `DesiredRouter`, `DesiredPeer`, `DesiredAdvertisement`, `DesiredPolicy`, `DesiredVRFInstance`, `RuntimeStatus`; re-exports BGP API enums | No         |
| `internal/hash`               | galactic-router | SHA-256 fingerprint of `DesiredRouter` for no-op suppression                                        | No         |
| `internal/metadata`           | both            | Build-time vars (`Version`, `GitCommit`, `GitTreeState`, `BuildDate`) stamped via `-ldflags`         | No         |
| `internal/gc`                 | galactic-router | Collects orphaned `BGPAdvertisement`/`BGPVRFInstance` CRDs and stale kernel VRFs; invoked by the GC controller's ticker | No |
| `internal/cni`                | galactic-cni    | `cmdAdd` / `cmdDel` / `cmdCheck`; CNI PluginConf parsing; BGPVRFInstance/BGPAdvertisement lifecycle; delegates kernel work to plumbing | No |
| `internal/cni/ipam`           | galactic-cni    | Built-in IPv6 pool allocator (in-memory, ephemeral) and static IP allocator                          | Yes (pool allocations) |
| `internal/cni/route`          | galactic-cni    | Host-side static route add/delete via netlink                                                        | No         |
| `internal/cni/tap`            | galactic-cni    | Tap interface create/delete for VM workloads (Kata, Firecracker, QEMU)                                | No         |
| `internal/cni/veth`           | galactic-cni    | veth pair create/delete                                                                               | No         |
| `internal/plumbing/intf`      | both            | Deterministic interface naming (`G{vpc9}{att3}V/H/G`); base62↔hex encoding | No |
| `internal/plumbing/srv6`      | galactic-cni    | SRv6 END.DT46 ingress route add/delete via netlink                                                   | No         |
| `internal/plumbing/vrf`       | galactic-cni    | Linux VRF create/delete/lookup via netlink                                                           | No         |
| `internal/plumbing/sysctl`    | galactic-cni    | Per-interface sysctl helpers                                                                          | No         |

---

## External Dependencies

| Dependency                              | Version  | Purpose                                                  |
|-----------------------------------------|----------|----------------------------------------------------------|
| `github.com/osrg/gobgp/v4`             | v4.7.0   | Embedded BGP server (tenant mode)                        |
| `go.datum.net/network`                  | bumped frequently | BGP CRD API types (BGPRouter, BGPPeer, BGPAdvertisement, BGPPolicy, BGPVRFInstance) |
| `sigs.k8s.io/controller-runtime`       | v0.24.1  | Reconciler framework, manager, field indexes             |
| `github.com/spf13/cobra`               | v1.10.2  | CLI command/flag handling for both binaries              |
| `github.com/spf13/viper`               | v1.21.0  | Config resolution (flags/env/defaults) for both binaries |
| `github.com/containernetworking/cni`   | v1.3.0   | CNI plugin spec, skel, invoke                            |
| `github.com/containernetworking/plugins` | v1.9.1 | `host-device` plugin, delegated to for moving the guest veth into the pod netns |
| `github.com/vishvananda/netlink`        | pinned pseudo-version | Linux netlink: VRF, veth, SRv6 routes           |
| `github.com/kenshaw/baseconv`           | v0.1.1   | Base62↔hex conversion for interface names               |
| `github.com/lorenzosaino/go-sysctl`    | v0.3.1   | Interface sysctl helpers                                 |
| `github.com/coreos/go-iptables`         | v0.8.0   | iptables manipulation (CNI path)                         |
| `google.golang.org/grpc`               | v1.82.0  | gRPC health server (default :5000)                       |
| `k8s.io/api`, `k8s.io/client-go`       | v0.36.0  | Kubernetes client, Node/Secret API types                 |

---

## Key Design Decisions

- **USID per endpoint.** Each (VPC, VPCAttachment) pair is assigned a unique /128 USID (via the CNI config's `srv6_sid` field, pre-computed upstream). The CNI installs an END.DT46 decap route for that /128 and stores it as an annotation for `galactic-router` to use as the EVPN GWIPAddress. VPC identity is not encoded in the SID itself — VPC scoping comes from the BGPVRFInstance's route target instead.
- **Base62 interface names.** Kernel interface names use the format `G{9-char-vpc-base62}{3-char-att-base62}{suffix}` (suffix: `V` = VRF, `H` = host veth/tap, `G` = guest veth pre-move), fitting in the 15-character kernel limit. The hex form is used for BGP route targets; base62 for kernel interfaces.
- **GoBGP embedded, lazy-started.** GoBGP runs in-process (`--mode=tenant` only) and starts only when the first `BGPRouter` is reconciled for that router; `Apply` re-runs on every subsequent reconcile too (subject to hash-based no-op suppression), re-applying peers/VRFs/EVPN/policies each time. `listenPort` defaults to `179`; `-1` (outbound-only) is an operator choice for specific deployments, not the codebase default. ASN or RouterID changes trigger a full `Reconfigure` (fresh `BgpServer` — `StopBgp` is not called because it permanently terminates the v4 Serve loop).
- **VRF/route-target model via BGPVRFInstance.** The CNI creates a `BGPVRFInstance` (RouteDistinguisher + import/export Route Targets, all set to the derived RT) before the `BGPAdvertisement`; `galactic-router`'s GoBGP runtime applies VRFs (`applyVRFs`) before originating EVPN paths (`applyEVPN`).
- **CRD-driven config, no sidecar gRPC.** `galactic-router` watches BGP CRDs directly via controller-runtime. The CNI writes `BGPVRFInstance`/`BGPAdvertisement` CRDs; the router reconciler picks them up. No in-node gRPC calls between the two binaries.
- **Hash-based no-op suppression.** SHA-256 over the sorted `DesiredRouter` prevents redundant GoBGP Apply calls on every CRD event.
- **RuntimeFactory pattern.** `--mode=tenant` (`GALACTIC_ROUTER_ROUTER_MODE=tenant`) selects GoBGP; `--mode=fabric` selects the FRR stub; `--mode=transit` is accepted by validation but returns an error at startup (not yet implemented). The mode is selected at startup; no controller changes are needed to add a new mode.
- **DEL is intentionally minimal; GC reclaims shared state asynchronously.** `cmdDel` only deallocates the pod's IPAM bookkeeping — it does not delete the VRF, veth/tap, routes, SRv6 ingress route, or `BGPAdvertisement`/`BGPVRFInstance` CRDs, because those are keyed by `(vpc, vpcAttachment)` and may be shared/reused by another pod (deleting them in DEL would race with a concurrent ADD during pod restarts). `galactic-router`'s GC controller (ticker-driven, default every 5m) reclaims orphaned CRDs and stale kernel VRFs once no live container still references them.
- **gRPC health, configurable port.** Liveness and readiness probes use the gRPC health protocol (`google.golang.org/grpc/health`) on a configurable port (default `5000`). No HTTP health endpoint.

---

## Testing

| Layer      | Command          | Framework           | Scope                                                                |
|------------|------------------|---------------------|------------------------------------------------------------------------|
| Unit       | `task test:unit` | `go test -race`     | `internal/cni` (`cni_test.go`, `bgp_test.go`, `netns_test.go` — `buildResult`, `parseConf`, `routeTarget`, `lookupBGPRouter`), `internal/cni/{ipam,tap,veth}`, `internal/plumbing/srv6`, `internal/gc`, `internal/reconcile`, `internal/controller`, `internal/plumbing/intf`, `internal/metadata`, `internal/runtime/gobgp` (partial), `internal/runtime/frr` |
| E2E        | `task test:e2e`  | Kind + `go test`    | Full BGPRouter lifecycle in a Kind cluster; builds and loads image    |
| CI full    | `task ci`        | all of the above    | lint → build → test:unit → test:e2e                                  |

`internal/plumbing/vrf` has no unit tests — it requires `CAP_NET_ADMIN` and a real kernel. `internal/cni` and `internal/plumbing/srv6` now have unit coverage for their pure-logic paths (this used to not be the case). `internal/plumbing/intf` is pure-function and fully unit-testable.

---

## CI/CD

**Pipeline:** `.github/workflows/ci.yaml`

Runs on every PR and push to `main`. Two tiers:

- **Tier 1 (parallel):** `lint` (golangci-lint v2.12.2 + yamlfmt), `test-unit` (race detector + codecov upload), `build`
- **Tier 2 (sequential):** `test-e2e` — blocked on all Tier 1 jobs passing

**Release pipeline:** none currently. `.github/workflows/release.yaml` (previously built and pushed `ghcr.io/datum-cloud/galactic:{version,major.minor,major,sha}`) was removed along with `containers/galactic/Dockerfile` after the image was found to advertise `galactic-router` (via `config/router/base/daemonset.yaml`'s `command: [/galactic-router]`) without ever building it. There is currently no path to a published production image for either binary — see Known Constraints below.

**Container image:** `containers/galactic-cni/Dockerfile` — multi-stage build (golang builder → distroless → final Alpine stage for `iproute2`/`nsenter`); builds only `galactic-cni` plus the delegated `host-device` CNI plugin binary, `ENTRYPOINT ["/galactic-cni"]`. This is used exclusively by `task test:e2e` (`scripts/ci.sh e2etest` builds it, tags `galactic-cni:e2e` by default, and `kind load`s it into the ephemeral e2e cluster) — it is not part of any release/publish path.

---

## Known Constraints

- **No production release image build path exists.** `containers/galactic/Dockerfile`, `task docker-build`, and `.github/workflows/release.yaml` were all removed after the image was found to advertise `galactic-router` (via `config/router/base/daemonset.yaml`'s `command: [/galactic-router]`) without ever building it. `config/router/base/daemonset.yaml` and `config/cni/daemonset.yaml` both still reference `ghcr.io/datum-cloud/galactic:latest`, which nothing in the repo publishes anymore. `containers/galactic-cni/Dockerfile` exists but is scoped to e2e testing only (`task test:e2e`), builds only `galactic-cni`, and is never pushed anywhere.
- **GoBGP RIB is ephemeral.** All BGP state is in-process memory. On restart, sessions and paths must be re-established from CRD state; controller-runtime's reconcile loop handles this automatically.
- **EVPN Type 5 is implemented, not deferred.** `internal/runtime/gobgp/paths.go`'s `buildEVPNPaths` builds real `EVPNIPPrefixRoute` NLRIs, deriving the Route Distinguisher from `routerID + ":0"` (not from the CRD). The `BGPVRFInstance` CRD carries its own explicit `RouteDistinguisher` and import/export Route Targets (see Key Design Decisions above), applied via `internal/runtime/gobgp/runtime.go`'s `applyVRFs`. There is no `ErrMissingRouteDistinguisher` or similar rejection path in the current code.
- **`cmdDel` does not tear down shared kernel/CRD state.** By design (see Key Design Decisions above) — cleanup of VRF, veth/tap, routes, SRv6 ingress, and BGP CRDs is deferred to `galactic-router`'s asynchronous GC controller, not performed synchronously in `cmdDel`.
- **`internal/plumbing/vrf` has no unit tests.** It requires `CAP_NET_ADMIN` and a real kernel. `internal/cni` and `internal/plumbing/srv6` do now have unit coverage for their pure-logic paths. `internal/plumbing/intf` is fully unit-testable (pure functions only). Kernel-path coverage otherwise comes from the e2e suite (`task test:e2e`).
- **`--mode=transit` is unimplemented.** Accepted by CLI/env validation, but `runCmd` returns an error at startup ("mode=transit is not yet supported").

---

## For Claude

**Where to start for each concern:**

| Concern                                    | Start here                                                   |
|--------------------------------------------|--------------------------------------------------------------|
| CNI attach/detach flow                     | `internal/cni/ops_add.go:cmdAdd`, `internal/cni/ops_del.go:cmdDel` (`internal/cni/cni.go` only holds `RunPlugin`) |
| BGP CRD publish (VRF + advertisement)      | `internal/cni/bgp.go:publishBGPState`                        |
| CRD → BGP translation                      | `internal/reconcile/reconcile.go:BuildDesiredRouter`         |
| BGP runtime application (GoBGP)            | `internal/runtime/gobgp/runtime.go:Apply`                   |
| BGP peer / VRF / advertisement / policy CRUD | `internal/runtime/gobgp/peers.go`, `runtime.go` (`applyVRFs`), `paths.go`, `policies.go` |
| Controller watch graph                     | `internal/controller/bgprouter_controller.go:SetupWithManager` |
| CRD status update logic                    | `internal/controller/status.go`, `bgprouter_controller.go:updateRouterStatus` |
| Orphaned CRD/VRF garbage collection         | `internal/controller/gc_controller.go`, `internal/gc/gc.go`   |
| RBAC pre-flight self-check                 | `cmd/galactic-router/main.go:checkWatchPermissions`           |
| Interface naming / base62 encoding         | `internal/plumbing/intf/intf.go`                             |
| Hash-based no-op suppression               | `internal/hash/hash.go`; annotation `galactic.datum.net/config-hash` on BGPRouter |
| GoBGP server lifecycle (start/reconfigure) | `internal/runtime/gobgp/server.go`                          |

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
- The CNI ADD result is printed to Multus **before** SRv6 ingress setup and BGP CRD publish run (`publishBGPState` is called after `PrintResult` inside `cmdAdd`) — a successful ADD response does not by itself guarantee the BGP CRDs exist yet.
- `cmdDel` never deletes the VRF, veth/tap, routes, SRv6 ingress route, or `BGPAdvertisement`/`BGPVRFInstance` CRDs — only IPAM bookkeeping. Shared-resource cleanup is entirely the GC controller's job (`internal/gc`), to avoid racing a concurrent ADD during pod restarts.
- **Known gap:** there is no production release image build path (the old shared Dockerfile, `task docker-build`, and the release workflow were all removed — see Known Constraints above). `containers/galactic-cni/Dockerfile` only exists for `task test:e2e` and is never published.
