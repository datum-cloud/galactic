# Repository Guidelines

## Architecture Reference

The architecture reference is split into three component-scoped documents —
each self-contained (layout, entry points, data flow, configuration, module
reference, external dependencies, key design decisions, testing, CI/CD, known
constraints, and a "For Claude" quick-start table). Start from whichever one
matches the binary or subsystem you're touching; each cross-links to the
other two where the boundary matters:

| Document                                                                   | Covers                                                                                                                                            | Start here when you're touching...                                                                                                                                                                                                                                                   |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [docs/agents/ARCHITECTURE-CNI.md](docs/agents/ARCHITECTURE-CNI.md)         | The CNI attach chain: `galactic-cni` (installer), `galactic-veth`, `galactic-tap`, `galactic-ipam`, `galactic-bgp`, `galactic-route` | Pod/VM attach or detach behavior, CNI config fields/conflists, IPAM, the SRv6 uSID TC-BPF datapath's CNI-side registration, or anything under `cmd/galactic-{cni,veth,tap,ipam,bgp,route}`, `internal/cni*`, `internal/installer`                  |
| [docs/agents/ARCHITECTURE-ROUTER.md](docs/agents/ARCHITECTURE-ROUTER.md)   | The BGP/EVPN control plane: `galactic-router` (BGPRouter/BGPPeer/BGPAdvertisement/BGPPolicy/BGPVRFInstance reconcilers, embedded GoBGP, GC)       | BGP CRD reconciliation, GoBGP runtime behavior, EVPN path construction, orphaned-CRD/VRF garbage collection, or anything under `cmd/galactic-router`, `internal/reconcile`, `internal/runtime`, `internal/gc`, `internal/model`, `internal/hash`                                     |
| [docs/agents/ARCHITECTURE-GATEWAY.md](docs/agents/ARCHITECTURE-GATEWAY.md) | The edge XDP NAT+LB gateway: `galactic-gateway`, `NetworkGateway`/`NetworkRule` reconcilers, the edge XDP datapath                                | Ingress load-balancing/NAT, `NetworkGateway`/`NetworkRule` CRDs, Active-Active BGP placement, or anything under `cmd/galactic-gateway`, `internal/gateway`, `internal/plumbing/ebpf/edge{prog,map,attach}`, the `NetworkGateway`/`NetworkRule`-related code in `internal/controller` |

These three documents supersede the former monolithic `ARCHITECTURE.md`,
which is now a short pointer to them.

## Purpose

Galactic is the SRv6 data plane for multi-cloud VPC networking. It consists of three binaries deployed on each Kubernetes node (the third only on dedicated gateway-role nodes):

- **`galactic-veth`** — CNI plugin that wires containers into VPC networks (VRF, veth, SRv6 ingress route) and writes `BGPAdvertisement` CRDs.
- **`galactic-router`** — controller-runtime reconciler that watches BGP CRDs and drives an embedded GoBGP server per node to distribute EVPN paths.
- **`galactic-gateway`** — controller-runtime process that loads an edge XDP NAT+LB datapath on gateway-role nodes and drives it from `NetworkGateway`/`NetworkRule` CRDs, publishing an Active-Active BGP local-preference model over the same EVPN mesh.

VPC and VPCAttachment CRD management lives in a separate companion operator; Galactic receives pre-populated identifiers through the CNI config and acts on them.

**Data flow:** CNI invoked with pre-populated VPC/VPCAttachment identifiers → CNI creates kernel SRv6 state and writes a `BGPAdvertisement` CRD → `galactic-router` reconciles the CRD → GoBGP advertises the EVPN path → BGP distributes routes between nodes.

## Tech Stack

- **Go 1.26** — every binary
- **controller-runtime** — BGPRouter/BGPPeer/BGPAdvertisement/BGPPolicy/BGPVRFInstance reconcilers (`galactic-router`) and NetworkGateway/NetworkRule reconcilers (`galactic-gateway`); a bare `pkg/client` (no manager) in `galactic-bgp`/`galactic-cni`
- **BGP API** (`go.datum.net/network`) — BGPRouter, BGPPeer, BGPAdvertisement, BGPPolicy, BGPVRFInstance, NetworkGateway, NetworkRule CRDs
- **GoBGP v4** — embedded BGP server (default role)
- **SRv6 + netlink** — kernel-level routing; `github.com/vishvananda/netlink`
- **eBPF** (`github.com/cilium/ebpf`) — TC-BPF SRv6 uSID decap datapath (CNI side) and XDP edge NAT+LB datapath (`galactic-gateway`)
- **Multus CNI** — multi-network for pods; NAD generation handled by the external operator

## Development Workflow

```
task build          # produces bin/galactic-veth and bin/galactic-router
task ci             # full pipeline: lint → build → test:unit → test:e2e
task test           # runs test:unit then test:e2e
task test:unit      # unit tests with race detection
task test:e2e       # Kind cluster lifecycle test
task lint           # golangci-lint; lint-fix applies safe auto-fixes
```

Production release images are built by `.github/workflows/publish.yaml`, not by any `task` in this file — see the CI/CD section of each component's architecture doc ([CNI](docs/agents/ARCHITECTURE-CNI.md#cicd), [router](docs/agents/ARCHITECTURE-ROUTER.md#cicd), [gateway](docs/agents/ARCHITECTURE-GATEWAY.md#cicd)) for the full pipeline (per-binary `containers/*/Dockerfile`s pushed to `ghcr.io/datum-cloud/*`, plus a `config/` Kustomize OCI bundle). This replaced an earlier single shared image (`containers/galactic/Dockerfile`, `.github/workflows/release.yaml`, both removed — see the router doc's History note) that was found to advertise `galactic-router` without ever building it. `containers/galactic-cni/Dockerfile` is also used directly by `task test:e2e` (not just by the publish pipeline).

**Before every PR:** `task ci` (lint → build → test:unit → test:e2e).

## Code Standards

See [docs/agents/CONVENTIONS.md](docs/agents/CONVENTIONS.md) for the full, prescriptive coding standards covering Go naming, error handling, testing patterns, linting, commit messages, and markdown table alignment.

Summary:
- Go: `gofmt`/`goimports` enforced; golangci-lint v2 with `errcheck`, `staticcheck`, `govet`, `revive`, `gocyclo`, `goconst`, `unused`, and more (see `.golangci.yaml` for the full list).
- Generated protobuf files (`*.pb.go`, `*_grpc.pb.go`) are committed; never hand-edit them.
- Always use `.yaml`, never `.yml`, for YAML files.

## Deployments

`config/` is Kustomize-composed: `kubectl apply -k config/` deploys everything (namespace, both DaemonSets' RBAC/ServiceAccounts, and all three DaemonSets) in one command — `kubectl` sorts by kind before applying, so the namespace and RBAC/ServiceAccounts always land before anything namespace-scoped needs them. Each component also has its own `kustomization.yaml` and can be applied independently:

**Node label strategy.** Every DaemonSet's node affinity keys off one or more of these labels — a primary-role enum (`node`) plus a mode enum per binary family (`galactic`, `fabric`), rather than one giant enum or a pile of independent booleans. `node`'s two values are mutually exclusive by design (a node is never both `compute` and `edge`), and so are each family's two mode values (a node running plain `galactic-router` never also runs `galactic-router-rr`) — but `node` and `galactic`/`fabric` are independent keys, so their values freely combine (e.g. `node=edge` + `galactic=router` + `fabric=router` on one node):

| Label | Deploys |
| ----- | ------- |
| `galactic.datumapis.com/node=compute` | `galactic-nat66` |
| `galactic.datumapis.com/node=edge` | `galactic-gateway` (standalone; the actual network-edge/ingress boundary — not to be confused with `compute`) |
| `galactic.datumapis.com/galactic=router` | `galactic-cni`, `galactic-router` (plain/tenant mode) — runs on both `compute` and `edge` nodes |
| `galactic.datumapis.com/galactic=control` | `galactic-router-rr`; mutually exclusive with `galactic=router` on the same node |
| `galactic.datumapis.com/fabric=router` | `fabric-router` |
| `galactic.datumapis.com/fabric=control` | `fabric-router-rr` (**future** — not yet implemented; `fabric-router` has no route-reflector variant today) |

See [docs/node-labels.md](docs/node-labels.md) for the full strategy — why `galactic`/`fabric` are each a mode enum rather than independent booleans, the naming collision between `node=edge` and `galactic-gateway`'s pre-existing "edge XDP" terminology, and the specific bugs this scheme replaced.

- **`config/galactic-system/`** — Creates the `galactic-system` namespace both components deploy into. Apply with `kubectl apply -k config/galactic-system/`.
- **`config/galactic-cni/`** — Production manifests for the CNI installer DaemonSet, ConfigMap, RBAC, and ServiceAccount; opts in via `galactic.datumapis.com/galactic: router`. Apply with `kubectl apply -k config/galactic-cni/`.
- **`config/galactic-router/`** — Shared RBAC/ServiceAccount plus DaemonSet roles:
  - **`config/galactic-router/base/`** — the role-agnostic DaemonSet spec both roles below patch; not applied directly (no affinity, no BGP listen port of its own).
  - **`config/galactic-router/overlays/router/`** — the plain (non-reflector) per-node role (`galactic-router`); runs on every `compute` *and* every `edge` node except Kubernetes control-plane nodes, opt-in via `galactic.datumapis.com/galactic: router` (the same label `galactic-cni` keys off of — see `config/galactic-cni/daemonset.yaml`). This is the default role, so it carries no role-specific name/label of its own — only `control` below needs one, to coexist as a second DaemonSet.
  - **`config/galactic-router/overlays/control/`** — the BGP route-reflector role (`galactic-router-rr`, `GALACTIC_ROUTER_REFLECTOR=true`); opt-in only, requires `galactic.datumapis.com/galactic: control` (stays at zero replicas otherwise). Mutually exclusive with `router`'s `galactic: router` value on the same node — one label key, single-valued, so a route-reflector node structurally can't also run plain-mode `galactic-router`. `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS` is auto-detected from the host's `lo` interface by default; see the comments in `daemonset-patch.yaml` for when to override it.
  - Apply both roles with `kubectl apply -k config/galactic-router/`, or a single role with e.g. `kubectl apply -k config/galactic-router/overlays/router/`. `galactic-router` no longer runs bundled inside `galactic-gateway`'s pod — see `config/galactic-gateway/` below.
- **`config/galactic-gateway/`** — the edge XDP NAT+LB gateway control plane, a single-container `galactic-gateway` DaemonSet — `galactic-router` used to run as a second container in this same pod; it's now a fully independent DaemonSet on `edge` nodes too (via `galactic.datumapis.com/galactic: router`, same as `compute`), so a crash on either side no longer takes the other's *pod* down with it, not just the other's binary. `config/galactic-gateway/{serviceaccount.yaml,rbac.yaml}` (safe/idempotent to apply cluster-wide) are what `kubectl apply -k config/galactic-gateway/` applies; `config/galactic-gateway/base/` (requiring nodes labeled `galactic.datumapis.com/node: edge` — the actual network-edge/ingress boundary, not to be confused with `compute`) is **not** included in that kustomization and is **not** applied as-is — the same exemption as `config/fabric-router/` below, for the same reason: `GALACTIC_GATEWAY_SRV6_ADDRESS` must be unique per gateway node and has no generic default (no in-cluster mechanism yet derives it automatically — see `internal/controller/networkgateway_controller.go`'s `publishSelfAddress` doc comment). It's designed to be instantiated once per gateway node by a further overlay that pins it to one node (`kubernetes.io/hostname`) and sets that node's own public-interface/SRv6-address values; see `deploy/containerlab/resources/galactic-gateway/` for a worked two-node example. Also **not** part of the root `config/kustomization.yaml`'s default resource list, matching `config/fabric-router/`'s exemption.
- **`config/fabric-router/`** — the FRR underlay eBGP DaemonSet (`fabric-router`; `galactic-router` needs a working underlay before it can start). Unlike `config/galactic-router/`, this is a single flat DaemonSet with no `default`/`rr`-style role split — its affinity matches any node labeled `galactic.datumapis.com/fabric: router` (a dedicated mode-enum label, independent of whatever `galactic.datumapis.com/node` role value or `galactic.datumapis.com/galactic` mode that node also carries) directly, since there's no env/config difference between running on a regular node vs. those roles — fabric-router itself is identical everywhere; only the per-node BGP underlay config it reads from the ConfigMap differs. That affinity can legitimately match more than one node per cluster, and BGP underlay config (hostname, router-id, interface addresses, remote-AS) inherently differs per physical node — so `frr-init` gets the pod's node name via a `NODE_NAME` downward-API env var and selects a per-node `frr.conf.<nodename>` key from the ConfigMap, rather than assuming one shared `frr.conf` for the whole DaemonSet. **Not** part of the root `config/kustomization.yaml` and not covered by `kubectl apply -k config/` — unlike every other component here, it has no generic default: the deployer must hand-author a `fabric-config` ConfigMap with one `frr.conf.<nodename>` key per matching node (`daemons`/`vtysh.conf` are baked into the `fabric-router` image and only need to be in the ConfigMap if overriding those defaults) before applying `kubectl apply -k config/fabric-router/`.
- **`deploy/containerlab/`** — ContainerLab topology (`gvpc.clab.yaml`) for three Kind clusters (dfw, iad, sjc) wired over an IPv6 SRv6 transit mesh. FRR runs as a hostNetwork DaemonSet on each worker for eBGP underlay; `galactic-router` (plain mode) handles EVPN path distribution over iBGP, the iad route reflector builds on `config/galactic-router/overlays/control/`, and iad additionally has two dedicated edge-role nodes (`iad-gateway1`/`iad-gateway2`, `config/galactic-gateway/base/`) as a canary for the edge XDP NAT+LB gateway. See `deploy/containerlab/README.md` and `deploy/containerlab/Taskfile.yaml` for bring-up commands.

## New Developer Entry Points

1. Run `task build` to verify toolchain; run `task test` to confirm unit tests pass.
2. Read `internal/cni/cni.go` (cmdAdd/cmdDel) to understand the container attach path and how `BGPAdvertisement` CRDs are created. See [ARCHITECTURE-CNI.md](docs/agents/ARCHITECTURE-CNI.md).
3. Read `internal/controller/` for the controller-runtime reconcilers (BGPRouter, BGPPeer, BGPAdvertisement, BGPPolicy, BGPVRFInstance, Node, Secret) plus garbage collection (`gc_controller.go`, backed by `internal/gc/`). Read `internal/reconcile/reconcile.go` to understand how the BGPRouter CRD is translated into a `DesiredRouter` applied to the runtime. See [ARCHITECTURE-ROUTER.md](docs/agents/ARCHITECTURE-ROUTER.md).
4. Read `internal/runtime/gobgp/runtime.go` to understand how `DesiredRouter` is applied to GoBGP.
5. Read `internal/plumbing/intf/intf.go` to understand SRv6 endpoint encoding, interface naming, and base62↔hex conversion.
6. Explore `internal/plumbing/` for shared kernel and network primitives (VRF, sysctl, interface naming, SRv6).
7. Read `internal/gateway/engine.go` and `internal/controller/networkgateway_controller.go` to understand the edge XDP NAT+LB gateway's convergence loop and Active-Active BGP placement model. See [ARCHITECTURE-GATEWAY.md](docs/agents/ARCHITECTURE-GATEWAY.md).
8. See `docs/cni/cni-cmd-sequence.md`, `docs/cni/gc-cmd-sequence.md`, and `docs/agent-startup.md` for Mermaid sequence diagrams of the CNI attach path, garbage collection, and router startup, respectively. `docs/cni/configuration.md` and `docs/router/configuration.md` document CNI config fields and router environment variables.
9. Read [docs/node-labels.md](docs/node-labels.md) to understand which `galactic.datumapis.com/*` labels put which DaemonSets on which nodes, and why it's five independent labels rather than one enum — this cuts across all five binaries and isn't owned by any single component's architecture doc.
