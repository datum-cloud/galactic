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
| [docs/agents/ARCHITECTURE-CNI.md](docs/agents/ARCHITECTURE-CNI.md)         | The CNI attach chain: `galactic-cni` (installer), `galactic-veth`, `galactic-tap`, `galactic-ipam`, `galactic-bgp`, `galactic-route`, `vmtap-cni` | Pod/VM attach or detach behavior, CNI config fields/conflists, IPAM, the SRv6 uSID TC-BPF datapath's CNI-side registration, or anything under `cmd/galactic-{cni,veth,tap,ipam,bgp,route}`/`cmd/vmtap-cni`, `internal/cni*`, `internal/installer`, `internal/vmtap`                  |
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
- **GoBGP v4** — embedded BGP server (tenant role)
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

- **`config/galactic-system/`** — Creates the `galactic-system` namespace both components deploy into. Apply with `kubectl apply -k config/galactic-system/`.
- **`config/galactic-cni/`** — Production manifests for the CNI installer DaemonSet, ConfigMap, RBAC, and ServiceAccount. Apply with `kubectl apply -k config/galactic-cni/`.
- **`config/galactic-router/`** — Shared RBAC/ServiceAccount plus DaemonSet roles:
  - **`config/galactic-router/tenant/`** — the per-node role (`galactic-router`); runs on every node except Kubernetes control-plane nodes and nodes labeled for the route-reflector or gateway roles.
  - **`config/galactic-router/tenant-control/`** — the BGP route-reflector role (`galactic-router-control`, `GALACTIC_ROUTER_REFLECTOR=true`); opt-in only, requires nodes labeled `galactic.datumapis.com/node: control` (stays at zero replicas otherwise). `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS` is auto-detected from the host's `lo` interface by default; see the comments in `daemonset-patch.yaml` for when to override it.
  - **`config/galactic-router/base/`** — the DaemonSet spec shared by both roles above; not applied directly.
  - Apply both roles with `kubectl apply -k config/galactic-router/`, or a single role with e.g. `kubectl apply -k config/galactic-router/tenant/`. `galactic-router` no longer has a gateway role of its own — see `config/galactic-gateway/` below.
- **`config/galactic-gateway/`** — the edge XDP NAT+LB gateway control plane, a separate `galactic-gateway` binary rather than a `galactic-router` role, so a crash on either side no longer takes the other down with it. `config/galactic-gateway/{serviceaccount.yaml,rbac.yaml}` (safe/idempotent to apply cluster-wide) are what `kubectl apply -k config/galactic-gateway/` applies; `config/galactic-gateway/base/` (the two-container `galactic-router` + `galactic-gateway` pod, requiring nodes labeled `galactic.datumapis.com/node: gateway`) is **not** included in that kustomization and is **not** applied as-is — the same exemption as `config/fabric-router/` below, for the same reason: `GALACTIC_GATEWAY_SRV6_ADDRESS` must be unique per gateway node and has no generic default (no in-cluster mechanism yet derives it automatically — see `internal/controller/networkgateway_controller.go`'s `publishSelfAddress` doc comment). It's designed to be instantiated once per gateway node by a further overlay that pins it to one node (`kubernetes.io/hostname`) and sets that node's own public-interface/SRv6-address values; see `deploy/containerlab/resources/galactic-gateway/` for a worked two-node example. Also **not** part of the root `config/kustomization.yaml`'s default resource list, matching `config/fabric-router/`'s exemption.
- **`config/fabric-router/`** — the FRR underlay eBGP DaemonSet (`fabric-router`; `galactic-router` needs a working underlay before it can start). Unlike `config/galactic-router/`, this is a single flat DaemonSet with no `tenant`/`tenant-control`-style role split — its affinity matches nodes labeled `galactic.datumapis.com/node` `In` `[edge, control, gateway]` directly, since (unlike galactic-router's route-reflector role and the gateway role above) there's no env/config difference between running on a regular node vs. those roles — fabric-router itself is identical everywhere; only the per-node BGP underlay config it reads from the ConfigMap differs. That affinity can legitimately match more than one node per cluster, and BGP underlay config (hostname, router-id, interface addresses, remote-AS) inherently differs per physical node — so `frr-init` gets the pod's node name via a `NODE_NAME` downward-API env var and selects a per-node `frr.conf.<nodename>` key from the ConfigMap, rather than assuming one shared `frr.conf` for the whole DaemonSet. **Not** part of the root `config/kustomization.yaml` and not covered by `kubectl apply -k config/` — unlike every other component here, it has no generic default: the deployer must hand-author a `fabric-config` ConfigMap with one `frr.conf.<nodename>` key per matching node (`daemons`/`vtysh.conf` are baked into the `fabric-router` image and only need to be in the ConfigMap if overriding those defaults) before applying `kubectl apply -k config/fabric-router/`.
- **`deploy/containerlab/`** — ContainerLab topology (`gvpc.clab.yaml`) for three Kind clusters (dfw, iad, sjc) wired over an IPv6 SRv6 transit mesh. FRR runs as a hostNetwork DaemonSet on each worker for eBGP underlay; `galactic-router` (tenant role) handles EVPN path distribution over iBGP, the iad route reflector builds on `config/galactic-router/tenant-control/`, and iad additionally has two dedicated gateway-role nodes (`iad-gateway1`/`iad-gateway2`, `config/galactic-gateway/base/`) as a canary for the edge XDP NAT+LB gateway. See `deploy/containerlab/README.md` and `deploy/containerlab/Taskfile.yaml` for bring-up commands.

## New Developer Entry Points

1. Run `task build` to verify toolchain; run `task test` to confirm unit tests pass.
2. Read `internal/cni/cni.go` (cmdAdd/cmdDel) to understand the container attach path and how `BGPAdvertisement` CRDs are created. See [ARCHITECTURE-CNI.md](docs/agents/ARCHITECTURE-CNI.md).
3. Read `internal/controller/` for the controller-runtime reconcilers (BGPRouter, BGPPeer, BGPAdvertisement, BGPPolicy, BGPVRFInstance, Node, Secret) plus garbage collection (`gc_controller.go`, backed by `internal/gc/`). Read `internal/reconcile/reconcile.go` to understand how the BGPRouter CRD is translated into a `DesiredRouter` applied to the runtime. See [ARCHITECTURE-ROUTER.md](docs/agents/ARCHITECTURE-ROUTER.md).
4. Read `internal/runtime/gobgp/runtime.go` to understand how `DesiredRouter` is applied to GoBGP.
5. Read `internal/plumbing/intf/intf.go` to understand SRv6 endpoint encoding, interface naming, and base62↔hex conversion.
6. Explore `internal/plumbing/` for shared kernel and network primitives (VRF, sysctl, interface naming, SRv6).
7. Read `internal/gateway/engine.go` and `internal/controller/networkgateway_controller.go` to understand the edge XDP NAT+LB gateway's convergence loop and Active-Active BGP placement model. See [ARCHITECTURE-GATEWAY.md](docs/agents/ARCHITECTURE-GATEWAY.md).
8. See `docs/cni-cmd-sequence.md` and `docs/agent-startup.md` for Mermaid sequence diagrams of the CNI attach path and router startup. `docs/cni/configuration.md` and `docs/router/configuration.md` document CNI config fields and router environment variables.
