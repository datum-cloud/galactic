# Repository Guidelines

## Architecture Reference

See [docs/agents/ARCHITECTURE.md](docs/agents/ARCHITECTURE.md) for a full architecture reference including module layout, entry points, data flow, configuration, external dependencies, and known constraints.

## Purpose

Galactic is the SRv6 data plane for multi-cloud VPC networking. It consists of two binaries deployed on each Kubernetes node:

- **`galactic-cni`** — CNI plugin that wires containers into VPC networks (VRF, veth, SRv6 ingress route) and writes `BGPAdvertisement` CRDs.
- **`galactic-router`** — controller-runtime reconciler that watches BGP CRDs and drives an embedded GoBGP server per node to distribute EVPN paths.

VPC and VPCAttachment CRD management lives in a separate companion operator; Galactic receives pre-populated identifiers through the CNI config and acts on them.

**Data flow:** CNI invoked with pre-populated VPC/VPCAttachment identifiers → CNI creates kernel SRv6 state and writes a `BGPAdvertisement` CRD → `galactic-router` reconciles the CRD → GoBGP advertises the EVPN path → BGP distributes routes between nodes.

## Tech Stack

- **Go 1.26** — router and CNI plugin
- **controller-runtime** — BGPRouter/BGPPeer/BGPAdvertisement/BGPPolicy/BGPVRFInstance reconcilers
- **BGP API** (`go.datum.net/network`) — BGPRouter, BGPPeer, BGPAdvertisement, BGPPolicy, BGPVRFInstance CRDs
- **GoBGP v4** — embedded BGP server (tenant role)
- **SRv6 + netlink** — kernel-level routing; `github.com/vishvananda/netlink`
- **Multus CNI** — multi-network for pods; NAD generation handled by the external operator

## Development Workflow

```
task build          # produces bin/galactic-cni and bin/galactic-router
task ci             # full pipeline: lint → build → test:unit → test:e2e
task test           # runs test:unit then test:e2e
task test:unit      # unit tests with race detection
task test:e2e       # Kind cluster lifecycle test
task lint           # golangci-lint; lint-fix applies safe auto-fixes
```

There is no production release image build in this repo (`task docker-build` and the release workflow were removed after the shared image was found to advertise `galactic-router` without ever building it — see [docs/agents/ARCHITECTURE.md](docs/agents/ARCHITECTURE.md#known-constraints)). `containers/galactic-cni/Dockerfile` exists solely for `task test:e2e`.

**Before every PR:** `task ci` (lint → build → test:unit → test:e2e).

## Code Standards

See [docs/agents/CONVENTIONS.md](docs/agents/CONVENTIONS.md) for the full, prescriptive coding standards covering Go naming, error handling, testing patterns, linting, commit messages, and markdown table alignment.

Summary:
- Go: `gofmt`/`goimports` enforced; golangci-lint v2 with `errcheck`, `staticcheck`, `govet`, `revive`, `gocyclo`, `goconst`, `unused`, and more (see `.golangci.yaml` for the full list).
- Generated protobuf files (`*.pb.go`, `*_grpc.pb.go`) are committed; never hand-edit them.
- Always use `.yaml`, never `.yml`, for YAML files.

## Deployments

`config/` is Kustomize-composed: `kubectl apply -k config/` deploys everything (namespace, both DaemonSets' RBAC/ServiceAccounts, and all three DaemonSets) in one command — `kubectl` sorts by kind before applying, so the namespace and RBAC/ServiceAccounts always land before anything namespace-scoped needs them. Each component also has its own `kustomization.yaml` and can be applied independently:

- **`config/system/`** — Creates the `galactic-system` namespace both components deploy into. Apply with `kubectl apply -k config/system/`.
- **`config/cni/`** — Production manifests for the CNI installer DaemonSet, ConfigMap, RBAC, and ServiceAccount. Apply with `kubectl apply -k config/cni/`.
- **`config/router/`** — Shared RBAC/ServiceAccount plus two DaemonSet roles, both running `GALACTIC_ROUTER_ROUTER_MODE=tenant`:
  - **`config/router/tenant/`** — the per-node role (`galactic-router`); runs on every node except Kubernetes control-plane nodes and nodes labeled for the route-reflector role below.
  - **`config/router/tenant-control/`** — the BGP route-reflector role (`galactic-router-control`, `GALACTIC_ROUTER_REFLECTOR=true`); opt-in only, requires nodes labeled `galactic.datum.net/node: control` (stays at zero replicas otherwise). `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS` is auto-detected from the host's `lo` interface by default; see the comments in `daemonset-patch.yaml` for when to override it.
  - **`config/router/base/`** — the DaemonSet spec shared by both roles; not applied directly.
  - Apply the whole router component (both roles) with `kubectl apply -k config/router/`, or a single role with e.g. `kubectl apply -k config/router/tenant/`.
- **`deploy/containerlab/`** — ContainerLab topology (`gvpc.clab.yaml`) for three Kind clusters (dfw, iad, sjc) wired over an IPv6 SRv6 transit mesh. FRR runs as a hostNetwork DaemonSet on each worker for eBGP underlay; `galactic-router` (tenant role) handles EVPN path distribution over iBGP, and the iad route reflector builds on `config/router/tenant-control/`. See `deploy/containerlab/README.md` and `deploy/containerlab/Taskfile.yaml` for bring-up commands.

## New Developer Entry Points

1. Run `task build` to verify toolchain; run `task test` to confirm unit tests pass.
2. Read `internal/cni/cni.go` (cmdAdd/cmdDel) to understand the container attach path and how `BGPAdvertisement` CRDs are created.
3. Read `internal/controller/` for the controller-runtime reconcilers (BGPRouter, BGPPeer, BGPAdvertisement, BGPPolicy, BGPVRFInstance, Node, Secret) plus garbage collection (`gc_controller.go`, backed by `internal/gc/`). Read `internal/reconcile/reconcile.go` to understand how the BGPRouter CRD is translated into a `DesiredRouter` applied to the runtime.
4. Read `internal/runtime/gobgp/runtime.go` to understand how `DesiredRouter` is applied to GoBGP.
5. Read `internal/plumbing/intf/intf.go` to understand SRv6 endpoint encoding, interface naming, and base62↔hex conversion.
6. Explore `internal/plumbing/` for shared kernel and network primitives (VRF, sysctl, interface naming, SRv6).
7. See `docs/cni-sequence.md` and `docs/agent-startup.md` for Mermaid sequence diagrams of the CNI attach path and router startup. `docs/cni/configuration.md` and `docs/router/configuration.md` document CNI config fields and router environment variables.
