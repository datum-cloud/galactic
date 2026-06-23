# Repository Guidelines

## Architecture Reference

See [ARCHITECTURE.md](ARCHITECTURE.md) for a full architecture reference including module layout, entry points, data flow, configuration, and known constraints.

## Purpose & Architecture

Galactic is the SRv6 data plane for multi-cloud VPC networking. It consists of a controller-runtime reconciler (`cmd/galactic-router/`) that watches Cosmos BGP CRDs and drives an embedded GoBGP server per node, and a CNI plugin (`internal/cni/`) that wires containers into VPC networks. VPC and VPCAttachment CRD management lives in a separate operator project; Galactic receives pre-populated identifiers through the CNI config and acts on them.

**Data flow:** CNI invoked with pre-populated VPC/VPCAttachment identifiers → CNI creates kernel SRv6 state (VRF, veth, ingress route) and writes a `BGPAdvertisement` CRD → `galactic-router` reconciles the CRD → GoBGP advertises the EVPN path → BGP distributes routes between nodes.

**Non-obvious decisions:**
- VPC identifiers are 48-bit hex; VPCAttachment identifiers are 16-bit hex. These are embedded into IPv6 SRv6 endpoint addresses for deterministic route lookups. Both are supplied by an external operator via the CNI config.
- Identifiers are also Base62-encoded for interface naming: `G{9-char-vpc}{3-char-att}V` (VRF), `G{9}{3}H` (host veth), `G{9}{3}G` (guest veth). The 14-char total fits within the 15-char kernel limit. See `internal/plumbing/intf/intf.go`.
- `galactic-cni` is a pure CNI plugin; `main()` calls `cni.RunPlugin()` directly with no CLI layer. `galactic-router` uses environment variables for configuration: `NODE_NAME` and `ROUTER_ROLE` are required; `BGP_LOCAL_ADDRESS` pins the BGP source address (used by numbered underlay links); `BGP_LISTEN_PORT` overrides the BGP listen port (default `-1`, outbound-only).
- `ROUTER_ROLE=fabric` uses an FRR runtime stub (`internal/runtime/frr/`) that is not yet implemented; every reconcile will return an error. Only `ROUTER_ROLE=tenant` (GoBGP) is functional.
- The Kubernetes operator, VPC/VPCAttachment CRDs, and webhook code have been removed from this repository. They live in a separate companion operator project.
- GoBGP starts lazily on the first `BGPRouter` reconcile (`listenPort=-1`, outbound-only). ASN or RouterID changes trigger a full `Reconfigure`.
- Liveness and readiness probes use the gRPC health protocol on port 5000. There is no HTTP health endpoint.

## Tech Stack

- **Go 1.26** — router and CNI plugin
- **controller-runtime** — BGPRouter/BGPPeer/BGPAdvertisement/BGPPolicy reconcilers
- **Cosmos BGP API** (`bgp.miloapis.com/v1alpha1`) — BGPRouter, BGPPeer, BGPAdvertisement, BGPPolicy CRDs
- **Multus CNI** — multi-network for pods; NAD generation is handled by the external operator
- **SRv6 + netlink** — kernel-level routing; `github.com/vishvananda/netlink`
- **GoBGP v4** — embedded BGP server for the tenant role

## Development Workflow

```
task build          # produces bin/galactic-cni and bin/galactic-router
task ci             # full pipeline: lint → build → test:unit → test:e2e
task test           # runs test:unit then test:e2e
task test:unit      # unit tests with race detection
task test:e2e       # Kind cluster lifecycle test
task lint           # golangci-lint; lint-fix applies safe auto-fixes
task docker-build   # build container image (IMG= to override tag)
```

**Before every PR:** `task ci` (lint → build → test:unit → test:e2e).

## Code Standards

See [CONVENTIONS.md](CONVENTIONS.md) for the full, prescriptive coding standards covering Go naming, error handling, testing patterns, linting, and commit messages.

Summary:
- Go: `gofmt`/`goimports` enforced; golangci-lint with `errcheck`, `staticcheck`, `govet`, `revive`, `gocyclo`, `dupl`, `unused` (see `.golangci.yml`). `lll` excluded from `internal/`.
- Generated protobuf files (`*.pb.go`, `*_grpc.pb.go`) are committed; never hand-edit them.

## Deployments

- **`deploy/galactic-router/`** — Production manifests for the router DaemonSet, RBAC, and ServiceAccount. Apply with `kubectl apply -f deploy/galactic-router/`.
- **`deploy/containerlab/`** — ContainerLab topology (`gvpc.clab.yaml`) for three Kind clusters (dfw, iad, sjc) wired over an IPv6 SRv6 transit mesh. FRR runs as a hostNetwork DaemonSet on each worker for eBGP underlay; `galactic-router` (tenant role) handles EVPN path distribution over iBGP. See `deploy/containerlab/README.md` and `deploy/containerlab/Taskfile.yaml` for bring-up commands.

## New Developer Entry Points

1. Run `task build` to verify toolchain; run `task test` to confirm unit tests pass.
2. Read `internal/cni/cni.go` (cmdAdd/cmdDel) to understand the container attach path and how `BGPAdvertisement` CRDs are created.
3. Read `internal/controller/` for the controller-runtime reconcilers (BGPRouter, BGPPeer, BGPAdvertisement, BGPPolicy, Node, Secret). Read `internal/reconcile/reconcile.go` to understand how the BGPRouter CRD is translated into a `DesiredRouter` applied to the runtime.
4. Read `internal/runtime/gobgp/runtime.go` to understand how `DesiredRouter` is applied to GoBGP.
5. Read `internal/plumbing/intf/intf.go` to understand SRv6 endpoint encoding, interface naming, and base62↔hex conversion.
6. Explore `internal/plumbing/` for shared kernel and network primitives (VRF, sysctl, interface naming, SRv6).
