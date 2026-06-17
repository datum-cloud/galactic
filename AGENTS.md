# Repository Guidelines

## Architecture Reference

See [ARCHITECTURE.md](ARCHITECTURE.md) for a full architecture reference including module layout, entry points, data flow, configuration, and known constraints.

## Purpose & Architecture

Galactic is the SRv6 data plane for multi-cloud VPC networking. It consists of a DaemonSet agent (`internal/agent/srv6/`) that manages kernel SRv6 routes and VRFs per node, and a CNI plugin (`internal/cni/`) that registers container endpoints with the agent via gRPC. VPC and VPCAttachment CRD management lives in a separate operator project; Galactic receives pre-populated identifiers through the CNI config and acts on them. BGP is used as the control plane for distributing SRv6 routes between agents.

**Data flow:** CNI invoked with pre-populated VPC/VPCAttachment identifiers → gRPC registers endpoint with agent → agent manages SRv6 ingress routes locally → BGP distributes SRv6 routes between agents.

**Non-obvious decisions:**
- VPC identifiers are 48-bit hex; VPCAttachment identifiers are 16-bit hex. These are embedded into IPv6 SRv6 endpoint addresses for deterministic route lookups. Both are supplied by an external operator via the CNI config.
- Identifiers are also Base62-encoded for interface naming (VRF: `vrfX-Y`, veth host side: `galX-Y`) to keep kernel interface name length within limits.
- `galactic-cni` is a pure CNI plugin; `main()` calls `cni.RunPlugin()` directly with no CLI layer. `galactic-agent` uses flag parsing for its configuration flags.
- The Kubernetes operator, VPC/VPCAttachment CRDs, and webhook code have been removed from this repository. They live in a separate companion operator project.

## Tech Stack

- **Go 1.26** — agent and CNI plugin
- **Multus CNI** — multi-network for pods; NAD generation is handled by the external operator
- **gRPC + protobuf** — CNI-to-agent local communication (`pkg/proto/local/`)
- **SRv6 + netlink** — kernel-level routing; `github.com/vishvananda/netlink`
- **BGP** — control plane for SRv6 route distribution between agents (in progress)

## Development Workflow

```
task build          # produces bin/galactic
task test           # runs test:unit then test:e2e
task test:unit      # unit tests with race detection
task test:e2e       # Kind cluster lifecycle test
task lint           # golangci-lint; lint-fix applies safe auto-fixes
task run-agent      # run agent (requires root / CAP_NET_ADMIN)
```

**Before every PR:** `task lint test`.

## Code Standards

See [CONVENTIONS.md](CONVENTIONS.md) for the full, prescriptive coding standards covering Go naming, error handling, testing patterns, linting, and commit messages.

Summary:
- Go: `gofmt`/`goimports` enforced; golangci-lint with `errcheck`, `staticcheck`, `govet`, `revive`, `gocyclo`, `dupl`, `unused` (see `.golangci.yml`). `lll` excluded from `internal/`.
- Generated protobuf files (`*.pb.go`, `*_grpc.pb.go`) are committed; never hand-edit them.

## Deployments

- **`deploy/galactic-agent/`** — Kustomize manifests for the agent DaemonSet, RBAC, and ServiceAccount. Apply with `kubectl apply -k deploy/galactic-agent/`.
- **`deploy/containerlab/`** — ContainerLab topology (`gvpc.clab.yaml`) for three Kind clusters (iad, sjc, infra) wired over an IPv6 SRv6 transit mesh. FRR runs as a hostNetwork DaemonSet on each worker for eBGP underlay; GoBGP handles L3VPN type-5 routes over iBGP to the infra route reflector. See `deploy/containerlab/README.md` and `deploy/containerlab/Taskfile.yaml` for bring-up commands.

## New Developer Entry Points

1. Run `task build` to verify toolchain; run `task test` to confirm unit tests pass.
2. Read `internal/cni/cni.go` (cmdAdd/cmdDel) to understand the container attach path.
3. Read `internal/agent/srv6/srv6.go` to understand the agent entry point and how it manages SRv6 routes and VRFs.
4. Read `pkg/proto/local/local.go` to understand the gRPC interface between the CNI and the agent.
5. Explore `pkg/common/` for shared utilities (VRF management, sysctl helpers, CNI types).
