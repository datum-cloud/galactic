# Repository Guidelines

## Purpose & Architecture

Galactic is the SRv6 data plane for multi-cloud VPC networking. It consists of a DaemonSet agent (`internal/agent/srv6/`) that manages kernel SRv6 routes and VRFs per node, and a CNI plugin (`internal/cni/`) that registers container endpoints with the agent via gRPC. VPC and VPCAttachment CRD management lives in a separate operator project; Galactic receives pre-populated identifiers through the CNI config and acts on them. BGP is used as the control plane for distributing SRv6 routes between agents.

**Data flow:** CNI invoked with pre-populated VPC/VPCAttachment identifiers → gRPC registers endpoint with agent → agent manages SRv6 ingress routes locally → BGP distributes SRv6 routes between agents.

**Non-obvious decisions:**
- VPC identifiers are 48-bit hex; VPCAttachment identifiers are 16-bit hex. These are embedded into IPv6 SRv6 endpoint addresses for deterministic route lookups. Both are supplied by an external operator via the CNI config.
- Identifiers are also Base62-encoded for interface naming (VRF: `vrfX-Y`, veth host side: `galX-Y`) to keep kernel interface name length within limits.
- The binary auto-detects CNI mode via the `CNI_COMMAND` env var; otherwise runs as a Cobra CLI with `agent`, `cni`, and `version` subcommands.
- The Kubernetes operator, VPC/VPCAttachment CRDs, and webhook code have been removed from this repository. They live in a separate companion operator project.

## Tech Stack

- **Go 1.24** (toolchain 1.24.2) — agent and CNI plugin
- **Multus CNI** — multi-network for pods; NAD generation is handled by the external operator
- **gRPC + protobuf** — CNI-to-agent local communication (`pkg/proto/local/`)
- **SRv6 + netlink** — kernel-level routing; `github.com/vishvananda/netlink`
- **BGP** — control plane for SRv6 route distribution between agents (in progress)

## Development Workflow

```
task build          # produces bin/galactic
task test           # fmt + vet + unit tests with coverage
task lint           # golangci-lint; lint-fix applies safe auto-fixes
task run-agent      # run agent (requires root / CAP_NET_ADMIN)
```

**Before every PR:** `task lint test`.

## Code Standards

See [CONVENTIONS.md](CONVENTIONS.md) for the full, prescriptive coding standards covering Go naming, error handling, testing patterns, linting, and commit messages.

Summary:
- Go: `gofmt`/`goimports` enforced; golangci-lint with `errcheck`, `staticcheck`, `govet`, `revive`, `gocyclo`, `dupl`, `unused` (see `.golangci.yml`). `lll` excluded from `internal/`.
- Generated protobuf files (`*.pb.go`, `*_grpc.pb.go`) are committed; never hand-edit them.

## Current State

- **Known debt:** Agent and CNI kernel-path code (`internal/agent/srv6/`, `internal/cni/`) has no unit coverage; these paths are best covered by integration or e2e tests. Only `pkg/common/util` has unit test coverage.
- **In flux:** The SRv6 route management (`internal/agent/srv6/`) and VRF utilities (`pkg/common/vrf/`) are the least tested and most likely to change as multi-cloud routing matures. BGP integration is in progress.

## Lab Environments

Two ContainerLab-based environments live under `lab/`:

- **`lab/network/`** — Standalone SRv6 underlay lab. Eight FRR + GoBGP nodes across PE, transit, and route-reflector roles. Use to develop and test BGP/SRv6 routing behaviour independently of Kubernetes.
- **`lab/gvpc/`** — Three Kind clusters (iad, sjc, infra) wired over an SRv6 transit mesh. FRR runs as a hostNetwork DaemonSet on each cluster's worker for the eBGP underlay; GoBGP on iad and sjc workers handles L3VPN type-5 routes over iBGP to the infra route reflector.

See `lab/README.md` for quick-start commands and prerequisites for each environment.

## New Developer Entry Points

1. Run `task build` to verify toolchain; run `task test` to confirm unit tests pass.
2. Read `internal/cni/cni.go` (cmdAdd/cmdDel) to understand the container attach path.
3. Read `internal/agent/srv6/srv6.go` to understand the agent entry point and how it manages SRv6 routes and VRFs.
4. Read `pkg/proto/local/local.go` to understand the gRPC interface between the CNI and the agent.
5. Explore `pkg/common/` for shared utilities (VRF management, sysctl helpers, CNI types).

**Likely trip-ups:**
- `task run-agent` requires elevated privileges (netlink, VRF, SRv6 operations need `CAP_NET_ADMIN`).
- There is no operator or webhook in this repository; those components are in a separate project.
