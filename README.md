# Galactic

**Multi-cloud networking for Kubernetes, simplified.**

Galactic connects Kubernetes workloads across multiple clouds and regions as if they were on a single, unified network. It provides secure, isolated Virtual Private Clouds (VPCs) that span cloud boundaries—without vendor lock-in or complex configuration.

## The Problem

Modern organizations run workloads everywhere: AWS, Azure, GCP, on-premises, and edge locations. Each environment brings its own networking model, APIs, and constraints. The result is fragmented networks, operational complexity, and cloud provider lock-in.

## Our Approach

Galactic provides the SRv6 data plane that makes multi-cloud VPC connectivity work at the kernel level. It runs as a DaemonSet agent on every node, managing SRv6 routes and VRF isolation, and as a CNI plugin that attaches pods to the correct virtual network. VPC and VPCAttachment definitions are managed by a companion operator; Galactic acts on the identifiers that operator assigns.

Under the hood, Galactic uses Segment Routing over IPv6 (SRv6) for efficient, deterministic routing and Virtual Routing and Forwarding (VRF) for true network isolation at the kernel level. BGP is used to distribute SRv6 routes between agents across nodes and clusters.

## Why Galactic

**For Developers** — Attach to a VPC with a single annotation. No networking code, no cloud-specific APIs.

**For Platform Teams** — Manage multi-cloud networking from Kubernetes using GitOps workflows and standard tooling.

**For Organizations** — Move workloads between providers without network redesign. One networking model instead of N cloud-specific implementations.

## Getting Started

Two ContainerLab environments are available under [`lab/`](./lab/):

- **[`lab/network/`](./lab/network/)** — Standalone SRv6 underlay lab (FRR + GoBGP, no Kubernetes). Good starting point for understanding the routing layer.
- **[`lab/gvpc/`](./lab/gvpc/)** — Three Kind clusters wired over an SRv6 transit mesh. The full GVPC multi-cluster environment.

See the [galactic DevContainer](./.devcontainer/galactic/) for development environment setup. On ARM64 / OrbStack, use the [containerlab DevContainer](./.devcontainer/containerlab-dood/) to run ContainerLab via Docker-out-of-Docker.

## Development

This project uses [Task](https://taskfile.dev) as its build tool. All build, test, lint, and lab operations are defined in `Taskfile.yaml` files at the repo root and under each `lab/` subdirectory.

### Install Task

```bash
# macOS
brew install go-task

# Linux (official installer)
sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b ~/.local/bin

# Go toolchain
go install github.com/go-task/task/v3/cmd/task@latest
```

See [taskfile.dev/installation](https://taskfile.dev/installation/) for the full list of options.

### Usage

```bash
task          # list available tasks
task build    # build the galactic binary (includes binary verification)
task lint     # run golangci-lint
task lint-fix # auto-fix lint issues
task clean    # remove build artifacts
```

#### Testing

```bash
task test            # run unit tests then e2e tests (requires Docker + Kind)
task ci:unittest     # unit tests only — race detector, coverage output
task ci:e2etest      # full e2e lifecycle — spins up a Kind cluster, builds and
                     # loads the image, then tears the cluster down on exit
```

`task ci:unittest` is the fast path for development; it runs the same command as the CI `test-unit` job. `task ci:e2etest` requires Docker and Kind and mirrors the CI `test-e2e` job exactly, including automatic cluster cleanup via a `trap` on exit.

Lab environments have their own `Taskfile.yaml`; run `task` from the relevant directory (`lab/network/` or `lab/gvpc/`) to see available tasks.

## License

See [LICENSE](./LICENSE) for details.

---

*Galactic is developed by [Datum](https://datum.net).*
