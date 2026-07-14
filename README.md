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

A ContainerLab environment is available under [`deploy/containerlab/`](./deploy/containerlab/):

- **[`deploy/containerlab/`](./deploy/containerlab/)** — Three Kind clusters wired over an SRv6 transit mesh. The full GVPC multi-cluster environment with FRR underlay and GoBGP L3VPN overlay.

See the [galactic DevContainer](./.devcontainer/galactic/) for development environment setup. On ARM64 / OrbStack, use the [containerlab DevContainer](./.devcontainer/containerlab-dood/) to run ContainerLab via Docker-out-of-Docker.

### Production Deployment

Manifests for a real cluster live under [`config/`](./config/), composed with [Kustomize](https://kustomize.io). One command deploys the `galactic-system` namespace (labeled `pod-security.kubernetes.io/enforce: privileged` — both DaemonSets need it, for hostPath volumes, hostNetwork, and elevated capabilities), the `galactic-cni` DaemonSet, and both `galactic-router` roles — `tenant` (per-node, runs everywhere except control-plane nodes) and `tenant-control` (BGP route reflector, opt-in — stays at zero replicas until nodes are labeled `galactic.datumapis.com/node: control`):

```bash
kubectl apply -k config/
```

Each component can also be applied on its own, e.g. `kubectl apply -k config/router` for just the router (both roles) or `kubectl apply -k config/router/tenant` for just the per-node role.

#### Prerequisites

- **Container images.** `.github/workflows/publish.yaml` builds `ghcr.io/datum-cloud/galactic-cni` and `ghcr.io/datum-cloud/galactic-router` (from `containers/galactic-cni/Dockerfile` and `containers/galactic-router/Dockerfile` respectively) on every push and release — but it never publishes a `:latest` tag, only date-stamped tags per push/release (e.g. `v0.0.0-main-20260713-170924`) and, for tagged releases, semver tags. The `image:` references committed in `config/cni/daemonset.yaml` and `config/router/base/daemonset.yaml` say `:latest` only as a placeholder that CI substitutes with a real published tag when it builds the `ghcr.io/datum-cloud/galactic-kustomize` OCI Kustomize bundle — that substitution never happens in the git checkout itself. Applying `config/` directly from a clone will therefore fail to pull `:latest`. Before applying, resolve the current tag (check the [package pages](https://github.com/orgs/datum-cloud/packages?repo_name=galactic) or the latest successful run of `publish.yaml` on `main`) and pin it, e.g.:

  ```bash
  cd config/cni && kustomize edit set image ghcr.io/datum-cloud/galactic-cni=ghcr.io/datum-cloud/galactic-cni:<resolved-tag>
  cd config/router/base && kustomize edit set image ghcr.io/datum-cloud/galactic-router=ghcr.io/datum-cloud/galactic-router:<resolved-tag>
  ```

- **Talos: gRPC health port.** `galactic-router` runs `hostNetwork: true` and defaults to gRPC health checks on port `5000`, which collides with Talos's built-in dashboard (`/sbin/dashboard` permanently binds `127.0.0.1:5000` on every Talos node). `config/router/base/daemonset.yaml` already ships with `GALACTIC_ROUTER_GRPC_HEALTH_PORT=5179` (and matching probe/containerPort) to avoid this; if you run `galactic-router` outside these manifests on Talos, set `GALACTIC_ROUTER_GRPC_HEALTH_PORT` to something other than `5000` yourself.

- **`galactic-router` tenant mode: BGP local address.** The node needs a global-unicast IPv6 address assigned to `lo` (typically by an underlay/fabric BGP daemon that starts before `galactic-router`), or you must set `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS` explicitly — this is required even when `GALACTIC_ROUTER_BGP_LISTEN_PORT=-1` (no inbound listener), since `galactic-router` still needs a source address for outbound BGP connections. Without one of these, startup fails with `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS not set and no address could be detected on lo: no global-unicast IPv6 address found on lo`. See [`docs/router/configuration.md`](./docs/router/configuration.md) for details.

See [`docs/router/configuration.md`](./docs/router/configuration.md) for the full `galactic-router` CLI flag / environment variable reference — note that env var names generally follow `GALACTIC_ROUTER_<FLAG_NAME>` but aren't always the naive uppercased guess (e.g. `--mode` is `GALACTIC_ROUTER_ROUTER_MODE`, not `GALACTIC_ROUTER_MODE`); the reference table has the exact name for every flag.

## Development

This project uses [Task](https://taskfile.dev) as its build tool. Build, test, and lint operations are defined in the root `Taskfile.yaml`.

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
```

#### Building

```bash
task build           # produces bin/galactic-cni and bin/galactic-router
task lint            # golangci-lint + yamlfmt; lint-fix applies safe auto-fixes
task ci              # full pipeline: lint → build → test:unit → test:e2e
```

There is no `task docker-build` — the shared production Dockerfile and release
workflow were removed (see Production Deployment above). `containers/galactic-cni/Dockerfile`
exists only to support `task test:e2e` below.

#### Testing

```bash
task test            # run unit tests then e2e tests (requires Docker + Kind)
task test:unit       # unit tests only — race detector, coverage output
task test:e2e        # full e2e lifecycle — spins up a Kind cluster, builds and
                     # loads the image, then tears the cluster down on exit
```

`task test:unit` is the fast path for development; it runs the same command as the CI `test-unit` job. `task test:e2e` requires Docker and Kind and mirrors the CI `test-e2e` job exactly, including automatic cluster cleanup via a `trap` on exit.

Run `task ci` before opening a pull request.

The lab environment has its own `Taskfile.yaml`; run `task` from `deploy/containerlab/` to see available tasks.

## Contributing

See [AGENTS.md](./AGENTS.md) for the contributor guide (development workflow, code standards, architecture pointers) and [docs/agents/ARCHITECTURE.md](./docs/agents/ARCHITECTURE.md) for the full architecture reference.

## License

See [LICENSE](./LICENSE) for details.

---

*Galactic is developed by [Datum](https://datum.net).*
