# Galactic

**Multi-cloud networking for Kubernetes, simplified.**

Galactic connects Kubernetes workloads across multiple clouds and regions as if they were on a single, unified network. It provides secure, isolated Virtual Private Clouds (VPCs) that span cloud boundaries—without vendor lock-in or complex configuration.

## The Problem

Modern organizations run workloads everywhere: AWS, Azure, GCP, on-premises, and edge locations. Each environment brings its own networking model, APIs, and constraints. The result is fragmented networks, operational complexity, and cloud provider lock-in.

## Our Approach

Galactic provides the SRv6 data plane that makes multi-cloud VPC connectivity work at the kernel level. It runs as a DaemonSet agent on every node, managing SRv6 routes and VRF isolation, and as a CNI plugin that attaches pods to the correct virtual network. On nodes dedicated to the gateway role, a third component loads an edge XDP NAT+LB datapath to handle ingress load balancing at the VPC boundary. VPC and VPCAttachment definitions are managed by a companion operator; Galactic acts on the identifiers that operator assigns.

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

Manifests for a real cluster live under [`config/`](./config/), composed with [Kustomize](https://kustomize.io). One command deploys the `galactic-system` namespace (labeled `pod-security.kubernetes.io/enforce: privileged` — every DaemonSet here needs it, for hostPath volumes, hostNetwork, and elevated capabilities), the `galactic-cni` DaemonSet, both `galactic-router` roles — `tenant` (per-node, runs everywhere except control-plane nodes) and `tenant-control` (BGP route reflector, opt-in — stays at zero replicas until nodes are labeled `galactic.datumapis.com/node: control`) — and the `vmtap-cni` DaemonSet (a second, standalone CNI plugin that gives Unikraft microVMs managed by `kraftlet` access to the pod's Cilium-assigned identity; see [`docs/vmtap-cni/configuration.md`](./docs/vmtap-cni/configuration.md)):

```bash
kubectl apply -k config/
```

Each component can also be applied on its own, e.g. `kubectl apply -k config/galactic-router` for just the router (both roles) or `kubectl apply -k config/galactic-router/tenant` for just the per-node role.

Two components are **not** part of `kubectl apply -k config/` and must be applied separately, each with its own per-node prerequisite:

- **`config/fabric-router/`** — the FRR underlay eBGP DaemonSet `galactic-router` depends on.
- **`config/galactic-gateway/`** — the edge XDP NAT+LB gateway control plane (`galactic-router` + `galactic-gateway` running together on dedicated gateway-role nodes). `kubectl apply -k config/galactic-gateway/` only installs the shared, cluster-safe ServiceAccount/RBAC; `config/galactic-gateway/base/` itself is a template meant to be instantiated once per gateway node by a further overlay (see `deploy/containerlab/resources/galactic-gateway/` for a worked example) — apply that overlay per node instead of `base/` directly.

```bash
kubectl apply -k config/fabric-router/
kubectl apply -k config/galactic-gateway/
```

#### Prerequisites

- **Container images.** `.github/workflows/publish.yaml` builds `ghcr.io/datum-cloud/galactic-cni`, `ghcr.io/datum-cloud/galactic-router`, `ghcr.io/datum-cloud/galactic-gateway`, and `ghcr.io/datum-cloud/fabric-router` (from `containers/galactic-cni/Dockerfile`, `containers/galactic-router/Dockerfile`, `containers/galactic-gateway/Dockerfile`, and `containers/fabric-router/Dockerfile` respectively) on every push and release — but it never publishes a `:latest` tag, only date-stamped tags per push/release (e.g. `v0.0.0-main-20260713-170924`) and, for tagged releases, semver tags. The `image:` references committed in `config/galactic-cni/daemonset.yaml`, `config/galactic-router/base/daemonset.yaml`, `config/galactic-gateway/base/daemonset.yaml`, and `config/fabric-router/daemonset.yaml` say `:latest` only as a placeholder that CI substitutes with a real published tag when it builds the `ghcr.io/datum-cloud/galactic-kustomize` OCI Kustomize bundle — that substitution never happens in the git checkout itself. Applying `config/` directly from a clone will therefore fail to pull `:latest`. Before applying, resolve the current tag (check the [package pages](https://github.com/orgs/datum-cloud/packages?repo_name=galactic) or the latest successful run of `publish.yaml` on `main`) and pin it, e.g.:

  ```bash
  cd config/galactic-cni && kustomize edit set image ghcr.io/datum-cloud/galactic-cni=ghcr.io/datum-cloud/galactic-cni:<resolved-tag>
  cd config/galactic-router/base && kustomize edit set image ghcr.io/datum-cloud/galactic-router=ghcr.io/datum-cloud/galactic-router:<resolved-tag>
  cd config/galactic-gateway/base && kustomize edit set image ghcr.io/datum-cloud/galactic-router=ghcr.io/datum-cloud/galactic-router:<resolved-tag> && kustomize edit set image ghcr.io/datum-cloud/galactic-gateway=ghcr.io/datum-cloud/galactic-gateway:<resolved-tag>
  cd config/fabric-router && kustomize edit set image ghcr.io/datum-cloud/fabric-router=ghcr.io/datum-cloud/fabric-router:<resolved-tag>
  ```

- **`config/fabric-router/`: per-node `frr.conf`.** Unlike every other component under `config/`, `config/fabric-router/daemonset.yaml` has no generic default config — the underlay eBGP session (interface addresses, remote-AS, etc.) is different for every physical node, and this DaemonSet's `nodeAffinity` (`galactic.datumapis.com/node` `In` `[edge, control]`) can legitimately match more than one node per cluster. Before applying `config/fabric-router/`, create a `fabric-config` ConfigMap in the `galactic-system` namespace with one `frr.conf.<nodename>` key per matching node (`<nodename>` is the Kubernetes node name, e.g. `frr.conf.worker-1`) — `frr-init` picks the right key at pod start via the pod's `NODE_NAME` downward-API env var. The other two files FRR needs, `daemons` and `vtysh.conf`, are already baked into the `fabric-router` image (see `containers/fabric-router/Dockerfile`); include them in the ConfigMap too only if you need to override the image defaults. `deploy/containerlab/resources/fabric/{dfw,iad,sjc}/frr.conf` are worked examples from the lab, not something you can apply as-is.

- **`config/fabric-router/` and `config/galactic-router/`: rolling out updates is manual.** Both `config/fabric-router/daemonset.yaml` and `config/galactic-router/base/daemonset.yaml` use `updateStrategy: OnDelete` — a `kubectl apply` (new image tag, or a spec change) will not restart any pod on its own. This is deliberate for both: each is a BGP speaker whose liveness/health probe only reflects "the process is up," not "the BGP session has reconverged," so `RollingUpdate` would advance to the next node on exactly the wrong signal — see the comment above `updateStrategy` in each manifest for the full reasoning. To actually roll out a change, delete pods one at a time and confirm the new pod's session(s) have reconverged before moving to the next node, e.g. for `fabric-router`:

  ```bash
  kubectl -n galactic-system get pods -l app.kubernetes.io/name=fabric-router -o wide
  kubectl -n galactic-system delete pod <fabric-router-pod-on-one-node>
  # wait for the new pod to be Ready, then confirm on that node:
  kubectl -n galactic-system exec <new-pod> -- vtysh -c "show bgp summary"
  # repeat for the next node only once the above shows the session Established
  ```

  A ConfigMap edit to `fabric-config` behaves the same way today regardless of `updateStrategy` — there's no checksum annotation wiring pod restarts to ConfigMap changes, so a config change also requires this same manual, node-by-node pod bounce to take effect.

- **`config/galactic-router/`: rollout order — reflector last, one tenant at a time.** For `tenant-control` (the route reflector), every `tenant` node's iBGP session pivots through that one pod, so bouncing it is a fleet-wide route flap, not a single-node one — roll it only after all `tenant` nodes are already on the new version, and confirm every client has re-peered before considering the rollout done. For `tenant`, a bounce only withdraws that one node's own advertised prefixes, so it's safe to go node-by-node as with `fabric-router`. Check session state via the `BGPPeer` CRD's `STATE` column rather than `vtysh` (there's no `vtysh` in this binary — `galactic-router` reports session state itself):

  ```bash
  kubectl -n galactic-system get pods -l app.kubernetes.io/name=galactic-router-tenant -o wide
  kubectl -n galactic-system delete pod <galactic-router-pod-on-one-node>
  # wait for the new pod to be Ready, then confirm its BGPPeer CRDs are back to STATE=Established
  kubectl get bgppeer
  # repeat for the next tenant node, then only last roll galactic-router-control the same way
  ```

- **`config/galactic-gateway/`: per-node public interface and SRv6 address.** `config/galactic-gateway/base/daemonset.yaml`'s `galactic-gateway` container requires `GALACTIC_GATEWAY_PUBLIC_INTERFACE` and `GALACTIC_GATEWAY_SRV6_ADDRESS` — the latter must be unique per gateway node and has no generic default (there's no in-cluster mechanism yet that derives it automatically; see `publishSelfAddress`'s doc comment in `internal/controller/networkgateway_controller.go`). Applying `base/` as shipped, without pinning both per node, produces a crash-looping container. Instantiate `base/` via a further overlay that pins it to one node (`kubernetes.io/hostname`) and sets that node's values — see `deploy/containerlab/resources/galactic-gateway/` for a worked two-node example.

- **Talos: gRPC health port.** `galactic-router` runs `hostNetwork: true` and defaults to gRPC health checks on port `5000`, which collides with Talos's built-in dashboard (`/sbin/dashboard` permanently binds `127.0.0.1:5000` on every Talos node). `config/galactic-router/base/daemonset.yaml` already ships with `GALACTIC_ROUTER_GRPC_HEALTH_PORT=5179` (and matching probe/containerPort) to avoid this; if you run `galactic-router` outside these manifests on Talos, set `GALACTIC_ROUTER_GRPC_HEALTH_PORT` to something other than `5000` yourself.

- **`galactic-router`: BGP local address.** The node needs a global-unicast IPv6 address assigned to `lo` (typically by `config/fabric-router/`'s underlay eBGP daemon, which must start and converge before `galactic-router`), or you must set `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS` explicitly — this is required even when `GALACTIC_ROUTER_BGP_LISTEN_PORT=-1` (no inbound listener), since `galactic-router` still needs a source address for outbound BGP connections. Without one of these, startup fails with `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS not set and no address could be detected on lo: no global-unicast IPv6 address found on lo`. See [`docs/router/configuration.md`](./docs/router/configuration.md) for details.

See [`docs/router/configuration.md`](./docs/router/configuration.md) for the full `galactic-router` CLI flag / environment variable reference — env var names follow `GALACTIC_ROUTER_<FLAG_NAME>` (hyphens become underscores, uppercased); the reference table has the exact name for every flag.

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
task build           # produces bin/{galactic-cni,galactic-veth,galactic-tap,galactic-ipam,
                     # galactic-bgp,galactic-route,galactic-router,galactic-gateway,vmtap-cni}
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

See [AGENTS.md](./AGENTS.md) for the contributor guide (development workflow, code standards, architecture pointers) and its [Architecture Reference](./AGENTS.md#architecture-reference) section for links to the full per-component architecture docs (CNI, router, gateway).

## License

See [LICENSE](./LICENSE) for details.

---

*Galactic is developed by [Datum](https://datum.net).*
