# Deployable Assets & Ports Quick Reference

A single cross-cutting reference for every workload `kubectl apply -k
config/` (or one of its subdirectories) can put on a node, and every TCP
port each one's containers configure. This is a quick-reference index, not
a how-to — for deployment steps and full configuration reference, see each
component's own doc: [docs/router/configuration.md](router/configuration.md),
[docs/cni/configuration.md](cni/configuration.md),
[docs/gateway/configuration.md](gateway/configuration.md), and the
per-component architecture docs under
[docs/agents/](agents/ARCHITECTURE-CNI.md). For which node label puts which
DaemonSet on which node, see [docs/node-labels.md](node-labels.md) — this
document assumes that scheme and doesn't repeat it.

> Last verified: 2026-08-25 against the current working tree of `config/`,
> `internal/config/`, and `internal/installer/installer.go`.

## Deployable assets

Every DaemonSet in this repo runs `hostNetwork: true` — its containers'
ports are real listen ports on the node itself, not something Kubernetes
publishes. That's why the "Ports" table below groups ports by *node role*
as well as by container: two DaemonSets that can co-locate on the same
node must never pick the same port, and several already coordinate their
defaults for exactly that reason (see the notes column there).

| Asset                | Container(s)                               | `config/` path                                                                                                  | Node label(s) required                                                                            | Applied via                                                                                                                                                                                                                                                                                          | In root `config/kustomization.yaml`?  |
| -------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| `galactic-system`    | —                                          | `config/galactic-system/`                                                                                       | none                                                                                              | `kubectl apply -k config/galactic-system/`                                                                                                                                                                                                                                                           | Yes                                   |
| `galactic-cni`       | `install-cni` (init), `credential-refresh` | `config/galactic-cni/`                                                                                          | `galactic.datumapis.com/node=compute`                                                             | `kubectl apply -k config/galactic-cni/`                                                                                                                                                                                                                                                              | Yes                                   |
| `galactic-router`    | `galactic-router`                          | `config/galactic-router/overlays/default/`                                                                      | `galactic.datumapis.com/node=compute`                                                             | `kubectl apply -k config/galactic-router/` (both roles) or `.../overlays/default/` alone                                                                                                                                                                                                             | Yes                                   |
| `galactic-router-rr` | `galactic-router`                          | `config/galactic-router/overlays/rr/`                                                                           | `galactic.datumapis.com/galactic-route-reflector=true`                                            | `kubectl apply -k config/galactic-router/` (both roles) or `.../overlays/rr/` alone                                                                                                                                                                                                                  | Yes                                   |
| `galactic-nat66`     | `galactic-nat66`                           | RBAC/SA: `config/galactic-nat66/`. DaemonSet: `config/galactic-nat66/base/` + a hand-authored per-shard overlay | `galactic.datumapis.com/node=compute`, plus `galactic.datumapis.com/fabric=true` for underlay BGP | RBAC/SA: `kubectl apply -k config/galactic-nat66/`, once. `base/` is **never applied as-is** — `GALACTIC_NAT66_UPLINK_INTERFACE`/`_SHARD_SID`/`_SHARD_PUB_ADDR` have no generic default; a per-shard overlay must set all three                                                                      | No — opt-in, not "batteries included" |
| `galactic-gateway`   | `galactic-router`, `galactic-gateway`      | RBAC/SA: `config/galactic-gateway/`. DaemonSet: `config/galactic-gateway/base/` + a per-node overlay            | `galactic.datumapis.com/node=edge`, plus `galactic.datumapis.com/fabric=true` for underlay BGP    | RBAC/SA: `kubectl apply -k config/galactic-gateway/`, once. `base/` is **never applied as-is** — `GALACTIC_GATEWAY_PUBLIC_INTERFACE`/`_SRV6_ADDRESS` have no generic default; a per-node overlay must set both. See [docs/gateway/configuration.md](gateway/configuration.md) for the worked example | No — opt-in, not "batteries included" |
| `fabric-router`      | `frr-init` (init), `frr`                   | `config/fabric-router/`                                                                                         | `galactic.datumapis.com/fabric=true`                                                              | `kubectl apply -k config/fabric-router/`, after hand-authoring a `fabric-config` ConfigMap with one `frr.conf.<nodename>` key per matching node                                                                                                                                                      | No — no generic default exists        |

Not deployed by anything in `config/` today:

- **The CNI attach-chain binaries** — `galactic-veth`, `galactic-tap`,
  `galactic-ipam`, `galactic-bgp`, `galactic-route`. These aren't
  DaemonSets of their own; `galactic-cni`'s `install-cni` initContainer
  copies them onto the host's `/opt/cni/bin` (see
  `internal/installer/installer.go`'s `SourceVethBinary`/`SourceTapBinary`/
  `SourceIPAMBinary`/`SourceBGPBinary`/`SourceRouteBinary`), and kubelet
  invokes them directly, one short-lived process per pod ADD/DEL/CHECK.
  They open no ports and have no `config/` path of their own — see
  [docs/agents/ARCHITECTURE-CNI.md](agents/ARCHITECTURE-CNI.md).
- **`galactic-vrf`** (`cmd/galactic-vrf`) — the ingress-sidecar binary for
  per-pod VPC backend VRF/SRv6 route lifecycle (see
  `docs/plans/855-ingress-sidecar-vpc-backend-connectivity.md`). The binary
  and its container image exist, but no manifest in `config/` deploys it
  yet — it's designed to run as a second container inside an externally
  generated Envoy Gateway pod, and that injection is tracked as separate,
  not-yet-implemented work (referenced there as `#856`). Listed here for
  completeness, not as something you can `kubectl apply` today.

## Ports

All ports below are the values actually configured in `config/` manifests
today (an explicit env var where one is set, the binary's own compiled-in
default otherwise) — not necessarily the binary's own default in isolation,
since several roles override it. `galactic-router`'s standalone binary
default for `--bgp-listen-port`, for instance, is `179`
([docs/router/configuration.md](router/configuration.md)), but every
manifest below overrides it.

### Compute-node pod group (`galactic-router` default role + `galactic-cni` + `galactic-nat66`)

These three DaemonSets are all opt-in on `galactic.datumapis.com/node=compute`
and routinely co-locate on the same node — their ports are chosen not to
collide with each other or with the route-reflector/gateway roles below.

| DaemonSet         | Container            | Port purpose | Port               | Configured via                                                            |
| ----------------- | -------------------- | ------------ | ------------------ | ------------------------------------------------------------------------- |
| `galactic-router` | `galactic-router`    | Metrics      | `9179`             | binary default (no override in `overlays/default/`)                       |
| `galactic-router` | `galactic-router`    | gRPC health  | `5179`             | `GALACTIC_ROUTER_GRPC_HEALTH_PORT=5179` (`base/daemonset.yaml`)           |
| `galactic-router` | `galactic-router`    | BGP listen   | _(disabled, `-1`)_ | `GALACTIC_ROUTER_BGP_LISTEN_PORT=-1` — outbound-only, no inbound listener |
| `galactic-cni`    | `credential-refresh` | gRPC health  | `5180`             | `--grpc-health-port` default (`cmd/galactic-cni/main.go`)                 |
| `galactic-cni`    | `credential-refresh` | Metrics      | `9180`             | `--metrics-port` default (`cmd/galactic-cni/main.go`)                     |
| `galactic-nat66`  | `galactic-nat66`     | Metrics      | `9182`             | binary default (`config.DefaultNAT66MetricsPort`; no override)            |
| `galactic-nat66`  | `galactic-nat66`     | gRPC health  | `5182`             | `GALACTIC_NAT66_GRPC_HEALTH_PORT=5182` (`base/daemonset.yaml`)            |

### Route-reflector node (`galactic-router-rr`)

Same container, patched from the same `base/daemonset.yaml` as the default
role above, but with BGP listening enabled — this is the one role in the
whole repo where `galactic-router` actually opens an inbound BGP port.

| Container         | Port purpose | Port   | Configured via                                                              |
| ----------------- | ------------ | ------ | --------------------------------------------------------------------------- |
| `galactic-router` | Metrics      | `9179` | inherited from `base/daemonset.yaml` (unchanged by the `rr` patch)          |
| `galactic-router` | gRPC health  | `5179` | inherited from `base/daemonset.yaml` (unchanged by the `rr` patch)          |
| `galactic-router` | BGP listen   | `1790` | `GALACTIC_ROUTER_BGP_LISTEN_PORT=1790` (`overlays/rr/daemonset-patch.yaml`) |

### Gateway node (`galactic-gateway` pod: `galactic-router` + `galactic-gateway`)

Two containers sharing one `hostNetwork` pod, so their ports must not
collide with each other — see
[docs/gateway/configuration.md](gateway/configuration.md#configuration-reference-internalconfiggatewaygo)
for why `galactic-gateway`'s defaults (`8081`/`5181`) were chosen
specifically to differ from `galactic-router`'s (`9179`/`5179`).

| Container          | Port purpose | Port               | Configured via                                                            |
| ------------------ | ------------ | ------------------ | ------------------------------------------------------------------------- |
| `galactic-router`  | Metrics      | `9179`             | binary default (no override in `base/daemonset.yaml`)                     |
| `galactic-router`  | gRPC health  | `5179`             | `GALACTIC_ROUTER_GRPC_HEALTH_PORT=5179` (`base/daemonset.yaml`)           |
| `galactic-router`  | BGP listen   | _(disabled, `-1`)_ | `GALACTIC_ROUTER_BGP_LISTEN_PORT=-1` — outbound-only, no inbound listener |
| `galactic-gateway` | Metrics      | `8081`             | binary default (`config.DefaultGatewayMetricsPort`; no override)          |
| `galactic-gateway` | gRPC health  | `5181`             | `GALACTIC_GATEWAY_GRPC_HEALTH_PORT=5181` (`base/daemonset.yaml`)          |

### Fabric node (`fabric-router`)

| Container | Port purpose  | Port  | Configured via                                                                                                                        |
| --------- | ------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `frr`     | eBGP underlay | `179` | opened by `bgpd` itself once the per-node `frr.conf.<nodename>` enables it; the manifest's `containerPort: 179` is documentation only |

### Not on a node today

| Binary         | Port purpose | Port   | Configured via                                                                          |
| -------------- | ------------ | ------ | --------------------------------------------------------------------------------------- |
| `galactic-vrf` | Metrics      | `9182` | `GALACTIC_VRF_METRICS_PORT` / `config.DefaultVRFMetricsPort` (`internal/config/vrf.go`) |

`galactic-vrf` shares the same numeric default as `galactic-nat66`'s
metrics port above — safe only because `galactic-vrf` is designed to run
as a second container inside a regular (non-`hostNetwork`) Envoy Gateway
pod, per its own port-choice comment in `internal/config/vrf.go`, not
because the two ever compete for the same node namespace.

## See also

- [docs/node-labels.md](node-labels.md) — the node-labeling strategy this
  document's "Node label(s) required" column assumes.
- [docs/router/configuration.md](router/configuration.md),
  [docs/gateway/configuration.md](gateway/configuration.md),
  [docs/cni/configuration.md](cni/configuration.md) — full configuration
  reference (all options, not just ports) for each binary.
- [docs/agents/ARCHITECTURE-CNI.md](agents/ARCHITECTURE-CNI.md),
  [docs/agents/ARCHITECTURE-ROUTER.md](agents/ARCHITECTURE-ROUTER.md),
  [docs/agents/ARCHITECTURE-GATEWAY.md](agents/ARCHITECTURE-GATEWAY.md) —
  design rationale for each component.
