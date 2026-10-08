# Architecture — fabric-api

> The fabric looking glass: a single `fabric-api` binary that answers
> bounded, asynchronous diagnostics about `fabric-router`'s FRR state. Its
> `node` subcommand runs as a sidecar in each `fabric-router` pod and reads
> FRR over its vty sockets or sends ICMP probes from the node's fabric
> loopback; its `gateway` subcommand runs once per edge cell, executes
> `FabricQuery` objects by fanning them out to the node sidecars over mTLS
> gRPC, and serves an operator debug service; its `janitor` subcommand
> deletes expired `FabricQuery` copies the federation failed to delete; its
> `certsync` subcommand runs in a separate per-node pod that obtains the
> sidecar's certificate. Everything is opt-in, and a diagnostic failure never
> gates routing.

_Last updated: 2026-10-07_

This document covers `cmd/fabric-api` and `internal/fabric/` only: the
galactic half of the looking glass. The public `LookingGlassQuery` API, the
federation hub plumbing (the `FabricQuery` hub CRD install, per-cell
propagation policies, Karmada status aggregation) and the cell issuer belong
to other repositories and are described here only where this code depends on
them. See [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md) for the
`galactic-router` control plane and [ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md)
for the unrelated `galactic-gateway` L4 load balancer: despite the name,
fabric-api's "gateway" is a cell-level query executor and has nothing to do
with `NetworkGateway`. `fabric-router` itself (the FRR underlay DaemonSet and
`fabric-config-agent`) is described in [AGENTS.md](../../AGENTS.md#deployments);
this document covers only the fourth container fabric-api adds to its pod.
Operator-facing configuration is in
[docs/fabric-api/configuration.md](../fabric-api/configuration.md), and the
`FabricQuery` contract is in [docs/fabric-api/api.md](../fabric-api/api.md).

---

## Overview

`fabric-router` runs FRR as the underlay eBGP speaker on every node, and
FRR's vty sockets live in a pod-scoped `emptyDir` (`/run/frr`), so nothing
outside the pod can read routing state. fabric-api is the supported way to
look at it: it answers seven query types, each against one router's own view.

| Query type       | Reads                                                                    | Cost                               |
| ---------------- | ------------------------------------------------------------------------ | ---------------------------------- |
| `RouteLookup`    | bgpd (`show bgp <afi> unicast <target> json`), zebra                     | One prefix; exact or longest match |
| `BGPSummary`     | bgpd (`show bgp <afi> unicast summary json`)                             | Peer table                         |
| `Ping`           | Raw ICMP socket                                                          | 3 echo requests                    |
| `Traceroute`     | Raw ICMP socket                                                          | Up to 20 hops, 1 probe per hop     |
| `ASPath`         | The sidecar's search index (default), or bgpd with `--search-source=frr` | Whole table; gated                 |
| `Community`      | The search index (default), or bgpd                                      | Whole table; gated                 |
| `LargeCommunity` | The search index (default), or bgpd                                      | Whole table; gated                 |

The three scanning types ("expensive" in the code) are refused with
`QueryTypeUnavailable` unless the node runs with `--enable-expensive-queries`.
They search the whole BGP table, so by default they are answered not by FRR but
by a local copy of bgpd's selected routes that the sidecar keeps from a BMP
stream (the search index, `internal/fabric/index`). The full-table load test in
[docs/fabric-api/load-test.md](../fabric-api/load-test.md) showed that FRR's own
scans pin bgpd's main thread and roughly triple convergence after a session reset,
and that the index passes the gate. Searches stay off by default until staging
confirms those numbers on real fabric routers.

Three principles shape everything below:

- **Bounded.** Every boundary has a byte, count or time limit that a caller
  cannot raise: FRR's response (4 MiB), a node's response (128 KiB), the
  `FabricQuery` object (384 KiB), the request lifetime (120 s) and a node's
  execution (30 s). Results are shaped down to budget with `truncated=true`,
  or refused with `ResponseTooLarge`; they are never persisted unbounded and
  trimmed later.
- **Per-router.** Each node's answer is its own observation, with its own
  sample time, router ID and ASN. Nothing merges paths across nodes or
  invents a location-wide best path. BGP selection and zebra installation
  are sampled separately and neither asserts end-to-end reachability.
- **Diagnostics never gate routing.** The sidecar has no readiness, liveness
  or startup probe, and a missing certificate, an unreachable vty socket or an
  unsupported FRR version makes it report "diagnostics unavailable", not fail.

The binary is separate from the `fabric-router` image, which carries FRR and
`fabric-config-agent`. The `fabric-api` image is a static Go binary on
`gcr.io/distroless/static:nonroot` with no FRR, no `vtysh` and no shell, and it
imports no eBPF packages, so building it needs no clang or `go generate`. The
same image serves the node sidecar, the gateway Deployment, the janitor
CronJob, the per-node `certsync` pod and the operator `query` client.

---

## Repository Layout

```
cmd/fabric-api/
  main.go                      Root command, logging flags, --version/--build-info
  node.go                      `node`: sidecar server, probe source selection
  gateway.go                   `gateway`: controller-runtime manager, debug server
  janitor.go                   `janitor`: expired FabricQuery sweeper
  query.go                     `query`: operator client for the node and the gateway
  certsync.go                  `certsync`: copies a csi-issued certificate to the node
  tracing.go                   W3C propagation; OTLP exporter when configured

api/fabric/v1/
  fabric.proto                 FabricService (node) and FabricGatewayService (debug)
  fabric.pb.go, fabric_grpc.pb.go   Generated by buf, committed

internal/fabric/
  api/v1alpha1/                FabricQuery types, deepcopy, CRD envtest
  query/                       Canonical query, destination policy, budgets
  frr/                         vty client, closed command builder, version gate, parsers
  probe/                       ICMP ping and traceroute on raw sockets
  index/                       BMP station and in-memory index of bgpd's selected routes
  identity/                    URI SAN identities, reloading mTLS credentials, certificate sync
  errcode/                     Typed error codes carried as gRPC ErrorInfo
  node/                        FabricService implementation (the sidecar's logic)
  gateway/                     Reconciler, Runner, Executor, Pool, Discoverer, Debug, Janitor
  testpki/                     Throwaway CA for tests

config/fabric-api/
  serviceaccount.yaml, rbac.yaml   Gateway and janitor identities and RBAC
  kustomization.yaml               Applies only the two files above
  base/                            Gateway Deployment, Service, PDB, janitor CronJob
  crd/                             Generated FabricQuery CRD (lab and tests only)

config/fabric-router/components/fabric-api/
  kustomization.yaml, daemonset-patch.yaml   The opt-in sidecar Component
  certs-daemonset.yaml             fabric-api-certs: obtains each node's certificate

config/monitoring/
  podmonitor-fabric-router.yaml    api-metrics endpoint (job=fabric-api-node)
  podmonitor-fabric-api-gateway.yaml
  prometheusrule.yaml              `fabric-api` rule group

containers/fabric-api/Dockerfile
hack/fabric-api-loadtest/        Full-table load harness (task test:fabric-api-load)
deploy/containerlab/             deploy:cert-manager, deploy:fabric-api, verify:fabric-api*
```

The generated Go files under `api/fabric/v1/` are committed and never hand
edited; regenerate them with `task generate:proto`. `zz_generated.deepcopy.go`
and `config/fabric-api/crd/` come from `task generate:crd`.

---

## Data Flow

### Federated path (`FabricQuery`)

A public `LookingGlassQuery` is turned into one `FabricQuery` per resolved cell
by NSO on the federation hub; Karmada propagates it to the one pinned member
cluster. From there the cell gateway takes over:

```
 hub (NSO, out of scope)             edge cell (this repo)
 ───────────────────────             ─────────────────────────────────────────────
 FabricQuery  ──Karmada──►  FabricQuery (spec immutable, expiresAt <= 120 s)
                                   │ watch (cached, all namespaces)
                                   ▼
                       gateway Reconciler (leader only)
                         1. predicate: spec.site and spec.clusterName match
                         2. validate: re-canonicalize, clamp budgets, check expiry
                         3. snapshot fabric-router pods ──► fixed node list
                         4. status: start marker (attempt, nodes, Running)
                         5. launch execution under the leader's context
                                   │
                                   ▼
                       Runner: one goroutine per selected node
                         Executor.Acquire (8 slots, 2 expensive, 256 queue,
                                           round robin across projects)
                                   │ mTLS gRPC Execute, hostIP:9344
                                   ▼
                       node sidecar (one per fabric-router pod)
                         identity ─► shape ─► node name ─► expiry ─► enabled
                         type ─► dedup (requestID, node, type) ─► budgets
                                   │
                    ┌──────────────┴───────────────┐
                    ▼                              ▼
          bgpd.vty / zebra.vty (read)     raw ICMP socket (probe)
                    └──────────────┬───────────────┘
                                   ▼
                            Observation, or a typed error
                                   │
                       Reconciler.persist: one terminal status write
                         shape to object budget, set conditions + coverage
                                   │
 FabricQuery.status  ◄──Karmada status return──  FabricQuery.status
 (NSO groups observations by location)
```

Execution is at-least-once. The node suppresses duplicates by
`(requestID, node, operation)`, and a completed query (`Complete=True`) is
never touched again. A gateway that dies after an RPC but before the terminal
write is replaced by a leader that resumes on the status's fixed snapshot with
`attempt` incremented, which may repeat node calls; the dedup cache absorbs
most repeats but is in memory, so a node restart or eviction permits one.

### Operator debug path

An operator with a certificate carrying an `operator` identity can bypass the
federation, for diagnosing a cell directly:

```
 fabric-api query ──mTLS──► gateway Service (ClusterIP :9346)
   --gateway host:9346           │ any replica; a follower forwards Query to the
                                 │ leader named by the election lease's holder
                                 ▼
                       Debug.Query ─► Runner (project key "operator/<name>")
                                 │ nodes see the *gateway* identity, so the
                                 ▼ public destination policy applies
                            node sidecars

 fabric-api query ──mTLS──► one node sidecar (hostIP:9344)
   --node host:9344             node sees an *operator* identity, so the
                                operator destination policy applies
```

Both routes run the same canonicalization, validation and limits as federated
execution. They differ only in which destination policy the node applies, which
follows the caller's role, not the route (see
[Known Constraints](#known-constraints)).

### Search path (BMP-fed index)

`ASPath`, `Community` and `LargeCommunity` do not go to bgpd's search commands.
bgpd streams its selected routes to the sidecar, which searches its own copy:

```
 bgpd ──BMP Loc-RIB (ipv4 + ipv6 unicast)──► Station 127.0.0.1:9348
        `bmp targets fabric-api`                 │ loopback peer, one session
                                                 ▼
                                    Index: prefix ─► interned attribute set
                                      BeginSession: empty, bgpd resends the table
                                      synced: update rate settles after the
                                              initial dump (or End-of-RIB)
                                      EndSession: unsynced
                                                 │
 Execute(ASPath|Community|LargeCommunity) ───────┤ synced: Search ─► matches +
                                                 │   exact total + index state
                                                 └ unsynced: QueryTypeUnavailable
                                                   (no scan of bgpd)
```

A search is subject to the same node checks as any other (identity, canonical
query, expiry, `--enable-expensive-queries`) and to the one-search-at-a-time
budget. Its result carries the index's state (`syncedAt`, `lastUpdate`, `version`,
`routes`) so a consumer can judge freshness.

---

## Entry Points

All subcommands share `--log-level` (env `LOG_LEVEL`, default `info`) and
`--log-format` (env `LOG_FORMAT`, `json` or `text`, default `json`). The root
command also takes `--version`/`-V` and `--build-info`. Every flag with an env
var is listed in [docs/fabric-api/configuration.md](../fabric-api/configuration.md).

### `cmd/fabric-api/node.go` — `fabric-api node`

The sidecar. It requires `--node-name`, `--namespace`, `--pod-name` and
`--host-ip` (all from the downward API in the Component) and exits with an
error without them. `--cell` is the exception: with an empty cell the process
does not exit. It logs an error and serves only metrics until signalled, so a
missing per-cell ConfigMap crash-loops nothing in the `fabric-router` pod.
Its certificate is issued to the `fabric-api-certs` pod on its node, not to its
own pod, so its credentials accept any node identity in its cell and namespace
(`Credentials.AcceptAnyNode`); the gateway pins the node's certs pods when it dials.
It reads the certificate from `/var/run/fabric-api/tls`, a read-only hostPath
mount of the node's `/run/fabric-api/tls`.

With a cell set, `runNode`:

1. Resolves per-family probe sources (`probeSources`).
2. With `--search-source=index` (the default), creates the search index and its
   BMP station on `--bmp-station-address` (`127.0.0.1:9348`) and registers the
   index metrics. `--search-source=frr` skips this and answers searches with FRR's
   own scans. Any other value is an error.
3. Builds a `node.Server` with a `frr.VTY` (4 MiB read cap), a `probe.Prober`,
   the index (if any), the public and operator destination policies and the node
   budgets.
4. Starts `identity.Credentials.Run` (reload every 10 s) and `Server.Run`
   (reads FRR's version, router ID and ASN every 60 s, every 5 s while FRR is
   unreachable; a request that finds the last read unreachable also re-reads
   FRR, at most once a second, so a node does not refuse diagnostics for a
   minute after FRR comes up).
5. Serves `FabricService` and the standard gRPC health service on
   `<host-ip>:9344` with TLS 1.3, a 64 KiB receive limit and a send limit of
   the node response ceiling plus 16 KiB. Health is `SERVING` only while
   `Info.diagnostics_available` is true, and is wired to no pod probe.
6. Serves `/metrics` on `<host-ip>:9345` unless `--metrics-bind-address` is set.

Shutdown is a graceful gRPC stop with a 10 s limit.

### `cmd/fabric-api/gateway.go` — `fabric-api gateway`

The cell executor. It requires `--site`, `--cluster-name`, `--cell` and
`--pod-name`. It builds a controller-runtime manager with leader election
(lease `fabric-api-gateway` in the pods' namespace, released on cancel), caches
`Pod`s only in the `fabric-router` namespace and `FabricQuery` cluster-wide, and
registers:

- the `fabricquery` controller (`gateway.Reconciler`, 8 concurrent reconciles),
  whose execution context exists only while this replica leads;
- a `StaleCounter` that publishes `fabric_api_gateway_stale_objects` on every
  replica, using `--retention` and `--cleanup-grace` (keep them equal to the
  janitor's);
- the operator debug gRPC server (`gateway.Debug`) on port 9346 (every address
  unless `--debug-bind-address` is set), authorized per role by
  `node.AuthInterceptor(gateway.DebugMethods)`.

Metrics are registered on controller-runtime's registry and served on `:9347`
along with its own; `/healthz` and `/readyz` are plain pings on `:8081`.

### `cmd/fabric-api/certsync.go` — `fabric-api certsync`

Runs in the `fabric-api-certs` DaemonSet pod on each fabric node. Every
`--interval` (10 s) it copies `tls.crt`, `tls.key` and `ca.crt` from `--source`
(the csi-driver volume, default `/var/run/fabric-api/csi`) to `--dest` (the
node-local directory the sidecar reads, default `/var/run/fabric-api/node`,
the hostPath `/run/fabric-api/tls` on the node). It copies only when all three
files exist, the key pair validates and the content differs, and it replaces
each file atomically (`internal/fabric/identity/sync.go`). If the Issuer cannot
issue, this pod waits and the sidecar reports no credentials; the
`fabric-router` pod is unaffected.

### `cmd/fabric-api/janitor.go` — `fabric-api janitor`

Lists `FabricQuery` in every namespace and deletes those whose expiration or
completion, whichever is later, is more than `--retention` plus `--grace` in the
past. `--interval 0` (the default) sweeps once and exits, which is how the
CronJob runs it. A non-zero interval loops.

### `cmd/fabric-api/query.go` — `fabric-api query`

The operator client: `fabric-api query [TYPE [TARGET]]` with exactly one of
`--gateway host:port` or `--node host:port` (plus `--node-name` and `--node-pod`,
the node's `fabric-api-certs` pod, whose identity its sidecar presents). `--info` asks a node for its identity and availability.
It canonicalizes the query locally, calls with the operator certificate
(`--cell`, `--operator`, `--tls-*`), and prints the response as JSON. Errors print
as `<code>: <message>` using the typed code.

### `cmd/fabric-api/tracing.go`

W3C trace context and baggage propagation is always on. An OTLP gRPC exporter is
enabled only when `OTEL_EXPORTER_OTLP_ENDPOINT` or
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set, with service name `fabric-api-node`
or `fabric-api-gateway`.

---

## Configuration

Flags and environment variables, ports, certificate identities, limits and
rollout are documented in
[docs/fabric-api/configuration.md](../fabric-api/configuration.md); this section
lists only what the architecture depends on.

| Port | Component | Binds to            | Purpose                                                |
| ---- | --------- | ------------------- | ------------------------------------------------------ |
| 9344 | node      | pod's `hostIP`      | mTLS gRPC `FabricService` (`fabric-api` port)          |
| 9345 | node      | `hostIP` by default | `/metrics` (`api-metrics` port)                        |
| 9346 | gateway   | all addresses       | mTLS gRPC operator debug service (`debug` port)        |
| 9347 | gateway   | all addresses       | `/metrics` (`metrics` port)                            |
| 9348 | node      | `127.0.0.1` only    | BMP station: bgpd's Loc-RIB stream to the search index |
| 8081 | gateway   | all addresses       | `/healthz`, `/readyz` (`health` port)                  |

The Component's `fabric-api` container reads `NODE_NAME`, `POD_NAME`,
`POD_NAMESPACE` and `HOST_IP` from the downward API, and `SITE` and `CELL` from
the optional per-cell `fabric-api` ConfigMap. The gateway reads `SITE`, `CELL`
and `CLUSTER_NAME` from the same ConfigMap (keys `site`, `cell`,
`cluster-name`). The fabric-router pod is `hostNetwork`, so 9344 and 9345 are on
the node's own address; they are bound to `hostIP` only and not to every
interface, because edge nodes carry public uplinks.

The Component also adds the `fabric-api-certs` DaemonSet (see
[Key Design Decisions](#key-design-decisions)), with the same placement as
`fabric-router`, no API token, and a `csi.cert-manager.io` volume named
`fabric-api-csi` whose URI SAN names that pod.

The Component sets `automountServiceAccountToken: false` on the pod and adds a
projected token volume mounted only into `frr-init` and `config-agent`, the two
containers that call the Kubernetes API. The `fabric-api` sidecar needs no API
access and gets no token.

---

## Module / Package Reference

| Package                                     | Responsibility                                                                                                                                                                                                     | Owns state                                        |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------- |
| `cmd/fabric-api`                            | Cobra commands (`node`, `gateway`, `janitor`, `query`, `certsync`), flag/env wiring, probe source selection, tracing                                                                                               | No                                                |
| `api/fabric/v1`                             | `FabricService` and `FabricGatewayService` contract: `Execute`, `Info`, `Query`, `ListNodes`; observations, budgets                                                                                                | No                                                |
| `internal/fabric/query`                     | `Canonicalize` (target rules, family inference, AS-path grammar, community forms), `DestinationPolicy`, `Budgets`/`Ceilings`, probe limits. Imports nothing from the rest of galactic                              | No                                                |
| `internal/fabric/frr` (`command.go`)        | Closed command builder: `VersionCommand`, `SummaryCommand`, `LookupCommand`, `SearchCommand`, `RouteCommand`. `Command` fields are unexported, so there is no free-text path                                       | No                                                |
| `internal/fabric/frr` (`vty.go`)            | Unix-socket client: `cmd\0` out, read to `\0\0\0<ret>`, per-command connection, byte cap, deadline handling                                                                                                        | No                                                |
| `internal/fabric/frr` (`parse.go`)          | Typed parsers for lookup, search, summary and zebra installation; malformed input is an error, never an empty answer                                                                                               | No                                                |
| `internal/fabric/frr` (`version.go`)        | `SupportedReleases = ["10.7"]`, `CheckSupported` (`FRRVersionUnsupported`)                                                                                                                                         | No                                                |
| `internal/fabric/probe`                     | `Prober.Ping`/`Traceroute` on raw ICMP/ICMPv6 sockets bound to a source; reply correlation by ID, sequence and quoted packet                                                                                       | No                                                |
| `internal/fabric/index` (`index.go`)        | `Index`: selected-path store with interned, reference-counted attribute sets; `Search` (AS-path, community, large community; exact total, first matches in prefix order); sync state; `MaxRoutes` overflow counter | Routes and attribute sets (memory)                |
| `internal/fabric/index` (`station.go`)      | `Station`: BMP (RFC 7854) station for Loc-RIB route monitoring (RFC 9069); loopback peers only, one session at a time; synced when the dump's update rate settles                                                  | The BMP session                                   |
| `internal/fabric/identity`                  | `ID` and its URI SAN; `Credentials` (reload, rotation, fail closed, `AcceptAnyNode`), `ServerConfig`/`ClientConfig`; `Sync` (certificate copy for `certsync`)                                                      | Loaded certificate, key and bundle                |
| `internal/fabric/errcode`                   | Typed codes, gRPC status mapping, `ErrorInfo` (domain `fabric-api.datumapis.com`; `InvalidQuery` carries the query package's code under metadata key `queryCode`)                                                  | No                                                |
| `internal/fabric/node` (`server.go`)        | `Execute` pipeline, `Info`, FRR identity refresh, expensive-query breaker, probe policy and budgets                                                                                                                | Semaphores, limiter, breaker, last-read FRR state |
| `internal/fabric/node` (`dedup.go`)         | Duplicate-suppression cache keyed by `(requestID, node, operation)`, bounded in entries and bytes                                                                                                                  | In-memory cache                                   |
| `internal/fabric/node` (`shape.go`)         | Per-node shaping: path and community caps, response fit                                                                                                                                                            | No                                                |
| `internal/fabric/node` (`auth.go`)          | `AuthInterceptor`: identity from the handshake, per-role method table, call logging                                                                                                                                | No                                                |
| `internal/fabric/gateway` (`reconciler.go`) | `FabricQuery` lifecycle: validation, snapshot, start marker, terminal status, conditions, coverage, shrink to budget                                                                                               | In-flight executions (memory)                     |
| `internal/fabric/gateway` (`runner.go`)     | `Pool` (one mTLS connection per sidecar, pinned to its certs pod's identity), `Runner` fan-out, per-node deadline, cheap-read retry                                                                                | Connections                                       |
| `internal/fabric/gateway` (`executor.go`)   | Cell-wide slots with an expensive sub-budget and per-project round-robin queue                                                                                                                                     | Queue state                                       |
| `internal/fabric/gateway` (`discovery.go`)  | Pod snapshot with omission reasons, one pod per node, node budget, node-to-certs-pod mapping (`NoCertificatePod`)                                                                                                  | No                                                |
| `internal/fabric/gateway` (`debug.go`)      | Operator debug service, leader forwarding through the election lease                                                                                                                                               | Connection to the leader                          |
| `internal/fabric/gateway` (`janitor.go`)    | `Janitor.Sweep`, `StaleCounter`                                                                                                                                                                                    | No                                                |
| `internal/fabric/gateway` (`metrics.go`)    | `fabric_api_gateway_*` and shared `fabric_api_*` collectors                                                                                                                                                        | Prometheus collectors                             |
| `internal/fabric/api/v1alpha1`              | `FabricQuery` Go types with kubebuilder markers, condition and reason constants, request labels                                                                                                                    | No                                                |

---

## External Dependencies

| Dependency                                  | Used for                                                                                                                                                                                                                                                                |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FRR 10.7 (`fabric-router` image)            | The only data source for non-probe queries. Read through `/run/frr/bgpd.vty` and `/run/frr/zebra.vty`; no `vtysh`, no `exec`                                                                                                                                            |
| bgpd's BMP module (`-M bmp`)                | Streams the Loc-RIB to the sidecar's station on `127.0.0.1:9348` when the node's `frr.conf` has the `bmp targets fabric-api` block. The `fabric-router` image's `daemons` file already loads the module. The production `frr.conf` renderer (infra) must emit the block |
| cert-manager and its csi-driver             | Issues each `fabric-api-certs` pod's and the gateway's short-lived certificate and renews it in place. A required prerequisite; this repo installs none of it                                                                                                           |
| The cell's `fabric-api` `Issuer`            | Backed by a dedicated per-cell CA. Owned by infra in production; the lab's own is `deploy/containerlab/resources/fabric-api/pki/`                                                                                                                                       |
| `FabricQuery` CRD (`network.datumapis.com`) | Installed by infra in every cell. `config/fabric-api/crd/` is the lab and test copy                                                                                                                                                                                     |
| NSO and Karmada                             | Create `FabricQuery` objects on the hub and propagate them to the pinned cluster; return status. Out of scope here                                                                                                                                                      |
| `sigs.k8s.io/controller-runtime`            | Manager, leader election, cached client for `FabricQuery` and `Pod`                                                                                                                                                                                                     |
| `google.golang.org/grpc`                    | Node and debug services, health service, keepalive                                                                                                                                                                                                                      |
| `golang.org/x/net/icmp`, `x/time/rate`      | Raw ICMP sockets; the node-wide probe packet limiter                                                                                                                                                                                                                    |
| `prometheus/client_golang`                  | Node metrics (private registry) and gateway metrics (controller-runtime's registry)                                                                                                                                                                                     |
| OpenTelemetry (`otelgrpc`, OTLP)            | Optional tracing of every RPC                                                                                                                                                                                                                                           |
| Prometheus Operator CRDs                    | Only for `config/monitoring/`, which is not part of the default `config/` kustomization                                                                                                                                                                                 |

---

## Key Design Decisions

- **`FabricQuery` types live in galactic until the `network` repository ships
  them.** The kind is `network.datumapis.com/v1alpha1`, as the plan locks, but
  `../network` does not contain it yet and is read-only from here. The Go types
  are in `internal/fabric/api/v1alpha1`; `config/fabric-api/crd/` holds a
  generated CRD for the lab and tests only (`task generate:crd`). The shared
  canonicalization in `internal/fabric/query` imports nothing from the rest of
  galactic so it can move to `network` unchanged, where NSO and galactic would
  both import it. Swapping is an import change.
- **FRR 10.7 only.** `frr.SupportedReleases` is `["10.7"]`. The sidecar reads
  `show version` at startup and on reconnect, and any other release reports
  `FRRVersionUnsupported` and diagnostics unavailable instead of parsing on a
  guess. The parser fixtures in `internal/fabric/frr/testdata/frr-10.7/` were
  captured from a standalone four-router FRR 10.7.1 topology (two eBGP
  upstreams with ECMP, communities, large communities and a default route; one
  iBGP neighbor; a local AS_SET aggregate; a down peer), so they do not depend
  on lab routing state. 10.2 support and its fixtures were dropped once the lab
  moved to 10.7.1. An `FRR_VERSION` bump in `fabric-router` needs a fabric-api
  release that supports it first: capture the new fixtures into
  `testdata/frr-<major>.<minor>/`, add the release to `SupportedReleases`, then
  move the image.
- **vty framing and warning-as-data.** The client writes `command\0` and reads
  until it sees `\0\0\0<ret>`. Return code 0 is success, 1 is a warning, and
  anything else (2 is "unknown command") is `CommandFailed`. A warning whose
  output is a complete JSON object is data: zebra answers an absent route with
  `{}` and code 1. A warning whose output is not JSON is FRR rejecting the
  command (for example a regular expression it cannot compile) and becomes
  `CommandFailed`. Each command uses its own connection, so a daemon restart
  costs one failed command. The response cap is 4 MiB; exceeding it closes the
  connection and returns `ResponseTooLarge` with no partial output. Parsers
  require complete valid JSON, and a path missing its AS path or next hops is
  malformed, not skipped.
- **Closed command builder.** `frr.Command` has unexported fields and is only
  built by five constructors, each a fixed template over typed values. A
  `show ` prefix and printable-ASCII check inside `build` is a second line of
  defence, not the authorization rule. There is no raw-command RPC. A read-only
  socket mount would not make the socket read-only, so this builder is what
  keeps fabric-api read-only; a compromised sidecar could bypass it, and the
  design treats the sidecar as trusted control-plane code accordingly.
- **gRPC `ErrorInfo` error model.** A successful `Execute` returns an
  `Observation`. Every failure is a gRPC status whose `google.rpc.ErrorInfo`
  reason is the typed code (domain `fabric-api.datumapis.com`), so the code
  survives the wire and maps onto `FabricQuery` and public reasons.
  `ResponseTooLarge` travels as `RESOURCE_EXHAUSTED`. `errcode.Of` falls back
  to a code derived from the gRPC status when no `ErrorInfo` is present.
- **Per-pod SPIFFE-style URI SAN identities.** Each certificate carries exactly
  one URI SAN in trust domain `fabric-api.datumapis.com`:
  `/cell/<cell>/gateway`, `/cell/<cell>/ns/<ns>/pod/<pod>` or
  `/cell/<cell>/operator/<name>`. The node identity names a pod rather than the
  node because cert-manager's csi-driver can template a pod's name but not its
  node's. That pod is the node's `fabric-api-certs` pod, not the
  `fabric-router` pod (see the next decisions). The gateway's `Discoverer` maps
  each node to its newest Running `fabric-api-certs` pod
  (`--certs-selector`, default `app.kubernetes.io/name=fabric-api-certs`),
  records it in `status.nodes[].certificatePod`, and dials accepting only the
  identities of that node's certs pods (`Credentials.ClientConfigAny`): the
  newest and any it is replacing, since the sidecar presents a replaced pod's
  certificate until the new one reaches it. A node with no running certs pod is omitted with reason
  `NoCertificatePod`. The sidecar cannot know that pod's name, so its
  credentials accept any node identity in its own cell and namespace
  (`AcceptAnyNode`). The trust bundle is per cell, and the cell segment is
  checked as well as the chain. Chain verification is done in
  `VerifyPeerCertificate` against the bundle current at handshake time, with
  `InsecureSkipVerify` set only to replace the stock verifier, which would pin
  roots at config creation and check a DNS name.
- **Credential reload.** `identity.Credentials` polls the mounted files every
  30 s and swaps in new ones only when the certificate matches `Self` (for the sidecar, any node identity in its cell and namespace), is valid
  now and chains to the bundle it ships with. A bad renewal keeps the previous
  credentials until they expire; with none loaded, every handshake fails closed
  and the process keeps running and retrying. Rotation therefore needs no
  restart, and CA rotation works through multi-certificate bundles.
- **Sidecar runs as UID 0 with only `NET_RAW`.** Raw ICMP sockets need
  `CAP_NET_RAW` in the effective set, and Kubernetes grants added capabilities
  to a non-root container's bounding set only. So the Component sets
  `runAsUser: 0`, `runAsGroup: 102` (`frrvty`), drops every capability and adds
  `NET_RAW`. Without `CAP_DAC_OVERRIDE` it reaches FRR's `0770 frr:frrvty`
  sockets through group 102, as `frr-exporter` does. The root filesystem is
  read-only and the `/run/frr` mount is read-only. The image's own `USER` is
  `65532`; the gateway, janitor and query client run as it, and the Component
  overrides it for the sidecar.
- **The certificate is issued in its own pod, not in `fabric-router`'s.** A
  `csi.cert-manager.io` volume blocks its pod until the certificate is issued,
  and `continueOnNotReady` does not change that: it only covers the driver's own
  readiness gates. A lab test with a broken Issuer left the `fabric-router` pod
  in `PodInitializing`, FRR down, with `MountVolume.SetUp` waiting for the
  Issuer. So the csi volume lives in a separate `fabric-api-certs` DaemonSet
  (`certs-daemonset.yaml`, added by the Component), placed like `fabric-router`,
  with no API token, running `fabric-api certsync`. It copies the certificate,
  key and bundle to the node's tmpfs `/run/fabric-api/tls` every 10 s, validating
  the key pair and replacing files atomically. The sidecar mounts that directory
  read-only as a hostPath of type `DirectoryOrCreate`, which never blocks the
  pod. A broken Issuer therefore stalls only the certs pod. Because `/run` is
  tmpfs the key never reaches the node's disk. `task verify:fabric-api-bootstrap`
  is the lab's check of this property.
- **The sidecar has no probes.** Readiness is FRR's. The sidecar reports
  availability through gRPC health, `Info` and
  `fabric_api_node_diagnostics_available`. A process crash can still affect
  aggregate Pod Ready and rollout progress, so that coupling is watched, not
  denied.
- **Node budgets and the expensive-search breaker.** Defaults: 4 concurrent
  `Execute` calls (later calls wait within their deadline), 1 expensive search
  and 2 probes (no queue; a full budget answers `NodeBusy`), a 20 packets per
  second limiter with burst 5 shared by every probe, a duplicate cache of 1024
  entries or 32 MiB, and a 10 minute breaker. Cancelling a client does not stop
  bgpd's scan, so a scan that times out suspends expensive searches for the
  cooldown (`QueryTypeUnavailable`, `fabric_api_node_expensive_breaker_open`). The
  breaker applies only with `--search-source=frr`; the index never scans bgpd. The
  one-expensive-search-at-a-time budget (no queue, `NodeBusy`) applies to both.
- **Executor fairness.** The gateway's `Executor` grants at most 8 node RPCs at
  once across all requests, at most 2 of them expensive so searches cannot take
  every slot. Waiters queue per project and are served round robin across
  projects, FIFO within one, so one project's burst cannot starve another. The
  queue is bounded at 256 and a full queue refuses at once (`NodeBusy`) rather
  than letting waits outlive requests. Each node's deadline (earlier of request
  expiry and 30 s) is fixed before it queues, so waiting counts against it.
- **Start marker, then one terminal status.** The gateway writes a small start
  marker (attempt, fixed node snapshot, coverage, `Running`) and later exactly
  one bounded terminal result. There are no incremental result payloads. The
  terminal write retries optimistic conflicts against the latest object (up to
  six tries) without rerunning any RPC, and stops if the object is gone,
  terminal, or belongs to another attempt. Once `Complete=True` the status never
  changes.
- **Resume on the fixed snapshot.** A non-terminal query with a start marker
  whose `observedGeneration` equals the object's generation and with a node
  snapshot reuses that snapshot with `attempt` incremented, instead of
  discovering nodes again. This is what a new leader does after a failover. A
  leadership loss stops local work, but not FRR's own command.
- **Discovered nodes are accounted for, never dropped.** A pod that is
  terminating, not running, without a `hostIP` or without a running `fabric-api`
  container stays in the snapshot with `selected=false` and an omission reason.
  Pod `Ready` is deliberately not consulted: FRR's probes drive it and the
  sidecar never gates it. During a rolling update a node can have two pods; one
  usable pod is selected and the rest are recorded as `DuplicatePod`, which does
  not count as missing coverage. A node whose certs pod is not running is
  omitted as `NoCertificatePod`. `status.nodes` is capped at its schema bound of
  64 entries with selected nodes listed first; coverage still counts every
  discovered node.
- **Searches run against a BMP-fed index, not FRR.** The load test
  ([docs/fabric-api/load-test.md](../fabric-api/load-test.md)) showed direct
  `regexp`, `community` and `large-community` scans saturating bgpd's main thread
  (101% of a core, cheap queries slowing from 2 ms to seconds, convergence 3.1
  times the idle time, and `ResponseTooLarge` still costing the scan). bgpd already
  streams its Loc-RIB incrementally over BMP, so the sidecar runs a BMP station and
  searches a local copy. With the index, expensive searches cost bgpd 2% of a core
  and convergence under load is +5%.
- **The index holds each prefix's selected path only.** Loc-RIB monitoring carries
  what bgpd selected, so a search matches the selected path's attributes. FRR's own
  search lists any path that matches, so the index can return fewer prefixes (see
  Known Constraints). Path attributes (AS path, origin, MED, local preference,
  communities, large communities, next hop) are interned and reference-counted:
  about 212,000 distinct sets serve about 1.4 million prefixes, and a search
  evaluates each set once, not each prefix. Results are the first matches in prefix
  order with an exact total.
- **Sync, and refusing instead of falling back.** Each BMP session starts empty
  (`BeginSession`) and bgpd resends the table. FRR 10.7 sends no End-of-RIB for
  Loc-RIB monitoring (verified on the wire: Initiation, Peer Up, then routes), and
  a quiet period never comes on a churning full table, so the station decides the
  initial dump is over from its rate: synced once the session has carried routes
  and the last 5 seconds' rate is at most 50 per second or 1% of the session's peak.
  An explicit End-of-RIB, from any peer header, also syncs. When the session ends the index is unsynced again. Unsynced, a search
  answers `QueryTypeUnavailable`; there is no fallback to scanning bgpd, since that
  is the thing the index exists to avoid. Every search reports the index's state
  (`index.syncedAt`, `lastUpdate`, `version`, `routes`).
- **The station accepts one loopback session.** It listens on `127.0.0.1:9348`,
  refuses non-loopback peers and refuses a second session while one is active. A
  local root process could connect first (see Known Constraints). Updates for new
  prefixes beyond `--search-index-max-routes` (4,000,000) are dropped and counted in
  `fabric_api_node_search_index_overflow_total`, never silently served as complete.
- **Janitor has separate RBAC.** The gateway's ClusterRole can read `FabricQuery`
  and update their status, nothing else. Deleting is a different ServiceAccount
  (`fabric-api-janitor`) with `list` and `delete` on `fabricqueries` only, run as
  a CronJob, so delete access never reaches the process that executes queries.
  Deletion carries a UID precondition so a reused name is never touched.
- **Stale-objects gauge on the gateway.** The janitor is an unscraped CronJob
  with no metrics (it logs what it deletes), so a cleanup backlog would otherwise
  be invisible. Every gateway replica publishes `fabric_api_gateway_stale_objects`
  from its cache each minute, using its `--retention` and `--cleanup-grace`
  (defaults 1h and 15m), which must be kept equal to the janitor's `--retention`
  and `--grace`.
- **Retries are narrow.** The gateway retries a node call once, and only for a
  cheap read (not a search, not a probe) that failed with `NodeUnreachable`,
  since the node deduplicates by request ID. A search or probe that may have run
  is never retried within an attempt; its error is preserved.
- **Probe sources are explicit.** Each family has at most one source address,
  loopback and unspecified addresses are refused at startup, and a family with
  no source answers `ProbeSourceUnavailable` instead of falling back to
  `127.0.0.1`, `::1` or an unrelated interface.

---

## Testing

| Layer       | Command                                                                                     | Framework                      | Scope                                                                                                                                                                                                                                                                                                                                    |
| ----------- | ------------------------------------------------------------------------------------------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unit        | `task test:unit`                                                                            | `go test -race`                | `internal/fabric/query` (canonicalization, destination policy, budgets); `frr` (10.7 fixtures, vty framing, partial reads, return codes, byte cap, early close, timeout, unavailable, command grammar); `probe` (fake socket, loss, hop limits, pacing)                                                                                  |
| Unit        | `task test:unit`                                                                            | `go test -race`                | `identity` (mutual TLS, load failures, rotation with an overlapping bundle, certificate sync); `errcode` (metadata); `node` (validation, expensive gate and breaker, no-queue expensive budget, deadline clamping, duplicates, eviction, shaping, probe policy and budget, gRPC over mTLS)                                               |
| Unit        | `task test:unit`                                                                            | `go test -race`, fake client   | `gateway` (reconcile outcomes, no-nodes, rejection, expiry before and during execution, resume on a fixed snapshot, status conflict retry without rerunning, deletion cancels, other cells ignored, shrink to budget, leader forwarding, janitor, executor)                                                                              |
| Unit        | `task test:unit`                                                                            | `go test -race`                | `internal/fabric/index`: apply and search, withdraw releasing attribute sets, `MaxRoutes`, a station fed over a real socket, rate-based sync, community values                                                                                                                                                                           |
| CRD schema  | `go test ./internal/fabric/api/v1alpha1/` with `KUBEBUILDER_ASSETS` set                     | envtest (kube-apiserver, etcd) | `TestCRDSchema` installs the generated CRD and checks structural bounds, CEL rules, the immutable spec and the status subresource. Skipped when `KUBEBUILDER_ASSETS` is unset                                                                                                                                                            |
| Raw socket  | `go test ./internal/fabric/probe/` with `FABRIC_PROBE_SOURCE` and `FABRIC_PROBE_TARGET` set | `go test`                      | `TestRawSocket` sends real probes; needs `CAP_NET_RAW` and a reachable target. Skipped otherwise                                                                                                                                                                                                                                         |
| Alert rules | `task test:alerts`                                                                          | `promtool test rules`          | `config/monitoring/tests/rules-test.yaml` covers every `FabricAPI*` alert. Not part of `task ci`                                                                                                                                                                                                                                         |
| E2E         | `task verify:fabric-api` (in `deploy/containerlab/`)                                        | bash, live containerlab lab    | Per node, directly with an operator certificate; through each cell's gateway debug service; and through a `FabricQuery` written as NSO would write it                                                                                                                                                                                    |
| Bootstrap   | `task verify:fabric-api-bootstrap` (in `deploy/containerlab/`)                              | bash, live containerlab lab    | Disruptive. Breaks the cell's `Issuer` and clears the node's synced credentials, then recreates its `fabric-api-certs` and `fabric-router` pods and checks that the certs pod waits while FRR and the underlay come up and the sidecar reports no credentials, then repairs the Issuer and checks the sidecar recovers without a restart |
| Load        | `task test:fabric-api-load MRT=<rib files>`                                                 | Go harness, Docker             | Full Internet tables (RouteViews MRT dumps) fed to FRR 10.7.1 with the real sidecar driven over mTLS; bgpd CPU and RSS, convergence and session drops by phase. Needs Docker and about 4 GiB; not part of CI. Results in [load-test.md](../fabric-api/load-test.md)                                                                      |

`task verify:fabric-api` checks, on every `fabric-router` node: `Info` reports
diagnostics available, FRR 10.7 and a router ID and ASN; every underlay session
`Established` for both families; an exact lookup and a longest-match lookup of
another site's loopback, each with a selected BGP path and zebra installation
evidence; a longest-match lookup of the site's gateway VIP; an exact lookup of
an unannounced prefix returning a successful empty answer; an AS-path and a
community search answered from the index with its freshness and equal to FRR's own
best-path matches; and operator ping and traceroute to another
site's loopback in both families. Through each gateway it checks that a debug
`BGPSummary` is answered by every node and that the same loopback ping is
refused with `DestinationNotAllowed` on every node (public policy never carries
the lab exceptions). It then writes a `FabricQuery` and expects `Succeeded` with
one observation per node, and that a query pinned to another cluster is left
untouched. It claims nothing about tenant EVPN tables.

Run the lab flow with `task build:fabric-api`, `task deploy:cert-manager` and
`task deploy:fabric-api` (all in `deploy/containerlab/`); `task deploy` also
runs them in order, with `deploy:cert-manager` before `deploy:fabric` so the
csi-driver exists when the `fabric-api-certs` pods start.

---

## CI/CD

**Pipeline:** `.github/workflows/ci.yaml` runs `task lint`, `task test:unit` and
`task build`, which cover the unit tests above and build `bin/fabric-api`; see [ARCHITECTURE-ROUTER.md#cicd](ARCHITECTURE-ROUTER.md#cicd) for
the shared tier structure. The envtest, raw-socket, `promtool` and containerlab
checks are not part of CI.

**Publish pipeline:** `.github/workflows/publish.yaml`'s
`publish-fabric-api-image` job builds and pushes `ghcr.io/datum-cloud/fabric-api`
for `linux/amd64` and `linux/arm64`. `publish-kustomize-bundles` stamps its tag
into both `config/fabric-router/components/fabric-api` and
`config/fabric-api/base`, so the Component and the gateway always reference a
published image.

**Container image:** `containers/fabric-api/Dockerfile` — golang builder with
`CGO_ENABLED=0` → `gcr.io/distroless/static:nonroot`, `ENTRYPOINT
["/usr/bin/fabric-api"]`. No clang, no `go generate`, and no FRR or shell in the
image. `task build` also produces `bin/fabric-api` for local use.

Because the sidecar lives in the `fabric-router` pod, changing the `fabric-api`
tag changes the DaemonSet pod template and the rolling update recreates the whole
pod, FRR included. Sidecar releases are routing rollouts; see
[Rollout](../fabric-api/configuration.md#rollout). Gateway-only releases do not
touch `fabric-router`; `fabric-api-certs` runs the same image, so its tag moves
with the Component but its restart does not touch FRR.

---

## Known Constraints

- **Searches are off until staging confirms the load test.** `ASPath`,
  `Community` and `LargeCommunity` need `--enable-expensive-queries` and answer
  `QueryTypeUnavailable` otherwise. The full-table load test passed for the index
  in a Docker lab ([load-test.md](../fabric-api/load-test.md)); the numbers have not
  been confirmed on real fabric routers, and enabling is an infra rollout step. The
  containerlab lab enables them.
- **The index holds only selected paths.** A search matches each prefix's best path
  as bgpd selected it, so it can return fewer prefixes than FRR's own search, which
  lists any path that matches. `matched` counts prefixes whose selected path
  matches. The index equalled FRR's best-path matches on all 40 load-test targets.
- **The index needs the BMP block in `frr.conf`.** Without `bmp targets fabric-api`
  the index never syncs and searches stay `QueryTypeUnavailable`. Infra's `frr.conf`
  renderer must emit it for production nodes. With the index the breaker is not used.
- **The BMP station trusts loopback.** Any local process on the node that can reach
  `127.0.0.1:9348` could connect first and feed the index, and bgpd's later session
  is then refused while that one is active. The port is on the loopback interface,
  so only processes on the node can reach it.
- **Index memory is sized for a full table.** The load test measured a sidecar RSS
  of about 430 MB for 1.39 million prefixes; the Component requests 64Mi and limits
  memory to 768Mi with `GOMEMLIMIT=640MiB`. Prefixes beyond
  `--search-index-max-routes` are dropped and counted, not refused.
- **Operator debug through the gateway applies the public policy.** The nodes see
  the gateway's identity on that route, so the public destination policy applies
  and the lab's loopback exceptions are unavailable. Operator exceptions
  (`--operator-allow-prefixes`) apply only to calls made directly to a node with
  an operator identity, and are never set in production.
- **The `FabricQuery` CRD copy is lab-only.** `config/fabric-api/crd/` exists for
  the containerlab lab and envtest. Infra owns the CRD in every cell and NSO on
  the hub. Types live here only until `network` ships them.
- **Hostnames are never resolved here.** A probe target reaching the gateway must
  already be a numeric address in the query's family; NSO resolves and pins it.
  The gateway rejects a hostname with `InvalidQuery`.
- **The duplicate cache is in memory.** A sidecar restart or an eviction can let
  a repeated request run again. Execution budgets and the packet limiter still
  apply; exactly-once is not a goal.
- **Late status never reopens a query.** Once `Complete=True` the gateway never
  touches the object again. NSO is responsible for resolving a cell that never
  returns to `DeadlineExceeded` at the absolute expiration.
- **Status lists are bounded.** `status.nodes` holds at most 64 entries and
  `status.observations` at most 32. The gateway selects at most 32 nodes and lists
  selected nodes first; discovered nodes beyond the 64-entry bound are counted in
  `coverage` but not listed.
- **The certificate hand-off is node-local and eventually consistent.** The
  sidecar sees a new certificate only after `certsync` copies it (every 10 s) and
  the sidecar reloads it (every 10 s). A node whose `fabric-api-certs` pod is not
  running is `NoCertificatePod` to the gateway, even if its sidecar still holds an
  unexpired certificate. The key sits in the node's tmpfs, readable by root on
  the node, as any hostPath secret is.
- **The janitor has no metrics.** It logs each deletion and, at debug level, each
  outcome. The gateway's `--retention` and `--cleanup-grace` are not read from the
  janitor, so they must be kept equal by hand.
- **Other repositories are out of scope.** The public `LookingGlassQuery`, hub
  CRD installation, per-cell propagation policies and Lua status aggregation
  (NSO, `network`), the per-cell issuer and certificate rotation prerequisites
  (infra) and the portal UI are not implemented or verified here.

---

## For Claude

**Where to start for each concern:**

| Concern                                            | Start here                                                                                                            |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| What a query means, target rules, family inference | `internal/fabric/query/query.go:Canonicalize`, `Lookup`                                                               |
| Probe destination policy                           | `internal/fabric/query/destination.go:DestinationPolicy.Check`, `ResolvedProbe`                                       |
| Byte, count and time ceilings                      | `internal/fabric/query/limits.go:Ceilings`, `Budgets.Clamp`                                                           |
| Which FRR commands may ever be sent                | `internal/fabric/frr/command.go` (every constructor)                                                                  |
| Searches from the BMP index, sync state            | `internal/fabric/index/index.go:Index.Search`, `station.go:Station`, `node/server.go:runIndexed`, `searchUnavailable` |
| vty framing, return codes, read cap                | `internal/fabric/frr/vty.go:VTY.Run`, `read`, `result`                                                                |
| Parsing FRR JSON, empty vs malformed               | `internal/fabric/frr/parse.go:ParseLookup`, `ParseSearch`, `ParseSummary`, `ParseInstallation`                        |
| Supported FRR releases                             | `internal/fabric/frr/version.go:SupportedReleases`                                                                    |
| The sidecar's request pipeline                     | `internal/fabric/node/server.go:Execute`, `validate`, `execute`                                                       |
| Duplicate suppression                              | `internal/fabric/node/dedup.go:dedupCache.do`                                                                         |
| Shaping a node response to budget                  | `internal/fabric/node/shape.go:fitResponse`, `prefixObservation`                                                      |
| Who may call what                                  | `internal/fabric/node/auth.go:nodeMethods`, `gateway/debug.go:DebugMethods`                                           |
| Identities and URI SAN formats                     | `internal/fabric/identity/identity.go`                                                                                |
| Certificate reload and rotation                    | `internal/fabric/identity/credentials.go:Credentials.Reload`                                                          |
| Certificate hand-off to the node (certsync)        | `internal/fabric/identity/sync.go:Sync.Once`, `config/fabric-router/components/fabric-api/certs-daemonset.yaml`       |
| Typed error codes and their gRPC mapping           | `internal/fabric/errcode/errcode.go`                                                                                  |
| FabricQuery lifecycle, conditions, coverage        | `internal/fabric/gateway/reconciler.go:Reconcile`, `terminalStatus`, `persist`                                        |
| Fan-out, deadlines, retries                        | `internal/fabric/gateway/runner.go:Runner.Run`, `one`                                                                 |
| Cell concurrency and fairness                      | `internal/fabric/gateway/executor.go:Executor.Acquire`                                                                |
| Node snapshot and omission reasons                 | `internal/fabric/gateway/discovery.go:Discoverer.Snapshot`, `omitReason`                                              |
| Operator debug service and leader forwarding       | `internal/fabric/gateway/debug.go:Debug.Query`, `forward`, `leaderAddress`                                            |
| Cleanup                                            | `internal/fabric/gateway/janitor.go:Janitor.Sweep`, `StaleCounter`                                                    |
| The `FabricQuery` schema and CEL rules             | `internal/fabric/api/v1alpha1/fabricquery_types.go` (regenerate with `task generate:crd`)                             |
| Wire contract                                      | `api/fabric/v1/fabric.proto` (regenerate with `task generate:proto`)                                                  |
| Sidecar pod spec, UID, capabilities, volumes       | `config/fabric-router/components/fabric-api/daemonset-patch.yaml`                                                     |
| Gateway Deployment, janitor CronJob, RBAC          | `config/fabric-api/base/`, `config/fabric-api/rbac.yaml`                                                              |
| Metrics and alerts                                 | `internal/fabric/node/metrics.go`, `gateway/metrics.go`, `config/monitoring/prometheusrule.yaml` (`fabric-api` group) |

**Stable vs. frequently changed:**
- Stable: `internal/fabric/frr/vty.go` and `command.go` (small, closed, fully unit-tested), `internal/fabric/identity` (the SAN formats are a deployment contract; changing them re-issues every certificate).
- Active: `internal/fabric/index` (the BMP-fed search path), `internal/fabric/query/limits.go` budgets (raising a ceiling needs boundary and load tests), the expensive-query gate, and the `FabricQuery` types, which move to `network` when it ships them.

**Non-obvious patterns:**
- The gateway's reconcile does not run an execution inline: it writes the start marker, then `launch`es a goroutine under the leader's context and returns. `running` is in memory, which is why a restarted gateway re-enters `Reconcile` for a non-terminal query and takes the resume path.
- A node validates `q != Canonicalize(q)` and rejects a non-canonical query rather than fixing it, so a caller that skipped canonicalization fails loudly. The gateway does the same for the spec's query.
- `errcode.Of` returns `ResponseTooLarge` for any `RESOURCE_EXHAUSTED` without an `ErrorInfo`; a node's `NodeBusy` also travels as `RESOURCE_EXHAUSTED` but always with its own `ErrorInfo`.
- `node.AuthInterceptor` is shared by the node and the gateway debug server; each passes its own method table, and `nil` selects the node's.
- The `fabric-api` pod's token mount is the Component's job. Adding a container to the `fabric-router` pod that needs the Kubernetes API means adding it to the projected volume's mounts in `daemonset-patch.yaml`.
