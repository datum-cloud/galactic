# Architecture

> Last verified: 2026-03-16 against go.miloapis.com/bgp v1alpha1

This document describes the internal architecture of the BGP control plane: how controllers compose, how GoBGP is integrated, how routes move from the RIB to the kernel, and how the system observes and reports its own state.

---

## Controller Composition

The controller binary registers five reconcilers with a `controller-runtime` manager. Each reconciler handles one CRD and is responsible for a specific aspect of the BGP control plane.

```
manager
├── ConfigReconciler          — BGPConfiguration → GoBGP StartBgp
├── SessionReconciler         — BGPSession       → GoBGP AddPeer / UpdatePeer / DeletePeer
├── PeeringPolicyReconciler   — BGPPeeringPolicy → BGPSession (materializes sessions)
├── AdvertisementReconciler   — BGPAdvertisement → GoBGP AddPath / DeletePath
└── RoutePolicyReconciler     — BGPRoutePolicy   → GoBGP AddPolicy / DeletePolicy
```

Each reconciler is decoupled from the others. The `PeeringPolicyReconciler` creates `BGPSession` resources as Kubernetes objects — it does not call GoBGP directly. The `SessionReconciler` then picks up those resources and calls GoBGP.

This means you can:
- Create `BGPSession` resources manually without any policy.
- Create a `BGPPeeringPolicy` without any `BGPAdvertisement`.
- Mix manually-created and policy-generated sessions.

### ConfigReconciler

Reconciles the singleton `BGPConfiguration` resource (expected name: `default`). When the configuration changes, it calls GoBGP's `StartBgp` API with the updated AS number, listen port, and address families.

The router ID is resolved based on `routerIDSource`:
- `NodeIP`: the reconciler looks up the node object for the node where this pod is running (from the `NODE_NAME` environment variable) and extracts the IPv6 `InternalIP`.
- `Manual`: uses `spec.routerID` directly.

### SessionReconciler

Reconciles `BGPSession` resources where `spec.localEndpoint` names an endpoint on this node. Each node only owns its own sessions.

The reconciler resolves both `spec.localEndpoint` and `spec.remoteEndpoint` to `BGPEndpoint` resources, builds a `gobgpapi.Peer` struct, and calls `AddPeer` or `UpdatePeer` on GoBGP.

On deletion, it calls `DeletePeer`.

### PeeringPolicyReconciler

Reconciles `BGPPeeringPolicy` resources and materializes `BGPSession` objects.

For `mesh` mode:
- Lists all `BGPEndpoint` resources matching `spec.selector`.
- Creates one `BGPSession` for every ordered pair `(A, B)` where `A.name < B.name`.

For `route-reflector` mode:
- Resolves the reflector endpoint from `routeReflectorConfig.reflectorSelector`. If more than one endpoint matches, sets an `InvalidConfig` condition and stops.
- Creates one `BGPSession` for each non-reflector endpoint, with `spec.routeReflector.clusterID` set.

The reconciler uses server-side apply to own the sessions it creates. Sessions for endpoints that no longer match the selector are deleted.

### AdvertisementReconciler

Reconciles `BGPAdvertisement` resources. For each resource, it calls GoBGP's `AddPath` API to inject each prefix into the local RIB with the configured communities and `LOCAL_PREF`. On deletion, it calls `DeletePath` for each prefix.

On GoBGP restart, the `FullReconcile` function bumps an annotation on each `BGPAdvertisement` to trigger re-reconciliation and re-inject all prefixes into the fresh GoBGP RIB.

### RoutePolicyReconciler

Reconciles `BGPRoutePolicy` resources. Translates each `PolicyStatement` into a GoBGP policy definition and calls the GoBGP policy API to install import or export filters.

---

## GoBGP Integration

The controller communicates with GoBGP via gRPC on `127.0.0.1:50051` (configurable via `--gobgp-addr`). Both containers share the pod's network namespace.

### Connection and Reconnection

At startup, `GoBGPClient.Connect` retries up to 30 times with 2-second intervals, pinging GoBGP's `GetBgp` endpoint after each dial. Reconcilers are not started until GoBGP is connected.

A background `WatchHealth` goroutine polls `GetBgp` every 5 seconds. If the ping fails, the goroutine:
1. Closes the stale gRPC connection.
2. Re-dials with the same retry logic.
3. On successful reconnection, calls `FullReconcile`.

### Stateless Treatment of GoBGP

GoBGP is treated as stateless. The CRDs are the source of truth. When GoBGP restarts (or is replaced), `FullReconcile` re-applies:

1. All `BGPSession` resources (calls `AddPeer` or `UpdatePeer` for each).
2. All `BGPAdvertisement` resources (triggers re-reconciliation via annotation bump).
3. All `BGPRoutePolicy` resources (triggers re-reconciliation via annotation bump).

This means GoBGP state is fully reproducible from the CRDs. No GoBGP configuration file persistence is required.

### GoBGP Configuration File

The GoBGP daemon requires a minimal `gobgp.conf` to start with an AS number, router ID, and listen port. The init container `config-gen` generates this file at pod start:

```toml
[global.config]
  as = 65000
  router-id = "2001:db8:1::1"   # resolved from NODE_IP_PLACEHOLDER
  local-address-list = ["2001:db8:1::1"]
  port = 1790
```

The `BGPConfiguration` resource overrides GoBGP's AS and router ID at runtime via the gRPC API. The config file is only used for initial bootstrap.

---

## Route Synchronization

The route watcher runs as a background goroutine. It opens a `WatchEvent` stream on GoBGP requesting best-path updates (`BEST` filter with `Init: true`).

For each best-path event:

1. The NLRI and next-hop are extracted from the BGP path attributes using `apiutil.GetNativeNlri` and `apiutil.GetNativePathAttributes`.
2. Routes matching the node's own SRv6 prefix (from `SRV6_NET` env var) are skipped to avoid self-routing.
3. For path additions: `bgpnetlink.AddRoute(prefix, nextHop)` programs a kernel route with protocol ID 196.
4. For path withdrawals: `bgpnetlink.DelRoute(prefix)` removes the kernel route.

The `Init: true` flag causes GoBGP to replay all current best paths when the stream opens. This means the route watcher rebuilds the full kernel FIB on every restart without needing to track state.

If the stream fails, the watcher retries after 2 seconds.

### Protocol ID 196

Kernel routes programmed by this controller use Linux route protocol ID 196. This distinguishes them from routes installed by other systems (e.g. the CNI uses 196 is just an identifier choice — confirm against your environment). You can list these routes with:

```bash
ip -6 route show proto 196
```

---

## Status and Observability

### Session State Polling

A `RunStatusPoller` goroutine polls GoBGP's `ListPeer` API every 10 seconds and updates each `BGPSession` status subresource. For each session, it:

- Sets `status.sessionState` to the current BGP FSM state (one of `Unknown`, `Idle`, `Connect`, `Active`, `OpenSent`, `OpenConfirm`, `Established`).
- Sets `status.receivedPrefixes` and `status.advertisedPrefixes` from the address family counters.
- Increments `status.flapCount` when transitioning from `Established` to a non-established state.
- Updates `status.lastTransitionTime` on state changes.
- Sets the `SessionEstablished` condition to `True` or `False`.

The poller only updates sessions it can resolve — if a `BGPEndpoint` reference is missing, that session is skipped silently.

### Prometheus Metrics

The controller exposes Prometheus metrics on the `--metrics-addr` port (default `:8086` in the DaemonSet manifest). The following metrics are available:

| Metric | Labels | Description |
|--------|--------|-------------|
| `bgp_session_state` | `session`, `state` | Gauge: 1 for the active FSM state, 0 for all others. One series per (session, state) pair. |
| `bgp_received_prefixes_total` | `session` | Gauge: prefixes received from the remote peer. |
| `bgp_session_flaps_total` | `session` | Counter: times a session left `Established` state. |
| `bgp_advertised_prefixes_total` | `advertisement` | Gauge: prefixes currently in the GoBGP RIB from a `BGPAdvertisement`. |
| `bgp_route_policies_applied` | `policy` | Gauge: 1 if the `BGPRoutePolicy` is applied to GoBGP, 0 otherwise. |

Metrics are registered with `controller-runtime`'s metrics registry and served on `/metrics`.

### Health and Readiness Probes

The controller serves HTTP probes on `--health-addr` (default `:8087` in the DaemonSet manifest):

- `/healthz` — liveness probe. Returns 200 if the controller process is alive.
- `/readyz` — readiness probe. Returns 200 when the controller-runtime manager is ready.

---

## The Producer/Consumer Pattern

The BGP controller is the consumer. It reads CRDs and reconciles them into GoBGP. It does not know or care who created the CRDs.

Any system that can write to the Kubernetes API can be a producer:

- A **node operator** creates one `BGPEndpoint` per node at node-join time.
- A **cluster discovery** system creates `BGPPeeringPolicy` resources when a new cluster registers.
- A **platform operator** creates `BGPAdvertisement` resources to announce service prefixes.
- A **human operator** creates `BGPSession` resources manually to debug or create one-off peering relationships.

This separation allows the BGP topology to be driven from multiple systems simultaneously without those systems needing to coordinate with each other — they each write their portion of the desired state, and the controller reconciles the whole.

---

## Startup Sequence

```
1. GoBGPClient.Connect()       — dial 127.0.0.1:50051 with retries
2. controller-runtime manager  — build manager with scheme (k8s + bgp types)
3. Register reconcilers         — ConfigReconciler, SessionReconciler, etc.
4. Add health/readiness checks  — /healthz, /readyz
5. Start background goroutines  — WatchHealth, RunStatusPoller, RunRouteWatcher
6. manager.Start()              — begins watching CRDs and reconciling
```

The controller will not start reconciling until GoBGP is reachable. If GoBGP takes longer than 60 seconds to start (30 attempts × 2s), the controller exits and Kubernetes restarts the pod.
