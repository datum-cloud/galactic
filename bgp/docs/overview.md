# BGP Control Plane — Overview

> Last verified: 2026-03-16 against go.miloapis.com/bgp v1alpha1

The BGP control plane is a Kubernetes-native system for managing BGP topology declaratively. It exposes six Custom Resource Definitions in the `bgp.miloapis.com` group and reconciles them into a GoBGP daemon that maintains BGP sessions and programs kernel routes via netlink.

The project is CNI-independent and topology-agnostic. It has no knowledge of nodes, clusters, or datacenter topology — all of that context lives in the resources that other systems (or humans) create.

---

## What Problem This Solves

Most BGP solutions for Kubernetes (Cilium BGP, Calico BGP, MetalLB) are tightly coupled to a specific CNI or network model. They are opinionated about topology: which nodes peer with which, what gets advertised, and how sessions form.

This project separates concerns differently:

- **BGP endpoints, sessions, and advertisements are resources** — not internal state. Any system can create them.
- **The BGP controller is topology-agnostic** — it reconciles CRDs into GoBGP without interpreting what they represent.
- **Topology is expressed through labels and selectors** — a `BGPPeeringPolicy` selects endpoints by labels and automates session creation. The policy controller does not know whether the endpoints are nodes, borders, or route reflectors.

---

## Design Principles

**Resources represent things, not actions.** A `BGPSession` declares "these two endpoints should peer." The controller makes it so. A `BGPAdvertisement` declares "these prefixes should be in the RIB." The controller injects them into GoBGP.

**Labels and selectors drive topology.** `BGPPeeringPolicy` selects `BGPEndpoint` resources by label selectors. You can create a full-mesh policy, a route-reflector policy, or both — just by selecting different sets of endpoints and choosing a mode.

**Controllers compose independently.** The `PeeringPolicyReconciler` creates `BGPSession` resources. The `SessionReconciler` reconciles those sessions into GoBGP. These two controllers are decoupled: you can create `BGPSession` resources manually without any policy, and the session reconciler will configure them.

**GoBGP is stateless from the controller's perspective.** If GoBGP restarts, the controller performs a full re-reconciliation from the CRD state. There is no persistent GoBGP state that the controller depends on.

---

## Architecture

```
CRD Producers                BGP CRDs                  BGP Controller          GoBGP
─────────────────────────────────────────────────────────────────────────────────────

Node operator         ──▶  BGPEndpoint              ┐
Cluster discovery     ──▶  BGPPeeringPolicy          │  PeeringPolicyReconciler
Human operator        ──▶  BGPSession                ├─▶ SessionReconciler     ──▶ AddPeer / UpdatePeer
                           BGPAdvertisement           │  AdvertisementReconciler ──▶ AddPath
                           BGPRoutePolicy             │  RoutePolicyReconciler  ──▶ AddPolicy
                           BGPConfiguration           ┘  ConfigReconciler       ──▶ StartBgp

                                                         RouteWatcher  ◀── WatchEvent ──▶ netlink
```

### The Three-Layer Model

**Layer 1 — CRD producers.** Anything that creates BGP CRD resources. A node operator creates one `BGPEndpoint` per node using the node's IPv6 address. A cluster discovery system creates `BGPPeeringPolicy` resources for multi-cluster peering. Human operators create resources manually for custom topologies or debugging.

**Layer 2 — BGP CRDs.** The API surface of this project. These resources live in etcd and represent the desired BGP state. The controller watches them and drives GoBGP to match.

**Layer 3 — BGP controller → GoBGP → kernel FIB.** The controller runs as a DaemonSet alongside a GoBGP sidecar container on each node. It communicates with GoBGP over a gRPC socket on `127.0.0.1:50051`. GoBGP maintains the BGP sessions and RIB. The route watcher streams best-path events from GoBGP and programs kernel routes using netlink with protocol ID 196.

### Per-Node Architecture

Each node runs one Pod containing two containers:

- **`bgp`** — the controller binary. Reconciles CRDs, polls session state, programs kernel routes.
- **`gobgpd`** — GoBGP daemon. Maintains BGP sessions and the RIB. Exposed to the controller on localhost:50051.

An init container (`config-gen`) discovers the node's global-scope IPv6 address and generates the initial `gobgp.conf` before GoBGP starts.

The controller only reconciles sessions where `spec.localEndpoint` resolves to this node's endpoint. Multiple nodes can run in the same cluster; each reconciles only its own sessions.

---

## How Sessions Form

1. A CRD producer (or human) creates `BGPEndpoint` resources, one per speaker, labelled with topology metadata (e.g. `bgp.miloapis.com/role: node`).
2. A `BGPPeeringPolicy` selects those endpoints by label and specifies a mode (`mesh` or `route-reflector`).
3. The `PeeringPolicyReconciler` materializes `BGPSession` resources — one per endpoint pair in mesh mode, or one per client–reflector pair in route-reflector mode.
4. The `SessionReconciler` on each node reconciles sessions where the local endpoint matches its node. It calls `AddPeer` (or `UpdatePeer`) on GoBGP.
5. GoBGP establishes the TCP session and runs the BGP FSM.
6. The status poller polls `ListPeer` every 10 seconds and writes `status.sessionState`, `status.receivedPrefixes`, `status.flapCount`, and the `SessionEstablished` condition back to each `BGPSession`.

---

## How Routes Are Advertised

1. A `BGPAdvertisement` resource declares one or more IPv6 prefixes.
2. The `AdvertisementReconciler` calls GoBGP's `AddPath` API to inject the prefixes into the local RIB.
3. GoBGP advertises them to established peers according to its routing policy.
4. Optionally, a `BGPRoutePolicy` applies import/export filters per-peer using prefix matching with optional length ranges.

---

## How Routes Reach the Kernel

The route watcher opens a `WatchEvent` stream on GoBGP and listens for best-path updates. For each IPv6 unicast best-path event, it:

- Extracts the prefix and next-hop from the BGP path attributes.
- Skips routes that match the node's own SRv6 prefix (configured via `SRV6_NET` environment variable).
- Adds or removes a kernel route via netlink with protocol ID 196.

---

## Comparison with Alternatives

| Feature | This project | Cilium BGP | Calico BGP | MetalLB |
|---------|-------------|------------|------------|---------|
| CNI dependency | None | Cilium | Calico | None |
| Topology awareness | None (by design) | Node-centric | Node-centric | LoadBalancer-centric |
| Session model | CRD (BGPSession) | Config map | BGPPeer CRD | BGPPeer CRD |
| Advertisement model | BGPAdvertisement CRD | Auto from services | Auto from pods/services | Auto from services |
| Route filtering | BGPRoutePolicy CRD | Policy CRD | BGPFilter CRD | Limited |
| Route-reflector support | BGPPeeringPolicy CRD | Yes | Yes | No |
| Multi-cluster support | Via label selectors | Limited | Limited | No |
| BGP daemon | GoBGP (sidecar) | GoBGP (embedded) | BIRD | FRR |
