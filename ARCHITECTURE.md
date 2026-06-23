# Architecture

> Galactic is the SRv6 data plane for multi-cloud VPC networking, deployed as two
> binaries on each Kubernetes node: a CNI plugin that attaches containers to VPC
> networks, and a router that reconciles Cosmos BGP CRDs and drives an embedded
> GoBGP server to distribute EVPN (L2VPN/EVPN AFI/SAFI) paths between nodes.

_Last updated: 2026-06-19_

---

## Overview

Galactic implements VPC isolation and cross-cluster reachability using Linux SRv6.
When a pod is attached to a VPC, the CNI plugin creates the required kernel state
(VRF, veth pair, SRv6 ingress route) and writes a `BGPAdvertisement` CRD.
`galactic-router` watches that CRD and injects the EVPN path into the node-local
GoBGP server. GoBGP distributes the path to a BGP route reflector, enabling pods
on different nodes or clusters to reach each other via SRv6-encapsulated traffic.

VPC and VPCAttachment CRDs are owned by a separate companion operator
(`go.miloapis.com/cosmos`). Galactic receives pre-populated identifiers through the
CNI config and acts on them. `galactic-router` reconciles BGP CRDs from the same
cosmos API group directly — no gRPC sidecar, no provider CRD lifecycle.

### SRv6 SID encoding

Each container endpoint is assigned a deterministic SRv6 SID:

```
[SRv6 locator prefix (≤64 bits)] | [VPC ID (48 bits)] | [VPCAttachment ID (16 bits)]
```

All nodes in the same VPC derive the same BGP Route Target via `fnv32a(vpcHex)`,
enabling automatic cross-node path import without explicit RT configuration.

---

## Repository Layout

```
galactic/
├── cmd/
│   ├── galactic-cni/        # CNI binary
│   └── galactic-router/     # Router binary (controller-runtime reconciler)
├── internal/
│   ├── controller/          # controller-runtime reconcilers (BGPRouter, BGPPeer,
│   │                        #   BGPAdvertisement, BGPPolicy, Secret, Node)
│   ├── reconcile/           # CRD → DesiredRouter translation (node/role checks,
│   │                        #   secret resolution, IPv6 next-hop from Node)
│   ├── runtime/             # RouterRuntime interface + RuntimeManager
│   │   ├── gobgp/           # GoBGP RouterRuntime (tenant role)
│   │   └── frr/             # FRR RouterRuntime stub (fabric role, Phase 2)
│   ├── model/               # DesiredRouter and family; re-exports cosmos enums
│   ├── hash/                # SHA-256 change detection over DesiredRouter
│   ├── metrics/             # Prometheus metrics (galactic_router_*)
│   ├── cni/                 # CNI cmdAdd / cmdDel
│   │   ├── route/           # Host-side static routes via netlink
│   │   └── veth/            # veth pair management
│   └── plumbing/            # Low-level kernel and network primitives
│       ├── intf/            # Interface naming, base62↔hex encoding, SRv6 endpoint encode/decode
│       ├── srv6/            # SRv6 ingress route add/del (END.DT46)
│       ├── sysctl/          # Interface sysctl helpers
│       └── vrf/             # Linux VRF create/delete/lookup
├── deploy/
│   ├── galactic-router/     # Kustomize: DaemonSet, RBAC, ServiceAccount
│   └── containerlab/        # ContainerLab lab topology and scripts
└── containers/
    └── galactic/            # Production Dockerfile
```

---

## Data Flow

See [docs/cni-sequence.md](docs/cni-sequence.md) for the full CNI ADD/DEL sequence diagram.

See [docs/agent-startup.md](docs/agent-startup.md) for the router startup sequence diagram.

---

## Components

| Component | Binary | Role |
|-----------|--------|------|
| `internal/controller` | `galactic-router` | controller-runtime reconcilers; field index registration; CRD status helpers |
| `internal/reconcile` | `galactic-router` | CRD → DesiredRouter translation |
| `internal/runtime/gobgp` | `galactic-router` | Embedded GoBGP server (tenant role) |
| `internal/runtime/frr` | `galactic-router` | FRR stub (fabric role, Phase 2) |
| `internal/model` | `galactic-router` | Internal BGP model types |
| `internal/hash` | `galactic-router` | Change detection |
| `internal/metrics` | `galactic-router` | Prometheus metrics |
| `internal/cni` | `galactic-cni` | CNI cmdAdd / cmdDel |
| `internal/plumbing/intf` | both | Interface naming, base62↔hex encoding, SRv6 endpoint encode/decode |
| `internal/plumbing/srv6` | both | SRv6 ingress route add/del (END.DT46) |
| `internal/plumbing/vrf` | both | Linux VRF create/delete/lookup |
| `internal/plumbing/sysctl` | both | Interface sysctl helpers |

---

## Key Design Decisions

- **Identifiers in the SID.** VPC (48-bit) and VPCAttachment (16-bit) identifiers are packed into the low 64 bits of the SRv6 SID, making forwarding state fully self-describing without a lookup table.
- **Base62 interface names.** Kernel interface names are Base62-encoded to stay within the 15-character limit (`vrfX-Y`, `galX-Y`). The hex form is used for BGP and SRv6; base62 for kernel interfaces.
- **GoBGP embedded, lazy-started.** GoBGP runs in-process and starts only when the first `BGPRouter` is reconciled (`listenPort=-1`, outbound-only). ASN or RouterID changes trigger a full `Reconfigure` (fresh `BgpServer` — `StopBgp` is not called because it permanently terminates the v4 Serve loop).
- **CRD-driven config, no sidecar gRPC.** `galactic-router` watches cosmos BGP CRDs directly via controller-runtime. The CNI writes a `BGPAdvertisement` CRD; the router reconciler picks it up. No in-node gRPC calls.
- **Hash-based no-op suppression.** SHA-256 over the sorted `DesiredRouter` prevents redundant GoBGP Apply calls on every CRD event touch.
- **RuntimeFactory pattern.** `ROUTER_ROLE=tenant` selects GoBGP; `ROUTER_ROLE=fabric` selects FRR (Phase 2 stub). The binary is selected at startup; no controller changes are needed for Phase 2.
- **gRPC health on :5000.** Liveness and readiness probes use the gRPC health protocol (`google.golang.org/grpc/health`) on port 5000. No HTTP health endpoint.

---

## Known Constraints

- **GoBGP RIB is ephemeral.** All BGP state is in-process memory. On restart, sessions and paths must be re-established from CRD state; controller-runtime's reconcile loop handles this automatically.
- **EVPN Type 5 deferred.** `BGPAdvertisement` does not carry a Route Distinguisher field in the current cosmos API. `galactic-router` returns `ErrMissingRouteDistinguisher` for l2vpn/evpn advertisements and sets `Accepted=False` on the CRD.
- **No kernel-path unit tests.** `internal/cni`, `internal/plumbing/srv6`, and `internal/plumbing/vrf` require `CAP_NET_ADMIN` and a real kernel. `internal/plumbing/intf` is fully unit-testable (pure functions only). Coverage comes from the e2e suite (`task test:e2e`).
