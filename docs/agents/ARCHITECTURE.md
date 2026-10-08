# Architecture

> **Superseded.** This document has been split into three component-scoped
> architecture references. This file is kept only as a redirect for old
> links; it carries no content of its own and will not be updated further.

_Last updated: 2026-09-09_

Galactic now ships four binaries per node (the third and fourth only on
dedicated gateway-role `edge` nodes); three of them have
their own architecture document:

| Document                                                 | Covers                                                                                                                                |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| [ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md)               | The CNI attach chain — `galactic-cni` (installer), `galactic-veth`, `galactic-tap`, `galactic-ipam`, `galactic-bgp`, `galactic-route` |
| [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md)         | The BGP/EVPN control plane — `galactic-router`                                                                                        |
| [ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md)       | The edge XDP DSR load balancer — `galactic-gateway`, `NetworkGateway`/`NetworkRule`                                                   |
| [ARCHITECTURE-FABRIC-API.md](ARCHITECTURE-FABRIC-API.md) | The fabric looking glass — `fabric-api` (`node` sidecar, cell `gateway`, `janitor`), `FabricQuery`                                    |

The fourth, `galactic-nat` (sharded stateful egress translation, `EgressShard`),
has no architecture document of its own yet — see
[docs/nat/configuration.md](../nat/configuration.md) for its
configuration reference in the meantime.

Separately, `fabric-api` (the fabric looking glass: a sidecar in each
`fabric-router` pod plus a per-cell gateway) was added after this split and has
its own document, [ARCHITECTURE-FABRIC-API.md](ARCHITECTURE-FABRIC-API.md).

See [AGENTS.md](../../AGENTS.md#architecture-reference) for guidance on
which document to start from for a given task.
