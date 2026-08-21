# Architecture

> **Superseded.** This document has been split into three component-scoped
> architecture references. This file is kept only as a redirect for old
> links; it carries no content of its own and will not be updated further.

_Last updated: 2026-08-13_

Galactic now ships three binaries per node (the third only on dedicated
gateway-role nodes), each with its own architecture document:

| Document                                           | Covers                                                                                                                                             |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| [ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md)         | The CNI attach chain — `galactic-cni` (installer), `galactic-veth`, `galactic-tap`, `galactic-ipam`, `galactic-bgp`, `galactic-route` |
| [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md)   | The BGP/EVPN control plane — `galactic-router`                                                                                                     |
| [ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md) | The edge XDP NAT+LB gateway — `galactic-gateway`, `NetworkGateway`/`NetworkRule`                                                                   |

See [AGENTS.md](../../AGENTS.md#architecture-reference) for guidance on
which document to start from for a given task.
