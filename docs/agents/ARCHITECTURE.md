# Architecture

> **Superseded.** This document has been split into three component-scoped
> architecture references. This file is kept only as a redirect for old
> links; it carries no content of its own and will not be updated further.

_Last updated: 2026-09-09_

Galactic now ships four binaries per node (the third only on dedicated
gateway-role nodes, the fourth on every compute node); three of them have
their own architecture document:

| Document                                           | Covers                                                                                                                                             |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| [ARCHITECTURE-CNI.md](ARCHITECTURE-CNI.md)         | The CNI attach chain — `galactic-cni` (installer), `galactic-veth`, `galactic-tap`, `galactic-ipam`, `galactic-bgp`, `galactic-route` |
| [ARCHITECTURE-ROUTER.md](ARCHITECTURE-ROUTER.md)   | The BGP/EVPN control plane — `galactic-router`                                                                                                     |
| [ARCHITECTURE-GATEWAY.md](ARCHITECTURE-GATEWAY.md) | The edge XDP NAT+LB gateway — `galactic-gateway`, `NetworkGateway`/`NetworkRule`                                                                   |

The fourth, `galactic-nat` (sharded stateful NAT66 egress, `EgressShard`),
has no architecture document of its own yet — see
[docs/nat/configuration.md](../nat66/configuration.md) for its
configuration reference in the meantime.

See [AGENTS.md](../../AGENTS.md#architecture-reference) for guidance on
which document to start from for a given task.
