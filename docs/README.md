# Galactic Docs

Index of everything under `docs/`. `AGENTS.md`/`CLAUDE.md` at the repo root
is the primary entry point for working in this codebase (architecture
reference table, dev workflow, deployment overview) — start there first.
This page exists to help you find a specific document once you already know
roughly what you're looking for.

## Architecture — the "why" and internal design

One self-contained reference per binary/subsystem (layout, entry points,
data flow, module reference, known constraints):

- [agents/ARCHITECTURE-CNI.md](agents/ARCHITECTURE-CNI.md) — the CNI attach
  chain (`galactic-cni`, `-veth`, `-tap`, `-ipam`, `-bgp`, `-route`).
- [agents/ARCHITECTURE-ROUTER.md](agents/ARCHITECTURE-ROUTER.md) — the
  BGP/EVPN control plane (`galactic-router`, embedded GoBGP, GC).
- [agents/ARCHITECTURE-GATEWAY.md](agents/ARCHITECTURE-GATEWAY.md) — the edge
  XDP DSR NAT+LB gateway (`galactic-gateway`, `NetworkGateway`/`NetworkRule`).
- [agents/ARCHITECTURE.md](agents/ARCHITECTURE.md) — superseded by the three
  documents above; kept only as a redirect for old links.
- [agents/CONVENTIONS.md](agents/CONVENTIONS.md) — Go naming, error
  handling, testing patterns, linting, and commit-message conventions
  enforced across every binary.
- [node-labels.md](node-labels.md) — the `galactic.datumapis.com/*`
  node-labeling scheme shared across `galactic-cni`, `-router`, `-gateway`,
  `-nat66`, and `fabric-router`; cross-cutting, owned by no single component.
- [architecture/README.md](architecture/README.md) — C4-model diagrams (system
  context, container) rendered from PlantUML sources.

## Configuration — the "how" of deploying and operating each binary

- [router/configuration.md](router/configuration.md) — `galactic-router`
  env vars/CLI flags, the webhook options, and DaemonSet examples.
- [gateway/configuration.md](gateway/configuration.md) — `galactic-gateway`
  deployment (node labeling, RBAC, per-node overlay), its config reference,
  and the `NetworkGateway`/`NetworkRule`/`ServiceVIPBinding` CRD fields.
- [nat/configuration.md](nat/configuration.md) — `galactic-nat` config
  reference, the `EgressShard` CRD, and the `galactic-cni`-side shard
  membership settings that point tenant nodes at it.
- [cni/README.md](cni/README.md) — entry point for the `galactic-cni` docs
  subtree; from there:
  - [cni/environment-variables.md](cni/environment-variables.md) — every
    `GALACTIC_CNI_*`/`GALACTIC_IPAM_*` env var and conflist `HostConf` field.
  - [cni/conflist-reference.md](cni/conflist-reference.md) /
    [cni/conflist-examples.md](cni/conflist-examples.md) — the conflist field
    reference and worked, copy-pasteable examples.
  - [cni/cni-cmd-sequence.md](cni/cni-cmd-sequence.md) /
    [cni/gc-cmd-sequence.md](cni/gc-cmd-sequence.md) — Mermaid sequence
    diagrams for the attach/detach path and orphan garbage collection.

## Proposals and exploratory design

Not descriptions of what's implemented today — read the architecture docs
above for that.

- [enhancements/proposals/masque-gateway-design.md](enhancements/proposals/masque-gateway-design.md)
  — an alternative MASQUE/QUIC/Iroh-based ingress gateway design, distinct
  from the implemented `galactic-gateway` (XDP DSR over a Maglev ring).
- [enhancements/networking/latency-aware-routing/README.md](enhancements/networking/latency-aware-routing/README.md)
  — latency-aware SRv6 path selection as a tenant-facing routing policy.
  `status: provisional`, `stage: alpha`.
