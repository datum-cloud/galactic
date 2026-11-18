# Connector decision

Status: decided (D14). [#1440](https://github.com/datum-cloud/galactic/issues/1440)
implements it.

## Decision

The provider connector is the existing `galactic-edge`. No `galactic-connector`
binary is created.

| Item        | Value                                                                                         |
| ----------- | --------------------------------------------------------------------------------------------- |
| Name        | `galactic-edge`                                                                               |
| Entry point | `cmd/galactic-edge`                                                                           |
| Seam        | `internal/edge/agent.Datapath` (`internal/edge/agent/agent.go:75`)                            |
| Change      | A Worker-backed `Datapath` replaces `agent.PinnedDatapath` (`cmd/galactic-edge/main.go:197`). |
| Conformance | `tests/edgeconformance`, plus the independent provider in `examples/edge-provider`            |

## How it works

`agent.Datapath` has four methods: `Register`, `Unregister`, `Forget` and
`SyncRoutes`. Today `PinnedDatapath` implements them by writing the pinned maps
directly through `attachreg`. The Worker-backed implementation turns them into
Worker calls instead:

- `Register` becomes a `Request` (or an `Update` with a new generation) for a
  `routed_link` claim on the EdgeAttachment, carrying the host link.
- `SyncRoutes` becomes an `Update` that replaces the claim's destinations.
- `Unregister` and `Forget` become a `Release`.

galactic-edge keeps everything specific to providers: admission of the
EdgeAttachment, the gates, provider status and the contract with provider pods.
Worker admits a connector claim only while its EdgeAttachment is `Admitted`, and
withdraws it when admission is revoked.

## Why not a new component

- galactic-edge already registers host links through `attachreg`, takes the
  per-VPC ownership fence that [ownership](ownership.md) generalizes, and is
  covered by `tests/edgeconformance`. A new binary would duplicate all three.
- The `Datapath` interface is already the boundary between provider handling
  and host programming, so the change stays inside one implementation of it.
- Providers that already ship, including the MASQUE provider, keep their
  contract with galactic-edge unchanged.
