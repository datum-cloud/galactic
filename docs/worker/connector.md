# Connector

Status: decided (D14), implemented by
[#1440](https://github.com/datum-cloud/galactic/issues/1440) with connector
claims (D37), an edge gate scope (D38) and a transfer step with rollback
(D39).

## Decision

The provider connector is the existing `galactic-edge`. No `galactic-connector`
binary is created.

| Item        | Value                                                                                    |
| ----------- | ---------------------------------------------------------------------------------------- |
| Name        | `galactic-edge`                                                                          |
| Entry point | `cmd/galactic-edge`                                                                      |
| Seam        | `internal/edge/agent.Datapath`                                                           |
| Change      | `agent.WorkerDatapath`, selected with `--worker-socket`, replaces `agent.PinnedDatapath` |
| Conformance | `tests/edgeconformance`, plus the independent provider in `examples/edge-provider`       |

### Why not a new component

- galactic-edge already registers host links, takes the per-VPC ownership
  fence that [ownership](ownership.md) generalizes, and is covered by
  `tests/edgeconformance`. A new binary would duplicate all three.
- The `Datapath` interface is already the boundary between provider handling
  and host programming, so the change stays inside one implementation of it.
- Providers that already ship, including the MASQUE provider, keep their
  contract with galactic-edge unchanged.

## What each side owns

galactic-edge keeps everything specific to providers. Galactic Worker writes
the shared state of the VPC.

| galactic-edge                                                                     | Galactic Worker                                                                |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Admission of the EdgeAttachment's link, provider status and the provider contract | Admission of the connector claim, while the EdgeAttachment is `Admitted`       |
| The host link, the pod VRF, the TUN and the routes inside the provider pod        | The VPC's host VRF, `BGPVRFInstance` and `vrf_table` row                       |
| Forwarding gates: the link row and each prefix's gate, under the edge gate scope  | The link's uSID registration and traffic policy rows, and its tc programs      |
| Which prefixes a link carries: its open gates and the routes it holds             | The VPC's `PassThroughEdge` entries in `egress_route_table` for those prefixes |
| `EdgeRoute.status.closedEpoch`                                                    | Withdrawing the link's rows on release, revocation or lease expiry             |

## Connector claims

A connector claim is a `routed_link` claim on an EdgeAttachment that names the
host link galactic-edge created (`ClaimSpec.edge_link`, D37). It lists no
destinations. Worker resolves one Local destination for it, the claim's own
attachment. Worker takes the link's address from `EdgeAttachment.status.address`,
never from the request, and never creates or deletes the link.

| Datapath call | Worker call                                                                                        |
| ------------- | -------------------------------------------------------------------------------------------------- |
| `Register`    | Write the link's gate row, then `Request` or `Update` the claim, and wait until it is `Programmed` |
| `SyncRoutes`  | `Update` each claim whose prefixes changed                                                         |
| `Unregister`  | Close the link's gates, then `Release` the claim, and wait until it is released                    |
| `Forget`      | None. galactic-edge removes the gate's link row once the link is deleted                           |

galactic-edge claims each new attachment before it creates the link, so Worker
creates the VPC's node state, and keeps it while the claim exists. Worker
registers the link only once the link carries the attachment's stamp
(`hostattach.LinkID`) and its gate row names the attachment's address. A link
with no gate row waits as `HandoffInterfaceMissing`, so no forwarding program is
attached to an ungated link. A link with another attachment's stamp, or a gate
row naming another address, is refused as `HandoffInterfaceNotOwned`, and Worker
writes nothing for it.

| Contract field   | Source                                                                   |
| ---------------- | ------------------------------------------------------------------------ |
| `caller`         | galactic-edge's ServiceAccount, allowed `local.routed_link`              |
| `vpc`            | `EdgeAttachment.status.vpc`                                              |
| `attachment_uid` | The EdgeAttachment's UID                                                 |
| `generation`     | One more than the generation Worker last reported for the claim          |
| `edge_link`      | The host link's name, and the prefixes of its open gates and held routes |

galactic-edge keeps no state of its own. One `Observe` stream reports the
generation of every claim, and a refusal carries the current generation, so a
restarted process continues from where Worker is.

## Authority

The connector reuses the authority that exists:

- **Approval.** Core admits the EdgeAttachment. Worker admits a connector claim
  only while the EdgeAttachment is `Admitted` and on this node.
- **Provider sessions.** Instance leases, route claims and acceptance are
  unchanged. Only galactic-edge decides which prefixes a link carries, from the
  accepted holder and its applied lease.
- **Revocation.** When core revokes an attachment, it sets `Admitted=False`
  and `Draining`. Two independent cuts stop delivery. galactic-edge closes the
  link's gates within the provider contract's revocation bound (15.5 s, with a
  2 s target while it is connected). Worker withdraws the claim with
  `AuthorizationRevoked` and removes the link's rows. The gate sets the bound;
  Worker's withdrawal is the second cut.
- **Replay.** Worker refuses an `Update` or `Release` at an older generation
  (`StaleGeneration`), a claim on an attachment that is deleted, replaced or not
  admitted (`VPCNotAuthorized`), a claim another caller holds
  (`AttachmentClaimedByAnotherCaller`), and a link stamped for another
  attachment (`HandoffInterfaceNotOwned`). A galactic-edge process that a newer
  one fenced cannot open a gate, because the newer process owns the edge gate
  scope.

## While Worker is down

Forwarding never depends on Worker. galactic-edge connects to Worker when a
call needs it, so it starts, renews gates and serves providers while Worker is
down. An attachment that is `Programmed` on a link Worker registered stays
`Programmed`: Worker keeps the link's rows while it is down and rebuilds them
from its store when it restarts. A new attachment waits, reporting
`WorkerUnavailable`, until Worker is back.

## Ownership transfer

Each VPC on the node has two scopes in `internal/ownership` (D38):

| Scope             | Owner                                            | Holds                                        |
| ----------------- | ------------------------------------------------ | -------------------------------------------- |
| `vpc-<id>`        | Galactic Worker once galactic-edge hands it over | The shared VPC state listed above            |
| `edge-gates-<id>` | The newest galactic-edge process; never Worker   | The forwarding gates of the VPC's edge links |

galactic-edge's transfer step (D39) for a `vpc-<id>` scope it, an older
process of it, or a Worker handback still holds:

1. Claim every live link of the scope. Worker records the claims and reports
   them `ScopeOwnedElsewhere`; it writes nothing yet.
2. Give the scope up with `ownership.Relinquish`, which advances the
   generation, so no ticket from before it can commit.
3. Send the claims again, so Worker reconciles at once. Worker takes the scope
   with `Claim` and commits a snapshot that already holds the claims, so every
   registered link keeps its rows throughout.

A gate opens, or is confirmed closed, only once no older galactic-edge process
holds the VPC's own scope.

## Compatibility

| Entry point or setting           | Without `--worker-socket` | With `--worker-socket`                                                            |
| -------------------------------- | ------------------------- | --------------------------------------------------------------------------------- |
| `cmd/galactic-edge`              | Unchanged                 | The same binary and image                                                         |
| Existing flags                   | Unchanged                 | Unchanged; `--bgp-namespace` is unused, since Worker creates the VPC's state      |
| `--worker-token-file`            | Unused                    | Projected token with audience `galactic-worker`                                   |
| `--worker-wait`                  | Unused                    | How long one link waits for Worker, 10 s by default                               |
| `config/galactic-edge` manifests | Unchanged                 | Add the `/run/galactic-worker` mount, the token and the flag; #1441 packages them |
| Provider contract and providers  | Unchanged                 | Unchanged                                                                         |
| Metrics                          | Unchanged                 | Adds `galactic_edge_foundation_worker_capability` and `_worker_claims`            |
| Condition reasons                | Unchanged                 | Adds `WorkerRefused` and `WorkerUnavailable` on `Programmed`                      |

Worker's allowlist must grant `galactic-system/galactic-edge` the
`local.routed_link` capability.

## Rollback

1. Stop Worker on the node.
2. Run `galactic-worker handback`, which gives each Worker-owned scope to a
   `galactic-handback:<timestamp>` owner.
3. Restart galactic-edge without `--worker-socket`.

galactic-edge takes each handed-back scope over with `Takeover` (D39) and
registers every link again in its first snapshot commit.

## Where provider adapters plug in

MASQUE, cloud and private-interconnect adapters are providers. They plug in at
the [provider contract](../edge/provider-contract.md), as `examples/edge-provider`
and the MASQUE provider do: an EdgeProvider, attachments, instances and routes.
None of them implements `agent.Datapath` or calls Worker. MASQUE negotiation and
its session lifecycle stay in the MASQUE provider.

## Evidence

| Evidence               | What it establishes                                                                                                   | Where                                                                        |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Worker unit tests      | Admission, refusal and replay rules of connector claims                                                               | `internal/worker/connector_test.go`                                          |
| Local module tests     | Registration, ownership checks and pass-through entries of edge links                                                 | `internal/worker/local/edgelinks_test.go`                                    |
| Revocation root test   | A provider's packet reaches the tenant through the link, and stops once Worker withdraws the claim                    | `internal/worker/local/edgelinks_root_test.go`                               |
| Connector fixture      | The agent against a real Worker: attach, delivery, withdrawal, replacement, denial, revocation, handover and rollback | `internal/edge/agent/connector_test.go`                                      |
| Provider qualification | One provider's behavior, such as MASQUE's, against the provider contract                                              | `tests/edgeconformance`, `task test:edge-provider` and the lab verifications |

The fixture uses a recording Local module, so it proves the protocol between
galactic-edge and Worker, not one provider. A provider is qualified only by its
own conformance run.
