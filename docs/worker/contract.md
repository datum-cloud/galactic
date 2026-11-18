# Worker service contract

Status: version `v1alpha1`.
[#1433](https://github.com/datum-cloud/galactic/issues/1433) implements the
service (`cmd/galactic-worker`, `internal/worker`), its protobuf API
(`api/galactic/worker/v1alpha1`), the client library (`pkg/workerclient`) and
the delivery module interface (`internal/worker/module`). The Tasks named in
each section own the rest and its tests. Decision IDs (D1, D2, …) refer to the
[decision log](README.md#decision-log).

Galactic Worker is one process per node. Service agents (NAT, Gateway, the
Envoy galactic-vrf sidecar and the provider connector) ask it to deliver tenant
traffic between their own handoff point and tenant destinations. Worker checks
the request against existing authority, decides whether each destination is
Local (on this node) or Fabric (on another node), programs the host, and reports
what it programmed and what it observed. Packets never pass through Worker: it
programs kernel hooks, maps and routes, and the datapath forwards on its own.

## Claims

A **delivery claim** is the unit of the API (D1).

| Field            | Meaning                                                                                                                                                     |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `caller`         | The authenticated client identity (D8). Worker derives it from the connection; a client cannot supply it.                                                   |
| `node`           | The physical node. A request naming another node is refused with `INVALID_ARGUMENT`.                                                                        |
| `vpc`            | The VPC the claim acts in. It must equal the VPC of the claim's attachment (see [trusted sources](#trusted-sources)).                                       |
| `attachment_uid` | UID of the VPCAttachment or EdgeAttachment that is the service's handoff point in that VPC.                                                                 |
| `generation`     | A client-assigned `uint64`. Every change to a claim carries a larger generation than the last accepted one.                                                 |
| `spec`           | The handoff kind (`tap`, `veth_pair`, `routed_link`, `socket`), the destinations (an attachment, shard or backend reference each), and the mode preference. |

The key is `(caller, node, vpc, attachment_uid)`. The handoff resources of one
attachment (its TAP, internal veth pair or routed link) belong to one caller.
A second caller that names the same attachment gets `PERMISSION_DENIED` with
reason `AttachmentClaimedByAnotherCaller`. Fabric state for a VPC is shared:
any number of claims may resolve destinations through the same VPC.

A destination names an attachment, a shard or a backend. Worker resolves
attachment destinations. The shard resolver, from NAT's trusted source, is added
inside Worker by [#1437](https://github.com/datum-cloud/galactic/issues/1437),
and the backend resolver by
[#1438](https://github.com/datum-cloud/galactic/issues/1438). Until then a shard
or backend destination is accepted and reports `Resolved=False` with reason
`DestinationKindUnsupported` (D20).

The mode preference is `auto`, `local` or `fabric`. `auto` lets Worker resolve
each destination. `local` and `fabric` restrict the result; a destination that
cannot resolve to the requested mode reports `Resolved=False` with reason
`ModeUnavailable`.

## Operations

The API is a gRPC service, `galactic.worker.v1alpha1.Worker` (D7).

| RPC               | Semantics                                                                                                                                                                                                                                                                                                                                        |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GetCapabilities` | Version negotiation and capability discovery. Must be the first call of a session. Returns the chosen API version, the session ID and lease, and each capability with its state and reason.                                                                                                                                                      |
| `Request`         | Creates a claim. Repeating the same generation and spec returns the current status and changes nothing. An existing claim with a different generation gets `FAILED_PRECONDITION`/`ClaimExists`; use `Update`. The same generation with a different spec gets `FAILED_PRECONDITION`/`GenerationConflict`.                                         |
| `Update`          | Replaces the spec of an existing claim. A generation smaller than the current one gets `ABORTED`/`StaleGeneration`. The same generation and spec is a no-op; the same generation with a different spec is `GenerationConflict`.                                                                                                                  |
| `Observe`         | Server stream of status snapshots for one claim or for all of the caller's claims. Each snapshot is complete, so a client can drop duplicates and reorderings by `observed_generation`. The stream also renews the session lease.                                                                                                                |
| `Release`         | Removes a claim. The generation must equal the current generation. An older generation gets `ABORTED`/`StaleGeneration` and a newer one `FAILED_PRECONDITION`/`GenerationConflict`; neither changes anything. A missing claim returns success, so a retried release is safe. A caller that does not own the attachment gets `PERMISSION_DENIED`. |

`Request`, `Update` and `Release` return once Worker has validated, authorized
and durably recorded the change. They do not wait for programming. The client
learns the outcome from `Observe`.

### Capabilities

`GetCapabilities` reports one row per capability: `local.tap`,
`local.veth_pair`, `local.routed_link`, `local.socket` and `fabric.srv6`. Each
row is `Available` or `Unavailable` with a machine reason, for example
`DatapathNotLoaded`, `HookUnsupported` (an XDP mode or device the
[qualified platform](qualification.md) excludes) or `ModuleNotRunning`. A claim
that needs an unavailable capability is accepted and reports `Programmed=False`
with the same reason, so a client can tell a temporary module outage from a
refused request.

A claim needs the Local capability of its handoff (`local.tap`,
`local.veth_pair`, `local.routed_link` or `local.socket`) for its Local
destinations, and `fabric.srv6` for its Fabric destinations. The caller must
be allowed the handoff's capability, and `fabric.srv6` when a destination is
on another node or resolves to Fabric at admission. Worker records the owner's
capabilities with each generation and does not program a destination that
later resolves to a mode they do not cover.

### Version negotiation

The client sends the range of API versions it supports. Worker picks the
highest version both support, or fails with `FAILED_PRECONDITION` and reason
`UnsupportedVersion`, listing the versions it serves. Within a version, fields
are added only, and clients ignore fields they do not know. A breaking change
is a new package (`v1alpha2`, `v1beta1`), served alongside the old one until
every client on the branch has moved to it (D7).

## State model

Worker keeps three states for each claim, and never reports one as another (D2).

| State      | What it holds                                                                                                       | Durable                                              |
| ---------- | ------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| Desired    | The accepted generation and spec, and the owner.                                                                    | Yes, under `/var/lib/galactic-worker`                |
| Programmed | What Worker wrote for each destination: mode, VRF table, SID, map rows, routes, and the read-back of each write.    | Rebuilt from the host after a restart                |
| Observed   | Readiness evidence Worker did not write: the TAP or veth exists and is up, the neighbor resolves, CNI has attached. | Rebuilt from the host and from CNI attachment events |

Status carries `observed_generation` and these conditions, matching the
EdgeAttachment condition names where they mean the same thing:

| Condition     | True when                                                                                              |
| ------------- | ------------------------------------------------------------------------------------------------------ |
| `Admitted`    | The caller is authorized for the VPC, attachment and every destination.                                |
| `Resolved`    | Every destination resolved to Local or Fabric.                                                         |
| `Programmed`  | Programmed state matches desired state for `observed_generation`, confirmed by read-back.              |
| `Ready`       | `Programmed` is true and observed state shows every handoff can carry traffic.                         |
| `Withdrawing` | A release, revocation or lease expiry is removing programmed state. Status names the withdrawal scope. |

The withdrawal scope names what stops: one destination, one claim, every claim
of a caller, or a whole VPC on the node. Operators read it to judge the reach
of a withdrawal ([#1441](https://github.com/datum-cloud/galactic/issues/1441)).

### Resolution

A destination whose locator is this node's locator resolves to Local; any other
locator resolves to Fabric (D11). Worker never falls back from Local to Fabric:
sending a Local destination out of the uplink would hairpin it and change the
return path the service depends on. A Local destination whose handoff is
missing waits, as the [worked transitions](#worked-transitions) show.

### Trusted sources

Worker takes these facts only from the sources below, never from the request (D10).

| Fact                     | Source                                                                                                                                |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| Physical locator         | The node's BGPRouter Block and Node-ID, the same source `internal/installer/locatorroute.go` uses for the locator's local route.      |
| VPC identity             | NetworkFabricIdentity for the VPC (`api/cloud/v1alpha1`), written by the fabric identity allocator.                                   |
| Authorized VPC           | `VPCAttachment.spec.vpc` for workload and service attachments, written by NSO; for a connector, an EdgeAttachment that is `Admitted`. |
| Owner                    | The authenticated caller (D8), recorded with the claim's desired state.                                                               |
| Backend SID              | The backend node's locator plus the slot the gateway encodes in the uSID, as `docs/gateway/architecture.md` describes.                |
| Interface traffic policy | TrafficPolicyBinding, resolved by the cell controller. Worker applies no policy of its own.                                           |

Worker compares a VPC as the base62 identifier the attachment's status records
(`VPCAttachment.status.vpc`, `EdgeAttachment.status.vpc`). That identifier is
the VPC's fabric identity as this cell received it, and a claim's `vpc` is the
same identifier. An attachment whose identifier is still empty authorizes
nothing.

A claim is cross-VPC when any destination belongs to a VPC other than the
claim's attachment VPC. Worker refuses it. Two VPCs may use the same addresses,
so Worker compares VPC identity, never addresses.

## Errors and retry

| gRPC code             | Reasons                                                                                    | Client action                                               |
| --------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------------- |
| `INVALID_ARGUMENT`    | `MalformedSpec`, `WrongNode`                                                               | Fix the request. Do not retry.                              |
| `UNAUTHENTICATED`     | `NoIdentity`, `IdentityExpired`                                                            | Refresh the credential, then retry.                         |
| `PERMISSION_DENIED`   | `VPCNotAuthorized`, `AttachmentClaimedByAnotherCaller`, `NotOwner`, `CapabilityNotAllowed` | Do not retry until authority changes.                       |
| `FAILED_PRECONDITION` | `UnsupportedVersion`, `ClaimExists`, `ClaimNotFound`, `GenerationConflict`                 | Re-read with `Observe`, then use the right operation.       |
| `FAILED_PRECONDITION` | `NoSession`                                                                                | Call `GetCapabilities` for a new session, then retry.       |
| `ABORTED`             | `StaleGeneration`                                                                          | Re-read with `Observe`; retry only with a newer generation. |
| `UNAVAILABLE`         | `Resyncing`, `ShuttingDown`                                                                | Retry with backoff.                                         |
| `RESOURCE_EXHAUSTED`  | `ClaimLimit`, `TableRangeExhausted`                                                        | Retry with backoff; report if it persists.                  |

`Update` of a claim that does not exist, or is being withdrawn, gets
`ClaimNotFound`.

Status carries these reasons besides the ones above:

| Reason                                             | Where         | Meaning                                                                                                   |
| -------------------------------------------------- | ------------- | --------------------------------------------------------------------------------------------------------- |
| `Pending`                                          | Any condition | Worker has not yet reconciled the generation                                                              |
| `DestinationKindUnsupported`                       | `Resolved`    | A shard or backend destination, until #1437 or #1438 resolves it                                          |
| `DestinationNotFound`                              | `Resolved`    | The destination attachment no longer exists                                                               |
| `LocatorUnknown`                                   | `Resolved`    | This node or the destination's node has no SRv6 locator yet                                               |
| `ModeUnavailable`                                  | `Resolved`    | The destination resolves to a mode the preference excludes                                                |
| `ModuleNotRunning` and other capability reasons    | `Programmed`  | The capability the destination needs is unavailable                                                       |
| `CapabilityNotAllowed`                             | `Programmed`  | The destination resolved to a mode the owner was not allowed at admission, so it stays unprogrammed       |
| `ProgrammingFailed`                                | `Programmed`  | The last commit failed; the message carries the error                                                     |
| `ScopeOwnedElsewhere`                              | `Programmed`  | Another writer owns the VPC scope's fence (see [ownership](ownership.md#bootstrap-adoption-and-transfer)) |
| `Released`, `LeaseExpired`, `AuthorizationRevoked` | `Withdrawing` | Why the claim is being withdrawn                                                                          |

Clients retry with exponential backoff from 200 ms to 30 s with full jitter.
Every mutating call is idempotent for a given generation, so a retry after a
lost response is safe (D3). Every refusal carries a gRPC code and a machine
reason from this table (D6). Worker retries its own programming from 1 s to
60 s and reports the last error as the reason on `Programmed=False`.

## Sessions, restart and stale deletion

Every call after `GetCapabilities` carries the session ID in the
`x-galactic-worker-session` metadata key. A call without a live session of the
caller gets `FAILED_PRECONDITION`/`NoSession`. A `GetCapabilities` that carries
a live session ID renews that session instead of starting another (D19).

A session starts with `GetCapabilities` and carries a lease of 120 s, renewed by
an open `Observe` stream or a call at least every 10 s. These are the XDP
dispatcher's slot lease values (`internal/plumbing/ebpf/xdpdispatch`), already
qualified for detecting a dead service agent (D5).

- **Client restart.** The client opens a new session and repeats `Request` for
  each claim with its last generation. Worker answers each as a duplicate. The
  owner is the caller identity, not the session, so a restart within the lease
  changes no host state.
- **Lease expiry.** When a caller has no live session for 120 s, Worker marks
  its claims `Withdrawing` with scope "every claim of the caller" and removes
  their programmed state. Desired state is deleted once the read-back confirms
  removal.
- **Authority revoked.** When the VPCAttachment is deleted or an EdgeAttachment
  loses `Admitted`, Worker sets `Admitted=False` with reason
  `AuthorizationRevoked` and withdraws the claim the same way
  ([#1440](https://github.com/datum-cloud/galactic/issues/1440) tests
  revocation).
- **Worker restart.** Worker reads desired state from disk, then for each scope
  fences, adopts and reconciles a full snapshot, as [ownership](ownership.md#bootstrap-adoption-and-transfer)
  describes. Programmed and observed state are rebuilt by reading the host.
  Forwarding continues while Worker is down, because the datapath does not call
  Worker.

## Transport, identity and access

D8 and D9 were confirmed on 2026-11-18.

- **Transport (D8).** gRPC over a unix socket at
  `/run/galactic-worker/worker.sock`, mode `0660`, owned by a dedicated group.
  No TCP listener serves the mutating API.
- **Client identity (D8).** Each call carries a projected ServiceAccount token
  with audience `galactic-worker`, bound to the calling pod, as
  `authorization: Bearer <token>`. Worker validates it with TokenReview, caches
  the result until the token expires, and checks that the bound pod runs on
  this node. Worker also reads the peer's credentials (`SO_PEERCRED`) and
  refuses a peer that is not a process of that pod. It maps the peer PID to a
  pod through the pod UID in `/proc/<pid>/cgroup`, so Worker runs in the host
  PID namespace and reads the host's `/proc`; in any other PID namespace the
  kernel reports PID 0 for a peer in another pod (D21).
  [#1441](https://github.com/datum-cloud/galactic/issues/1441) packages
  `hostPID` and the `/proc` mount.
- **Allowlist (D8, D22).** A static YAML file, passed with `--allowlist`, maps
  each ServiceAccount to the capabilities it may use. A ServiceAccount it does
  not list may use none.

  ```yaml
  serviceAccounts:
    - serviceAccount: galactic-system/galactic-nat
      capabilities: [local.veth_pair, fabric.srv6]
  ```

- **Access model (D9).** Host-network agents (NAT, Gateway, galactic-edge) mount
  `/run/galactic-worker` with a `hostPath` volume. The galactic-vrf sidecar runs
  in the Envoy pod's network namespace and mounts the same directory; pod
  security admission limits that `hostPath` to the sidecar's ServiceAccount.

## Worked transitions

Each case names the decision it exercises and the Task that owns its test.

| Case                             | Start                                                                                                                          | Event                                                                                                              | Worker action                                                                                                                                                                                                                                                                      | Result                                                                                                                                                                                                         | Decision     | Test owner                                                                                                                                                                                              |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Duplicate request                | Claim at generation 4, `Ready=True`.                                                                                           | The client's response was lost, so it sends `Request` again with generation 4 and the same spec.                   | Compares generation and spec hash with desired state. Takes no ticket and writes nothing.                                                                                                                                                                                          | `OK` with the current status. Host state is byte-for-byte unchanged. The same generation with a different spec gets `FAILED_PRECONDITION`/`GenerationConflict`.                                                | D1, D3       | [#1433](https://github.com/datum-cloud/galactic/issues/1433) unit test: duplicate and out-of-order requests                                                                                             |
| Stale release                    | Claim updated from generation 4 to 5, programming in progress.                                                                 | A delayed `Release` with generation 4 arrives.                                                                     | Compares the generation with desired state and refuses before taking a ticket.                                                                                                                                                                                                     | `ABORTED`/`StaleGeneration`, carrying current generation 5. The claim and host state are unchanged, and programming of generation 5 continues.                                                                 | D3, D4       | [#1433](https://github.com/datum-cloud/galactic/issues/1433) unit test: release from a stale generation and from a non-owner                                                                            |
| Unauthorized cross-VPC claim     | The caller has a claim on an attachment in VPC A. VPC B uses the same guest addresses.                                         | `Update` adds a destination whose attachment is in VPC B.                                                          | Resolves the destination's VPC from its attachment record and its identity from NetworkFabricIdentity, finds B ≠ A, and refuses. Records nothing durable, takes no ticket, logs the refusal and counts it in a metric.                                                             | `PERMISSION_DENIED`/`VPCNotAuthorized`. The existing generation keeps running. Routes, rules, links and pinned maps are unchanged.                                                                             | D1, D10      | [#1433](https://github.com/datum-cloud/galactic/issues/1433) zero-mutation snapshot test; [#1442](https://github.com/datum-cloud/galactic/issues/1442) observes the unauthorized destination in the lab |
| Local locator with a missing TAP | Claim admitted; one destination is a guest on this node.                                                                       | Resolution finds the node's own locator, but the guest's TAP does not exist (not yet attached, or being replaced). | Resolves the destination to Local and does not fall back to Fabric. Programs the other destinations. Leaves the missing one unprogrammed and watches CNI attachment events. When CNI ADD creates the TAP, programs it on the new ifindex and reads it back.                        | Until the TAP appears: `Resolved=True`, `Programmed=False` and `Ready=False`, with reason `HandoffInterfaceMissing` naming the destination. Afterwards: `Ready=True`.                                          | D2, D11      | [#1435](https://github.com/datum-cloud/galactic/issues/1435) root test for Local programming; [#1434](https://github.com/datum-cloud/galactic/issues/1434) for CNI attachment observation               |
| Withdrawal during repair         | A commit failed part-way, so the VPC scope is resync-required and Worker's repair holds a ticket while it prepares a snapshot. | The owner sends `Release` with the current generation.                                                             | Records the release durably and answers. Fences the scope, which invalidates the repair's ticket, then adopts it and commits a snapshot computed from desired state without the released claim. The repair's late commit fails with a transitioning or stale error and is dropped. | `Release` returns `OK`. Status shows `Withdrawing` with scope "one claim" until the read-back confirms removal, then `Observe` reports the claim released. No row of the released claim survives the snapshot. | D3, D12, D13 | [#1433](https://github.com/datum-cloud/galactic/issues/1433) crash and interleaving tests; [#1436](https://github.com/datum-cloud/galactic/issues/1436) for Fabric rows                                 |
