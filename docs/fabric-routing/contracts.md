# Fabric routing activation, recovery and coordination contracts

These are the contracts the fabric routing controller and agent implement.
Each section states the selected behavior, the reasoning, and the
acceptance cases that test it. Where a choice depends on a fact this
repository cannot establish (a Talos property, a measured budget), the
section names it as a gate in [README.md](README.md#external-gates).

## Components and ownership

| Component                                  | Binary / package                                              | Writes                                                                                                       | Reads                                                                                       |
| ------------------------------------------ | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| Compiler and rollout manager, one per cell | `fabric-router-controller run`; `internal/fabric/routing/...` | `FabricRouterRevision` (create only), `FabricRouterDeployment.spec`, parent conditions on `BGPRouter.status` | Fabric-class `BGPRouter` graph, `Node`, `FabricReleaseAuthorization`, `FabricRolloutPolicy` |
| Node agent                                 | `fabric-config-agent` (existing), source modes added          | `FabricRouterDeployment.status` for its own node; local journal and checkpoint; FRR                          | Its node's deployment and revisions; referenced Secrets                                     |
| Fleet release tool                         | `fabric-router-controller release ...`                        | `FabricReleaseAuthorization` in each affected cell                                                           | Authorizations in every cell of the routing domain                                          |
| Central identity allocator                 | `galactic-controller --role=fabric` (unchanged)               | `NetworkFabricIdentity`                                                                                      | —                                                                                           |
| NSO cell manager (external)                | `network-services-operator`                                   | VPC/attachment/interface resources                                                                           | —                                                                                           |

The controller runs as its own Deployment and ServiceAccount
(`fabric-router-controller`) with leader-election lease
`fabric-router-controller.galactic.datumapis.com`. It holds no hub or IPAM
credentials and does not reuse `--role=fabric`. Only the agent writes FRR.

## Revisions

A `FabricRouterRevision` is created once and never updated (its spec is
immutable by CEL). It carries:

- `target`: router name and UID, Node name and UID.
- `parametersRef` and the parameters' generation.
- `compiler`: semantics version and the FRR capability set it targets.
- `configuration`: the resolved typed router (sessions, families,
  policies, lists, sets, static routes, origination, BMP), with no Secret
  material and no raw CLI.
- `inputs`: every source object's kind, name, UID, generation and digest.
- `credentials`: each referenced Secret's name, UID and a version digest
  (SHA-256 of the key's value, never the value).
- `semanticsDigest`: SHA-256 over `configuration` in canonical JSON.
- `activationDependencyDigest`: SHA-256 over target identity,
  `semanticsDigest`, parameters identity, compiler/FRR versions and
  credential version digests. A credential rotation changes this digest
  while `semanticsDigest` stays the same.

The revision name is `<router>-<first 10 hex of the dependency digest>`, so
identical inputs produce the same revision and the controller creates at
most one object per distinct activation input. Revisions are retained
while active, candidate, recovery target or among the newest 10 per
router; older ones are deleted by count, then by age (30 days).

Compilation resolves the full graph, records each input's generation, then
re-reads them; if any generation moved, the candidate is discarded and the
router requeued. For multi-object changes, authors create new policy
objects first and switch references last. A release that touches several
mutable objects names an input manifest (object and expected digest) in
the `FabricReleaseAuthorization`; the controller refuses to promote a
candidate whose inputs differ.

## Activation identity and replay protection

An activation is the tuple (cluster ID, Node UID, deployment UID, epoch,
revision name, activation dependency digest). Cluster ID is the
`kube-system` namespace UID.

- The rollout manager is the only writer of `spec.activationEpoch`, and
  writes it together with `spec.activeRevisionRef` and
  `spec.activationDependencyDigest` in one update. Epochs increase by one
  per promotion within one deployment UID.
- The agent keeps a per-deployment-UID high-water mark in its journal. It
  accepts an activation only when its epoch is greater than the mark, or
  equal with an identical tuple (idempotent redelivery). A lower epoch, or
  an equal epoch with a different tuple, is rejected with
  `Accepted=False`, reason `StaleActivation`.
- A failed activation (validation, apply error, timeout, or a stabilization
  failure) is journaled before recovery starts. The agent never retries
  the same epoch; a retry needs a new epoch, even for the same revision.
- A deployment with a different UID than the journal's, or a deployment
  whose epoch is below the journal's mark (an API restore), puts the agent
  in `RecoveryConflict`: it keeps the running authorized configuration,
  accepts nothing, and reports the conflict. `fabric-router-controller
  rebind` resolves it (below).

## Agent stages

1. Resolve: target Node UID matches the bound Node; revision exists and
   its digest verifies; referenced Secrets exist at the recorded version;
   the update-source addresses and interfaces exist locally.
2. Render and validate: render `frr.conf` from the typed revision; run
   `vtysh -C -f`; compute the diff with `frr-reload.py --test` against
   the running configuration; classify it as `NoChange`,
   `NonDisruptive`, `SessionReset` (a neighbor is added, removed, or its
   transport changes) or `RestartRequired` (daemons, defaults profile).
   A staged candidate is reported in `status.staged` and never applied.
3. Journal: append `Accepted` with the activation tuple, the previous
   last-known-good, and the recovery target and revocations the
   deployment carries. Fsync.
4. Apply: `frr-reload.py --reload` under the existing single-writer lock
   (also taken by the IPv4-mapped next-hop reset), bounded by
   `--apply-timeout` (default 60s). Append `Applied` or `ApplyFailed`.
5. Observe: compare `show running-config` (normalized by the same
   `frr-reload.py` parser) with the rendered file; check required static
   routes are in the FIB and required sessions reach Established; collect
   observer evidence for the stabilization window.
6. Commit: append `Committed` and write the checkpoint (below). Only then
   report `Ready=True` for the epoch.

A reload that errors after applying some commands leaves the runtime
uncertain: the agent observes, applies the authorized recovery target if
the activation recorded one, reports `Degraded` with the observed
difference, and pauses. It does not alternate between candidate and
recovery.

## Crash boundaries

| Last durable journal record                            | Restart behavior                                                                                                                                                                                                                |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| none for this epoch (candidate only)                   | Keep running config. Staging grants nothing.                                                                                                                                                                                    |
| `Accepted`                                             | Observe. If running equals the candidate, continue at stage 5; if it equals the previous last-known-good, re-apply the candidate under the same epoch (the epoch was accepted, never failed); otherwise treat as `ApplyFailed`. |
| `ApplyFailed` or apply timed out                       | Observe, recover to the recorded target, record the failure.                                                                                                                                                                    |
| `Applied`                                              | Repeat stabilization checks before committing.                                                                                                                                                                                  |
| `Committed`, status unwritten                          | Rebuild status from the journal and fresh observation; no reapply.                                                                                                                                                              |
| any, with a deployment UID or epoch behind the journal | `RecoveryConflict`; nothing is applied until rebind.                                                                                                                                                                            |

Journal records are JSON lines in `journal.log`, each with a CRC32C, and
fsynced before the next stage. A torn last line is discarded; an earlier
corrupt line puts the agent in `RecoveryConflict`. The checkpoint
(`checkpoint.json`) is written to a temp file, fsynced, renamed, and the
directory fsynced. Tests kill the agent at every boundary
(`internal/fabricconfig/activation` fault injection), including during
recovery.

## Checkpoint storage and machine binding on Talos

The agent's state directory is a hostPath at
`/var/lib/galactic/fabric-router`, mode 0700. On Talos `/var` survives pod
replacement, reboot and OS upgrade, and is wiped by `talosctl reset` and
reimaging. An `emptyDir` is not used.

`identity.json`, written once when the directory is first used, binds the
state to the machine: Node UID, the node's `/etc/machine-id`, the cluster
ID, and a random 128-bit storage nonce. At every start the agent compares
the live machine ID and (when the API is reachable) the Node UID. Any
mismatch, which is what copied storage or a same-name replacement node
looks like, makes the agent refuse the checkpoint and take the bootstrap
path. A reimaged node has an empty directory and also bootstraps.

The checkpoint holds the last committed activation tuple, its rendered
configuration, the recovery target, the revocation set, compiler and FRR
versions, `bootAuthorizedUntil`, and a SHA-256 over the rest.

Bootstrap path: a node without a valid checkpoint never starts a
permissive empty router. With the API reachable the agent waits for its
activation; without it, FRR stays without BGP configuration (zebra only)
and the agent reports `Bootstrapping`.

## Offline authorization

- Boot authorization: `bootAuthorizedUntil` is set at commit from the
  rollout policy's `offlineBootLifetime` (default 7 days). At start without
  API access, the agent applies the checkpoint only if the wall clock is
  before that time and not earlier than the last clock reading in the
  journal; a clock that moved backwards is treated as expired.
- Continued runtime: an already running router is not stopped by boot
  expiry. Stopping a stale isolated router needs external fencing (switch
  port shutdown or provider session removal). Reusing a router's identity
  requires a recorded fence (`FabricRouterDeployment.spec.fence`), set by
  the operator after fencing; the controller refuses to bind a new node to
  an identity without it.

## Credentials

The fixtures use no BGP authentication. The contract for when they do:

- `authSecretRef` must name an immutable Secret (`immutable: true`); a
  rotation is a new Secret name and a reference update, which produces a
  new activation dependency digest and a new epoch.
- Revisions and the journal record Secret name, UID and value digest only.
  Status, events, diffs and logs never include values; the renderer writes
  the password only into the file handed to `frr-reload.py`, mode 0600,
  removed after apply.
- Offline restart of an authenticated session needs the value on disk.
  Without an approved encrypted local store, a revision with credential
  dependencies is not boot-eligible offline: the checkpoint records it as
  `requiresAPI` and an offline boot leaves those sessions unconfigured.
- A revoked credential (its Secret listed in
  `spec.recovery.revokedCredentials`) makes every revision that depends on
  it ineligible for recovery.

## Recovery eligibility and revocation

`FabricRouterDeployment.spec.recovery` carries:

- `targetRevisionRef`: the revision the agent may restore on a confirmed
  failure of this activation. The controller sets it to the current active
  revision unless that is ineligible, in which case it names the newest
  eligible one, or none.
- `revokedPrefixes`, `revokedCredentials`, `retired`: added by the
  controller when an advertisement is withdrawn, a credential rotated out,
  or the router decommissioned.

The agent journals these with `Accepted`, before applying the activation
that removes the old authorization, and refuses any recovery target that
originates a revoked prefix or uses a revoked credential. With no eligible
target it does not roll back: it reports `Degraded`, reason
`NoEligibleRecovery`, and the operator uses drain or fencing.

## Emergency withdrawal

`fabric-router-controller withdraw --router R --prefix P...` builds a
restricted revision from the active revision, removing only the named
origination (network statements, aggregates, and permit terms in
redistribution policies that admit only those prefixes), and fails if the
result would change any filter or session. It validates aggregate
contributors (an aggregate whose last contributor is withdrawn is
reported) and adds the prefixes to `revokedPrefixes`. The revision goes
through a normal epoch and the agent's journal. It does not need the
unrelated missing references that block ordinary compilation, and it
requires an `EmergencyWithdrawal` authorization instead of a fleet
release.

## Fleet release authorization

Activation needs a `FabricReleaseAuthorization` in the target's cell
naming the deployment, the revision and its dependency digest, the
affected failure domains, the fleet release ID and a monotonic fleet
sequence. Within a cell the controller allows at most one non-terminal
authorization per routing domain. Across cells,
`fabric-router-controller release create` lists authorizations in every
cell context given for the routing domain and refuses to issue while any
is `Pending`, `Started` or `Unknown`. An authorization stays outstanding
until it is `Completed`, `Failed` with recovery verified, or `Cancelled`
before it started; `startDeadline` passing only stops a start, it never
releases an authorization whose outcome is unknown. Losing the fleet tool
pauses new activation; recovery under an existing authorization
continues.

## Health observation

| Evidence                                                  | Owner                                                     | Rule                                                                                                     |
| --------------------------------------------------------- | --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Runtime config matches the revision; static routes in FIB | agent                                                     | Required for `Programmed=True`.                                                                          |
| Required sessions Established                             | agent                                                     | Required peers come from the rollout policy; optional and maintenance-disabled peers are listed there.   |
| Receiver-side routes and attributes                       | controller, through `FabricQuery` on other routers        | Each origination the revision adds or keeps must be seen with its expected communities at the observers. |
| Forwarding probes                                         | controller, through `FabricQuery` ping from other routers | Probes come from at least one other node; the changed router is never its own only witness.              |
| Agent heartbeat                                           | controller                                                | Stale after `heartbeatTimeout` (default 60s); parent `Ready` becomes `Unknown`.                          |

Missing, stale or failed-to-run evidence makes the check `Unknown` and
pauses promotion. A confirmed application failure (runtime mismatch, a
required session down only on this router, a missing origination at all
observers) triggers recovery to the authorized target. A failure that
also affects routers this activation did not touch is classified as
remote and pauses without rollback.

## Source modes

The agent's `--config-source` is `ConfigMap`, `Shadow` or `Managed`.
`ConfigMap` is today's behavior. `Shadow` runs the ConfigMap writer and,
separately, stages and validates the node's typed candidate, reporting
the diff in deployment status without writing FRR. `Managed` reads the
per-node owner from `FabricRouterDeployment.spec.source`
(`ConfigMap`, `Shadow` or `CRD`) and journals each change. Once the
journal records `CRD`, a missing or invalid deployment keeps the
checkpointed configuration and reports an error; it never falls back to a
ConfigMap, including after restart. Handing a node back to `ConfigMap`
needs `spec.source: ConfigMap` and a named ConfigMap generation in
`spec.sourceHandoff`, which the agent verifies before writing.
