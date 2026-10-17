# Operating fabric routing through the API

This guide is for operators who move a fabric router's FRR configuration from its
per-node ConfigMap to the typed `galactic.datumapis.com` API. It covers what to
install, how a node moves between configuration sources, how releases promote
revisions, and how to recover when something goes wrong.

Every step here is opt-in. A cluster that installs none of it keeps applying each
node's `fabric-router.<node>` ConfigMap exactly as before.

## The pieces

| Piece                 | Where                                                | What it does                                                                                                                                                                         |
| --------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| CRDs                  | `config/crd`                                         | `BGPRouter` and the objects it reads, plus `FabricRouterRevision`, `FabricRouterDeployment`, `FabricReleaseAuthorization` and `FabricRolloutPolicy`. Needs Kubernetes 1.32 or later. |
| Revision compiler     | `config/fabric-router-controller` and its `base/`    | `fabric-router-controller run` compiles every fabric-class `BGPRouter` into immutable revisions and reports the result on the router. It writes no FRR.                              |
| Rollout manager       | `config/fabric-router-controller/components/rollout` | Adds `--rollout`: one `FabricRouterDeployment` per compiled router, and the controller that runs release authorizations.                                                             |
| Node agent activation | `config/fabric-router/components/activation`         | `fabric-config-agent` acts on its node's deployment: stages candidates, and on the CRD source activates the active revision. Adds a host state directory and `/etc/machine-id`.      |

Install them in that order. Each one is safe on its own. Node agent
activation needs `/etc/machine-id` on every fabric router host, and adding it
changes the pod template, so every fabric-router pod restarts and FRR with it:
roll it out like a routing change, one canary node first. Without the rollout
manager no deployment exists. Without node activation, a deployment changes
nothing on the node.

## Configuration sources

A node's `FabricRouterDeployment` has `spec.source`:

| Source                | Who writes FRR               | What the agent reports                                                                             |
| --------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------- |
| `ConfigMap` (default) | The ConfigMap path, as today | Nothing beyond the heartbeat                                                                       |
| `Shadow`              | The ConfigMap path           | The candidate revision, validated and diffed against the running configuration, in `status.staged` |
| `CRD`                 | The activation path only     | Every epoch's outcome in `status.epochs`, the committed revision in `status.applied*`              |

One lock file in the pod, `/run/frr/fabric-agent.lock`, serializes every writer, so
the two paths never touch FRR at the same time.

### Enrolling a node

1. Move the deployment to `Shadow`, and watch `status.staged` and the `Staged`
   condition. A `NoChange` class with no added or removed lines means the typed
   API reproduces the node's configuration.
2. Move it to `CRD`. Until a release promotes a revision the node keeps running
   what it runs, and a restarted pod still starts from its ConfigMap.
3. Create a release authorization for it (see below).

### Handing a node back to its ConfigMap

A node leaves `CRD` only for `ConfigMap`, and only with `spec.sourceHandoff`
naming the node's ConfigMap by UID and `resourceVersion`. The agent checks both
against the live ConfigMap before it switches, then applies that ConfigMap even
if it did not change. Until the check passes, the deployment reports `Accepted`
False with reason `HandoffPending` and the node stays on `CRD`.

## Releases

A `FabricReleaseAuthorization` names the deployments, by name and UID, and the
revision and digest each may activate. It is immutable. The rollout manager:

1. Starts it once no earlier release in its routing domain is outstanding. It
   cancels it if a later fleet sequence already started, its start deadline
   passes, or a target cannot be promoted (wrong UID, not on `CRD`, suspended,
   retired, wrong digest, or originating a prefix revoked on the deployment).
2. Promotes targets one epoch at a time, at most `maxUnavailable` at once per
   failure domain (the Node label `failureDomainLabel`, by default
   `topology.kubernetes.io/zone`). Every deployment still activating counts,
   whichever release promoted it.
3. Completes when every target commits, fails (and promotes nothing more) when
   one fails, and goes `Unknown` while a promoted router stops reporting.

An `EmergencyWithdrawal` release names the prefixes it withdraws, may start
beside an outstanding release, and adds those prefixes to the deployment's
revoked prefixes, so no later release or recovery brings them back.

A failed release keeps blocking its routing domain until every failed router
reports `Recovered` on its recovery target. A router with no eligible recovery
never will. Once an operator has confirmed the routers are safe, set the
annotation `galactic.datumapis.com/recovery-verified-by: <who>` on the release to
release the domain.

A failed release does not roll back routers it already committed. Roll forward
with a new release.

## Recovery and boot

Each epoch carries a recovery target, the last committed revision, and the
prefixes and credentials no recovery may use. When an activation fails (the
reload fails, the running configuration differs, or a required peer or static
route stays down through the stabilization window), the agent restores the
recovery target if it is still allowed, and reports `Recovered`. Otherwise it
reports `Degraded` with reason `NoEligibleRecovery`.

The committed or recovered configuration is checkpointed in the host state
directory. A pod that restarts without the API restores the checkpoint while
its boot authorization (`offlineBootSeconds`) lasts, unless a later revocation
or retirement forbids it. With the API it restores the checkpoint regardless of
that lifetime, or starts from the active revision when it has none.

## Moving a router to another node

A deployment's target changes only with `spec.fence` naming the node being
left, after that node has been cut off from the fabric (for example its switch
ports shut down). The rollout manager never moves a deployment: when a
`BGPRouter` is retargeted it raises a `DeploymentMismatch` warning and waits.

## When the agent refuses to act

| Condition                                                             | Meaning                                                                                      | What to do                                                                                                                                             |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `RecoveryConflict`, journal bound to another deployment               | The deployment was deleted and recreated                                                     | Set `spec.rebind` naming the old deployment UID, after confirming the old one is gone                                                                  |
| `RecoveryConflict`, state belongs to another Node, cluster or machine | The host state directory came from elsewhere, or the Node was recreated                      | Remove `/var/lib/fabric-router/agent` on the host and restart the pod. Its replay protection starts over, so check no older promotion is pending first |
| A pod held in Init on the CRD source                                  | Nothing may start yet: the router is retired, its epoch failed, or the journal is unreadable | Promote a new revision, hand the node back to its ConfigMap, or repair the state directory                                                             |

## Ports

| Component                  | Port | Purpose       |
| -------------------------- | ---- | ------------- |
| `fabric-router-controller` | 9185 | Metrics       |
| `fabric-router-controller` | 8081 | Health probes |
