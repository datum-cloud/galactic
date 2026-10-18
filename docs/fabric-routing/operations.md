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

## Commands

`fabric-router-controller` carries the operator workflows. Each writes only the
API objects the rollout manager and node agents act on, through the API, so the
CRDs' admission rules hold every write to the activation contract. None writes
FRR or a node's status. They use the current kubeconfig; `-n` sets the
namespace, `galactic-system` by default.

| Command                                                     | What it does                                                                                                                                                                                                           |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `status`                                                    | One line per router: node, source, epoch, active and applied revision, waiting candidate, conditions that need attention, last report                                                                                  |
| `source DEPLOYMENT Shadow\|CRD\|ConfigMap`                  | Moves a node's source. Leaving CRD names the node's ConfigMap, as it is now, in the handoff the agent checks. Running it again before the agent hands the node back names the ConfigMap as it is then                  |
| `release create NAME --domain D --sequence N [DEPLOYMENT…]` | Authorizes promoting the named deployments, or every changed one on CRD, to their candidates. A deployment the rollout manager would refuse is an error when named and left out otherwise. `--dry-run` prints it first |
| `release create … --withdraw PREFIX`                        | The same as an emergency withdrawal of those prefixes, which no later release or recovery restores                                                                                                                     |
| `release create … --retire DEPLOYMENT…`                     | Decommissions the named routers with this last promotion. It cannot be undone, so it never applies to the whole fleet                                                                                                  |
| `release status NAME`                                       | The release's phase and where each router stands                                                                                                                                                                       |
| `release confirm-recovery NAME --by WHO`                    | Releases a failed release's routing domain once an operator confirmed its routers are safe                                                                                                                             |
| `suspend DEPLOYMENT`, `resume DEPLOYMENT`                   | Stops and allows promotion; the router keeps running what it runs                                                                                                                                                      |
| `rebind DEPLOYMENT --from-uid UID --by WHO`                 | Lets a recreated or restored deployment take over its node's journal                                                                                                                                                   |
| `move DEPLOYMENT NODE --fenced-by WHO --method HOW`         | Retargets a router once the node it leaves is fenced                                                                                                                                                                   |
| `import`, `preview`, `diff`                                 | Turn a rendered `frr.conf` into typed resources, show what resources compile to, and compare that with a running configuration                                                                                         |

## Configuration sources

A node's `FabricRouterDeployment` has `spec.source`:

| Source                | Who writes FRR               | What the agent reports                                                                             |
| --------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------- |
| `ConfigMap` (default) | The ConfigMap path, as today | Nothing beyond the heartbeat                                                                       |
| `Shadow`              | The ConfigMap path           | The candidate revision, validated and diffed against the running configuration, in `status.staged` |
| `CRD`                 | The activation path only     | Every epoch's outcome in `status.epochs`, the committed revision in `status.applied*`              |

One lock file in the pod, `/run/frr/fabric-agent.lock`, serializes every writer, so
the two paths never touch FRR at the same time.

Only `Shadow` and `CRD` dry-run the candidate. A node on its ConfigMap never
runs `frr-reload.py --test` for a candidate, even though the rollout manager
names one on every deployment.

Every fabric-router pod shares one ServiceAccount, so an admission policy, not
RBAC, keeps a node from reporting for another: the agent may write only the
status of the deployment targeting the Node its token is bound to, by name and
UID.

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

## Metrics and alerts

`config/monitoring` scrapes `fabric-router-controller` on port `metrics` (9185)
as `job="fabric-router-controller"`, and each node's `fabric-config-agent` on
port `agent-metrics` (9343) as `job="fabric-config-agent"`. The
`fabric-routing` rule group in its PrometheusRule alerts on both.

### Fleet state, from the controller

The leader exports the fleet as it stands in its cache, at every scrape; the
standby replica exports none of it. Deployments and releases need `--rollout`.
Every deployment series carries `namespace`, `deployment` and `node`. Revision
names are never labels.

| Metric                                                                       | Labels                                                      | Meaning                                                                                          |
| ---------------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `galactic_fabric_routing_deployment_info`                                    | `source`, `effective_source`                                | `1` per deployment: the source its spec asks for, and the one the agent reports honouring        |
| `galactic_fabric_routing_deployment_activation_epoch`                        |                                                             | `spec.activationEpoch`, the newest promotion                                                     |
| `galactic_fabric_routing_deployment_applied_epoch`                           |                                                             | `status.appliedEpoch`, the last epoch the agent committed                                        |
| `galactic_fabric_routing_deployment_last_epoch`                              | `stage`                                                     | The newest journaled epoch, labelled with the stage it reached                                   |
| `galactic_fabric_routing_deployment_heartbeat_timestamp_seconds`             |                                                             | The agent's last report. Absent until it first reports                                           |
| `galactic_fabric_routing_deployment_boot_authorized_until_timestamp_seconds` |                                                             | When the checkpoint stops being restorable at boot without the API                               |
| `galactic_fabric_routing_deployment_condition`                               | `type`, `status`, `reason`                                  | `1` per condition the agent reports                                                              |
| `galactic_fabric_routing_deployment_staged`                                  | `class`                                                     | `1` while a validated candidate is staged, labelled with what applying it disturbs               |
| `galactic_fabric_routing_deployment_staged_lines`                            | `change` (`added`, `removed`)                               | Lines the staged candidate adds or removes                                                       |
| `galactic_fabric_routing_deployment_candidate_differs`                       |                                                             | `1` when the candidate is not the active revision, so a release would change the router          |
| `galactic_fabric_routing_release_outstanding`                                | `namespace`, `release`, `routing_domain`, `type`, `phase`   | `1` per release still blocking its domain: Pending, Started, Unknown, or Failed without recovery |
| `galactic_fabric_routing_releases`                                           | `namespace`, `routing_domain`, `phase`, `recovery_verified` | Every release, counted by phase                                                                  |
| `galactic_fabric_routing_router_accepted`                                    | `namespace`, `router`, `node`, `reason`                     | `1` when a fabric router's inputs compiled, `0` when the controller refused them                 |

### Activation, from the node agent

Served beside the next-hop check's metrics, on the node's port 9343.

| Metric                                      | Type      | Labels    | Meaning                                                                                                                                                  |
| ------------------------------------------- | --------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fabric_router_activations_total`           | counter   | `outcome` | Epochs that ended `committed`, `recovered` or `degraded`, were `refused`, or stopped on an `error` the agent retries. Each epoch counts once per outcome |
| `fabric_router_activation_duration_seconds` | histogram | `outcome` | Time to commit, recover or degrade an activation, stabilization window included                                                                          |
| `fabric_router_staging_runs_total`          | counter   | `result`  | Candidates validated and diffed: `staged`, `rejected`, `revision_not_found`. A rejected candidate is retried every sync                                  |
| `fabric_router_writer_lock_wait_seconds`    | histogram | `writer`  | Time each writer waited for `/run/frr/fabric-agent.lock`: `configmap`, `deployment`, `activation`, `nexthop`                                             |
| `fabric_router_boot_source`                 | gauge     | `source`  | `1` for what FRR started from: `configmap`, `checkpoint_offline`, `checkpoint_online` or `active_revision`                                               |

`refused` is a promotion the agent will never activate: its release
authorization does not cover it, or the epoch is stale, the digest differs, or
the journal is bound elsewhere. The `frr-init` container chooses the boot
source but serves no metrics, so it records its choice in
`/run/frr/fabric-boot.json`, which lasts as long as the pod, and the watch
container exports it.

### Alerts

None fires merely because routing does not go through the API: every one
reads a deployment, a release or a fabric-class router, and a node on its
ConfigMap is held to nothing but its compile result.

| Alert                               | Fires when                                                               | For | Severity |
| ----------------------------------- | ------------------------------------------------------------------------ | --- | -------- |
| `FabricRoutingNoEligibleRecovery`   | `Degraded` with reason `NoEligibleRecovery`                              | 5m  | critical |
| `FabricRoutingDeploymentDegraded`   | `Degraded` for any other reason than that or `Recovered`                 | 15m | warning  |
| `FabricRoutingRecoveryConflict`     | `RecoveryConflict` True                                                  | 10m | warning  |
| `FabricRoutingAgentHeartbeatStale`  | on Shadow or CRD, by spec or as reported, and no report for 5m, or never | 5m  | warning  |
| `FabricRoutingReleaseFailed`        | a failed release still blocks its routing domain                         | 30m | warning  |
| `FabricRoutingReleaseUnknown`       | a release is `Unknown`                                                   | 15m | warning  |
| `FabricRoutingHandoffPending`       | `Accepted` False with reason `HandoffPending`                            | 15m | warning  |
| `FabricRoutingCandidateRejected`    | `Staged` False on a node staging on Shadow or CRD                        | 15m | warning  |
| `FabricRoutingRevisionRefused`      | the controller refuses a fabric router's inputs                          | 15m | warning  |
| `FabricRouterControllerMetricsDown` | a `fabric-router-controller` scrape fails                                | 5m  | warning  |

Each carries a `runbook_url` into infra's galactic runbook, anchored at the
alert's name. The rules aggregate away the exporting pod, so a leader handoff
does not restart their timers. `fabric-router-controller status` shows the
same state one line per router.

## Ports

| Component                  | Port | Purpose              |
| -------------------------- | ---- | -------------------- |
| `fabric-router-controller` | 9185 | Metrics              |
| `fabric-router-controller` | 8081 | Health probes        |
| `fabric-config-agent`      | 9343 | Metrics, on the node |
