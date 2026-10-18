# Operating fabric routing through the API

This guide is for operators who move a fabric router's FRR configuration from its
per-node ConfigMap to the typed `galactic.datumapis.com` API. It covers what to
install, how a node moves between configuration sources, how releases promote
revisions, and how to recover when something goes wrong.

Every step here is opt-in. A cluster that installs none of it keeps applying each
node's `fabric-router.<node>` ConfigMap exactly as before. Once every node runs
from the API, [retiring the ConfigMap path](#retiring-the-configmap-path) stops
the agent reading ConfigMaps at all.

## The pieces

| Piece                 | Where                                                 | What it does                                                                                                                                                                                                                               |
| --------------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| CRDs                  | `config/crd`                                          | `BGPRouter` and the objects it reads, plus `FabricRouterRevision`, `FabricRouterDeployment`, `FabricReleaseAuthorization`, `FabricRolloutPolicy`, `FabricEndpoint` and `FabricTopology`. Needs Kubernetes 1.32 or later.                   |
| Revision compiler     | `config/fabric-router-controller` and its `base/`     | `fabric-router-controller run` compiles every fabric-class `BGPRouter` into immutable revisions and reports the result on the router. It writes no FRR.                                                                                    |
| Rollout manager       | `config/fabric-router-controller/components/rollout`  | Adds `--rollout`: one `FabricRouterDeployment` per compiled router, and the controller that runs release authorizations.                                                                                                                   |
| Node agent activation | `config/fabric-router/components/activation`          | `fabric-config-agent` acts on its node's deployment: stages candidates, and on the CRD source activates the active revision. Adds a host state directory and `/etc/machine-id`.                                                            |
| Topology generator    | `config/fabric-router-controller/components/topology` | Adds `--topology`: generates `BGPPeer`s from `FabricTopology` relationships and `FabricEndpoint` records, with its own ClusterRole for writing peers. Optional; see [Generating peers from a topology](#generating-peers-from-a-topology). |

Install the first four in that order; the topology generator can come at any
point after the compiler. Each one is safe on its own. Node agent
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
| `import`, `preview`, `diff`                                 | Turn a rendered `frr.conf` into typed resources, show what resources or a stored revision (`preview --revision`) compile to, and compare that with a running configuration                                             |

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

| Condition                                                             | Meaning                                                                                      | What to do                                                                                                                                                                                                       |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RecoveryConflict`, journal bound to another deployment               | The deployment was deleted and recreated                                                     | Set `spec.rebind` naming the old deployment UID, after confirming the old one is gone                                                                                                                            |
| `RecoveryConflict`, state belongs to another Node, cluster or machine | The host state directory came from elsewhere, or the Node was recreated                      | Remove `/var/lib/fabric-router/agent` on the host and restart the pod. Its replay protection starts over, so check no older promotion is pending first                                                           |
| A pod held in Init on the CRD source                                  | Nothing may start yet: the router is retired, its epoch failed, or the journal is unreadable | Promote a new revision, hand the node back to its ConfigMap, or repair the state directory. With the ConfigMap path retired a handback is refused: see [A node that lost its state](#a-node-that-lost-its-state) |
| `Accepted` False with reason `ConfigMapRetired`                       | The deployment asks for a source other than CRD on a node whose ConfigMap path is retired    | Move it back to `CRD`, or take [the way back](#the-way-back) first                                                                                                                                               |
| frr-init exits with `the ConfigMap path is retired`                   | The ConfigMap path is retired and the node's journal records the ConfigMap or Shadow source  | Take [the way back](#the-way-back) for the node, which never reached CRD                                                                                                                                         |

## Retiring the ConfigMap path

Once every node runs from the API, the `config/fabric-router/components/configmap-retired`
Component turns the ConfigMap path off. List it after `components/activation`,
which it requires; a build without that, or with the two in the other order,
fails. It sets `FABRIC_CONFIGMAPS=false` on `frr-init` and `config-agent`, and
deletes the `fabric-router-configmaps` Role and RoleBinding, so the agent
neither reads, watches nor raises events on any ConfigMap, the node's own or the
legacy shared `fabric-config`, and could not if it tried. It keeps the events
permission, for the `MappedNextHopReset` events on the agent's own Pod. The
opt-in fabric-api sidecar's `fabric-api` ConfigMap (the cell's site and name)
is not routing configuration and stays.

With it, `frr-init` starts FRR as follows, and never from a ConfigMap:

| The node's journal                                    | `frr-init` starts FRR from                                                                                                                                                                                                                                                                                                   |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| On `CRD`, activated                                   | The checkpoint or the active revision, exactly as with the ConfigMap path on (see [Recovery and boot](#recovery-and-boot)); the active revision needs its release `Started`                                                                                                                                                  |
| On `CRD` with nothing activated, or none (a new node) | The deployment's active revision, once the deployment is on `CRD` and a `Started` release, or one `Unknown` only because this node has not reported yet, authorizes it, and its recovery authorization neither retires the router nor revokes a prefix or credential the revision uses. Until then the pod is held in `Init` |
| On `ConfigMap` or `Shadow`                            | Nothing. `frr-init` exits with `the ConfigMap path is retired`, and the kubelet retries it with backoff                                                                                                                                                                                                                      |

`config-agent` runs only the deployment agent and the next-hop check. A
deployment asking for a source other than `CRD` reports `Accepted` False with
reason `ConfigMapRetired`, and the node stays on `CRD`: no handoff is checked or
made. The `source` command still writes such a move, since it cannot tell the
node is retired; leaving `CRD` still needs the node's ConfigMap, and the command
says so when it is missing.

The Role split ships as separate objects, so a bundle bump that crosses it can
briefly deny ConfigMap reads to a pod that restarts at that moment, before the
new `fabric-router-configmaps` binding lands. That is harmless: `frr-init`
retries until the read succeeds.

### Preconditions

- Every fabric router has a deployment on `CRD`, reported as its effective
  source, with its active revision committed (`fabric-router-controller status`
  shows `Ready` and no `HandoffPending`), and no node's journal records another
  source.
- Every fabric-router pod runs an image whose agent knows `FABRIC_CONFIGMAPS`.
  An older agent ignores it, and once the Role is gone its ConfigMap watch fails.
- Every node's checkpoint and active revision come from the compiler and FRR
  version the image carries: a node restores neither from another, and no
  ConfigMap remains to start from. Keep fabric-router image upgrades out of the
  retirement until it completes, and recompile and promote before one later.
- Recovery is proven on a canary node: a pod restarted with the API reachable
  starts from `checkpoint_online` or `checkpoint_offline`
  (`fabric_router_boot_source`), and one restarted with the API unreachable,
  within `offlineBootSeconds`, from `checkpoint_offline`.

### Procedure

1. Add the Component to the fabric-router overlay, after `components/activation`.
   It changes the pod template, so every fabric-router pod restarts and FRR
   with it: roll it out as a routing change, one canary node first, checking its
   underlay sessions, convergence and boot source, then paced across the rest.
2. Once every pod runs with it, delete each `fabric-router.<node>` ConfigMap
   and the legacy `fabric-config`.
3. Remove what the deployment pipeline still carries for the ConfigMap path:
   - the generators rendering each node's ConfigMap, and anything that depends
     on them being applied first;
   - the DaemonSet patch adding the legacy shared ConfigMap's volume;
   - any ConfigMap permission granted to the `fabric-router` ServiceAccount
     outside this repository;
   - the legacy shared `fabric-config` and whatever renders it, the fallback a
     node with no ConfigMap of its own consulted;
   - committed `frr.conf` files, except as fixtures the compiler is tested
     against (`import`, `diff`).

### Verifying

- RBAC denies the reads:
  `kubectl auth can-i get configmaps -n galactic-system --as system:serviceaccount:galactic-system:fabric-router`
  answers `no`, and so do `list` and `watch`.
- The API audit log shows no ConfigMap request from that ServiceAccount after
  the rollout.
- Every node reports `fabric_router_boot_source` as `checkpoint_offline`,
  `checkpoint_online` or `active_revision`, never `configmap`, and its
  `config-agent` logs `configMaps=false` at start.
- A canary pod restarted with the API unreachable, within `offlineBootSeconds`,
  starts from `checkpoint_offline`, with every ConfigMap deleted.

### A node joining after retirement

A new node has no journal and no ConfigMap, so its pod is held in `Init` until
its deployment's active revision may start:

1. The rollout manager creates its deployment on the `ConfigMap` source; `frr-init`
   logs that it is not on `CRD`.
2. `fabric-router-controller source DEPLOYMENT CRD`, which needs no ConfigMap.
3. `fabric-router-controller release create` naming only that deployment. Once
   the release starts, `frr-init` starts FRR from the active revision, and the
   sidecar activates and commits it. The release is `Unknown` until the node
   first reports, which does not stop it booting.

Its first boot needs the API: the agent reads the Node's UID and the cluster's
before anything may start.

### A node that lost its state

A node whose checkpoint can no longer be restored, because its host lost the
state directory (a reimage, a wiped `/var/lib/fabric-router/agent`) or the
checkpoint is from another compiler or FRR version, starts only from its
deployment's active revision. Once that revision's release has completed, it
authorizes nothing more, and the pod is held in `Init` with the release named.
With the ConfigMap path retired, handing the node back is refused, so:

1. If the host kept its state directory, remove it, so the node starts as a new
   node does: an activated node needs its release `Started`, and a node that
   cannot report makes it `Unknown`. Its replay protection starts over, so check
   no older promotion is pending first.
2. Promote a revision other than the one the deployment's status reports
   committed. A release naming the deployment for that same revision promotes
   nothing, since the rollout manager reads the deployment as running it.
   - After a compiler or FRR upgrade the deployment's candidate is the
     recompiled revision: `fabric-router-controller release create` naming only
     the deployment promotes it, and the node starts from it.
   - Otherwise roll back and forward: write a release by hand (`release create
     --dry-run` prints one to start from) naming only the deployment, with its
     `spec.recovery.targetRevisionRef` revision and that revision's digest, and
     once the node commits it, `release create` naming the deployment promotes
     its candidate, the revision it ran before, again. Each release needs
     `--domain` and a `--sequence` above every earlier release in the domain,
     and is refused for a retired router or a revision that originates a
     revoked prefix. A release does not check revoked credentials; a node
     refuses to start a revision that uses one, so check its Secret
     references first. A deployment with no
     recovery target has committed only one revision; a change to its
     router's resources compiles a new candidate to promote instead.

### The way back

To run a node from its ConfigMap again:

1. Re-create its `fabric-router.<node>` ConfigMap from the revision FRR runs:
   the deployment's committed revision, `status.appliedRevision` at
   `status.appliedEpoch`, with `Ready` True, which means FRR runs it.
   `spec.activeRevisionRef` can name a newer promotion the node has not
   committed. Then:
   - `kubectl get fabricrouterrevision APPLIED_REVISION -n galactic-system -o yaml > rev.yaml`
     and `fabric-router-controller preview --revision rev.yaml > frr.conf`. It
     prints the revision's `frr.conf` only when it matches the digests the
     revision records, and refuses a revision compiled for another compiler or
     FRR version, so run the `fabric-router-controller` build that compiled it.
   - Compare it with what the node runs before going further:
     `kubectl exec POD -c frr -- cat /etc/frr/frr.conf | diff - frr.conf`
     shows nothing, since the agent writes each committed revision there, and
     `kubectl exec POD -c frr -- vtysh -c 'show running-config'` shows the same
     configuration.
   - Create the ConfigMap with the single key `frr.conf`. A retired node runs
     the image's default `daemons` and `vtysh.conf`; any override the node's
     old ConfigMap carried is gone, and comes back only if added again.
2. Remove the Component, a routing change paced like adding it. The Role comes
   back, and every node keeps running from `CRD`.
3. Hand the node back with `fabric-router-controller source DEPLOYMENT ConfigMap`.

## Generating peers from a topology

With `--topology`, `fabric-router-controller` writes a cell's fabric peers
from one `FabricEndpoint` per router per transport network and a
`FabricTopology` saying which records peer: a mesh, route reflection, and
external peers such as transits. Each cell generates only its own routers'
side, from records of every cell, so both ends of a session come from the
same records. The design, including what is not implemented yet, is
[topology.md](topology.md).

Generated peers are ordinary `BGPPeer`s, labelled
`app.kubernetes.io/managed-by: fabric-topology` and controlled by their
topology. They compile into candidates like any other peer, and a node runs
one only once a release promotes it.

### Installing

1. Apply the CRDs, which include `FabricEndpoint` and `FabricTopology`.
2. Add `config/fabric-router-controller/components/topology` to the
   controller's overlay. It adds `--topology` and the
   `fabric-router-controller-topology` ClusterRole, the only grant that lets
   the controller write `BGPPeer`s. It restarts the controller, not FRR.
3. Apply every cell's records, then this cell's topology.

A record looks like this, one per router per transport:

```yaml
apiVersion: galactic.datumapis.com/v1alpha1
kind: FabricEndpoint
metadata:
  name: edge-a-private-mesh
  namespace: galactic-system
  labels:
    fabric.example/role: client
spec:
  routingDomain: fabric
  cell: cell-a
  routerRef:
    name: edge-a
  transport: private-mesh
  asn: 64512
  addresses:
    ipv6: 2001:db8:100::5
  failureDomain: zone-1
```

Records of other cells must be present in this cell too, with the same
content. Nothing in the cluster copies them: infra's per-cell bundles carry
every cell's records.

### Moving from hand-authored or imported peers

The topology never changes or deletes a peer it did not create. Applied next
to the peers it would generate, it reports each one as a conflict and
generates nothing for that session:

1. Apply the records and topology. Check `kubectl get fabrictopology` shows
   the expected `CONFLICTING` count and every record is `Ready`
   (`kubectl get fabricendpoint`).
2. Outside any release, delete one router's conflicting peers; the
   `Conflicts` condition names them. The topology creates its own at once.
3. The router's new candidate renders the same sessions, possibly in another
   order. With the node on `Shadow` or `CRD`, its staged candidate should report
   `NoChange` with no lines added or removed. Release it as usual, or not at all.
4. Repeat for the next router.

Until a router's own peers are back, its candidate lacks those sessions; a
release naming every changed deployment would promote that. Keep step 2 and
the generated peers' appearance between releases.

### Adding a node or a cell

Create the router's `BGPRouter` with the topology's member labels and its
records; for a cell, deliver its records to every cell of the routing domain.
Every member that should peer with it gets a peer, and the new router's peers
are generated in its own cell. Release the changed routers.

### Removing a node or a cell

A session is only released on evidence that an end is out of service, never
because a record or label changed:

1. Retire the router: `fabric-router-controller release create … --retire
   DEPLOYMENT`. Once its node commits that release, the topology releases
   every session toward it in this cell, and its own.
2. Release the other routers' new candidates.
3. Delete its records, from every cell, and its `BGPRouter`. In another cell,
   deleting the record is what releases the sessions toward it.

For a node that will never report, list its router in the topology's
`spec.drain.routers`, or a record in `spec.drain.endpoints`, to release its
sessions without the retirement. The controller never removes an entry:
remove it yourself once the router is gone for good, before a router of the
same name joins.

Deleting a `BGPRouter` releases its sessions at once.

### Deleting a topology

Deleting a `FabricTopology` drops no session. Its finalizer holds it until
the controller has handed every peer it generated to manual control: the
peers keep their spec, lose the topology's controller reference and
generated labels, and are annotated
`galactic.datumapis.com/released-from-fabric-topology`. They then compile as
hand-authored peers. Use the default cascade; `--cascade=foreground` lets
the garbage collector delete peers before the hand-off.

A topology created again reports every such peer as a conflict and adopts
none. To hand a session back to it, delete the released peer outside a
release, as in [moving from hand-authored
peers](#moving-from-hand-authored-or-imported-peers), and the topology
generates its own. With `--topology` off, nothing removes the finalizer: turn
the controller back on, or remove the finalizer by hand, which leaves the
peers to the garbage collector.

### Reading its status

| Condition                           | Meaning                                                                       | What to do                                                                                         |
| ----------------------------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `Accepted` False, `InvalidSelector` | A selector does not parse                                                     | Fix it. Nothing was changed                                                                        |
| `Accepted` False, `TooManySessions` | A member would get more than `maxSessionsPerRouter` peers                     | Narrow the selectors or raise the limit. Nothing was changed                                       |
| `ResolvedRefs` False                | A profile or policy a relationship names does not exist                       | Create it. Nothing was changed                                                                     |
| `Conflicts` True                    | A peer the topology did not create, or a retained one, blocks a session       | Delete the named peer if the topology should own the session                                       |
| `Ready` False, `MissingEndpoints`   | A member has no usable record, or an external peer's source record is missing | Write the record, or check its own `Ready`                                                         |
| `status.retained` above zero        | Sessions kept until an end is retired, deleted or drained                     | Expected while a router is leaving; otherwise check for a member that left its selector by mistake |

On a record, `Ready` False with `RouterNotFound` or `ASNMismatch` means the
record of this cell disagrees with its `BGPRouter`, and `Conflict` True means
an older record holds its identity or an address. Either way topologies do not
peer over it, and keep the sessions they already generated toward it.

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

| Metric                                                                       | Labels                                                      | Meaning                                                                                                                 |
| ---------------------------------------------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `galactic_fabric_routing_deployment_info`                                    | `source`, `effective_source`                                | `1` per deployment: the source its spec asks for, and the one the agent reports honouring                               |
| `galactic_fabric_routing_deployment_activation_epoch`                        |                                                             | `spec.activationEpoch`, the newest promotion                                                                            |
| `galactic_fabric_routing_deployment_applied_epoch`                           |                                                             | `status.appliedEpoch`, the last epoch the agent committed                                                               |
| `galactic_fabric_routing_deployment_last_epoch`                              | `stage`                                                     | The newest journaled epoch, labelled with the stage it reached                                                          |
| `galactic_fabric_routing_deployment_heartbeat_timestamp_seconds`             |                                                             | The agent's last report. Absent until it first reports                                                                  |
| `galactic_fabric_routing_deployment_boot_authorized_until_timestamp_seconds` |                                                             | When the checkpoint stops being restorable at boot without the API                                                      |
| `galactic_fabric_routing_deployment_condition`                               | `type`, `status`, `reason`                                  | `1` per condition the agent reports                                                                                     |
| `galactic_fabric_routing_deployment_staged`                                  | `class`                                                     | `1` while a validated candidate is staged, labelled with what applying it disturbs                                      |
| `galactic_fabric_routing_deployment_staged_lines`                            | `change` (`added`, `removed`)                               | Lines the staged candidate adds or removes                                                                              |
| `galactic_fabric_routing_deployment_candidate_differs`                       |                                                             | `1` when the candidate is not the active revision, so a release would change the router                                 |
| `galactic_fabric_routing_release_outstanding`                                | `namespace`, `release`, `routing_domain`, `type`, `phase`   | `1` per release still blocking its domain: Pending, Started, Unknown, or Failed without recovery                        |
| `galactic_fabric_routing_releases`                                           | `namespace`, `routing_domain`, `phase`, `recovery_verified` | Every release, counted by phase                                                                                         |
| `galactic_fabric_routing_router_accepted`                                    | `namespace`, `router`, `node`, `reason`                     | `1` when a fabric router's inputs compiled, `0` when the controller refused them                                        |
| `galactic_fabric_routing_collect_success`                                    | `kind`                                                      | `1` when the scrape read every object of the kind from the cache, `0` when it failed and that kind's series are missing |

### Activation, from the node agent

Served beside the next-hop check's metrics, on the node's port 9343.

| Metric                                      | Type      | Labels             | Meaning                                                                                                                                                                          |
| ------------------------------------------- | --------- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fabric_router_activations_total`           | counter   | `outcome`          | Activations by outcome. `committed`, `recovered`, `degraded` and `refused` count each epoch once per agent process; `error` counts every failed attempt                          |
| `fabric_router_activation_duration_seconds` | histogram | `outcome`          | Time to commit, recover or degrade an activation, stabilization window included                                                                                                  |
| `fabric_router_staging_runs_total`          | counter   | `result`           | Candidates validated and diffed: `staged`, `rejected`, `revision_not_found`. A rejected candidate is retried every sync                                                          |
| `fabric_router_writer_lock_wait_seconds`    | histogram | `writer`, `result` | Time each writer waited for `/run/frr/fabric-agent.lock`, by writer (`configmap`, `deployment`, `activation`, `nexthop`) and how the wait ended (`acquired`, `timeout`, `error`) |
| `fabric_router_boot_source`                 | gauge     | `source`           | `1` for what FRR started from: `configmap`, `checkpoint_offline`, `checkpoint_online` or `active_revision`                                                                       |

`refused` is a promotion the agent will never activate: its release
authorization does not cover it, or the epoch is stale, the digest differs, or
the journal is bound elsewhere. The agent remembers what it counted only while
it runs, so after a restart it can count an epoch it meets again once more;
`error` counts every attempt, so its rate is the retry rate. The lock is
polled every 100ms, so waits shorter than that are not resolved.

The `frr-init` container chooses the boot source but serves no metrics, so it
records its choice in `/run/frr/fabric-boot.json`, which lasts as long as the
pod, and the watch container exports it. Init removes an earlier init's record
before it installs anything, so a record it fails to write leaves no
`fabric_router_boot_source` series rather than a stale one.

### Alerts

None fires merely because routing does not go through the API: apart from the
controller's own scrape and cache reads, which succeed with nothing to read,
every one reads a deployment, a release or a fabric-class router, and a node
on its ConfigMap is held to nothing but its compile result.

| Alert                               | Fires when                                                                             | For | Severity |
| ----------------------------------- | -------------------------------------------------------------------------------------- | --- | -------- |
| `FabricRoutingNoEligibleRecovery`   | `Degraded` with reason `NoEligibleRecovery`                                            | 5m  | critical |
| `FabricRoutingDeploymentDegraded`   | `Degraded` for any other reason than that or `Recovered`                               | 15m | warning  |
| `FabricRoutingRecoveryConflict`     | `RecoveryConflict` True                                                                | 10m | warning  |
| `FabricRoutingAgentHeartbeatStale`  | on Shadow or CRD, by spec or as reported, and no report for 5m, or never               | 5m  | warning  |
| `FabricRoutingReleaseFailed`        | a failed release still blocks its routing domain                                       | 30m | warning  |
| `FabricRoutingReleaseUnknown`       | a release is `Unknown`                                                                 | 15m | warning  |
| `FabricRoutingHandoffPending`       | `Accepted` False with reason `HandoffPending` or `ConfigMapRetired`                    | 15m | warning  |
| `FabricRoutingCandidateRejected`    | `Staged` False on a node staging on Shadow or CRD                                      | 15m | warning  |
| `FabricRoutingPromotionRefused`     | `Accepted` False with reason `PromotionRefused`, `NotAuthorized` or `RevisionNotFound` | 15m | warning  |
| `FabricRoutingRevisionRefused`      | the controller refuses a fabric router's inputs                                        | 15m | warning  |
| `FabricRoutingCollectFailing`       | the leader cannot read a kind from its cache, so its series are missing                | 10m | warning  |
| `FabricRouterControllerMetricsDown` | a `fabric-router-controller` scrape fails                                              | 5m  | warning  |

Each carries a `runbook_url` into infra's galactic runbook, anchored at the
alert's name. Only the leader exports the fleet, and a leader change leaves
its series absent for up to about a minute, so the rules read each series'
last value over 2 minutes and aggregate away only `pod` and `instance`, the
labels that differ between the two replicas: a leader change neither resets a
pending alert nor resolves a firing one, and an alert on a deleted deployment
or a finished release clears up to 2 minutes late. Every other label is kept,
so where the rules run centrally over many clusters an alert carries its
`cluster` label, and one cluster's failure is never hidden by another's
healthy series. `fabric-router-controller status` shows the same state one
line per router.

## Ports

| Component                  | Port | Purpose              |
| -------------------------- | ---- | -------------------- |
| `fabric-router-controller` | 9185 | Metrics              |
| `fabric-router-controller` | 8081 | Health probes        |
| `fabric-config-agent`      | 9343 | Metrics, on the node |
