# Fabric routing through Kubernetes APIs

The fabric underlay (FRR in each `fabric-router` pod) is configured today
by per-node `frr.conf` ConfigMaps that infra renders from host variables.
This work replaces that with typed `galactic.datumapis.com/v1alpha1`
routing resources, a cell-local compiler and rollout manager, and an agent
that applies immutable revisions under an activation journal and a
recovery checkpoint. FRR stays the routing engine.

```text
BGPRouterClass -> FRRRouterParameters
BGPRouter (Node, class, plane Underlay)
  BGPPeer -> BGPPeerProfile -> BGPPolicy -> BGPPrefixList / BGPCommunitySet
  BGPStaticRoute
  BGPAdvertisement (network / aggregate / redistribute) -> BGPPolicy
        |
fabric-router-controller: resolve -> compile -> FabricRouterRevision
                          rollout  -> FabricRouterDeployment (epoch, authorization)
        |
fabric-config-agent: stage -> journal -> frr-reload -> observe -> checkpoint
```

These documents are the contract for work in progress. Where they name a
kind, field, command or package that does not exist yet, they describe the
target that the implementing change adds.

| Document                                         | Contents                                                                                                                                                         |
| ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [conformance.md](conformance.md)                 | Every FRR construct in the 19 rendered configurations and the typed field that produces it                                                                       |
| [contracts.md](contracts.md)                     | Revisions, activation identity, journal, checkpoint, Talos storage, credentials, recovery eligibility, emergency withdrawal, fleet release, health, source modes |
| [ownership-inventory.md](ownership-inventory.md) | Every consumer and producer of the BGP kinds and its class-isolation change                                                                                      |
| [frr-k8s-evaluation.md](frr-k8s-evaluation.md)   | Why FRR-K8s is not the backend                                                                                                                                   |

## Resources

| Kind                         | Scope                   | Written by                             | Status                                                                                                                                                   |
| ---------------------------- | ----------------------- | -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BGPRouterClass`             | Cluster                 | platform admins                        | new                                                                                                                                                      |
| `FRRRouterParameters`        | Cluster, immutable spec | platform admins                        | new                                                                                                                                                      |
| `BGPRouter`                  | Namespace               | operators (Git)                        | to extend: `routerClassName`, `plane`, `lifecycle`, `frr.retain`                                                                                         |
| `BGPPeerProfile`             | Namespace               | network operators                      | new                                                                                                                                                      |
| `BGPPeer`                    | Namespace               | operators, topology controller         | to extend: `peerProfileRef`, `transport`, `familySettings`                                                                                               |
| `BGPPolicy`                  | Namespace               | network policy owners                  | to extend: optional target and direction, `defaultAction`, term `description`, set references, interface match, community operations, `frr.routeMapName` |
| `BGPPrefixList`              | Namespace               | network policy owners                  | to fix: family-aware `ge`/`le` to 128, `int64` sequence; to extend: `frr.name`                                                                           |
| `BGPCommunitySet`            | Namespace               | network policy owners                  | to extend: `frr.name`                                                                                                                                    |
| `BGPStaticRoute`             | Namespace               | network operators                      | new                                                                                                                                                      |
| `BGPAdvertisement`           | Namespace               | operators, authorized controllers      | to extend: `aggregation`                                                                                                                                 |
| `FabricRouterRevision`       | Namespace, immutable    | compiler                               | new                                                                                                                                                      |
| `FabricRouterDeployment`     | Namespace               | rollout manager (spec), agent (status) | new                                                                                                                                                      |
| `FabricReleaseAuthorization` | Namespace               | fleet release tool                     | new                                                                                                                                                      |
| `FabricRolloutPolicy`        | Namespace               | network operators                      | new                                                                                                                                                      |
| `FabricTopology`             | Namespace               | network operators                      | new, milestone 7                                                                                                                                         |

Everything lives in `galactic-system` initially. The compiler enforces one
fabric router per Node and one listener per Node across namespaces.

`BGPRouter.spec.lifecycle` is `Active` (default), `Draining` (the compiler
adds graceful-shutdown to every export and suppresses new origination, and
the rollout manager waits for alternative paths) or `Decommissioning`
(sessions and origination are withdrawn, then the agent removes owned
routes and acknowledges; a finalizer holds the router until it does).

## Milestones

| Milestone | Scope                                                                           |
| --------- | ------------------------------------------------------------------------------- |
| 0         | This contract set                                                               |
| 1         | API extensions and fixes, class isolation of every consumer                     |
| 2         | Compiler, revisions, preview and semantic diff, shadow mode, 19-router parity   |
| 3         | Agent activation, journal, checkpoint, recovery, rollout, fleet release, health |
| 4         | Staging cutover (operator-run)                                                  |
| 5         | Production cutover (operator-run)                                               |
| 6         | ConfigMap removal                                                               |
| 7         | Topology generation, inventory/IPAM and service integration                     |

## Decisions

These close the plan's "decisions to close before implementation".

1. **API-group migration and consumer upgrade.** Migration is a separate,
   per-cell prerequisite verified before fabric activation (infra already
   carries staging migration wiring). Class isolation ships in its own
   Galactic release; fabric objects are applied only to cells running it.
   Ownership is taken from the code
   ([ownership-inventory.md](ownership-inventory.md)): the Galactic cell
   controller projects BGP status only; NSO owns attachments.
2. **FRR-K8s.** Not adopted ([frr-k8s-evaluation.md](frr-k8s-evaluation.md)).
3. **Checkpoint storage and machine identity.** hostPath
   `/var/lib/galactic/fabric-router`, bound to `/etc/machine-id`, Node UID,
   cluster ID and a storage nonce; separate boot and runtime authorization
   ([contracts.md](contracts.md#checkpoint-storage-and-machine-binding-on-talos)).
4. **Transport endpoints.** Explicit per peer in the first phase, as today.
   Topology generation consumes endpoint records whose source is named in
   the topology; it never infers them from Node addresses.
5. **Budgets.** `FabricRolloutPolicy` carries stabilization windows,
   deadlines, required peers and probes; numerical values come from
   staging measurements (gate below).
6. **Fleet release authorization.** `FabricReleaseAuthorization` objects,
   at most one outstanding per routing domain, issued across cells by
   `fabric-router-controller release`.
7. **Credentials.** Immutable versioned Secrets; digests only in
   revisions; offline restart of authenticated sessions unsupported until
   an encrypted local store is approved.
8. **Emergency withdrawal and health.** Restricted revisions through the
   same writer; observers via `FabricQuery` from other routers; missing
   evidence pauses, confirmed failure recovers.
9. **Entry point.** `cmd/fabric-router-controller`, packages under
   `internal/fabric/routing/`, its own ServiceAccount and lease.
   `galactic-controller --role=fabric` is unchanged. Subcommands: `run`
   (controller), `preview` and `diff` (offline compile and semantic/FRR
   diff), `release` (fleet authorization), `withdraw` (emergency
   withdrawal), `rebind` (resolve a recovery conflict), `suspend` and
   `resume` (audited reconciliation suspension), `handoff` (per-node source
   ownership).

## External gates

These need facts or authority this repository cannot supply. Source work
proceeds; activation in a cell waits on them.

| Gate                                                                                                                             | Needed before                                 | Evidence                                               |
| -------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | ------------------------------------------------------ |
| Per-cell API-group migration complete (CRDs, RBAC, webhooks, NSO version, NAD ownership, new-group interface/claim `Programmed`) | fabric objects in that cell                   | the migration guide's checks, recorded per cell        |
| Class-aware Galactic release running in the cell                                                                                 | fabric objects in that cell                   | image digests of every consumer                        |
| Talos keeps `/etc/machine-id` stable across reboot and upgrade, and `/var/lib` survives both                                     | relying on the checkpoint offline             | lab reboot/upgrade test on a Talos node                |
| Measured convergence, loss and stabilization budgets                                                                             | staging cutover                               | baseline from staging under the current ConfigMap path |
| Deployed FRR versions per node                                                                                                   | first activation                              | `vtysh -c 'show version'` inventory                    |
| Encrypted local credential store                                                                                                 | authenticated peers surviving offline restart | security review                                        |
| Live staging and production cutover                                                                                              | milestones 4–6                                | operator authorization                                 |
