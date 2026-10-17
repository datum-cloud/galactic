# BGP resource consumers, producers and the class-isolation change

Every component that reads or writes `BGPRouter`, `BGPPeer`,
`BGPAdvertisement`, `BGPPolicy`, `BGPPrefixList`, `BGPCommunitySet` or
`BGPVRFInstance`, as of Galactic `c245fed5`, and what each must do before
any fabric-class object exists in a cluster. Line references are to that
commit.

## Ownership rule

- A `BGPRouter` with no `spec.routerClassName` is a legacy object, owned by
  the existing Galactic EVPN implementation. Every current consumer keeps
  treating it as it does today.
- A router with a `routerClassName` is owned by the controller its
  `BGPRouterClass` names. The EVPN consumers own a classed router only if
  its class name is in their configured set
  (`GALACTIC_ROUTER_CLASS_NAMES`, empty by default), so they never need to
  read classes. The fabric controller owns routers whose class names
  `controllerName: galactic.datumapis.com/fabric-router`.
- An unknown or missing class is owned by nobody: every consumer ignores
  the router, including on deletion, and writes no status to it.
- An advertisement, peer, policy or VRF instance belongs to its router's
  owner. A consumer that resolves those through a router applies the
  router rule; one that reads advertisements directly resolves
  `spec.routerRef` first.
- `spec.plane: Underlay` requires a class (CEL). Neither the listen port
  (179 underlay, 2179 EVPN) nor a name pattern is an ownership signal.

The class-isolation change adds `api/network/v1alpha1.IsLegacyOwned(router,
classNames)` to implement the rule, and changes every consumer below to call
it. The **Change** columns describe that change; none of it exists before
it.

## Router discovery

| Consumer                                                                                                                                                                              | Today                                                      | Change                                                                                                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `routerNameForNode` (`internal/controller/networkgateway_controller.go:922`), shared by gateway VIP advertisement and NAT `applyShardAdvertisement` (`egressshard_controller.go:538`) | first item from the `targetRef.name` index                 | filter to legacy-owned, then error on more than one match; the caller reports the ambiguity instead of attaching to an arbitrary router |
| `encapSourceFromRouters` (`cmd/galactic-gateway/encapsource.go:107`)                                                                                                                  | all namespaces, checks kind, errors on differing addresses | filter to legacy-owned before the address check                                                                                         |
| `buildBackendSIDIndex` / `resolveUSID` (`internal/controller/usidresolver.go:55,111`)                                                                                                 | every router by name                                       | index only legacy-owned routers; an advertisement on a fabric router never yields a backend SID                                         |
| `resolveVIPBindingVRF` (`servicevipbinding_controller.go:742`)                                                                                                                        | ranges over a Go map; random pick on duplicates            | legacy-owned only, and an error on more than one router for the node                                                                    |
| `ServiceRoutePolicyReconciler.sidResolver` (`serviceroute_controller.go:532`)                                                                                                         | VRF instance → router → target check                       | reject a router that is not legacy-owned                                                                                                |
| `advertisementRequests` (`servicevipbinding_controller.go:862`)                                                                                                                       | router target equals this node                             | also require legacy ownership                                                                                                           |
| `routerLocatorConflict` (`egressshard_controller.go:331`)                                                                                                                             | every router                                               | unchanged: a shard /64 must not collide with any router's locator, whatever its owner                                                   |
| `ResolveNodeSourceAddress` (`internal/ingresssidecar/nodesourceaddress.go:64`)                                                                                                        | first usable match                                         | legacy-owned only; more than one usable match is an error                                                                               |
| `lookupBGPRouter` (`internal/ingresssidecar/gateway.go:138`)                                                                                                                          | errors on 0 or >1                                          | filter to legacy-owned first                                                                                                            |
| `lookupBGPRouter` (`internal/cnibgp/bgp.go:218`)                                                                                                                                      | errors on 0 or >1                                          | filter to legacy-owned first                                                                                                            |
| `nodeLocatorPrefix` (`internal/installer/locatorroute.go:157`)                                                                                                                        | returns on the first match even without a locator          | legacy-owned only; error on more than one                                                                                               |
| `routersForNode` / `routerNamesForNode` (`internal/gc/gc.go:97,115`), `nodeSRv6Identity` (`datapath_repair.go:282`)                                                                   | every match                                                | legacy-owned only, so GC and repair never touch fabric objects                                                                          |
| `nodeForRouter` (`internal/cloud/controller/bgpadvertisement_controller.go:219`)                                                                                                      | router by name                                             | see cell projection                                                                                                                     |
| `sidecarGatewayEndpoints` (`internal/installer/sidecarreturn.go:353`), `sidecarreap.go:196`                                                                                           | compare `routerRef.name` to the node name                  | resolve the router and compare its target, legacy-owned only                                                                            |
| `nodeToRouterRequests` (`internal/controller/node_controller.go:48`), `enqueueRoutersForTarget` (`routing.go:21`), `secretToRouterRequests` (`secret_controller.go:43`)               | enqueue every matching router                              | unchanged; the enqueued router is ignored by the `BGPRouterReconciler` guard below                                                      |
| `deleteRuleAdvertisements` (`networkservice_controller.go:277`)                                                                                                                       | lists advertisements by rule label                         | unchanged; fabric advertisements never carry the gateway's labels                                                                       |

## Reconciliation and status

| Consumer                                                                                        | Change                                                                                              |
| ----------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `BuildDesiredRouter` (`internal/reconcile/reconcile.go:53`)                                     | return nil for a router that is not legacy-owned, alongside the existing target check               |
| `BGPRouterReconciler` (`internal/controller/bgprouter_controller.go:56`)                        | ignore non-legacy routers entirely: no runtime, no hash annotation, no status, no deletion handling |
| Peer, policy, advertisement and VRF-instance status writers (`bgprouter_controller.go:257-529`) | already reached through a legacy router; no change beyond the router guard                          |
| `PeerStateEventEmitter` (`peer_events.go:87`)                                                   | events come from the GoBGP runtime, which never holds a fabric peer                                 |
| Gateway, NAT and VIP-binding watches                                                            | map functions filter the same way, so fabric object churn does not wake them                        |

## Advertisement producers

The CNI (`internal/cnibgp`), gateway, NAT, and ingress sidecar producers
all pick their router through the discovery helpers above, so they attach
only to legacy routers once those helpers are fixed. Nothing in Go creates
peers, policies, prefix lists or community sets. Fabric advertisements are
authored in Git (infra) and, from milestone 7, generated by the topology
controller; they always name a fabric router.

## Cell status projection

`BGPAdvertisementReconciler` (`internal/cloud/controller/bgpadvertisement_controller.go`)
derives a VPC attachment identity from any advertisement whose name splits
into three `-` parts with hex-decodable leading parts, then projects
`Programmed` onto the attachment, its `NetworkInterface` and the claim. A
fabric advertisement can have such a name.

Change: before splitting the name, resolve `spec.routerRef`; if that
router is not legacy-owned, do nothing. The replay path
(`advertisementForInterface`, added in `c19ecf5f`) applies the same filter
to the advertisements it lists from the `metadata.identity` index, so a
fabric advertisement never enters a replay. The new-group attachment guard
(`AttachmentRef.APIGroup` must be the Galactic group) and the
cross-namespace node-qualified replay are unchanged. Tests cover a tenant
advertisement projecting normally and through the group-switch replay, and
fabric advertisements named exactly like tenant ones (in both list orders)
projecting nothing.

## Unconsumed today

`BGPPrefixList` and `BGPCommunitySet` have no Go consumer and no RBAC
grant. Most `BGPPeer`, `BGPAdvertisement` and `BGPPolicy` fields
(`description`, `ebgpMultiHop`, `routeMapIn/Out`, `redistribute`,
`policyRef`, policy prefix and community matches, AS-path and next-hop
sets) are read by nothing. The GoBGP runtime consumes only community
add/remove and local preference from policies, and only `l2vpn`
advertisements. That is why the fabric compiler can define these fields'
semantics without breaking an existing consumer, and why the legacy fields
are rejected on fabric routers rather than reinterpreted.

## RBAC

| Component                                                                                    | Change                                                                                                                                                                                                                    |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic-router`, `galactic-cni`, `galactic-gateway`, `galactic-nat`, `galactic-controller` | none needed: they keep reading routers and advertisements, and the rule needs no class lookup                                                                                                                             |
| `fabric-router-controller` (new)                                                             | read routers, peers, profiles, policies, prefix lists, community sets, static routes, advertisements, classes, parameters, nodes, rollout policies, authorizations; create revisions; write deployments and router status |
| `fabric-config-agent` (extended)                                                             | read its deployment and revisions; write deployment status; read referenced Secrets in `galactic-system`                                                                                                                  |
