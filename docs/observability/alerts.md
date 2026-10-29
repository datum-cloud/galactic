# Shipped alerts

See [scraping and component ports](README.md#where-the-metrics-come-from) and [shipped alerts](alerts.md).

`config/monitoring/prometheusrule.yaml` (the `galactic-bgp` PrometheusRule,
unit-tested with `task test:alerts`) covers routing, fabric routing through
the API, the NAT session table
and ports, the egress shards' state, drop ratio and uplinks, the compute
nodes' egress shard groups, the fabric-api looking glass, the Galactic
Edge foundation and the MASQUE connector's provider pods. Every alert
carries `service: galactic`, `team: connect` and a `runbook_url`.

| Alert                                  | Fires when                                                                  | For   | Severity   |
| -------------------------------------- | --------------------------------------------------------------------------- | ----- | ---------- |
| FabricBGPSessionDown                   | `frr_bgp_peer_state == 0`                                                   | 5m    | critical   |
| FabricBGPSessionAdminDown              | `frr_bgp_peer_state == 2`                                                   | 1h    | warning    |
| FabricBGPSessionFlapping               | `resets(frr_bgp_peer_uptime_seconds[30m]) >= 3`                             | 0     | warning    |
| FabricBGPPrefixesDropped               | received prefixes under half of an hour ago, session up                     | 15m   | warning    |
| FabricRouterExporterCollectorFailing   | `frr_collector_up == 0`                                                     | 10m   | warning    |
| FabricRouterMetricsDown                | `fabric-router` scrape down                                                 | 5m    | warning    |
| FabricBGPMappedNextHop                 | `fabric_router_bgp_mapped_nexthop == 1`                                     | 15m   | critical   |
| FabricBGPRoutesNotInstalled            | `fabric_router_bgp_uninstalled_routes > 0`                                  | 10m   | warning    |
| FabricConfigAgentMetricsDown           | `fabric-config-agent` scrape down                                           | 5m    | warning    |
| FabricRoutingNoEligibleRecovery        | `Degraded` with reason `NoEligibleRecovery`                                 | 5m    | critical   |
| FabricRoutingDeploymentDegraded        | `Degraded` for another reason than that or `Recovered`                      | 15m   | warning    |
| FabricRoutingRecoveryConflict          | `RecoveryConflict` True                                                     | 10m   | warning    |
| FabricRoutingAgentHeartbeatStale       | on Shadow or CRD, no agent report for 5m, or never                          | 5m    | warning    |
| FabricRoutingReleaseFailed             | a failed release still blocks its routing domain                            | 30m   | warning    |
| FabricRoutingReleaseUnknown            | a release is `Unknown`                                                      | 15m   | warning    |
| FabricRoutingHandoffPending            | `Accepted` False with reason `HandoffPending` or `ConfigMapRetired`         | 15m   | warning    |
| FabricRoutingCandidateRejected         | `Staged` False on a node staging on Shadow or CRD                           | 15m   | warning    |
| FabricRoutingPromotionRefused          | `Accepted` False: `PromotionRefused`, `NotAuthorized`, `RevisionNotFound`   | 15m   | warning    |
| FabricRoutingRevisionRefused           | the controller refuses a fabric router's inputs                             | 15m   | warning    |
| FabricRoutingCollectFailing            | the leader cannot read a kind from its cache                                | 10m   | warning    |
| FabricRouterControllerMetricsDown      | `fabric-router-controller` scrape down                                      | 5m    | warning    |
| GalacticRouterBMPStationDown           | `galactic_router_bmp_station_up == 0`                                       | 10m   | warning    |
| GalacticRouterRoutesNotInstalled       | `galactic_router_route_install_failing > 0`                                 | 10m   | warning    |
| GalacticRouterMetricsDown              | `galactic-router` or `galactic-router-rr` scrape down                       | 5m    | warning    |
| GalacticNatSessionTableEvictingLive    | table over 90% full, oldest row under 7440 s                                | 15m   | warning    |
| GalacticNatPortExhausted               | `*_pat_exhausted` drops in every 10-minute window                           | 15m   | warning    |
| GalacticNatUplinkRxQueueStalled        | one uplink rx queue delivers nothing while discarding                       | 10m   | critical   |
| GalacticNatUplinkRxQueueLossy          | one uplink rx queue discards >1%, most siblings do not                      | 30m   | warning    |
| GalacticNatNotProgrammed               | turned on, no EgressShard identity                                          | 10m   | warning    |
| GalacticNatUplinkUncovered             | `galactic_nat_uplink_covered == 0`                                          | 10m   | critical   |
| GalacticNatForwardDropRatio            | owned-traffic drops over 1% of translated, over 10 packets/s                | 15m   | warning    |
| GalacticNatNotTranslating              | compute nodes send to the shard's SID, it translates none outbound          | 10m   | critical   |
| GalacticNatPortsNearExhaustion         | busiest destination holds over half its port range                          | 10m   | warning    |
| GalacticNatDispatchLeaseFailing        | more than two lease renewal errors in every 5-minute window                 | 5m    | warning    |
| GalacticNatDispatchLeaseExpiring       | no successful lease renewal in 2 minutes                                    | 0     | critical   |
| GalacticNatMetricsDown                 | `galactic-nat` scrape down                                                  | 5m    | warning    |
| GalacticEgressPoolEmpty                | no active shard for a class while routes on the node name it                | 2m    | critical   |
| GalacticEgressPoolBelowMinimum         | fewer active shards than `galactic_cni_egress_pool_min_active`              | 10m   | warning    |
| GalacticEgressClassUnserved            | every shard ineligible for a class                                          | 15m   | warning    |
| GalacticEgressShardGroupDropping       | `group_empty`, `shard_dead` or `parse_failed` in every 5m window            | 10m   | warning    |
| GalacticEgressShardWatchNotSynced      | hashed mode, `EgressShard` watch never listed                               | 10m   | warning    |
| GalacticEgressSweepFailing             | sweep errors in every 10-minute window                                      | 15m   | warning    |
| GalacticCNIMetricsDown                 | `galactic-cni` scrape down                                                  | 5m    | warning    |
| FabricAPIExecutionStalled              | gateway has executions in flight, finished none in 10m                      | 10m   | warning    |
| FabricAPINodeDiagnosticsUnavailable    | `fabric_api_node_diagnostics_available == 0`                                | 15m   | warning    |
| FabricAPINodeUnreachable               | over half of 5+ node calls in 30m unreachable or timed out                  | 15m   | warning    |
| FabricAPIResultsOversized              | 10+ `ResponseTooLarge` requests on a node in an hour                        | 15m   | warning    |
| FabricAPICleanupBacklog                | over 50 expired `FabricQuery` objects left                                  | 1h    | warning    |
| FabricAPICertificateRenewalFailing     | mTLS certificate expires in under 4 hours                                   | 15m   | warning    |
| FabricAPICredentialsMissing            | `fabric_api_credentials_loaded == 0`                                        | 15m   | warning    |
| FabricAPISearchIndexUnsynced           | search index holds routes but is not synced with bgpd                       | 15m   | warning    |
| FabricAPILimiterUnavailable            | no gateway replica has had a ready aggregate limiter                        | 10m   | warning    |
| FabricAPIClockUnsynchronized           | limiter or permit-checking kernel clock not synchronised                    | 10m   | warning    |
| FabricAPIServiceThrottled              | over half of 20+ Looking Glass requests in 30m throttled                    | 15m   | warning    |
| FabricAPIServiceExecutionFailing       | over half of 10+ executed Looking Glass requests in 30m failed              | 15m   | warning    |
| FabricAPIMetricsDown                   | `fabric-api-node` or `fabric-api-gateway` scrape down                       | 10m   | warning    |
| GalacticEdgeAttachmentNotProgrammed    | admitted and allocated attachments not programmed by their node             | 15m   | warning    |
| GalacticEdgeServicePolicyUnresolved    | an `EdgeService`'s `TrafficPolicyResolved` is False                         | 10m   | warning    |
| GalacticEdgeScopeLost                  | `galactic_edge_foundation_scopes_lost > 0`                                  | 5m    | warning    |
| GalacticEdgeCleanupFailing             | more than two cleanup failures in every 15-minute window                    | 15m   | warning    |
| GalacticEdgeMetricsDown                | `galactic-edge` or `galactic-controller` scrape down                        | 5m    | warning    |
| GalacticMasqueRequestsFailing          | over a quarter of 10+ requests in 30m fail on the provider's side           | 15m   | warning    |
| GalacticMasqueRouteClaimsFailing       | more than two refused or failed route claims in every 15m window            | 15m   | warning    |
| GalacticMasqueLeaseNotHeld             | `galactic_masque_lease_held == 0`                                           | 5m    | warning    |
| GalacticMasqueLeaseLost                | the instance lost its Lease twice or more in an hour                        | 0     | warning    |
| GalacticMasquePathMTUTooSmall          | over a quarter of 10+ probed requests in 30m cannot carry 1280 bytes        | 15m   | warning    |
| GalacticMasqueMetricsDown              | `masque-provider` scrape down                                               | 5m    | warning    |
