# Routing

See [scraping and component ports](README.md#where-the-metrics-come-from) and [shipped alerts](alerts.md).

Two planes: FRR (`fabric-router`) carries the underlay to the upstream
routers, and GoBGP (`galactic-router`) carries tenant EVPN/VPN routes.

### Underlay — `frr_*`

Exported by the `frr-exporter` sidecar with the `bgp`, `bgp6` and
`bgp.advertised-prefixes` collectors on; OSPF and BFD are off.

| Metric                                           | Use                                                                                          |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| `frr_bgp_peer_state`                             | `0` down, `1` established, `2` administratively down; labels include `peer`, `afi`, `safi`   |
| `frr_bgp_peer_uptime_seconds`                    | Resets on every session drop, so `resets()` counts flaps                                     |
| `frr_bgp_peer_prefixes_received_count_total`     | Prefixes received per peer; a gauge despite the `_total` suffix                              |
| `frr_bgp_peer_prefixes_advertised_count_total`   | Prefixes advertised per peer                                                                 |
| `frr_collector_up`                               | `0` means the exporter can't read FRR, so every other `frr_*` on that node is stale          |

```promql
# Session table for a dashboard
max by (node, peer, afi) (frr_bgp_peer_state)

# Flaps in the last 30m
resets(frr_bgp_peer_uptime_seconds{job="fabric-router"}[30m])

# Received prefixes halved while the session stays up
frr_bgp_peer_prefixes_received_count_total < 0.5 * (frr_bgp_peer_prefixes_received_count_total offset 1h)
  and frr_bgp_peer_state == 1
```

### Underlay config — `fabric_router_*`

| Metric                                            | Type      | Labels                   | Meaning                                                                                                                                                                              |
| ------------------------------------------------- | --------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `fabric_router_bgp_mapped_nexthop`                | gauge     | `peer`                   | `1` when a session from a global IPv6 address announces an IPv4-mapped next hop (`::ffff:<router-id>`); remote sites then lose their routes to this node's locators and NAT shards   |
| `fabric_router_bgp_mapped_nexthop_resets_total`   | counter   | `peer`                   | Hard resets the agent issued to clear a mapped next hop                                                                                                                              |
| `fabric_router_bgp_uninstalled_routes`            | gauge     | `afi` (`ipv4`, `ipv6`)   | Prefixes zebra has a BGP route for but that have no kernel route from any protocol                                                                                                   |
| `fabric_router_connected_routes_missing`          | gauge     | `afi` (`ipv4`, `ipv6`)   | Global addresses on `lo` with no selected connected route in zebra, so `redistribute connected` does not announce them; detection only                                               |

The gauges refresh every 30s. A count the agent cannot read, because vtysh or
the netlink address listing fails, keeps its last value and the error is
logged. On a node routed through the API the agent
also exports `fabric_router_activations_total`,
`fabric_router_activation_duration_seconds`,
`fabric_router_staging_runs_total`, `fabric_router_writer_lock_wait_seconds`
and `fabric_router_boot_source`; see below.

### Fabric routing — `galactic_fabric_routing_*`

`fabric-router-controller`'s leader exports each FabricRouterDeployment's
source, epochs, heartbeat, conditions and staged candidate, each outstanding
FabricReleaseAuthorization, and each fabric router's compile result, read from
its cache at scrape time. The full list, with the node agent's activation
metrics, lives with the rest of the operator guide in
[fabric-routing/operations.md](../fabric-routing/operations.md#metrics-and-alerts).

### Tenant routing — `galactic_router_*`

| Metric                                    | Type    | Labels                              | Meaning                                                                                                                                                                                                                                               |
| ----------------------------------------- | ------- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic_router_route_install_failing`   | gauge   | `router` (namespace/name), `kind`   | Routes with a known best path whose last kernel/datapath install failed. `kind="vrf"` is tenant VRF routes, `kind="plain"` routes with no route target (egress shards, VIPs). Above zero means part of a VPC or shard is unreachable from this node   |
| `galactic_router_bmp_station_up`          | gauge   | `router`, `station`                 | BMP session to the collector: `1` up, `0` down                                                                                                                                                                                                        |

`galactic-router` also exposes the standard controller-runtime metrics
(`controller_runtime_reconcile_total`,
`controller_runtime_reconcile_errors_total`, `workqueue_*`) and Go process
metrics. GoBGP session state is not a metric: read it from `BGPPeer` status
(`STATE=Established`) or the BMP stream.

```promql
sum by (node, kind) (galactic_router_route_install_failing) > 0
sum by (controller) (rate(controller_runtime_reconcile_errors_total{job=~"galactic-router.*"}[10m]))
```

### Private service routes — `galactic_service_route_*`

The node-local `ServiceRoutePolicy` controller in plain-mode
`galactic-router`, which programs attachment-scoped eBPF service paths.
The route reflector doesn't run it. Resource names are kept in logs, not
labels, so the series stay bounded.

| Metric                                              | Type      | Labels                                                         | Meaning                                                   |
| --------------------------------------------------- | --------- | -------------------------------------------------------------- | --------------------------------------------------------- |
| `galactic_service_route_reconciliations_total`      | counter   | `result` (`success`, `error`)                                  | `ServiceRoutePolicy` reconciliations                      |
| `galactic_service_route_reconcile_duration_seconds` | histogram | none                                                           | Time per reconcile (default buckets)                      |
| `galactic_service_route_route_operations_total`     | counter   | `operation` (`apply`, `remove`), `result` (`success`, `error`) | Datapath writes and removals                              |
| `galactic_service_route_programmed_routes`          | gauge     | none                                                           | Attachment-scoped service paths the controller now tracks |
| `galactic_service_route_producers`                  | gauge     | `state` (`Healthy`, `Unhealthy`, `Unknown`)                    | Producers of `Spread` endpoints this node probes          |

Datapath drops on these paths are the `service_route_*` reasons of
`galactic_usid_drops_total`.

```promql
sum by (node, operation) (rate(galactic_service_route_route_operations_total{result="error"}[10m])) > 0
```
