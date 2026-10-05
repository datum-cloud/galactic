# Metrics Reference

Every Prometheus metric galactic exports for VPC traffic, routing and NAT,
with the label values each one can carry and PromQL to start dashboards and
monitors from. Names, labels and value sets come from the collectors
themselves; when this page and the code disagree, the code wins.

## Where the metrics come from

Every DaemonSet under `config/` runs `hostNetwork: true`, so its port is
bound on the node itself. `galactic-vrf` runs as a sidecar in the ingress
proxy's pod instead, and shares the 9182 default with `galactic-nat`
without clashing, since the two never share a node.

| Area                   | Component                                                 | Metric prefix                           | Port           | `job` from `config/monitoring/`          |
|------------------------|-----------------------------------------------------------|-----------------------------------------|----------------|------------------------------------------|
| VPC dataplane          | `galactic-cni` (`credential-refresh`, the datapath owner) | `galactic_usid_*`                       | 9180           | none shipped                             |
| VPC ingress            | `galactic-vrf`                                            | `galactic_ingress_sidecar_*`            | 9182 (default) | none shipped                             |
| Tenant routing (GoBGP) | `galactic-router`, `galactic-router-rr`                   | `galactic_router_*`, controller-runtime | 9179           | `galactic-router` / `galactic-router-rr` |
| Underlay routing (FRR) | `fabric-router` `frr-exporter` sidecar                    | `frr_*`                                 | 9342           | `fabric-router`                          |
| Underlay config        | `fabric-router` `fabric-config-agent`                     | `fabric_router_*`                       | 9343           | `fabric-config-agent`                    |
| NAT66 / NAT64          | `galactic-nat` (one per egress shard)                     | `galactic_nat_*`                        | 9182           | none shipped                             |

`config/monitoring/` ships PodMonitors for `galactic-router` and
`fabric-router` only. Scraping `galactic-cni`, `galactic-vrf` or
`galactic-nat` needs a scrape object of your own. Copy the shipped
PodMonitors' relabeling of `__meta_kubernetes_pod_node_name` into `node`:
every galactic metric is per node, and `node` is the label you group and
alert by.

The eBPF-backed metrics (`galactic_usid_*`, `galactic_nat_*`) are read from
BPF maps at scrape time, and a pod restart that reloads the program resets
them. Always use `rate()` / `increase()`, never raw counter values.

## VPC dataplane — `galactic_usid_*`

The SRv6 uSID datapath on every node, forwarding packets between the fabric
and tenant VRFs.

### Traffic

| Metric                            | Type    | Labels                                                       | Meaning                                                                  |
|-----------------------------------|---------|--------------------------------------------------------------|--------------------------------------------------------------------------|
| `galactic_usid_vrf_packets_total` | counter | `block`, `argument`, `vrf_table_id`, `vpc`, `vpc_attachment` | Packets forwarded into a tenant VRF for one (uSID Block, Argument) entry |
| `galactic_usid_vrf_bytes_total`   | counter | same                                                         | Bytes for the same entry                                                 |

- Both reset when an entry is re-registered, not only on restart; `rate()`
  copes with this.
- `vpc` and `vpc_attachment` are empty when the VPC attribution map has no
  entry for that Argument. Treat `vpc=""` traffic as unattributed and watch
  for it.
- Cardinality is one series per active Argument per node: at most 4095 per
  Block.

```promql
# Throughput per VPC, bits/s
sum by (vpc) (rate(galactic_usid_vrf_bytes_total[5m])) * 8

# Top 10 attachments by packet rate
topk(10, sum by (vpc, vpc_attachment) (rate(galactic_usid_vrf_packets_total[5m])))

# Traffic the datapath can't attribute to a VPC
sum by (node) (rate(galactic_usid_vrf_bytes_total{vpc=""}[5m]))
```

### Drops

`galactic_usid_drops_total{reason}` (counter) counts packets dropped by
`usid_ingress`. Every named reason is always emitted, at zero when unused,
plus `unknown_<n>` for an index the binary has no name for.

| Reason group     | Values                                                                                                                         | Usually means                                                                                   |
|------------------|--------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|
| Unknown SID      | `unknown_function`, `unknown_argument`                                                                                         | Traffic for a VRF or Argument this node no longer, or never, registered: stale routes elsewhere |
| Malformed        | `malformed_inner`, `unknown_inner_version`, `unexpected_nexthdr`, `unsupported_behavior`, `strip_failed`                       | Bad or unsupported packets; a sustained rate is a bug                                           |
| FIB / forwarding | `fib_lookup_failed`, `fib_no_neigh`, `fib_unreachable`, `fib_frag_needed`, `redirect_failed`                                   | Kernel route or neighbor missing for the inner destination                                      |
| Egress           | `egress_route_encap_failed`, `egress_route_fib_lookup_failed`, `egress_route_redirect_failed`, `public_uplink_redirect_failed` | Tenant traffic leaving the node couldn't be encapsulated or sent                                |

```promql
sum by (node, reason) (rate(galactic_usid_drops_total[5m])) > 0
```

### SID capacity

| Metric                                           | Type  | Labels  | Meaning                                                |
|--------------------------------------------------|-------|---------|--------------------------------------------------------|
| `galactic_usid_block_arguments_used`             | gauge | `block` | Arguments (VRF entries) registered in the Block        |
| `galactic_usid_block_argument_utilization_ratio` | gauge | `block` | `arguments_used / 4095`, the usable capacity per Block |

```promql
max by (node, block) (galactic_usid_block_argument_utilization_ratio) > 0.8
```

### MTU handling

| Metric                                    | Type    | Labels   | Meaning                                                                   |
|-------------------------------------------|---------|----------|---------------------------------------------------------------------------|
| `galactic_usid_tcp_mss_clamp_syns_total`  | counter | `result` | TCP SYNs the MSS clamp examined                                           |
| `galactic_usid_tcp_mss_clamp_limit_bytes` | gauge   | `family` | MSS that SYNs are clamped to; `0` means clamping is off for that family   |
| `galactic_usid_pmtu_packets_total`        | counter | `result` | Tenant packets too big for the fabric once encapsulated                   |
| `galactic_usid_pmtu_limit_bytes`          | gauge   | none     | Largest tenant packet the egress encapsulates; `0` means the check is off |

`galactic_usid_tcp_mss_clamp_syns_total` result values:

- **Clamping worked:** `clamped_ipv4`, `clamped_ipv6`, `within_limit`.
- **SYN crossed the fabric unclamped:** `no_mss_option`,
  `skipped_extension_header`, `malformed_options`, `rewrite_failed`,
  `walk_limit`.

`galactic_usid_pmtu_packets_total` result values:

- **Tenant got an ICMP error back:** `too_big_sent_ipv6`,
  `frag_needed_sent_ipv4`.
- **Dropped without an ICMP error (black-hole risk):** `dropped_no_df`,
  `dropped_icmp_error`, `rate_limited`, `no_gateway`, `build_failed`.

```promql
# SYNs that crossed unclamped
sum by (node, result) (rate(galactic_usid_tcp_mss_clamp_syns_total{result!~"clamped_.*|within_limit"}[5m]))

# PMTU drops with no ICMP error, the case that stalls connections silently
sum by (node, result) (rate(galactic_usid_pmtu_packets_total{result!~"too_big_sent_ipv6|frag_needed_sent_ipv4"}[5m]))

# Clamp off for a family
galactic_usid_tcp_mss_clamp_limit_bytes == 0
```

### Datapath lifecycle

| Metric                                       | Type    | Labels                                               | Meaning                                                            |
|----------------------------------------------|---------|------------------------------------------------------|--------------------------------------------------------------------|
| `galactic_usid_datapath_load_events_total`   | counter | `result` (`success`, `failure`)                      | BPF program load attempts                                          |
| `galactic_usid_datapath_attach_events_total` | counter | `interface`, `action` (`attach`, `detach`), `result` | TC ingress attach/detach, including every netlink-driven re-attach |

```promql
increase(galactic_usid_datapath_load_events_total{result="failure"}[15m]) > 0
increase(galactic_usid_datapath_attach_events_total{result="failure"}[15m]) > 0

# Re-attach churn: a flapping interface
sum by (node, interface) (increase(galactic_usid_datapath_attach_events_total{action="attach"}[1h])) > 5
```

## VPC ingress — `galactic_ingress_sidecar_*`

`galactic-vrf` installs per-VPC VRF devices and per-pod seg6 egress routes on
ingress nodes.

| Metric                                                | Type      | Labels | Meaning                                                                                    |
|-------------------------------------------------------|-----------|--------|--------------------------------------------------------------------------------------------|
| `galactic_ingress_sidecar_vrf_active`                 | gauge     | none   | VRF devices installed                                                                      |
| `galactic_ingress_sidecar_route_active`               | gauge     | none   | seg6 egress routes installed                                                               |
| `galactic_ingress_sidecar_vrf_teardown_pending`       | gauge     | none   | VRFs past their last pod, waiting out the teardown grace period                            |
| `galactic_ingress_sidecar_route_teardown_pending`     | gauge     | none   | Routes whose EndpointSlice is gone, waiting out the teardown grace period                  |
| `galactic_ingress_sidecar_reconcile_errors_total`     | counter   | `kind` | `ensure_vrf`, `ensure_route`, `remove_vrf`, `remove_route`, `reapply_vrf`, `reapply_route` |
| `galactic_ingress_sidecar_reconcile_duration_seconds` | histogram | none   | Duration of each desired-state apply (default buckets)                                     |
| `galactic_ingress_sidecar_reapply_total`              | counter   | none   | Full reapplies after the shared eBPF datapath reloaded                                     |

```promql
sum by (node, kind) (rate(galactic_ingress_sidecar_reconcile_errors_total[10m])) > 0
histogram_quantile(0.99, sum by (le, node) (rate(galactic_ingress_sidecar_reconcile_duration_seconds_bucket[5m])))

# Teardown backlog that never drains
min_over_time(galactic_ingress_sidecar_vrf_teardown_pending[1h]) > 0
```

## Routing

Two planes: FRR (`fabric-router`) carries the underlay to the upstream
routers, and GoBGP (`galactic-router`) carries tenant EVPN/VPN routes.

### Underlay — `frr_*`

Exported by the `frr-exporter` sidecar with the `bgp`, `bgp6` and
`bgp.advertised-prefixes` collectors on; OSPF and BFD are off.

| Metric                                         | Use                                                                                        |
|------------------------------------------------|--------------------------------------------------------------------------------------------|
| `frr_bgp_peer_state`                           | `0` down, `1` established, `2` administratively down; labels include `peer`, `afi`, `safi` |
| `frr_bgp_peer_uptime_seconds`                  | Resets on every session drop, so `resets()` counts flaps                                   |
| `frr_bgp_peer_prefixes_received_count_total`   | Prefixes received per peer; a gauge despite the `_total` suffix                            |
| `frr_bgp_peer_prefixes_advertised_count_total` | Prefixes advertised per peer                                                               |
| `frr_collector_up`                             | `0` means the exporter can't read FRR, so every other `frr_*` on that node is stale        |

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

| Metric                                          | Type    | Labels                 | Meaning                                                                                                                                                                            |
|-------------------------------------------------|---------|------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `fabric_router_bgp_mapped_nexthop`              | gauge   | `peer`                 | `1` when a session from a global IPv6 address announces an IPv4-mapped next hop (`::ffff:<router-id>`); remote sites then lose their routes to this node's locators and NAT shards |
| `fabric_router_bgp_mapped_nexthop_resets_total` | counter | `peer`                 | Hard resets the agent issued to clear a mapped next hop                                                                                                                            |
| `fabric_router_bgp_uninstalled_routes`          | gauge   | `afi` (`ipv4`, `ipv6`) | Prefixes zebra has a BGP route for but that have no kernel route from any protocol                                                                                                 |

Both gauges refresh every 30s.

### Tenant routing — `galactic_router_*`

| Metric                                  | Type  | Labels                            | Meaning                                                                                                                                                                                                                                             |
|-----------------------------------------|-------|-----------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `galactic_router_route_install_failing` | gauge | `router` (namespace/name), `kind` | Routes with a known best path whose last kernel/datapath install failed. `kind="vrf"` is tenant VRF routes, `kind="plain"` routes with no route target (egress shards, VIPs). Above zero means part of a VPC or shard is unreachable from this node |
| `galactic_router_bmp_station_up`        | gauge | `router`, `station`               | BMP session to the collector: `1` up, `0` down                                                                                                                                                                                                      |

`galactic-router` also exposes the standard controller-runtime metrics
(`controller_runtime_reconcile_total`,
`controller_runtime_reconcile_errors_total`, `workqueue_*`) and Go process
metrics. GoBGP session state is not a metric: read it from `BGPPeer` status
(`STATE=Established`) or the BMP stream.

```promql
sum by (node, kind) (galactic_router_route_install_failing) > 0
sum by (controller) (rate(controller_runtime_reconcile_errors_total{job=~"galactic-router.*"}[10m]))
```

## NAT66 / NAT64 — `galactic_nat_*`

One `galactic-nat` pod per egress shard; every value is per shard.

| Metric                                           | Type    | Labels                                   | Meaning                                                                                                                              |
|--------------------------------------------------|---------|------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| `galactic_nat_conns`                             | gauge   | `family` (`nat66`, `nat64`)              | Rows in the connection table, expired sessions included. A session holds two rows                                                    |
| `galactic_nat_sessions`                          | gauge   | `family`, `proto` (`tcp`, `udp`, `icmp`) | Live sessions: one per session within its idle timeout                                                                               |
| `galactic_nat_conn_table_oldest_row_age_seconds` | gauge   | none                                     | Seconds since the least recently seen session, expired ones included, last translated a packet. Meaningful only on a near-full table |
| `galactic_nat_conn_table_max_entries`            | gauge   | none                                     | Table capacity in rows, shared by both families                                                                                      |
| `galactic_nat_drops_total`                       | counter | `reason`                                 | Packets dropped by the NAT datapath                                                                                                  |

Caveats for the session table:

- Expired sessions keep their rows until the LRU evicts them or a new claim
  reuses their port, so `galactic_nat_conns` sits near capacity on any busy
  shard. That is normal. Use `galactic_nat_sessions` for live sessions.
- Live sessions are at risk only when the table is full and its oldest row is
  younger than the longest session timeout, 7440 s for established TCP. The
  table's LRU evicts in approximate order, so the age is an estimate.
- The table is a self-evicting LRU, so the counts can move without traffic
  changing.

| Reason group        | Values                                                                                                                                                                          | Meaning                                                                                                       |
|---------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| Port exhaustion     | `nat66_pat_exhausted`, `nat64_pat_exhausted`                                                                                                                                    | No free port on the shard's public address; tenants see failed connections                                    |
| Shard availability  | `nat64_shard_unavailable`                                                                                                                                                       | NAT64 had no shard to send to                                                                                 |
| Return-path misses  | `nat66_no_return_conn`, `nat64_no_return_conn`, `nat66_icmp_no_conn`, `nat64_icmp_no_conn`, `icmp_unsolicited`                                                                  | Inbound packets with no matching session; background noise is normal, a jump after a restart means lost state |
| Malformed           | `nat66_malformed_forward`, `nat66_malformed_return`, `nat64_malformed_forward`, `nat64_malformed_return`, `nat66_icmp_malformed`, `nat64_icmp_malformed`, `icmp_untranslatable` | Packets that couldn't be translated                                                                           |
| IPv4 limits (NAT64) | `nat64_v4_fragment`, `nat64_v4_options`, `nat64_non_global_dest`                                                                                                                | Unsupported IPv4 fragments or options, or a non-global destination                                            |
| Forwarding          | `fib_lookup_failed`, `fib_no_neigh`, `fib_unreachable`, `fib_frag_needed`, `adjust_head_failed`, `no_egress_ifindex`, `redirect_failed`, `hop_limit_exceeded`                   | Route, neighbor or redirect failure after translation                                                         |
| Rate limit          | `icmp_rate_limited`                                                                                                                                                             | ICMP errors suppressed by the rate limiter                                                                    |

```promql
# Live sessions per family
sum by (node, family) (galactic_nat_sessions)

# Idle live sessions being evicted: table full, oldest row younger than the TCP timeout
sum by (node) (galactic_nat_conns) / on (node) galactic_nat_conn_table_max_entries > 0.9
  and on (node) galactic_nat_conn_table_oldest_row_age_seconds < 7440

# Port exhaustion or no shard
sum by (node, reason) (rate(galactic_nat_drops_total{reason=~".*_pat_exhausted|nat64_shard_unavailable"}[5m])) > 0

# Drop rate by reason
sum by (node, reason) (rate(galactic_nat_drops_total[5m])) > 0
```

## Shipped alerts

`config/monitoring/prometheusrule.yaml` (the `galactic-bgp` PrometheusRule,
unit-tested with `task test:alerts`) covers routing only. Every alert
carries `service: galactic`, `team: connect` and a `runbook_url`.

| Alert                                | Fires when                                              | For | Severity |
|--------------------------------------|---------------------------------------------------------|-----|----------|
| FabricBGPSessionDown                 | `frr_bgp_peer_state == 0`                               | 5m  | critical |
| FabricBGPSessionAdminDown            | `frr_bgp_peer_state == 2`                               | 1h  | warning  |
| FabricBGPSessionFlapping             | `resets(frr_bgp_peer_uptime_seconds[30m]) >= 3`         | 0   | warning  |
| FabricBGPPrefixesDropped             | received prefixes under half of an hour ago, session up | 15m | warning  |
| FabricRouterExporterCollectorFailing | `frr_collector_up == 0`                                 | 10m | warning  |
| FabricRouterMetricsDown              | `fabric-router` scrape down                             | 5m  | warning  |
| FabricBGPMappedNextHop               | `fabric_router_bgp_mapped_nexthop == 1`                 | 15m | critical |
| FabricBGPRoutesNotInstalled          | `fabric_router_bgp_uninstalled_routes > 0`              | 10m | warning  |
| FabricConfigAgentMetricsDown         | `fabric-config-agent` scrape down                       | 5m  | warning  |
| GalacticRouterBMPStationDown         | `galactic_router_bmp_station_up == 0`                   | 10m | warning  |
| GalacticRouterRoutesNotInstalled     | `galactic_router_route_install_failing > 0`             | 10m | warning  |
| GalacticRouterMetricsDown            | `galactic-router` or `galactic-router-rr` scrape down   | 5m  | warning  |
