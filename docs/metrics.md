# Metrics Reference

Every Prometheus metric galactic exports for VPC traffic, egress, ingress
load balancing, routing and NAT, with the label values each one can carry
and PromQL to start dashboards and monitors from. Names, labels and value
sets come from the collectors themselves; when this page and the code
disagree, the code wins.

## Where the metrics come from

Every DaemonSet under `config/` runs `hostNetwork: true`, so its port is
bound on the node itself. `galactic-vrf` runs as a sidecar in the ingress
proxy's pod instead, which has its own network namespace, so it shares
the 9182 default with `galactic-nat` without clashing, even on the edge
nodes that run both. `galactic-controller` and the fabric-api gateway are
Deployments, scraped per pod.

| Area                    | Component                                                 | Metric prefix                           | Port           | `job` from `config/monitoring/`          |
| ----------------------- | --------------------------------------------------------- | --------------------------------------- | -------------- | ---------------------------------------- |
| VPC dataplane           | `galactic-cni` (`credential-refresh`, the datapath owner) | `galactic_usid_*`                       | 9180           | `galactic-cni`                           |
| Tenant egress pool      | `galactic-cni`                                            | `galactic_cni_egress_*`                 | 9180           | `galactic-cni`                           |
| VPC ingress             | `galactic-vrf`                                            | `galactic_ingress_sidecar_*`            | 9182 (default) | none shipped                             |
| VPC ingress return path | `galactic-cni` (`credential-refresh`)                     | `galactic_sidecar_return_*`             | 9180           | `galactic-cni`                           |
| Edge load balancer      | `galactic-gateway`                                        | `galactic_edge_*`, controller-runtime   | 8081           | none shipped                             |
| Tenant routing (GoBGP)  | `galactic-router`, `galactic-router-rr`                   | `galactic_router_*`, controller-runtime | 9179           | `galactic-router` / `galactic-router-rr` |
| Private service routes  | `galactic-router` (plain mode only)                       | `galactic_service_route_*`              | 9179           | `galactic-router`                        |
| Traffic policy          | `galactic-router` with `GALACTIC_ROUTER_TRAFFIC_POLICY`   | `galactic_cni_traffic_policy_*`         | 9179           | `galactic-router`                        |
| Traffic policy webhook  | `galactic-controller`                                     | controller-runtime only                 | 9184           | none shipped                             |
| Underlay routing (FRR)  | `fabric-router` `frr-exporter` sidecar                    | `frr_*`                                 | 9342           | `fabric-router`                          |
| Underlay config         | `fabric-router` `fabric-config-agent`                     | `fabric_router_*`                       | 9343           | `fabric-config-agent`                    |
| Fabric looking glass    | `fabric-api` node sidecar                                 | `fabric_api_node_*`, `fabric_api_*`     | 9345           | `fabric-api-node`                        |
| Fabric looking glass    | `fabric-api` cell gateway                                 | `fabric_api_gateway_*`, `fabric_api_*`  | 9347           | `fabric-api-gateway`                     |
| NAT66 / NAT64           | `galactic-nat` (one per egress shard)                     | `galactic_nat_*`                        | 9182           | `galactic-nat`                           |

`config/monitoring/` ships PodMonitors for `galactic-cni`,
`galactic-router`, `fabric-router` (including the opt-in fabric-api
sidecar), the fabric-api gateway and `galactic-nat`. Scraping
`galactic-vrf`, `galactic-gateway` or `galactic-controller` needs a scrape
object of your own. Copy the shipped PodMonitors' relabeling of
`__meta_kubernetes_pod_node_name` into `node`: every galactic metric is per
node, and `node` is the label you group and alert by.

The eBPF-backed metrics (`galactic_usid_*`, `galactic_cni_egress_shard_*`,
`galactic_edge_*`, `galactic_nat_*`) are read from BPF maps at scrape time,
and a pod restart that reloads the program resets them. Always use
`rate()` / `increase()`, never raw counter values.

## VPC dataplane — `galactic_usid_*`

The SRv6 uSID datapath on every node, forwarding packets between the fabric
and tenant VRFs.

### Traffic

Each node keeps one VRF per VPC, so every series below is one VPC on one
node, keyed by its uSID (Block, Argument). `vpc_attachment` names the
attachment that registered the VRF last, not each attachment's own traffic.
`vrf_interface` is the name of the VPC's VRF device on the node, as
`ip link` shows it.

| Metric                                      | Type    | Labels                                                                                     | Meaning                                                                         |
|---------------------------------------------|---------|--------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| `galactic_usid_vrf_forwarded_packets_total` | counter | `block`, `argument`, `vrf_table_id`, `vpc`, `vpc_attachment`, `vrf_interface`, `direction` | Packets forwarded into (`ingress`) or out of (`egress`) the VRF                 |
| `galactic_usid_vrf_forwarded_bytes_total`   | counter | same                                                                                       | Tenant bytes of those packets: the IP header and payload, in both directions    |
| `galactic_usid_vrf_dropped_packets_total`   | counter | same                                                                                       | Packets dropped after the datapath resolved them to the VRF, by direction       |
| `galactic_usid_vrf_packets_total`           | counter | `block`, `argument`, `vrf_table_id`, `vpc`, `vpc_attachment`, `vrf_interface`              | Inbound packets that matched the VRF, counted before any later drop             |
| `galactic_usid_vrf_bytes_total`             | counter | same                                                                                       | Bytes of those packets, measured as the whole tunneled frame with outer headers |

What each `direction` counts:

| `direction` | Counted when                                                                                                                                                                    |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ingress`   | `usid_ingress` decapsulates a packet and redirects it to an attachment, or another attachment on the same node sends one to it                                                  |
| `egress`    | a tenant packet is encapsulated toward another node or an egress shard, sent unencapsulated out the public uplink (a VIP reply), or delivered to another attachment on the node |

- A packet counts once, when the datapath has committed to forwarding it.
  Traffic the datapath hands to the kernel to route (no matching egress
  route) and fail-open paths are not counted.
- A packet too big for the fabric, answered with a Packet Too Big or
  Fragmentation Needed, counts as neither forwarded nor dropped; see
  `galactic_usid_pmtu_packets_total`.
- Traffic between two attachments of one VPC on the same node counts once
  as `egress` and once as `ingress` on that VPC's series, when it is handed
  to the kernel for delivery, so the kernel can still drop it. Traffic to the
  sender's own gateway address counts in neither; traffic to another
  attachment's gateway address in the same VPC counts as delivered.
- A private service route delivering to another attachment on the node
  counts `egress` on the sender's VPC and `ingress` on the receiver's, which
  may be a different VPC.
- A GSO or GRO super-packet counts as one packet carrying all its bytes.
- Drop reasons are in `galactic_usid_drops_total`, which has no VRF.
  `galactic_usid_vrf_dropped_packets_total` has the VRF but no reason, and
  covers drops in decapsulation, delivery, encapsulation and the PMTU check,
  including inbound private service tunnels. Outbound private service route
  drops (`service_route_*` from the sending attachment) and failed
  public-uplink redirects appear only in `galactic_usid_drops_total`.
- The two older series keep their meaning: inbound only, claimed before any
  drop, and the full frame. Prefer the `forwarded` series for throughput.
- Registering a VRF again never resets its counters. They reset when the
  datapath reloads, or when the VRF's rows are removed and created again,
  which `rate()` copes with.
- `vpc`, `vpc_attachment` and `vrf_interface` are empty when the VPC
  attribution map has no entry for that Argument. Treat `vpc=""` traffic as
  unattributed and watch for it.
- Cardinality is one series per active Argument per node for the older pair,
  at most 4095 per Block, and twice that for each `direction` metric.

```promql
# Throughput per VPC and direction, bits/s
sum by (vpc, direction) (rate(galactic_usid_vrf_forwarded_bytes_total[5m])) * 8

# Top 10 VPCs on a node by outbound packet rate
topk(10, sum by (node, vpc) (rate(galactic_usid_vrf_forwarded_packets_total{direction="egress"}[5m])))

# Share of a VPC's packets dropped after the datapath claimed them
sum by (vpc, direction) (rate(galactic_usid_vrf_dropped_packets_total[5m]))
  / (sum by (vpc, direction) (rate(galactic_usid_vrf_forwarded_packets_total[5m]))
     + sum by (vpc, direction) (rate(galactic_usid_vrf_dropped_packets_total[5m])))

# Traffic the datapath can't attribute to a VPC
sum by (node) (rate(galactic_usid_vrf_forwarded_bytes_total{vpc=""}[5m]))
```

### Drops

`galactic_usid_drops_total{reason}` (counter) counts packets the uSID
datapath dropped, inbound and outbound. Every named reason is always
emitted, at zero when unused, plus `unknown_<n>` for an index the binary
has no name for.

| Reason group     | Values                                                                                                                         | Usually means                                                                                   |
|------------------|--------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|
| Unknown SID      | `unknown_function`, `unknown_argument`                                                                                         | Traffic for a VRF or Argument this node no longer, or never, registered: stale routes elsewhere |
| Malformed        | `malformed_inner`, `unknown_inner_version`, `unexpected_nexthdr`, `unsupported_behavior`, `strip_failed`                       | Bad or unsupported packets; a sustained rate is a bug                                           |
| FIB / forwarding | `fib_lookup_failed`, `fib_no_neigh`, `fib_unreachable`, `fib_frag_needed`, `redirect_failed`                                   | Kernel route or neighbor missing for the inner destination                                      |
| Egress           | `egress_route_encap_failed`, `egress_route_fib_lookup_failed`, `egress_route_redirect_failed`, `public_uplink_redirect_failed` | Tenant traffic leaving the node couldn't be encapsulated or sent                                |
| Service routes   | `service_route_denied`, `service_route_redirect_failed`                                                                        | A private service route refused the sender, or its redirect to the target failed                |

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

## Tenant egress pool — `galactic_cni_egress_*`

How each compute node spreads tenant egress across the cluster's
`EgressShard`s. With `GALACTIC_CNI_EGRESS_MODE=hashed`, `usid_egress` keeps
one shard group per translation class: `nat66`, and `nat64:<prefix>` for
each NAT64 prefix. See
[nat/configuration.md](nat/configuration.md#active-active-egress).

The pool series come from the maps, so a node with no group publishes
none. The control-loop series (`mode`, `shard_watch_synced`,
`group_routes`, the sweep pair) are always exported, so a node told to run
hashed mode that never published a group still shows it.

| Metric                                                        | Type    | Labels                                                                        | Meaning                                                                                           |
| ------------------------------------------------------------- | ------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `galactic_cni_egress_shard_packets_total`                     | counter | `shard_sid`, `class`                                                          | Tenant packets this node encapsulated toward each shard, since the shard took its slot            |
| `galactic_cni_egress_shard_bytes_total`                       | counter | `shard_sid`, `class`                                                          | Tenant bytes of those packets                                                                     |
| `galactic_cni_egress_shard_selections_total`                  | counter | `result`                                                                      | How `usid_egress` placed each packet whose route names a shard group                              |
| `galactic_cni_egress_pool_members`                            | gauge   | `class`, `state` (`active`, `draining`, `unreachable`, `local`, `ineligible`) | The class's shards as this node's group sees them                                                 |
| `galactic_cni_egress_pool_min_active`                         | gauge   | none                                                                          | `GALACTIC_CNI_EGRESS_POOL_MIN_ACTIVE`, the fewest active shards each class should have            |
| `galactic_cni_egress_pool_enabled`                            | gauge   | `class`                                                                       | 1 while the class's group takes new routes; a group being retired still forwards but reads 0      |
| `galactic_cni_egress_mode`                                    | gauge   | `mode` (`ordered`, `hashed`)                                                  | 1 for the configured mode, 0 for the other                                                        |
| `galactic_cni_egress_shard_watch_synced`                      | gauge   | none                                                                          | 1 once the `EgressShard` watch has listed the cluster                                             |
| `galactic_cni_egress_group_routes`                            | gauge   | `class`                                                                       | `egress_route_table` entries naming a shard group. Must be 0 before rolling back past hashed mode |
| `galactic_cni_egress_sweep_errors_total`                      | counter | `stage` (`apply`, `refresh`, `watch`, `close`, `disable`)                     | Egress route sweep failures, by step                                                              |
| `galactic_cni_egress_last_successful_sweep_timestamp_seconds` | gauge   | none                                                                          | Unix time of the last sweep that finished without an error                                        |

`galactic_cni_egress_shard_selections_total` result values:

- **Forwarded:** `pin_hit` (the tenant address's pin still names a live
  shard), `maglev` (placed by the Maglev table).
- **Re-placed:** `pin_stale` (the pin named a shard that left the group).
- **Dropped:** `group_empty`, `shard_dead`, `parse_failed`.

`state` values: `active` shards take new tenant addresses; `draining` ones
(`spec.drain`) serve only the tenants already pinned to them; `unreachable`
ones have no route from this node; `local` ones run on this node and take
no tenant from it; `ineligible` ones cannot translate the class (no
masquerade address in its family, or another NAT64 prefix).

```promql
# Active shards per class, per node
sum by (node, class) (galactic_cni_egress_pool_members{state="active"})

# Egress bytes/s each shard receives from the cluster's compute nodes
sum by (shard_sid, class) (rate(galactic_cni_egress_shard_bytes_total[5m])) * 8

# Packets dropped on the way to a shard group (GalacticEgressShardGroupDropping)
sum by (node, result) (increase(galactic_cni_egress_shard_selections_total{result=~"group_empty|shard_dead|parse_failed"}[5m])) > 0

# Seconds since the last clean sweep
time() - galactic_cni_egress_last_successful_sweep_timestamp_seconds
```

## VPC ingress — `galactic_ingress_sidecar_*`

`galactic-vrf` installs per-VPC VRF devices and per-pod seg6 egress routes on
ingress nodes. It runs in the ingress proxy's pod, so each sidecar exports its
own copy of these.

| Metric                                                | Type      | Labels | Meaning                                                                                                                                              |
| ----------------------------------------------------- | --------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic_ingress_sidecar_vrf_active`                 | gauge     | none   | VRF devices the store tracks as installed, including those draining. Store state, not a kernel check                                                 |
| `galactic_ingress_sidecar_route_active`               | gauge     | none   | Installed route claims, one per EndpointSlice, including draining ones. Claims sharing a prefix share one kernel route                               |
| `galactic_ingress_sidecar_vrf_teardown_pending`       | gauge     | none   | VRFs past their last route at the last sweep: within their grace period, or whose removal failed                                                     |
| `galactic_ingress_sidecar_route_teardown_pending`     | gauge     | none   | Route claims whose EndpointSlice is gone at the last sweep: within their grace period, or whose removal failed                                       |
| `galactic_ingress_sidecar_reconcile_errors_total`     | counter   | `kind` | Backend errors: `ensure_vrf`, `ensure_route`, `remove_vrf`, `remove_route`, `reapply_vrf`, `reapply_route`, `prune_datapath`. No attempt denominator |
| `galactic_ingress_sidecar_reconcile_duration_seconds` | histogram | none   | Each desired-state update, including waiting for the store's lock (default buckets). Not sweeps                                                      |
| `galactic_ingress_sidecar_reapply_total`              | counter   | none   | Reapply passes: after a datapath reload, after this sidecar's rows went missing, and retries of a failed pass. Not unique reloads                    |

`route_active` does not measure an apply backlog: a route stays counted as
installed while a later update to it is still unapplied.

### Startup and sweep

A sidecar serves `/metrics` from the moment it starts, before its startup has
finished and whether or not its sweep is still running, so `up` and the
gauges above cannot tell a working sidecar from a stuck one. Startup runs
three stages in order: list the selected EndpointSlices and apply them
(`seed`, retried until the list succeeds), adopt existing host state
(`inventory`), and remove an earlier pod's rows from the shared eBPF maps
(`prune`, skipped after a failed inventory). Neither inventory nor prune is
retried, and the sweep starts either way.

| Metric                                                            | Type      | Labels            | Meaning                                                                                                                                                     |
| ----------------------------------------------------------------- | --------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic_ingress_sidecar_startup_stage_status`                   | gauge     | `stage`, `status` | 1 for each stage's current status, 0 for its others. `stage`: `seed`, `inventory`, `prune`. `status`: `pending`, `running`, `complete`, `failed`, `skipped` |
| `galactic_ingress_sidecar_startup_attempts_total`                 | counter   | `stage`, `result` | Completed stage attempts, `result` `success` or `error`. Only the seed is retried                                                                           |
| `galactic_ingress_sidecar_startup_complete`                       | gauge     | none              | 1 once the seed succeeded, inventory and prune were handled, and the sweep started. A failed inventory or prune still reports 1                             |
| `galactic_ingress_sidecar_sweep_last_completed_timestamp_seconds` | gauge     | none              | Unix time the last sweep finished, whatever its operations' results; 0 before the first                                                                     |
| `galactic_ingress_sidecar_sweep_duration_seconds`                 | histogram | none              | Each sweep, including waiting for the store's lock (1ms to 120s). One overrunning its interval absorbs the ticks it missed                                  |
| `galactic_ingress_sidecar_sweep_interval_seconds`                 | gauge     | none              | Configured time between sweeps                                                                                                                              |
| `galactic_ingress_sidecar_teardown_grace_seconds`                 | gauge     | none              | Configured grace period, applied to a route and then, in turn, to its VRF                                                                                   |
| `galactic_ingress_sidecar_pruned_rows_total`                      | counter   | none              | Shared eBPF map rows the startup prune removed, including any removed before it failed                                                                      |

`startup_complete` is the startup procedure, not readiness: it says nothing
about whether routes are installed or traffic flows, and a degraded start
stays visible in `startup_stage_status`. These add 43 series per sidecar,
fixed: no label carries a VPC, route or error.

```promql
sum by (node, kind) (rate(galactic_ingress_sidecar_reconcile_errors_total[10m])) > 0
histogram_quantile(0.99, sum by (le, node) (rate(galactic_ingress_sidecar_reconcile_duration_seconds_bucket[5m])))

# Teardown backlog that never drains
min_over_time(galactic_ingress_sidecar_vrf_teardown_pending[1h]) > 0

# Startup still not complete two minutes after the sidecar process started.
# instance and job pick the sidecar's own process, not another container's.
galactic_ingress_sidecar_startup_complete == 0
  and on (instance, job) (time() - process_start_time_seconds > 120)

# A stage that ended badly: the inventory failed, or the prune failed or was skipped
galactic_ingress_sidecar_startup_stage_status{status=~"failed|skipped"} == 1

# Sweep stalled: the last sweep finished more than three intervals ago.
(galactic_ingress_sidecar_sweep_last_completed_timestamp_seconds > 0)
  and (time() - galactic_ingress_sidecar_sweep_last_completed_timestamp_seconds
    > 3 * galactic_ingress_sidecar_sweep_interval_seconds)

# Never swept: startup completed but no sweep has finished. The first sweep is
# due one interval after startup, so alert with a "for" well beyond three
# intervals.
galactic_ingress_sidecar_startup_complete == 1
  and galactic_ingress_sidecar_sweep_last_completed_timestamp_seconds == 0

histogram_quantile(0.99, sum by (le, namespace, pod) (rate(galactic_ingress_sidecar_sweep_duration_seconds_bucket[10m])))
```

### Convergence

How far a sidecar's host state is from what its EndpointSlices ask for. A
claim is one selected, ready EndpointSlice's route; claims sharing a prefix
share one kernel route.

| Metric                                                                  | Type    | Labels                | Meaning                                                                                                                                        |
| ----------------------------------------------------------------------- | ------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic_ingress_sidecar_route_claims_desired`                         | gauge   | none                  | Claims the sidecar wants installed, including any whose install failed                                                                         |
| `galactic_ingress_sidecar_route_claims_apply_pending`                   | gauge   | none                  | Desired claims whose latest update is not applied, whether or not an earlier version of the route is installed                                 |
| `galactic_ingress_sidecar_route_apply_oldest_pending_timestamp_seconds` | gauge   | none                  | Unix time the longest-pending claim stopped being applied; 0 when none is pending                                                              |
| `galactic_ingress_sidecar_teardown_overdue`                             | gauge   | `resource`            | Routes or VRFs (`route`, `vrf`) whose own grace period ran out but whose removal has not completed, as of the last sweep                       |
| `galactic_ingress_sidecar_operations_total`                             | counter | `operation`, `result` | Completed backend operations: `ensure_vrf`, `ensure_route`, `remove_vrf`, `remove_route`, `reapply_vrf`, `reapply_route`; `success` or `error` |

- A claim's pending age starts when it first fails to apply after being
  applied or created, and survives failed retries and newer updates of the
  same claim: the route has been unapplied since then. It clears when the
  claim applies or stops being desired; a claim reactivated during its grace
  period starts a new age.
- The claim counts and the oldest pending time are exact after every update
  and sweep, at a constant cost per update however large the backlog.
- `teardown_overdue` counts only removals that failed after their own grace
  period. Draining within the grace period is normal and shows only in the
  `*_teardown_pending` gauges. A route's and then its VRF's grace periods run
  one after the other. It is set at each sweep, so a claim reactivated after a
  failed removal still counts until the next one: alert on it with a `for`
  of at least one sweep interval.
- A reapply that fails after a datapath reload leaves the claim applied as
  far as these gauges know; it shows in
  `operations_total{operation=~"reapply_.*",result="error"}`.
- `operations_total{result="error"}` counts the same failures as
  `reconcile_errors_total` for those six kinds, each failure once. Never add
  the two. `reconcile_errors_total` alone also counts `prune_datapath`.
- These add 17 fixed series per sidecar.

```promql
# Apply backlog: how long the oldest claim has been unapplied. 0 means none.
time() - galactic_ingress_sidecar_route_apply_oldest_pending_timestamp_seconds
  and galactic_ingress_sidecar_route_apply_oldest_pending_timestamp_seconds > 0

# Teardown stuck past its grace period
galactic_ingress_sidecar_teardown_overdue > 0

# Backend error ratio by operation; absent, not zero, when nothing ran
sum by (namespace, pod, operation) (rate(galactic_ingress_sidecar_operations_total{result="error"}[5m]))
  / sum by (namespace, pod, operation) (rate(galactic_ingress_sidecar_operations_total[5m]))
```

### EndpointSlice inputs

The selected EndpointSlices a sidecar reads, whether or not they have a
route. A selected slice carries the tenant label. It is `ready` once it parses
into a route, `waiting_sid` while its node's SID annotation has not appeared
(normal for a freshly published slice), and `invalid` when it cannot be
parsed, for a malformed tenant identifier, SID or address, or a non-IPv6
address type. Parsing reads only the first endpoint's first address.

| Metric                                                      | Type    | Labels             | Meaning                                                                                                    |
| ----------------------------------------------------------- | ------- | ------------------ | ---------------------------------------------------------------------------------------------------------- |
| `galactic_ingress_sidecar_endpoint_slices`                  | gauge   | `state`            | Selected slices by `state`: `ready`, `waiting_sid`, `invalid`                                              |
| `galactic_ingress_sidecar_endpoint_slice_evaluations_total` | counter | `source`, `result` | Evaluations by `source` (`seed`, `watch`) and `result` (`ready`, `waiting_sid`, `invalid`, `not_selected`) |

- A slice that turns `invalid` keeps any route it had: the sidecar keeps the
  last good desired state rather than tearing the route down. A successful
  reconcile therefore does not mean the slice was usable.
- The startup seed and the watch evaluate slices concurrently. Once the watch
  has seen a slice during a seed, the seed's result for it counts as an
  evaluation but does not set its state, so a list taken earlier can neither
  overwrite a newer update nor bring back a deleted slice.
- The state is eventually consistent: a watch observation read from a
  lagging cache can briefly hold older data than the seed's list, until the
  slice's next event.
- One entry per selected slice is kept, removed when the reconciler finds the
  slice deleted or without the tenant label. The watch currently drops an
  update that only removes the label, so a deselected slice keeps its last
  state here, and its route, until it is deleted or the sidecar restarts.
  These add 11 fixed series per sidecar.

```promql
# Slices that cannot be parsed, and slices still waiting for their SID
galactic_ingress_sidecar_endpoint_slices{state=~"invalid|waiting_sid"} > 0
```

### Datapath checks

Every sweep reads the shared eBPF datapath's generation and, when it has not
changed, reads this sidecar's rows back from the two registration maps
(`vrf_table`, `ifindex_vrf_table`). A changed generation, missing rows, or a
pass that left something unapplied makes it reapply every tracked VRF and
route. These checks do not cover every route, the TC attachment, the
gateway's local route or the host return path, so `ok` here is not full
datapath health.

| Metric                                                                     | Type    | Labels             | Meaning                                                                                                                                   |
| -------------------------------------------------------------------------- | ------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic_ingress_sidecar_datapath_checks_total`                           | counter | `check`, `result`  | Completed checks: `generation` (`ok`, `error`) and `registration_rows` (`ok`, `missing`, `error`)                                         |
| `galactic_ingress_sidecar_datapath_check_status`                           | gauge   | `check`, `status`  | 1 for each check's latest status, 0 for its others: `unknown` (not read yet, or an `ok` not re-read this sweep), `ok`, `missing`, `error` |
| `galactic_ingress_sidecar_datapath_check_last_completed_timestamp_seconds` | gauge   | `check`            | Unix time each check last completed, whatever its result; 0 before the first                                                              |
| `galactic_ingress_sidecar_datapath_reapply_total`                          | counter | `reason`, `result` | Reapply passes by `reason` (`generation_changed`, `rows_missing`, `retry`) and `result` (`success` when every reapply succeeded, `error`) |
| `galactic_ingress_sidecar_datapath_reapply_pending`                        | gauge   | none               | 1 while a pass left something unapplied, until a later one succeeds                                                                       |

- A failed read is `error`, not `ok`: the state is unknown. Repair stays
  conservative and does not reapply on a failed read; the next successful
  read decides.
- The rows are read only while the generation is unchanged and no retry is
  due, and only when there is a VRF to read back. On any other sweep, and
  after a reapply rewrote them, a last `ok` becomes `unknown`; a `missing` or
  `error` stays until a read replaces it, so a problem never turns into an
  unverified healthy result. Its timestamp shows when the rows were last read.
- A pass's reason is `generation_changed` whenever the generation moved, even
  if a retry was also due; otherwise `rows_missing` when this sweep found rows
  gone, otherwise `retry`. `reapply_total` keeps counting every pass, of any
  reason. These add 22 fixed series per sidecar.

```promql
# A check that failed or found rows missing
galactic_ingress_sidecar_datapath_check_status{status=~"missing|error"} == 1

# A check that completed before but not in the last three sweeps (15s at the
# default 5s sweep interval)
(galactic_ingress_sidecar_datapath_check_last_completed_timestamp_seconds > 0)
  and (time() - galactic_ingress_sidecar_datapath_check_last_completed_timestamp_seconds > 15)

# Reapply churn by reason
sum by (namespace, pod, reason) (increase(galactic_ingress_sidecar_datapath_reapply_total[10m]))
```

### Return-path gateway

With a node name configured, the sidecar publishes one return-path gateway
advertisement per VPC, so a backend's replies have a route back to this
node: it resolves the VPC's gateway address, then writes a
`BGPAdvertisement`. Either step can fail without failing the route that
triggered it.

| Metric                                                              | Type    | Labels                | Meaning                                                                                          |
| ------------------------------------------------------------------- | ------- | --------------------- | ------------------------------------------------------------------------------------------------ |
| `galactic_ingress_sidecar_gateway_publication_enabled`              | gauge   | none                  | 1 when the sidecar publishes return-path advertisements                                          |
| `galactic_ingress_sidecar_gateway_address_assignment_enabled`       | gauge   | none                  | 1 when the sidecar assigns each VPC's gateway address from its own gateway prefix                |
| `galactic_ingress_sidecar_gateway_vrfs`                             | gauge   | `state`               | Installed, non-draining VRFs by `state`: `awaiting_address`, `awaiting_publication`, `published` |
| `galactic_ingress_sidecar_gateway_oldest_pending_timestamp_seconds` | gauge   | none                  | Unix time the longest-unpublished VRF started waiting; 0 when none waits                         |
| `galactic_ingress_sidecar_gateway_operations_total`                 | counter | `operation`, `result` | `resolve` (`success`, `error`, `not_provisioned`), `publish` and `withdraw` (`success`, `error`) |

- `published` is local publication only: the advertisement was written.
  It does not show the route reached any BGP peer, or that the
  advertisement still exists; nothing re-checks it after publication.
- With publication disabled every `gateway_vrfs` series is 0, so check
  `gateway_publication_enabled` before reading 0 as healthy. Disabled,
  idle (enabled with no VRFs), waiting and published are all distinct.
- With publication enabled but address assignment off, the sidecar only
  finds an address something else provisioned, so VRFs waiting in
  `awaiting_address` and `resolve{result="not_provisioned"}` counting up on
  every attempt are expected there.
- A successful withdrawal clears a VRF's published state, so a VRF
  withdrawn for teardown that then survives, because its removal failed,
  and whose VPC comes back is published again, like any VRF waiting.
- A VRF waits from when it is first counted unpublished, through retries,
  until it is published or starts draining. A failed withdrawal is counted
  and teardown carries on; garbage collection removes the advertisement it
  leaves. These add 13 fixed series per sidecar.

```promql
# Gateway publication pending for more than a minute, only where the sidecar
# both publishes and assigns the address itself
(time() - galactic_ingress_sidecar_gateway_oldest_pending_timestamp_seconds > 60)
  and (galactic_ingress_sidecar_gateway_oldest_pending_timestamp_seconds > 0)
  and on (namespace, pod) (galactic_ingress_sidecar_gateway_publication_enabled == 1)
  and on (namespace, pod) (galactic_ingress_sidecar_gateway_address_assignment_enabled == 1)

# Resolve and publish failures, as opposed to waiting for an address
sum by (namespace, pod, operation) (
  rate(galactic_ingress_sidecar_gateway_operations_total{result="error"}[10m]))
```

### Node source address

`node_src_addr_table` holds this node's SRv6 source address, which
`usid_egress` stamps on every packet it encapsulates. Until it holds one,
encapsulation fails open and nothing is counted. While any VRF is installed,
each sweep reads the table, writes the address resolved from this node's
`BGPRouter` when the table is unset or holds another, and reads the write
back.

| Metric                                                                        | Type    | Labels   | Meaning                                                                                 |
| ----------------------------------------------------------------------------- | ------- | -------- | --------------------------------------------------------------------------------------- |
| `galactic_ingress_sidecar_node_source_address_status`                         | gauge   | `status` | 1 for the last check's result: `unknown`, `unconfigured`, `ok`, `unresolved` or `error` |
| `galactic_ingress_sidecar_node_source_address_last_checked_timestamp_seconds` | gauge   | none     | Unix time of the last sweep that checked the table; 0 before the first                  |
| `galactic_ingress_sidecar_node_source_address_repairs_total`                  | counter | none     | Sweeps that found the table unset or holding another address and wrote this node's      |

- `unknown` means no VRF has been installed since the sidecar started, so
  nothing has checked. Sweeps check only while a VRF is installed, so after
  the last one is removed the status and timestamp keep their last values;
  alert on the timestamp's age only where VRFs are installed.
- `unconfigured` means the sidecar has no node name, so it cannot resolve the
  address. `unresolved` means this node's `BGPRouter` has no SRv6 locator and
  node ID yet, and the table was left as it was.
- `error` covers a failed read or write, and a write that did not read back.
  The status and timestamp are read from one snapshot.
- The repair count includes a sweep that sets the address after a restart,
  when it could not be resolved as the VRF was created. A count that keeps
  rising means something keeps changing the table: a datapath reload,
  another writer, or galactic-cni writing an address that disagrees with this
  node's `BGPRouter` as the sidecar reads it. These add 7 fixed series per
  sidecar.

```promql
# Encapsulation failing open: the source address is not set
max_over_time(galactic_ingress_sidecar_node_source_address_status{status=~"unresolved|error"}[10m]) == 1
```

### Host return path — `galactic_sidecar_return_*`

`galactic-cni` installs the host side of each sidecar's return path: for every
gateway address a sidecar on the node advertises, a route, a permanent
neighbor and a `vrf_table` entry that point a decapsulated reply at the
sidecar's pod. It runs one pass each tick, and these series report it. A
published advertisement only shows the sidecar's half; these show whether
replies can reach the pod.

| Metric                                                     | Type    | Labels                | Meaning                                                                                   |
| ---------------------------------------------------------- | ------- | --------------------- | ----------------------------------------------------------------------------------------- |
| `galactic_sidecar_return_endpoints`                        | gauge   | `state`               | `desired` (advertised), `applied` (installed by the last pass), `pending` (not installed) |
| `galactic_sidecar_return_reconcile_total`                  | counter | `result`              | Passes: `success`, `partial`, `waiting_identity`, `error`                                 |
| `galactic_sidecar_return_last_completed_timestamp_seconds` | gauge   | none                  | Unix time of the last pass that listed the advertisements; 0 before the first             |
| `galactic_sidecar_return_operations_total`                 | counter | `operation`, `result` | `install` (per endpoint), `register`, `prune`, `reap`, each `success` or `error`          |

- `applied` and `pending` partition `desired`; do not add all three. A
  scrape reads the three counts and the timestamp from one pass.
- `partial` means an endpoint failed to install or the prune failed.
  `waiting_identity` means endpoints are advertised but this node's
  `BGPRouter` has no SRv6 locator yet, so all are pending. `error` means
  nothing could be installed: listing the advertisements, reading the node's
  identity, or registering the node in the maps failed. A failed prune on a
  `waiting_identity` or `error` pass shows only in `operations_total`.
- A pass that cannot list the advertisements leaves the counts and the
  timestamp as they were. An ageing timestamp, not a zero count, is how a
  failing or stalled pass shows. A node with no sidecar reports a fresh
  timestamp and 0 desired. A node without a Kubernetes client or node name
  never runs a pass, and its timestamp stays 0.
- `install` success means the route, neighbor and map entry were written. It
  does not prove a reply reached the pod. These add 16 fixed series per node.

```promql
# Return path not installed for some endpoint for 10 minutes; a fresh node
# waiting for its SRv6 locator is pending briefly
min_over_time(galactic_sidecar_return_endpoints{state="pending"}[10m]) > 0

# Return path pass stalled (passes run every 30s)
time() - galactic_sidecar_return_last_completed_timestamp_seconds > 300
```

## Edge load balancer — `galactic_edge_*`

`galactic-gateway`'s XDP DSR load balancer on gateway-role edge nodes.
Every gateway node serves every VIP identically (anycast), so the same
series appear on each one. Direct server return keeps no per-flow state,
so there is no connection table to report. See
[ARCHITECTURE-GATEWAY.md](agents/ARCHITECTURE-GATEWAY.md).

| Metric                                                  | Type    | Labels                              | Meaning                                                                                              |
| ------------------------------------------------------- | ------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `galactic_edge_rule_packets_total`                      | counter | `proto`, `port`, `vip`, `vpc`       | Packets that matched the VIP, port and protocol, whatever happened to them next                      |
| `galactic_edge_rule_bytes_total`                        | counter | same                                | Bytes of those packets                                                                               |
| `galactic_edge_rule_dropped_packets_total`              | counter | same                                | Matched packets the datapath then dropped, such as for no backends. A subset of `rule_packets_total` |
| `galactic_edge_rule_backends`                           | gauge   | same                                | Backends registered for the VIP                                                                      |
| `galactic_edge_rule_seconds_since_last_packet`          | gauge   | same                                | Seconds since a packet last matched the VIP. Absent until the first one                              |
| `galactic_edge_return_packets_total`                    | counter | `vip`, `vpc`                        | Replies sourced from the VIP that this node forwarded past the kernel (`edge_return`)                |
| `galactic_edge_return_bytes_total`                      | counter | same                                | Bytes of those replies                                                                               |
| `galactic_edge_return_dropped_packets_total`            | counter | same                                | Replies sourced from the VIP that the datapath dropped. A subset of `return_packets_total`           |
| `galactic_edge_drops_total`                             | counter | `reason`                            | Packets `edge_lb` and `edge_return` dropped, by reason                                               |
| `galactic_edge_control_plane_drops_total`               | counter | `rule`, `reason` (`quota_exceeded`) | Rule applications refused before they reached the datapath                                           |
| `galactic_edge_dispatch_lease_renewals_total`           | counter | `slot`, `result`                    | Renewals of the gateway's XDP dispatcher slot leases. Dispatch mode only                             |
| `galactic_edge_dispatch_lease_expiry_timestamp_seconds` | gauge   | `slot`                              | Unix time each lease, as last renewed, expires. Dispatch mode only                                   |

- `proto` is `tcp`, `udp`, or the protocol number for anything else.
- `vpc` is empty until the process has applied a rule that owns the VIP,
  as after a restart before the first reconcile. A VIP address used by
  rules of more than one VPC has an empty `vpc` on its return series, since
  the return counters can't be split between them.
- The per-VIP counters survive re-registration, such as a reconcile that
  only changes the backend list. The return series read zero, not absent,
  on a node with no compute tier behind it.
- `galactic_edge_drops_total` reasons: `empty_backend_list`,
  `no_encap_config`, `fib_no_neigh`, `fib_unreachable`, `fib_frag_needed`,
  `fib_lookup_failed`, `adjust_head_failed`, `no_egress_ifindex`,
  `redirect_failed`, `return_hop_limit`, `icmp_rate_limited`, plus
  `unknown_<n>` for an index the binary has no name for.

The port also serves controller-runtime's metrics for the
`NetworkGateway`/`NetworkService` reconcilers.

```promql
# Requests per second per VIP and port
sum by (vpc, vip, port, proto) (rate(galactic_edge_rule_packets_total[5m]))

# VIPs with no backends
max by (vip, port, proto) (galactic_edge_rule_backends) == 0

# Drops by reason
sum by (node, reason) (rate(galactic_edge_drops_total[5m])) > 0

# Rules refused by quota
sum by (node, rule) (increase(galactic_edge_control_plane_drops_total[1h])) > 0
```

## Traffic policy — `galactic_cni_traffic_policy_*`

Interface traffic policy decisions in the uSID datapath. The counters live in
per-CPU BPF maps the datapath writes; `galactic-router`, which allocates
every counter row and knows the rule, policy and interface it belongs to,
reads and labels them, so they are served on its port (9179) and scraped by
the `galactic-router` PodMonitor. The prefix names the datapath, not the
process. Only routers running with `GALACTIC_ROUTER_TRAFFIC_POLICY=true`
export them. See [traffic-policy/node.md](traffic-policy/node.md).

| Metric                                                 | Type    | Labels                                                                                            | Meaning                                                                                 |
| ------------------------------------------------------ | ------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `galactic_cni_traffic_policy_rule_hits_total`          | counter | namespace, vpc, attachment, interface, interface_uid, direction, policy, policy_uid, rule, action | Packets evaluated with this rule as the winning rule                                    |
| `galactic_cni_traffic_policy_rule_bytes_total`         | counter | the same                                                                                          | Tenant IP bytes evaluated with this rule as the winning rule                            |
| `galactic_cni_traffic_policy_fallback_packets_total`   | counter | namespace, vpc, attachment, interface, interface_uid, direction, reason                           | Packets denied without a winning rule                                                   |
| `galactic_cni_traffic_policy_fallback_bytes_total`     | counter | the same                                                                                          | Tenant IP bytes denied without a winning rule                                           |
| `galactic_cni_traffic_policy_unattributed_drops_total` | counter | direction, reason                                                                                 | Policy denials whose interface or fallback row could not be resolved                    |
| `galactic_cni_traffic_policy_accounting_errors_total`  | counter | direction, action, reason                                                                         | Verdicts whose rule counter row was missing; the verdict stood, the count was lost      |
| `galactic_cni_traffic_policy_counter_read_errors`      | gauge   | none                                                                                              | Counter rows the last scrape could not read, and so left out rather than reporting zero |

- `direction` is `ingress` or `egress`; `action` is `allow` or `deny`.
- `reason` is one of `no_match`, `policy_unavailable`, `parse_error` or
  `classification_error`; `accounting_errors_total` uses
  `missing_rule_counter`.
- `interface_uid` is the VPCAttachment UID. `policy_uid` is the policy's
  UID, or `builtin:default-deny-all:v1` for a direction with no reference,
  which gets the built-in default. Its deny-all rule is a rule hit, not a
  fallback, so the default stays visible per interface and direction.
- One evaluation produces one outcome: a rule's hit and bytes, or one
  fallback pair. A packet between two managed interfaces is two
  evaluations, the sender's egress and the receiver's ingress.
- A hit is a policy decision, not forwarded traffic: an allowed packet
  dropped later still counts.
- Bytes are the tenant IP packet at the evaluation point, without Ethernet
  or outer SRv6. A GSO packet counts once, at its buffer length. A packet
  whose IP boundary cannot be found adds zero bytes.
- A rule keeps its series while its name and action stay the same within
  one policy and interface lifetime, so editing its match keeps counting.
  Rename a rule to start a fresh measurement. Rebinding another policy,
  removing a rule, flipping its action, or recreating the interface starts
  from zero.
- A node reboot or a datapath reload resets them. Use `rate()` or
  `increase()`.

```promql
# Rule hits per second, aggregated across nodes and interfaces.
sum by (namespace, policy, rule, direction, action) (
  rate(galactic_cni_traffic_policy_rule_hits_total[5m])
)

# Tenant bytes per second explicitly denied by a rule on each interface.
sum by (namespace, attachment, interface, interface_uid, direction, rule) (
  rate(galactic_cni_traffic_policy_rule_bytes_total{action="deny"}[5m])
)

# Failures and no-match denies, which are not attributed to a winning rule.
sum by (namespace, direction, reason) (
  rate(galactic_cni_traffic_policy_fallback_packets_total[5m])
)

# Interfaces still on the built-in default deny.
count by (namespace, attachment, direction) (
  galactic_cni_traffic_policy_rule_hits_total{policy_uid="builtin:default-deny-all:v1"}
)

# Counts the datapath lost or could not attribute.
sum by (node, direction, reason) (
  rate(galactic_cni_traffic_policy_unattributed_drops_total[5m])
  or rate(galactic_cni_traffic_policy_accounting_errors_total[5m])
) > 0
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

Datapath drops on these paths are the `service_route_*` reasons of
`galactic_usid_drops_total`.

```promql
sum by (node, operation) (rate(galactic_service_route_route_operations_total{result="error"}[10m])) > 0
```

## NAT66 / NAT64 — `galactic_nat_*`

One `galactic-nat` pod per egress shard; every value is per shard.

| Metric                                                 | Type    | Labels                                                                    | Meaning                                                                                                                              |
|--------------------------------------------------------|---------|---------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| `galactic_nat_conns`                                   | gauge   | `family` (`nat66`, `nat64`)                                               | Rows in the connection table, expired sessions included. A session holds two rows                                                    |
| `galactic_nat_sessions`                                | gauge   | `family`, `proto` (`tcp`, `udp`, `icmp`)                                  | Live sessions: one per session within its idle timeout                                                                               |
| `galactic_nat_conn_table_oldest_row_age_seconds`       | gauge   | none                                                                      | Seconds since the least recently seen session, expired ones included, last translated a packet. Meaningful only on a near-full table |
| `galactic_nat_conn_table_max_entries`                  | gauge   | none                                                                      | Table capacity in rows, shared by both families                                                                                      |
| `galactic_nat_drops_total`                             | counter | `reason`                                                                  | Packets dropped by the NAT datapath                                                                                                  |
| `galactic_nat_packets_total`                           | counter | `family`, `direction` (`outbound`, `return`), `action` (`redirect`, `tx`) | Packets the shard translated and queued for transmit. Every combination is reported, zero included                                   |
| `galactic_nat_bytes_total`                             | counter | same                                                                      | Bytes of those packets: the translated IP packet, without Ethernet or the SRv6 outer header                                          |
| `galactic_nat_datapath_enabled`                        | gauge   | none                                                                      | 1 when the datapath is turned on by configuration, 0 when it is turned off                                                           |
| `galactic_nat_datapath_attached`                       | gauge   | none                                                                      | 1 once the datapath has loaded and attached, 0 before that or while turned off                                                       |
| `galactic_nat_programmed`                              | gauge   | none                                                                      | 1 while the datapath holds an EgressShard identity, 0 while it claims no packet                                                      |
| `galactic_nat_uplink_covered`                          | gauge   | `interface`                                                               | 1 for each resolved uplink the datapath translates on, 0 for one it misses. Absent while turned off                                  |
| `galactic_nat_family_enabled`                          | gauge   | `family`                                                                  | 1 when the programmed identity has a masquerade address for the family                                                               |
| `galactic_nat_info`                                    | gauge   | `shard_sid`, `nat64_prefix`, `xdp_attach`, `version`                      | Always 1. Empty `shard_sid` and `nat64_prefix` while unprogrammed; `xdp_attach="off"` while turned off                               |
| `galactic_nat_masquerade_ports_in_use`                 | gauge   | `family`, `address`, `proto`                                              | Distinct masquerade ports live sessions hold on the address, toward any destination                                                  |
| `galactic_nat_masquerade_destination_ports_max`        | gauge   | `family`, `address`, `proto`                                              | The most ports live sessions hold toward any single destination address and port. New flows to it fail as this nears the range       |
| `galactic_nat_masquerade_port_range`                   | gauge   | none                                                                      | Ports (or ICMP Echo Identifiers) available toward each destination: 28000                                                            |
| `galactic_nat_dispatch_lease_renewals_total`           | counter | `slot`, `result` (`success`, `error`)                                     | Renewals of the shard's XDP dispatcher slot lease. Dispatch mode only                                                                |
| `galactic_nat_dispatch_lease_expiry_timestamp_seconds` | gauge   | `slot`                                                                    | Unix time the lease, as last renewed, expires. Dispatch mode only                                                                    |
| `galactic_nat_session_creates_total`                   | counter | `family`, `proto`                                                         | New sessions the shard opened, one masquerade port claim each                                                                        |
| `galactic_nat_masquerade_claim_probes_total`           | counter | `family`, `proto`, `probes` (`1`..`8`)                                    | Those claims by how many probes each took. Rising multi-probe shares mean busy destinations are filling                              |
| `galactic_nat_uplink_resolve_errors_total`             | counter | none                                                                      | Failed re-resolutions of the uplinks after a link or route change; the shard keeps its previous coverage                             |
| `galactic_nat_uplink_rx_queue_packets_total`           | counter | `interface`, `driver`, `queue`                                            | Packets one NIC receive queue of an uplink received, from `ethtool -S`. Exported for `bnxt_en`, `ixgbe`, `ice`, `i40e`, `mlx5_core`  |
| `galactic_nat_uplink_rx_queue_discards_total`          | counter | `interface`, `driver`, `queue`                                            | Packets one receive queue discarded before the datapath saw them. Reported only by drivers that count per queue: `bnxt_en` today     |
| `galactic_nat_uplink_queue_driver_stat_total`          | counter | `interface`, `driver`, `queue`, `stat`                                    | One of a queue's other driver counters, under its `ethtool -S` name. `bnxt_en` only, see below                                       |
| `galactic_nat_uplink_info`                             | gauge   | `interface`, `driver`, `driver_version`, `firmware_version`, `kernel`     | Always 1. Names each uplink's driver and NIC firmware versions and the node's kernel release                                         |

Caveats for the translated traffic and state series:

- `outbound` is tenant traffic the shard decapsulated and translated toward
  the internet; `return` is a reply translated back and encapsulated toward
  the tenant. `tx` means the packet left over the uplink it arrived on,
  `redirect` over another one.
- Messages the shard sends on its own behalf (Packet Too Big, Fragmentation
  Needed, echo replies to its own address) and packets it passes on
  unclaimed are not translations and are not counted.
- The counters live in a pinned map, so they outlive a pod restart, like
  `galactic_nat_drops_total`.
- A shard can be attached and programmed and still translate nothing, when
  its uplinks never hand it the traffic. Compare
  `galactic_nat_packets_total{direction="outbound"}` with the compute nodes'
  `galactic_cni_egress_shard_packets_total` for its `shard_sid`
  (`GalacticNatNotTranslating`).
- Cardinality: 8 series each for packets and bytes, one `uplink_covered`
  series per uplink, and one `info` series per shard.

Caveats for the masquerade port series:

- A port is claimed per destination address and port, not per masquerade
  address, so the same port can serve many destinations at once.
  `galactic_nat_masquerade_ports_in_use` can sit near the range on a healthy
  shard that talks to many destinations;
  `galactic_nat_masquerade_destination_ports_max` is what predicts exhaustion.
- A claim probes 8 of the range's ports, so a destination fails new flows well
  before it is full: about 0.4% of new flows at half full, 17% at 80%
  (`GalacticNatPortsNearExhaustion` warns at half full).
- Every protocol of every address the programmed identity serves is reported,
  zero included, except when the session clock cannot be read: then only the
  range is reported, rather than zeros that would read as an idle shard. An
  address a re-programmed identity replaced is reported while live sessions
  still hold its ports.
- Both are read from the session table walk at scrape time, like
  `galactic_nat_sessions`, so they are approximate on a churning table.

Caveats for session creation:

- `galactic_nat_session_creates_total` is the sum of
  `galactic_nat_masquerade_claim_probes_total` over `probes`. A claim that
  finds no port is a `*_pat_exhausted` drop, and a claim that adopts a live
  session's lost port opens no new session; neither is counted.
- With a share u of a destination's ports held, a claim needs more than k
  probes with probability of roughly u^k (the probes walk consecutive ports,
  and held ports cluster, so it is an estimate). The share of claims needing more than one
  probe therefore estimates how full the destinations taking new flows are,
  before `galactic_nat_masquerade_destination_ports_max` names the worst one
  and long before `*_pat_exhausted` drops start.
- Cardinality: 6 creates series and 48 probe series per shard.

The `EgressShard` reconciler's controller-runtime metrics
(`controller_runtime_reconcile_total{controller="egressshard"}`,
`controller_runtime_reconcile_errors_total`, `workqueue_*`) are served on the
same port, from the same registry.

The dispatcher lease series are registered in dispatch mode only. The
edge gateway exports the same pair as `galactic_edge_dispatch_lease_*` for
its two slots; no shipped alert reads the gateway's yet.

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

Caveats for the uplink queue counters:

- `galactic_nat_uplink_queue_driver_stat_total` carries `bnxt_en`'s other
  per-ring counters: transmit packets, discards and errors, `rx_errors`,
  `rx_buf_errors`, `rx_resets` and `missed_irqs`. A ring's receive and transmit
  share one completion ring, so comparing a stalled ring's transmit rate with
  its siblings' shows whether transmit stopped along with receive.
- `galactic_nat_uplink_info` is exported for every uplink, whatever its
  driver, so per-queue behavior can be matched against driver, firmware and
  kernel versions across nodes.

```promql
# Live sessions per family
sum by (node, family) (galactic_nat_sessions)

# Idle live sessions being evicted: table full, oldest row younger than the TCP timeout
# (GalacticNatSessionTableEvictingLive)
sum by (node) (galactic_nat_conns) / on (node) max by (node) (galactic_nat_conn_table_max_entries) > 0.9
  and on (node) max by (node) (galactic_nat_conn_table_oldest_row_age_seconds) < 7440

# Port exhaustion or no shard
sum by (node, reason) (rate(galactic_nat_drops_total{reason=~".*_pat_exhausted|nat64_shard_unavailable"}[5m])) > 0

# New flows dropped for want of a port, held for 15 minutes (GalacticNatPortExhausted)
sum by (node, reason) (increase(galactic_nat_drops_total{reason=~"nat(66|64)_pat_exhausted"}[10m])) > 0

# Drop rate by reason
sum by (node, reason) (rate(galactic_nat_drops_total[5m])) > 0

# Translated packets per shard and direction
sum by (node, direction) (rate(galactic_nat_packets_total[5m]))

# Share of the shard's own traffic it dropped (GalacticNatForwardDropRatio)
sum by (node) (rate(galactic_nat_drops_total{reason=~"nat(66|64)_pat_exhausted|nat(66|64)_malformed_forward|redirect_failed|no_egress_ifindex|adjust_head_failed"}[10m]))
  / (sum by (node) (rate(galactic_nat_drops_total{reason=~"nat(66|64)_pat_exhausted|nat(66|64)_malformed_forward|redirect_failed|no_egress_ifindex|adjust_head_failed"}[10m]))
     + sum by (node) (rate(galactic_nat_packets_total[10m])))

# Busiest destination per masquerade address, as a share of the range (GalacticNatPortsNearExhaustion)
max by (node, family, address, proto) (galactic_nat_masquerade_destination_ports_max)
  / on (node) group_left () max by (node) (galactic_nat_masquerade_port_range)

# Share of new sessions whose port claim needed more than one probe
sum by (node, family) (rate(galactic_nat_masquerade_claim_probes_total{probes!="1"}[10m]))
  / sum by (node, family) (rate(galactic_nat_session_creates_total[10m]))

# Seconds left on the dispatcher lease, by the node's clock
galactic_nat_dispatch_lease_expiry_timestamp_seconds - time()

# No successful lease renewal in two minutes (GalacticNatDispatchLeaseExpiring)
changes(galactic_nat_dispatch_lease_renewals_total{result="success"}[2m]) == 0

# Shards turned on but not programmed, and uplinks not covered
galactic_nat_datapath_enabled == 1 and on (node) galactic_nat_programmed == 0
galactic_nat_uplink_covered == 0

# Discard share per uplink receive queue (#673)
rate(galactic_nat_uplink_rx_queue_discards_total[5m])
  / (rate(galactic_nat_uplink_rx_queue_discards_total[5m]) + rate(galactic_nat_uplink_rx_queue_packets_total[5m]))

# Transmit rate on each uplink ring, to compare a stalled ring with its siblings (#673)
sum by (node, interface, queue) (
  rate(galactic_nat_uplink_queue_driver_stat_total{stat=~"tx_(ucast|mcast|bcast)_packets"}[5m])
)
```

## Fabric looking glass — `fabric_api_*`

The opt-in fabric-api exports `fabric_api_node_*` from each node sidecar
(9345) and `fabric_api_gateway_*` from each cell gateway (9347). Both
export `fabric_api_credentials_loaded` and
`fabric_api_certificate_expiry_timestamp_seconds` for their mTLS identity.
Its full metric list, with labels and meanings, lives with the rest of
its operator reference in
[fabric-api/configuration.md](fabric-api/configuration.md).

## Shipped alerts

`config/monitoring/prometheusrule.yaml` (the `galactic-bgp` PrometheusRule,
unit-tested with `task test:alerts`) covers routing, the NAT session table
and ports, the egress shards' state, drop ratio and uplinks, the compute
nodes' egress shard groups, and the fabric-api looking glass. Every alert
carries `service: galactic`, `team: connect` and a `runbook_url`.

| Alert                                | Fires when                                                         | For | Severity |
|--------------------------------------|--------------------------------------------------------------------|-----|----------|
| FabricBGPSessionDown                 | `frr_bgp_peer_state == 0`                                          | 5m  | critical |
| FabricBGPSessionAdminDown            | `frr_bgp_peer_state == 2`                                          | 1h  | warning  |
| FabricBGPSessionFlapping             | `resets(frr_bgp_peer_uptime_seconds[30m]) >= 3`                    | 0   | warning  |
| FabricBGPPrefixesDropped             | received prefixes under half of an hour ago, session up            | 15m | warning  |
| FabricRouterExporterCollectorFailing | `frr_collector_up == 0`                                            | 10m | warning  |
| FabricRouterMetricsDown              | `fabric-router` scrape down                                        | 5m  | warning  |
| FabricBGPMappedNextHop               | `fabric_router_bgp_mapped_nexthop == 1`                            | 15m | critical |
| FabricBGPRoutesNotInstalled          | `fabric_router_bgp_uninstalled_routes > 0`                         | 10m | warning  |
| FabricConfigAgentMetricsDown         | `fabric-config-agent` scrape down                                  | 5m  | warning  |
| GalacticRouterBMPStationDown         | `galactic_router_bmp_station_up == 0`                              | 10m | warning  |
| GalacticRouterRoutesNotInstalled     | `galactic_router_route_install_failing > 0`                        | 10m | warning  |
| GalacticRouterMetricsDown            | `galactic-router` or `galactic-router-rr` scrape down              | 5m  | warning  |
| GalacticNatSessionTableEvictingLive  | table over 90% full, oldest row under 7440 s                       | 15m | warning  |
| GalacticNatPortExhausted             | `*_pat_exhausted` drops in every 10-minute window                  | 15m | warning  |
| GalacticNatUplinkRxQueueStalled      | one uplink rx queue delivers nothing while discarding              | 10m | critical |
| GalacticNatUplinkRxQueueLossy        | one uplink rx queue discards >1%, most siblings do not             | 30m | warning  |
| GalacticNatNotProgrammed             | turned on, no EgressShard identity                                 | 10m | warning  |
| GalacticNatUplinkUncovered           | `galactic_nat_uplink_covered == 0`                                 | 10m | critical |
| GalacticNatForwardDropRatio          | owned-traffic drops over 1% of translated, over 10 packets/s       | 15m | warning  |
| GalacticNatNotTranslating            | compute nodes send to the shard's SID, it translates none outbound | 10m | critical |
| GalacticNatPortsNearExhaustion       | busiest destination holds over half its port range                 | 10m | warning  |
| GalacticNatDispatchLeaseFailing      | more than two lease renewal errors in every 5-minute window        | 5m  | warning  |
| GalacticNatDispatchLeaseExpiring     | no successful lease renewal in 2 minutes                           | 0   | critical |
| GalacticNatMetricsDown               | `galactic-nat` scrape down                                         | 5m  | warning  |
| GalacticEgressPoolEmpty              | no active shard for a class while routes on the node name it       | 2m  | critical |
| GalacticEgressPoolBelowMinimum       | fewer active shards than `galactic_cni_egress_pool_min_active`     | 10m | warning  |
| GalacticEgressClassUnserved          | every shard ineligible for a class                                 | 15m | warning  |
| GalacticEgressShardGroupDropping     | `group_empty`, `shard_dead` or `parse_failed` in every 5m window   | 10m | warning  |
| GalacticEgressShardWatchNotSynced    | hashed mode, `EgressShard` watch never listed                      | 10m | warning  |
| GalacticEgressSweepFailing           | sweep errors in every 10-minute window                             | 15m | warning  |
| GalacticCNIMetricsDown               | `galactic-cni` scrape down                                         | 5m  | warning  |
| FabricAPIExecutionStalled            | gateway has executions in flight, finished none in 10m             | 10m | warning  |
| FabricAPINodeDiagnosticsUnavailable  | `fabric_api_node_diagnostics_available == 0`                       | 15m | warning  |
| FabricAPINodeUnreachable             | over half of 5+ node calls in 30m unreachable or timed out         | 15m | warning  |
| FabricAPIResultsOversized            | 10+ `ResponseTooLarge` requests on a node in an hour               | 15m | warning  |
| FabricAPICleanupBacklog              | over 50 expired `FabricQuery` objects left                         | 1h  | warning  |
| FabricAPICertificateRenewalFailing   | mTLS certificate expires in under 4 hours                          | 15m | warning  |
| FabricAPICredentialsMissing          | `fabric_api_credentials_loaded == 0`                               | 15m | warning  |
| FabricAPISearchIndexUnsynced         | search index holds routes but is not synced with bgpd              | 15m | warning  |
| FabricAPIMetricsDown                 | `fabric-api-node` or `fabric-api-gateway` scrape down              | 10m | warning  |
