# Tenant egress pool — `galactic_cni_egress_*`

See [scraping and component ports](README.md#where-the-metrics-come-from) and [shipped alerts](alerts.md).

How each compute node spreads tenant egress across the cluster's
`EgressShard`s. With `GALACTIC_CNI_EGRESS_MODE=hashed`, `usid_egress` keeps
one shard group per translation class: `nat66`, and `nat64:<prefix>` for
each NAT64 prefix. See
[nat/configuration.md](../nat/configuration.md#active-active-egress).

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
