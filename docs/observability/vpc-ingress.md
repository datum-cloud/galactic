# VPC ingress — `galactic_ingress_sidecar_*`

See [scraping and component ports](README.md#where-the-metrics-come-from) and [shipped alerts](alerts.md).

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
(`prune`, skipped after a failed inventory). The sweep starts after the first
inventory attempt either way. A failed inventory is retried before each sweep
until it succeeds, and the prune runs once it does: on a node that has just
booted, the inventory fails until galactic-cni pins the shared eBPF maps. The
prune is not retried.

| Metric                                                            | Type      | Labels            | Meaning                                                                                                                                                     |
| ----------------------------------------------------------------- | --------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic_ingress_sidecar_startup_stage_status`                   | gauge     | `stage`, `status` | 1 for each stage's current status, 0 for its others. `stage`: `seed`, `inventory`, `prune`. `status`: `pending`, `running`, `complete`, `failed`, `skipped` |
| `galactic_ingress_sidecar_startup_attempts_total`                 | counter   | `stage`, `result` | Completed stage attempts, `result` `success` or `error`. The prune is not retried                                                                           |
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

# A stage that ended badly: the inventory is still failing, or the prune failed
# or was skipped
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

### Backend EndpointSlice repair — `galactic_endpointslice_repair_*`

`galactic-cni` recreates the per-pod EndpointSlice of any Running pod on its
node that has a galactic IPv6 attachment but no slice, every 5 minutes (see
[conflist-reference.md](../cni/conflist-reference.md#endpointslice-publish-http-ingress-backend-discovery)).
The HTTP ingress sidecar finds a VPC backend only through that slice, so each
recreated slice is a pod whose HTTP ingress was down until the pass.

| Metric                                         | Type    | Labels | Meaning                                                                        |
| ---------------------------------------------- | ------- | ------ | ------------------------------------------------------------------------------ |
| `galactic_endpointslice_repair_restored_total` | counter | none   | Missing EndpointSlices the repair recreated                                    |
| `galactic_endpointslice_repair_failures_total` | counter | none   | Passes that could not list the node's pods, or read or create an EndpointSlice |

A pod the pass cannot resolve (no NetworkAttachmentDefinition, `BGPRouter` or
`BGPVRFInstance`) is logged and retried on the next pass, not counted as a
failure.

```promql
# Slices going missing on a node: something removed them while their pods ran
increase(galactic_endpointslice_repair_restored_total[1h]) > 0
```
