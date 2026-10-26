# Active/active egress

By default a compute node sends each tenant VRF to one shard: the first entry
of `GALACTIC_CNI_EGRESS_SHARD_SIDS` that resolves, with every later entry
standing by. Hashed mode spreads tenants across every healthy shard in the
cluster instead, so each shard carries a share of the metro's egress and
losing one costs only the sessions it held. Staging and production rollout,
and rollback, follow
[active-active-rollout.md](active-active-rollout.md).

| Option                | Environment Variable                  | Set on                                          | Default   |
| --------------------- | ------------------------------------- | ----------------------------------------------- | --------- |
| Egress mode           | `GALACTIC_CNI_EGRESS_MODE`            | `galactic-cni`'s `credential-refresh` container | `ordered` |
| Hash                  | `GALACTIC_CNI_EGRESS_HASH`            | `galactic-cni`'s `credential-refresh` container | `source`  |
| Pin idle timeout      | `GALACTIC_CNI_EGRESS_PIN_IDLE`        | `galactic-cni`'s `credential-refresh` container | `2h4m`    |
| Pool minimum (alerts) | `GALACTIC_CNI_EGRESS_POOL_MIN_ACTIVE` | `galactic-cni`'s `credential-refresh` container | `1`       |

Unlike the shard list, these are read by `galactic-cni run`, the long-running
container, not by the init container. A value that does not parse stops the
container at startup rather than falling back to ordered mode, and so does
hashed mode with more than three NAT64 prefixes in
`GALACTIC_CNI_NAT64_PREFIX`.

### Prerequisites

- **The `EgressShard` CRD with `spec.drain`.** `galactic-cni` is built
  against the `network` API version that adds it, but a Go dependency does
  not change a cluster's schema: install the CRD from that `network` release
  in every cluster first. Without it the API server prunes `spec.drain` and
  a drain silently does nothing. Check by writing the field and reading it
  back:
  `kubectl patch egressshard <name> -n galactic-system --type=merge -p '{"spec":{"drain":false}}'`
  then `kubectl get egressshard <name> -n galactic-system -o jsonpath='{.spec.drain}'`
  must print `false`.
- **`galactic-cni` may watch `EgressShard`s.** `config/galactic-cni/rbac.yaml`
  grants `get`, `list` and `watch` on `egressshards`;
  `kubectl auth can-i watch egressshards.galactic.datumapis.com -n galactic-system --as=system:serviceaccount:galactic-system:galactic-cni`
  must answer `yes`.
- **Every shard has its own identity and return route.** Each shard needs a
  distinct `shardSID` locator, a distinct `shardAddressIPv6` and, for NAT64,
  a distinct `shardAddressIPv4`, each originated from that shard's own node.
  In ordered mode only the first shard carried traffic, so a second shard's
  addresses may never have been tested: check that a reply to each of them
  reaches that shard before tenants are spread onto it.

### How a shard is chosen

- **One group per translation class.** A compute node needs `::/0` for
  NAT66 and one route per entry of `GALACTIC_CNI_NAT64_PREFIX` for NAT64.
  Each route names the group for its class, and a group holds only the shards
  that can translate that class: NAT66 needs a `shardAddressIPv6`; NAT64
  toward a prefix needs a `shardAddressIPv4` and that prefix as the shard's
  `nat64Prefix`, or, for the Well-Known Prefix `64:ff9b::/96`,
  `translatesWellKnownPrefix`. A NAT66-only shard therefore never receives
  NAT64 traffic, and a shard translating another NAT64 prefix never receives
  this one's. A shard that is ready but cannot serve a class is counted as
  `ineligible` for it and logged. When no shard can serve NAT66, `::/0`
  gets no route, as an empty shard list gives none. When no shard can serve
  a configured NAT64 prefix, its route still names its own empty group, so
  its packets are dropped and counted as `group_empty` instead of matching
  `::/0` and reaching a NAT66 shard. Either way
  `GalacticEgressClassUnserved` fires. A cluster whose shards all serve one
  family is a legitimate single-family deployment.
- **The pool is the cluster.** One metro is one cluster, so a class's pool is
  every eligible `EgressShard` in `galactic-cni`'s namespace. A shard is a
  candidate once its status carries a `shardSID` and both `Programmed` and
  `Ready` are `True`, and it is not being deleted.
  `GALACTIC_CNI_EGRESS_SHARD_SIDS` is not used for placement in hashed mode.
- **A shard counts only while it is reachable.** A dead node's `EgressShard`
  status goes stale, but its BGP session drops and the route to its SID is
  withdrawn. A candidate takes tenants only while its SID resolves to a
  neighbor on an SRv6 uplink. `galactic-cni` rebuilds the groups on every
  route or neighbor change that can affect a candidate, and every 30 seconds
  as a backstop, so failover takes as long as BGP takes to withdraw the
  route, plus a fraction of a second.
- **The datapath picks per packet.** `usid_egress` hashes the packet and looks
  the hash up in the group's 1021-slot Maglev table. When a shard joins or
  leaves, about `1/N` of tenant addresses move.
- **Placement is per node.** The hash includes the VRF's Linux routing table
  ID, which each compute node allocates for itself. Every node builds the same
  Maglev table, but the same tenant address on two nodes may land on two
  shards. Nothing depends on it doing otherwise: a tenant's NAT sessions,
  its pins and the source SID a shard replies to are all specific to the node
  it runs on, so a workload that moves to another node starts new sessions
  wherever it lands.
- **`source` hashes the tenant's address.** Every connection from one tenant
  address uses one shard per class and so one public address per family,
  which RFC 4787 REQ-2 asks for and which sites that tie a login to the
  client address rely on. One heavy tenant address can never use more than
  one shard. `flow` hashes the 5-tuple and spreads that address over every
  shard, but gives up the single public address. Placement balances
  addresses (or flows), not bytes: shards serving a few heavy tenants carry
  more traffic than their count suggests.
- **Fragments.** In `flow` mode every fragment of a datagram, the first
  included, hashes on its addresses and protocol only, so the fragments of
  one datagram reach one shard. That keeps the shard choice consistent; it
  says nothing about whether the shard translates fragments, which the NAT
  datapath does not fully support (see Known constraints).
- **Pins hold sessions in place.** The first packet from a tenant address
  (in `flow` mode, from a flow) records the shard it went to. Later packets
  follow that pin while the shard is reachable, even after a new shard joins
  or the pinned shard starts draining. A pin expires after
  `GALACTIC_CNI_EGRESS_PIN_IDLE` without a packet, which matches the shard's
  longest idle timeout, so a pin never outlives the session it protects. Pins
  live in a 65536-entry LRU on each compute node and are not shared between
  nodes. One evicted under pressure falls back to the Maglev table, which
  gives the same shard unless the membership changed since it was made. `0`
  turns pins off.
- **Sessions are not replicated.** A session lives on one shard. When a shard
  fails, its sessions break and their tenants are placed elsewhere; only
  sessions on surviving shards continue.

### Draining and removing a shard

Removing a shard without breaking its sessions takes three steps:

1. Set `spec.drain: true`:

   ```sh
   kubectl patch egressshard <name> -n galactic-system --type=merge -p '{"spec":{"drain":true}}'
   ```

   A draining shard takes no new tenant address, and every pinned one keeps
   reaching it until it goes idle. The shard itself changes nothing: it keeps
   translating, advertising its SID and receiving replies.
2. Wait for its sessions to end: `galactic_nat_sessions` on its node falls to
   zero, or to a level you accept losing. A tenant address that keeps
   sending refreshes its pin forever and keeps the shard busy; drain cannot
   move it without breaking its sessions, so decide how long to wait.
3. Delete the `EgressShard` (and remove the node's `nat=enabled` label).

Deleting an `EgressShard` is not a drain. Deletion withdraws the shard's
advertisement and clears its datapath at once, every session on it breaks,
and `galactic-cni` drops it from every group as soon as it sees the deletion.
With pins turned off (`GALACTIC_CNI_EGRESS_PIN_IDLE=0`) there is nothing to
hold a tenant on a draining shard, so draining moves every one of its tenant
addresses at once and breaks their sessions just as a failure would.

### When nothing is reachable

There is no spill-over to another metro. When no shard of a class is
reachable, a new attachment fails its ADD, as it does in ordered mode, and an
existing VRF's packets of that class are dropped and counted as `group_empty`
rather than sent untranslated into the node's main table. A cluster with no
`EgressShard` at all gives VRFs no egress route, which is not an error.

### How the groups are published

A group is one immutable snapshot: its Maglev table and every member's SID,
next hop, drain state and slot generation in a single value. `galactic-cni`
writes a new one-entry inner map for every change and swaps it into
`egress_shard_groups`, an `ARRAY_OF_MAPS`, in one update. A packet therefore
sees the old snapshot or the new one, never a mix of the two; an earlier
design that updated ordinary array values in place let a packet read one
shard's SID with another's MAC addresses while a slot was rewritten.

Every member slot carries a generation that identifies the shard's tenure of
it; a pin is honoured only while its slot still carries the generation it
recorded. Generations come from a counter published in the snapshot
(`next_slot_generation`) and a high-water mark in the running process that
also covers snapshots it built but failed to publish. Neither goes down:
disabling a group keeps the counter, and a restarted `galactic-cni` resumes
from the published value. A generation only an unpublished snapshot held was
never visible to a packet, so no pin can hold it. The counter is 32 bits and
skips 0; wrapping takes four billion slot assignments, far longer than any
pin lives.

### Changing the NAT64 prefix list

A group keeps the class it was first published for, so a class keeps its
group across edits to `GALACTIC_CNI_NAT64_PREFIX` and across restarts. The
pinned group map is the record of which group serves which class; nothing
depends on the order of the list.

- **Reordering** the list changes nothing.
- **Adding** a prefix gives it a group that has never been used, or a retired
  one that no route names any more.
- **Removing** a prefix retires its group. Within one sweep of `galactic-cni`
  restarting, the group is marked closing, so no CNI ADD names it again, and
  every VRF's route toward the removed prefix is deleted. That leaves the
  VRF exactly as an attachment made under the new list: traffic to the old
  prefix follows `::/0`. The next sweep that finds no route naming the group
  disables it, and only then can another prefix take it.
- **Replacing** a prefix when all three NAT64 groups are in use takes two
  sweeps: the new prefix gets a group once the old one is disabled, and has
  no group, so no route, until then.

A route the ingress sidecar owns is never deleted by `galactic-cni`, so a
group it still names stays retired but enabled, serving its old class, and a
new prefix waits for it. A route that names a group published for a
different class, which only an earlier release could leave behind, is moved
to its own class's group, even an empty one, which drops rather than
translate the wrong class.

### Turning it on and off

Follow [active-active-rollout.md](active-active-rollout.md). In short: install
the prerequisites, set `GALACTIC_CNI_EGRESS_MODE=hashed` and roll
`galactic-cni`. Within one sweep of starting, each node builds the groups and
moves every VRF route that pointed at a shard onto its class's group. The
move breaks sessions whose new shard differs from the one they were on,
roughly `(N-1)/N` of them, once.

To go back, set `GALACTIC_CNI_EGRESS_MODE=ordered` and roll `galactic-cni`
again, with `GALACTIC_CNI_EGRESS_SHARD_SIDS` still set on the init container.
Each node first marks its groups closing, so no CNI ADD writes a new route
naming one while they keep forwarding; then moves every route back to the
first reachable shard of the static list; and disables the groups only after
a sweep that read and rewrote every route without an error and found none
left. A sweep that fails leaves the groups forwarding and is retried. A CNI
ADD that read the groups open checks again after writing its routes and
rewrites them in ordered mode if the groups closed meanwhile.
`galactic_cni_egress_group_routes` reaching `0` on every node is the signal
that no route names a group any more. **Do not roll back to a release that
predates hashed mode until it does.** An older `usid_egress` reads a group
route as a redirect to a nonexistent interface and drops the traffic.

### Observability

| Metric                                                     | Meaning                                                                                                                              |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `galactic_cni_egress_mode{mode}`                           | 1 for the configured mode. Always present, so a node configured for hashed mode that never published a group still says so.          |
| `galactic_cni_egress_shard_watch_synced`                   | 1 once the `EgressShard` watch has listed the cluster.                                                                               |
| `galactic_cni_egress_group_routes{class}`                  | Routes naming each class's group after the last successful sweep. Must be 0 before rolling back to an older release.                 |
| `galactic_cni_egress_sweep_errors_total{stage}`            | Sweep failures: `apply`, `refresh`, `watch`, `close`, `disable`.                                                                     |
| `galactic_cni_egress_pool_members{class,state}`            | Each class's shards: `active`, `draining`, `unreachable`, `local` (runs on this node), and `ineligible` (cannot translate it).       |
| `galactic_cni_egress_pool_enabled{class}`                  | 1 while the class's group takes new routes; 0 while it is being retired.                                                             |
| `galactic_cni_egress_pool_min_active`                      | `GALACTIC_CNI_EGRESS_POOL_MIN_ACTIVE`.                                                                                               |
| `galactic_cni_egress_shard_packets_total{shard_sid,class}` | Tenant packets this node sent to each shard for each class, since the shard took its slot. `..._bytes_total` is the same in bytes.   |
| `galactic_cni_egress_shard_selections_total{result}`       | How each packet was placed: `maglev`, `pin_hit`, `pin_stale` (re-placed), or dropped as `group_empty`, `shard_dead`, `parse_failed`. |

A node that never published a group exports no `pool_*` series. That is not
a healthy empty pool: read it together with `galactic_cni_egress_mode` and
`galactic_cni_egress_shard_watch_synced`.

A shard whose `spec.targetRef` names the node itself is `local` on that node.
The node originates the shard's locator, so the SID never resolves over an
uplink there, and it takes no tenant from that node. Hashed mode does not
resolve a local shard's SID at all. Ordered mode, which tries each SID in the
list, fails to resolve it and moves on, so neither mode sends that node's
traffic to its own shard. An edge node running the cluster's only shard
therefore has no active member. It also has no tenant, so
`GalacticEgressPoolEmpty` and `GalacticEgressPoolBelowMinimum` fire only on a
node with routes on the group (`galactic_cni_egress_group_routes` above 0):
an empty pool on a node with nothing to egress is no outage. `config/monitoring/` alerts on these
(`GalacticEgressPoolEmpty`, `GalacticEgressPoolBelowMinimum`,
`GalacticEgressClassUnserved`, `GalacticEgressShardGroupDropping`,
`GalacticEgressShardWatchNotSynced`, `GalacticEgressSweepFailing`,
`GalacticCNIMetricsDown`). That file is the tested source of the rules, not
where they run: on Datum's infra the rules are evaluated centrally from
infra's own copy, so they take effect only once infra installs them there.
To compare shards' load from their own side, compare `galactic_nat_sessions`
across the cluster's shard nodes.

## Rollout

Use the [staging acceptance and rollback checklist](active-active-rollout.md) before enabling hashed mode. The [configuration reference](configuration.md) defines node and shard settings.
