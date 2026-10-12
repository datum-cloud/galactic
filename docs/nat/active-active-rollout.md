# Active/active egress: staging acceptance and rollback

Checklist for enabling hashed egress (`GALACTIC_CNI_EGRESS_MODE=hashed`) in a
cluster, proving it there, and backing it out. How hashed mode works is in
[configuration.md](configuration.md#active-active-egress). Run every step in
staging first; production follows the same list after a release.

Nothing here is done by a `galactic` change alone. The CRD, the RBAC, the
`galactic-cni` environment, the routing for every shard and the alert rules
are deployed by infra.

## 1. Before enabling

- [ ] The release fixes the open findings R02, R03 and R05 recorded in
      [the review resolution](../feature_reviews/egress-active-active_2026-10-09-resolution.md#re-review-findings).
      Until then hashed mode can send a class's traffic to shards that cannot
      translate it.
- [ ] The release running in the cluster contains hashed mode, and the
      privileged CI job (`task test:unit-root`) passed for it on the target
      kernel version. A green unprivileged run skips every datapath test.
- [ ] The `EgressShard` CRD from the `network` release that adds
      `spec.drain` is installed. Prove it persists: patch `spec.drain` to
      its current value on one shard and read it back with
      `-o jsonpath='{.spec.drain}'`. An empty answer means the API server is
      pruning the field.
- [ ] `galactic-cni`'s ClusterRole grants `get`, `list` and `watch` on
      `egressshards`:
      `kubectl auth can-i watch egressshards.network.datumapis.com -n galactic-system --as=system:serviceaccount:galactic-system:galactic-cni`
      answers `yes`.
- [ ] Every shard is `Ready` and `Programmed`, and has its own SID locator,
      its own `shardAddressIPv6` and, for NAT64, its own `shardAddressIPv4`.
      No two shards share any of them.
- [ ] Every shard translates what the compute nodes need: an IPv6 address for
      NAT66, and for each entry of `GALACTIC_CNI_NAT64_PREFIX`, an IPv4
      address and that prefix (or `translatesWellKnownPrefix` for
      `64:ff9b::/96`). A shard missing one is kept out of that class's group,
      which is safe but reduces capacity; decide whether that is intended.
- [ ] Each shard's masquerade addresses are routed back to that shard from
      the internet border: query the border's or transit's BGP for each
      `/128` and `/32` and confirm the path leads to the shard's own node.
- [ ] `GALACTIC_CNI_EGRESS_SHARD_SIDS` stays set on `galactic-cni`'s init
      container. Hashed mode does not read it, but rollback does.
- [ ] Alerting: the `galactic-cni` PodMonitor scrapes every node as
      `job="galactic-cni"` with a `node` label, and the `galactic-cni-egress`
      rule group from `config/monitoring/prometheusrule.yaml` is installed
      in the evaluator that actually notifies (infra's central copy, not
      only this repository). Each rule has its runbook anchor in infra.

## 2. Enable

- [ ] Set on `galactic-cni`'s `credential-refresh` container:
      `GALACTIC_CNI_EGRESS_MODE=hashed`, `GALACTIC_CNI_EGRESS_HASH=source`,
      leave `GALACTIC_CNI_EGRESS_PIN_IDLE` at its default `2h4m`, and set
      `GALACTIC_CNI_EGRESS_POOL_MIN_ACTIVE` to the cluster's shard count.
- [ ] Roll `galactic-cni`. Expect sessions on roughly `(N-1)/N` of tenant
      addresses to break once, as their VRFs move onto the groups.
- [ ] On every compute node: `galactic_cni_egress_mode{mode="hashed"}` is 1,
      `galactic_cni_egress_shard_watch_synced` is 1,
      `galactic_cni_egress_pool_members{state="active"}` equals the shard
      count for every class, `ineligible` is what you expect, and
      `galactic_cni_egress_sweep_errors_total` does not move. Missing pool
      series on a node are a failure, not an idle pool.

## 3. Prove it

Run each with a tenant you can watch from outside, over NAT66 and NAT64, and
over TCP, UDP and ICMP where the cluster supports them. The lab's
`task verify:nat-active-active` automates most of this against the
containerlab topology and is the reference for what to check.

- [ ] Every shard carries traffic: `galactic_cni_egress_shard_packets_total`
      rises for every shard and class, and `galactic_nat_sessions` grows on
      every shard node. Equal tenant counts need not mean equal bytes.
- [ ] One tenant address keeps one public address per family across TCP,
      UDP and ICMP.
- [ ] Large packets and long transfers: a sustained download and a transfer
      with full-size segments complete through each shard.
- [ ] Restart `galactic-cni` during a long download: it completes, and
      tenants keep their shards.
- [ ] Withdraw one shard's route for real (stop its node originating the SID,
      or take its BGP session down) during a download through another shard:
      that download completes, the withdrawn shard's tenants move, and
      `galactic_cni_egress_pool_members{state="unreachable"}` rises. Note the
      time it took. A local prohibit route proves only the node's own
      reaction, not BGP convergence. Sessions on the withdrawn shard break;
      nothing replicates them. Restore it and confirm it rejoins.
- [ ] Drain one shard (`spec.drain: true`): new tenant addresses go to the
      others, a download already on it completes, and its session count
      falls. Undrain it.
- [ ] Add a shard, if the cluster has a spare: established sessions stay
      where they are, and new tenant addresses start reaching it.
- [ ] Make every shard unavailable at once, in a maintenance window only:
      egress stops, `GalacticEgressPoolEmpty` fires, `group_empty` drops are
      counted, nothing leaves untranslated. Restore.
- [ ] Revoke the watch permission and restart `galactic-cni` on one node:
      `GalacticEgressShardWatchNotSynced` fires and egress keeps working
      through the groups it already had. Restore the permission.

## 4. Remove a shard

- [ ] Set `spec.drain: true` and confirm with a read-back.
- [ ] Wait for `galactic_nat_sessions` on its node to reach zero, or a level
      you accept losing. A tenant that never goes quiet keeps it above zero.
- [ ] Only then delete the `EgressShard`. Deletion is not a drain: it tears
      down the shard and every session on it at once.

## 5. Roll back

- [ ] `GALACTIC_CNI_EGRESS_SHARD_SIDS` is set on the init container and
      lists the cluster's shards in preference order.
- [ ] Set `GALACTIC_CNI_EGRESS_MODE=ordered` (keeping the new release) and
      roll `galactic-cni`. Expect sessions whose tenants move to the first
      shard to break.
- [ ] On every compute node, wait for `galactic_cni_egress_group_routes` to
      read 0 for every class and `galactic_cni_egress_pool_enabled` to read 0.
      While a route still names a group the group keeps forwarding, and
      `GalacticEgressSweepFailing` says why a sweep cannot finish.
- [ ] Only now, if needed, roll back the `galactic-cni` image to a release
      without hashed mode. Rolling back earlier blackholes every VRF whose
      route still names a group.
