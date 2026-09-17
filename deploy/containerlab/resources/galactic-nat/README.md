# galactic-nat lab overlay (3-shard, now wired up)

What's here: a per-site containerlab overlay for `galactic-nat`, the
sharded egress translation datapath control plane (`config/galactic-nat/`),
built on the same base/per-node-overlay shape
`resources/galactic-gateway/` uses:

- `base/` — the lab's patch onto `config/galactic-nat/base` (image
  override for Kind's locally-built images; see `base/kustomization.yaml`
  and `base/nat-lab-patch.yaml`). Not applied directly, same reason
  `config/galactic-nat/base` itself isn't (`GALACTIC_NAT_UPLINK_INTERFACES`
  and `_SHARD_SID` are required and must be unique per shard node).
- `dfw/`, `sjc/`, `iad/` — one per-site overlay each, per the redesign
  plan's own §8 suggestion to reuse the three existing site workers
  (`dfw-worker`, `iad-worker`, `sjc-worker`) as a 3-shard DaemonSet rather
  than inventing new lab topology. Each pins the DaemonSet to that site's
  own worker via `kubernetes.io/hostname` (`node-patch.yaml`, mirroring
  `resources/galactic-gateway/<edge-node>/`'s per-node-pin pattern) and
  sets that shard's own `GALACTIC_NAT_UPLINK_INTERFACES` and
  `GALACTIC_NAT_SHARD_SID` — `dfw` names both of its
  dual-homed compute node's uplinks (`eth1,eth2`), `sjc` and `iad` their
  single `eth1` —
  see each `node-patch.yaml`'s own comments for the exact uFMT 48+16
  encoding, including the note on why the shards use `Argument=1` rather
  than reusing the gateway nodes' `Argument=0` on iad's shared locator.
  Each site directory also carries that shard's `EgressShard` object
  (`egressshard.yaml`), which is where the masquerade address now lives:
  `spec.shardAddressIPv6`, hand-written here in place of the
  `GALACTIC_NAT_SHARD_PUB_ADDR6` env var a cell controller replaces in
  production. `galactic-nat` rejects that variable at startup rather than
  ignoring it, so a leftover setting fails the DaemonSet loudly.

  Applying these needs the `EgressShard` CRD that carries the spec
  addresses. `deploy-system.sh` installs it from the local `../network`
  checkout (`network_crds_local`), so that checkout has to be on the branch
  that has them — an older CRD has no such field and the API server prunes
  it silently, leaving shards that never get an address.

What this reuses: the three existing site workers as shard nodes (no new
lab topology, no new containerlab nodes), and the exact
base/per-node-overlay/patch shape `resources/galactic-gateway/` already
established.

## Wired up

This is now applied by `task deploy:galactic-nat`
(`deploy/containerlab/Taskfile.yaml`'s `scripts/deploy-galactic-nat.sh`),
part of the main `task deploy` chain, right after `deploy:galactic-router`
and before `deploy:scenarios` — deliberately in that order, since a tenant
pod's own CNI ADD now installs a default egress route toward these three
shard SIDs (`internal/plumbing/srv6.EgressDefaultRouteAdd`, called from
`internal/cnibgp`) and would fail outright if the shards' own SIDs weren't
reachable yet. `task build`/`task deploy:images` build and load
`galactic-nat:latest` the same way the other lab images are; RBAC
(`config/galactic-nat/{serviceaccount,rbac}.yaml`) is applied by
`scripts/deploy-system.sh` alongside `galactic-cni`/`galactic-router`'s
own, and `EgressShard`/`BGPVRFInstance` (the latter for NPTv6's own
`nptv6` field) are installed from the local `../network` checkout by that
same script — see its own comments for why.

Each shard's `Status.ShardSID` is advertised as a plain, RT-less
BGPAdvertisement by `EgressShardReconciler`
(`internal/controller/egressshard_controller.go`) — the same shape
`NetworkGatewayReconciler` uses for its own ingress VIP — so every other
node in the mesh learns a real kernel route to it via the existing
RT-less-EVPN main-table import path
(`internal/runtime/gobgp/monitor.go`'s `matchTableID`/`RouteMainAdd`).

It is the SID's covering `/64` (Block + Node-ID, e.g.
`2001:db8:ff01:9::/64` for dfw's shard), not a `/128`. Each tenant VRF
encapsulates toward this shard with its own 12-bit Argument written into
the SID, so the destination differs per tenant and a host route would
cover exactly one of them. Note that a missing `/64` does not
necessarily fail loudly here: each site originates its locator as a
`/48` into the underlay (`resources/fabric-router/*/frr.conf.*-worker`),
so an Argument-bearing SID can still resolve on the sending node and be
discarded by that aggregate's `Null0` at the far site instead. The shard
address (`Status.ShardAddressIPv6`, which reports what the datapath was
programmed with from `Spec.ShardAddressIPv6`) stays a `/128` — it is an
ordinary masquerade source, not a uSID.
`GALACTIC_CNI_EGRESS_SHARD_SIDS` (set identically on every site's
`galactic-cni` DaemonSet, `resources/galactic-cni/daemonset-patch.yaml`)
carries the fabric-wide membership list every compute node needs to build
its own default route — operator-supplied in this phase, not learned
in-cluster; see that env var's own doc comment
(`internal/config/cni.go`) for why.

That variable is now deprecated, and this lab is deliberately left in the
mid-rollout state it describes: it is read only by an attachment whose
`galactic-bgp` conflist stanza carries no `egress` key, which is every
attachment here until the conflist generator emits one. A stanza that does
carry `egress.shardSIDs` decides for that network alone, and an empty list
there is a network stating it has no egress — which is what makes a
network-level opt-out mean anything. See
[docs/cni/conflist-reference.md](../../../../docs/cni/conflist-reference.md#internet-egress-egress).

`task verify:nat66-sharding` checks each site's `EgressShard` status and
`BGPAdvertisement` list.


## NAT64 in this lab

Every shard here serves IPv6 only: `spec.shardAddressIPv6` is assigned, and
`GALACTIC_NAT_SHARD_PUB_ADDR4`/`GALACTIC_NAT_NAT64_PREFIX` are not set. That is a limitation of the topology, not a default worth copying.

This lab's transit mesh is IPv6-only and has no IPv4 upstream, so there is
nothing for a translated packet to reach and nothing to send a reply back.
Turning NAT64 on here would produce shards that translate outbound traffic
correctly and then blackhole it — which looks identical, from every counter
this component exposes, to a NAT64 deployment that is simply broken. Leaving
it off keeps the lab's NAT66 signal trustworthy.

To enable it on a site once a real IPv4 upstream exists, add to that site's
`node-patch.yaml`:

```yaml
- name: GALACTIC_NAT_SHARD_PUB_ADDR4
  value: "<this shard's own public IPv4 address>"
- name: GALACTIC_NAT_NAT64_PREFIX
  value: "<the fabric-wide /96>"
```

and set `GALACTIC_CNI_NAT64_PREFIX` to the same prefix on every site's
`galactic-cni` DaemonSet (`resources/galactic-cni/daemonset-patch.yaml`),
so each tenant VRF gets a route toward it. Three things have to agree or the
path is a silent blackhole: the prefix the shards translate for, the prefix
the CNI installs a route for, and the prefix DNS64 synthesizes into.

Unlike the assigned IPv6 address, the IPv4 address is not advertised
into the fabric by anything in this repo — a NAT64 reply arrives from the
IPv4 internet, so the underlay or an upstream announcement has to attract
it to that node.

What this lab therefore does **not** validate: the NAT64 forward and return
legs end to end. Those are covered at the datapath level instead, in
`internal/plumbing/ebpf/natprog/nat64_test.go`, which runs real packets
through the loaded programs and verifies both translated checksums against
independent full recomputes rather than against the datapath's own
arithmetic.
