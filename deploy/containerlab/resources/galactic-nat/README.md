# galactic-nat lab overlay (3-shard, now wired up)

What's here: a per-site containerlab overlay for `galactic-nat`, the
sharded egress translation datapath control plane (`config/galactic-nat/`),
built on the same base/per-node-overlay shape
`resources/galactic-gateway/` uses:

- `base/` — the lab's patch onto `config/galactic-nat/base` (image
  override for Kind's locally-built images; see `base/kustomization.yaml`
  and `base/nat-lab-patch.yaml`). Not applied directly, same reason
  `config/galactic-nat/base` itself isn't (`GALACTIC_NAT_UPLINK_INTERFACE`
  and `_SHARD_SID` are required and must be unique per shard node, and at
  least one address family has to be turned on).
- `dfw/`, `sjc/`, `iad/` — one per-site overlay each, per the redesign
  plan's own §8 suggestion to reuse the three existing site workers
  (`dfw-worker`, `iad-worker`, `sjc-worker`) as a 3-shard DaemonSet rather
  than inventing new lab topology. Each pins the DaemonSet to that site's
  own worker via `kubernetes.io/hostname` (`node-patch.yaml`, mirroring
  `resources/galactic-gateway/iad-gateway1/`'s per-node-pin pattern) and
  sets that shard's own `GALACTIC_NAT_SHARD_SID`/`_SHARD_PUB_ADDR` —
  see each `node-patch.yaml`'s own comments for the exact uFMT 48+16
  encoding and address choices, including the note on why the NAT66
  shards use `Argument=1` rather than reusing the gateway nodes'
  `Argument=0` on iad's shared locator. Each site directory also carries
  a sample `EgressShard` object (`egressshard.yaml`) targeting that site's
  worker node.

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

Each shard's `Status.ShardSID` is advertised as a plain, RT-less `/128`
BGPAdvertisement by `EgressShardReconciler`
(`internal/controller/egressshard_controller.go`) — the same shape
`NetworkGatewayReconciler` uses for its own ingress VIP — so every other
node in the mesh learns a real kernel route to it via the existing
RT-less-EVPN main-table import path
(`internal/runtime/gobgp/monitor.go`'s `matchTableID`/`RouteMainAdd`).
`GALACTIC_CNI_EGRESS_SHARD_SIDS` (set identically on every site's
`galactic-cni` DaemonSet, `resources/galactic-cni/daemonset-patch.yaml`)
carries the fabric-wide membership list every compute node needs to build
its own default route — operator-supplied in this phase, not learned
in-cluster; see that env var's own doc comment
(`internal/config/cni.go`) for why.

`task verify:nat66-sharding` checks each site's `EgressShard` status and
`BGPAdvertisement` list.


## NAT64 in this lab

Every shard here is configured for NAT66 only: `GALACTIC_NAT_SHARD_PUB_ADDR`
is set, and `GALACTIC_NAT_SHARD_PUB_ADDR4`/`GALACTIC_NAT_NAT64_PREFIX` are
not. That is a limitation of the topology, not a default worth copying.

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

Unlike `GALACTIC_NAT_SHARD_PUB_ADDR`, the IPv4 address is not advertised
into the fabric by anything in this repo — a NAT64 reply arrives from the
IPv4 internet, so the underlay or an upstream announcement has to attract
it to that node.

What this lab therefore does **not** validate: the NAT64 forward and return
legs end to end. Those are covered at the datapath level instead, in
`internal/plumbing/ebpf/natprog/nat64_test.go`, which runs real packets
through the loaded programs and verifies both translated checksums against
independent full recomputes rather than against the datapath's own
arithmetic.
