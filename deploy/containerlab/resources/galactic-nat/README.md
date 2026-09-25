# galactic-nat lab overlay (3-shard, now wired up)

What's here: a per-site containerlab overlay for `galactic-nat`, the
sharded egress translation datapath control plane (`config/galactic-nat/`),
built on the same base/per-node-overlay shape
`resources/galactic-gateway/` uses:

- `base/` — the lab's patch onto `config/galactic-nat/base` (image
  override for Kind's locally-built images; see `base/kustomization.yaml`
  and `base/nat-lab-patch.yaml`). Not applied directly: each site's
  uplinks have to be named, since auto-detection would also claim Kind's
  `eth0`, which carries every node's IPv6 default route.
- `dfw/`, `sjc/`, `iad/` — one per-site overlay each, per the redesign
  plan's own §8 suggestion to reuse the three existing site workers
  (`dfw-worker`, `iad-worker`, `sjc-worker`) as a 3-shard DaemonSet rather
  than inventing new lab topology. Each site's `node-patch.yaml` sets
  only `GALACTIC_NAT_UPLINK_INTERFACES` — `dfw` names both of its
  dual-homed compute node's uplinks (`bond0,bond1`, one LACP bond to
  each edge node), `sjc` and `iad` their single `bond0` — each a bond
  the shard attaches to through its members. The shard's identity lives
  in that site's `EgressShard` (`egressshard.yaml`), whose spec assigns
  the SID, both masquerade addresses and the NAT64 prefix; see its
  comments for the exact uFMT 48+16 encoding and address choices. The
  `galactic-nat` process on the target worker programs its datapath from
  that spec.

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

Each shard's `status.shardSID` is advertised as a plain, RT-less
BGPAdvertisement by `EgressShardReconciler`
(`internal/controller/egressshard_controller.go`) — the same shape
`NetworkGatewayReconciler` uses for its own ingress VIP — so every other
node in the mesh learns a real kernel route to it via the existing
RT-less-EVPN main-table import path
(`internal/runtime/gobgp/monitor.go`'s `matchTableID`/`RouteMainAdd`).

It is the SID's covering `/64` (Block + Node-ID, e.g.
`2001:db8:ff01:2001::/64` for dfw's shard), not a `/128`. Each tenant VRF
encapsulates toward this shard with its own 12-bit Argument written into
the SID, so the destination differs per tenant and a host route would
cover exactly one of them. Note that a missing `/64` does not
necessarily fail loudly here: each site originates its locator as a
`/48` into the underlay (`resources/fabric-router/*/frr.conf.*-worker`),
so an Argument-bearing SID can still resolve on the sending node and be
discarded by that aggregate's `Null0` at the far site instead. The shard
address (`status.shardAddressIPv6`) stays a `/128` — it is an ordinary
masquerade source, not a uSID.
`GALACTIC_CNI_EGRESS_SHARD_SIDS` (set identically on every site's
`galactic-cni` DaemonSet, `resources/galactic-cni/shared/daemonset-patch.yaml`)
carries the fabric-wide membership list every compute node needs to build
its own default route — operator-supplied in this phase, not learned
in-cluster; see that env var's own doc comment
(`internal/config/cni.go`) for why.

`task verify:nat-sharding` checks each site's `EgressShard` status and
`BGPAdvertisement` list.


## NAT64 in this lab

Every shard here serves both families: its `EgressShard` spec assigns
`shardAddressIPv6` (NAT66) and the `shardAddressIPv4`/`nat64Prefix` pair
(NAT64). The pair is all-or-nothing; leave both out of a shard's spec to
make it NAT66-only.

Three things have to agree or the NAT64 path is a silent blackhole: the
`nat64Prefix` every shard translates for, `GALACTIC_CNI_NAT64_PREFIX` on
every site's `galactic-cni` DaemonSet
(`resources/galactic-cni/shared/daemonset-patch.yaml`), which gives each
tenant VRF a route toward it, and the prefix DNS64 synthesizes into.

Unlike `shardAddressIPv6`, the IPv4 address is not advertised into the
fabric by anything in this repo — a NAT64 reply arrives over the IPv4
underlay, which carries no EVPN, so each shard node's
`resources/fabric-router/*/frr.conf.*-worker` originates its own `/32`.
`task verify:nat-datapath` drives both families end to end to the
off-fabric host.
