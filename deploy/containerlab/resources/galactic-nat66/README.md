# galactic-nat66 lab overlay (3-shard, now wired up)

What's here: a per-site containerlab overlay for `galactic-nat66`, the
sharded NAT66 egress datapath control plane (`config/galactic-nat66/`),
built on the same base/per-node-overlay shape
`resources/galactic-gateway/` uses:

- `base/` — the lab's patch onto `config/galactic-nat66/base` (image
  override for Kind's locally-built images; see `base/kustomization.yaml`
  and `base/nat66-lab-patch.yaml`). Not applied directly, same reason
  `config/galactic-nat66/base` itself isn't ("all three of
  `GALACTIC_NAT66_UPLINK_INTERFACE`/`_SHARD_SID`/`_SHARD_PUB_ADDR` are
  required and must be unique per shard node").
- `dfw/`, `sjc/`, `iad/` — one per-site overlay each, per the redesign
  plan's own §8 suggestion to reuse the three existing site workers
  (`dfw-worker`, `iad-worker`, `sjc-worker`) as a 3-shard DaemonSet rather
  than inventing new lab topology. Each pins the DaemonSet to that site's
  own worker via `kubernetes.io/hostname` (`node-patch.yaml`, mirroring
  `resources/galactic-gateway/iad-gateway1/`'s per-node-pin pattern) and
  sets that shard's own `GALACTIC_NAT66_SHARD_SID`/`_SHARD_PUB_ADDR` —
  see each `node-patch.yaml`'s own comments for the exact uFMT 48+16
  encoding and address choices, including the note on why the NAT66
  shards use `Argument=1` rather than reusing the gateway nodes'
  `Argument=0` on iad's shared locator. Each site directory also carries
  a sample `NAT66Shard` object (`nat66shard.yaml`) targeting that site's
  worker node.

What this reuses: the three existing site workers as shard nodes (no new
lab topology, no new containerlab nodes), and the exact
base/per-node-overlay/patch shape `resources/galactic-gateway/` already
established.

## Wired up

This is now applied by `task deploy:galactic-nat66`
(`deploy/containerlab/Taskfile.yaml`'s `scripts/deploy-galactic-nat66.sh`),
part of the main `task deploy` chain, right after `deploy:galactic-router`
and before `deploy:scenarios` — deliberately in that order, since a tenant
pod's own CNI ADD now installs a default egress route toward these three
shard SIDs (`internal/plumbing/srv6.EgressDefaultRouteAdd`, called from
`internal/cnibgp`) and would fail outright if the shards' own SIDs weren't
reachable yet. `task build`/`task deploy:images` build and load
`galactic-nat66:latest` the same way the other lab images are; RBAC
(`config/galactic-nat66/{serviceaccount,rbac}.yaml`) is applied by
`scripts/deploy-system.sh` alongside `galactic-cni`/`galactic-router`'s
own, and `NAT66Shard`/`BGPVRFInstance` (the latter for NPTv6's own
`nptv6` field) are installed from the local `../network` checkout by that
same script — see its own comments for why.

Each shard's `Status.ShardSID` is advertised as a plain, RT-less `/128`
BGPAdvertisement by `NAT66ShardReconciler`
(`internal/controller/nat66shard_controller.go`) — the same shape
`NetworkGatewayReconciler` uses for its own ingress VIP — so every other
node in the mesh learns a real kernel route to it via the existing
RT-less-EVPN main-table import path
(`internal/runtime/gobgp/monitor.go`'s `matchTableID`/`RouteMainAdd`).
`GALACTIC_CNI_NAT66_SHARD_SIDS` (set identically on every site's
`galactic-cni` DaemonSet, `resources/galactic-cni/daemonset-patch.yaml`)
carries the fabric-wide membership list every tenant node needs to build
its own default route — operator-supplied in this phase, not learned
in-cluster; see that env var's own doc comment
(`internal/config/cni.go`) for why.

`task verify:nat66-sharding` checks each site's `NAT66Shard` status and
`BGPAdvertisement` list.
