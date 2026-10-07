# galactic-nat lab overlay (4 shards, one per edge node)

What's here: a per-site containerlab overlay for `galactic-nat`, the
sharded egress translation datapath control plane (`config/galactic-nat/`).
Every edge node runs a shard — `dfw-worker2` and `dfw-worker3` in dfw,
`sjc-worker2` in sjc, `iad-worker2` in iad. Every edge node also runs
`galactic-gateway`, so every shard runs from its own slot of the node's XDP
dispatcher, sharing the uplinks with the gateway. Compute nodes run none.

- `base/` — the lab's patch onto `config/galactic-nat/base` (image
  override for Kind's locally-built images; see `base/kustomization.yaml`
  and `base/nat-lab-patch.yaml`). Not applied directly: each site's
  uplinks have to be named, since auto-detection would also claim Kind's
  `eth0`, which carries every node's IPv6 default route.
- `dfw/`, `sjc/`, `iad/` — one per-site overlay each, applying one
  `galactic-nat` DaemonSet to that site's edge nodes. There is no per-node
  pin: the base's affinity (`galactic.datumapis.com/node: edge` plus
  `galactic.datumapis.com/nat: enabled`) already selects them (the lab
  labels every edge node with both), and nothing about a
  shard's identity lives in the
  DaemonSet. Each site's `node-patch.yaml` sets only
  `GALACTIC_NAT_UPLINK_INTERFACES=bond0,bond1` — an edge node's transit
  bond (replies arrive there) and its compute-facing bond (tenant egress
  arrives there), the two the shard's XDP program runs on. iad's
  also sets `GALACTIC_NAT_ECHO_RESPONDER=true`, so `verify:nat-icmp` can
  ping one shard's masquerade addresses and see the others refuse. The shard's identity lives in that site's
  `egressshard.yaml`, one `EgressShard` per edge node (dfw's holds two),
  whose spec assigns the SID, both masquerade addresses and the NAT64
  prefix; see its comments for the exact uFMT 48+16 encoding. The
  `galactic-nat` process on the target node programs its datapath from
  that spec.

| EgressShard          | Node          | `shardSID`                  | `shardAddressIPv6`   | `shardAddressIPv4` |
|----------------------|---------------|-----------------------------|----------------------|--------------------|
| `dfw-worker2-egress` | `dfw-worker2` | `2001:db8:ff01:2002:e001::` | `2001:db8:9966:1::1` | `192.0.2.1`        |
| `dfw-worker3-egress` | `dfw-worker3` | `2001:db8:ff01:2003:e001::` | `2001:db8:9966:4::1` | `192.0.2.4`        |
| `sjc-worker2-egress` | `sjc-worker2` | `2001:db8:ff02:2002:e001::` | `2001:db8:9966:3::1` | `192.0.2.3`        |
| `iad-worker2-egress` | `iad-worker2` | `2001:db8:ff03:2002:e001::` | `2001:db8:9966:2::1` | `192.0.2.2`        |

Every shard translates for the same `nat64Prefix`, `2001:db8:64::/96`. The
Node-ID is service `0x2` over the edge node's own index, beside its router
(`0x1NNN`) identity.

## Run from the XDP dispatcher

The lab base sets `GALACTIC_NAT_XDP_ATTACH=dispatch`: an interface takes
one native XDP program, and every edge node also runs `galactic-gateway`
(`resources/galactic-gateway/`), so the shard and the gateway each run from
their own slot of the node's pinned XDP dispatcher on every member of
`bond0` and `bond1`. Either can then restart without detaching the other,
which `task verify:gateway-restart` checks. See
[docs/nat/configuration.md](../../../../docs/nat/configuration.md) for
both modes.

## Wired up

This is applied by `task deploy:galactic-nat`
(`deploy/containerlab/Taskfile.yaml`'s `scripts/deploy-galactic-nat.sh`),
part of the main `task deploy` chain, right after `deploy:galactic-router`
and before `deploy:scenarios` — deliberately in that order. The shard
advertises its SID through the edge node's `BGPRouter`
(`resources/galactic-router/<site>/bgprouter-<node>.yaml`), which
`deploy:galactic-router` creates. And a tenant pod's own CNI ADD
installs a default egress route toward its site's shard SIDs
(`internal/plumbing/srv6.EgressDefaultRouteAdd`, called from
`internal/cnibgp`), which fails outright if none of them is reachable
yet. The script waits for every shard's `Programmed` condition, not just
the rollout: a shard reports ready once attached, before its identity is
programmed.

`task deploy:galactic-gateway` runs later, after `deploy:scenarios`: the
gateway's `ServiceVIPBinding`s bind the `ns60` backends that step creates.
Because the shard and the gateway share the uplinks through the dispatcher,
neither has to be deployed first for the other to attach.

A lab brought up while the shards ran in direct mode moves to dispatch when
this script re-applies the base. That first deploy bounces each uplink: the
old shard's unpinned program detaches when its pod exits, and the
dispatcher's first attach bounces it again. After that, a restart bounces no
uplink. Re-run `scripts/deploy-fabric.sh` as well, so each edge node
originates its site's VIP `/64`.

`task build`/`task deploy:images` build and load `galactic-nat:latest`
onto the edge nodes the same way the other lab images are; RBAC
(`config/galactic-nat/{serviceaccount,rbac}.yaml`) is applied by
`scripts/deploy-system.sh` alongside `galactic-cni`/`galactic-router`'s
own, and the `EgressShard` CRD is installed from datum-cloud/network by
that same script.

Each shard's `status.shardSID` is advertised as a plain, RT-less
BGPAdvertisement by `EgressShardReconciler`
(`internal/controller/egressshard_controller.go`), so every other
node in the mesh learns a kernel route to it as a plain route
(`internal/runtime/gobgp/plainroutes.go`), in a table consulted only
when the main table has nothing more specific than its default route,
so the underlay route below wins wherever it exists.
It is the SID's covering `/64` (Block + Node-ID, e.g.
`2001:db8:ff01:2002::/64` for dfw-worker2's shard), not a `/128`. Each
tenant VRF encapsulates toward this shard with its own 12-bit Argument
written into the SID, so the destination differs per tenant and a host
route would cover exactly one of them. Each edge node's
`resources/fabric-router/<site>/frr.conf.<node>` also originates that
`/64` into the underlay: only the site's compute node originates the
site's `/48`, so without it a packet for `dfw-worker3`'s shard could enter
the site through `dfw-worker2`. The shard address
(`status.shardAddressIPv6`) stays a `/128` in EVPN — it is an ordinary
masquerade source, not a uSID.

`GALACTIC_CNI_EGRESS_SHARD_SIDS` is set per site, on each site's
`galactic-cni` DaemonSet
(`resources/galactic-cni/<site>/egress-shards-patch.yaml`), to that site's
own edge shards only: dfw lists `dfw-worker2`'s then `dfw-worker3`'s, sjc
and iad their single shard. The first that resolves wins at CNI ADD, and
with no other site's shard in the list a site's egress never hairpins
through another site's edge. It is operator-supplied in this phase, not
learned in-cluster; see that env var's own doc comment
(`internal/config/cni.go`) for why.

`task verify:nat-sharding` checks that every edge node's `EgressShard` is
`Programmed` and lists each site's `BGPAdvertisement`s;
`task verify:nat-local` proves each site's tenant egress leaves from its
own site's shard.

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
underlay, which carries no EVPN, so each shard's edge node originates its
own `/32` in `resources/fabric-router/<site>/frr.conf.<node>`. The reply
reaches the shard because its XDP program runs on `bond0`'s members.
`task verify:nat-datapath` drives both families end to end to the
off-fabric host.
