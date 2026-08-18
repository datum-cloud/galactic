# galactic-nat66 lab overlay (3-shard, not yet wired up)

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
- `dfw/`, `iad/`, `sjc/` — one per-site overlay each, per the redesign
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

What this is **not**: none of this is wired into `gvpc.clab.yaml` or
`Taskfile.yaml` yet — no bring-up target applies it, no image build step
adds `galactic-nat66` to the Kind image load sequence, and no
`ClusterRoleBinding` from `config/galactic-nat66/` is applied anywhere in
this lab today. That's a deliberate, separate integration decision (new
`task deploy:galactic-nat66`/`task verify:nat66-sharding` targets, per the
redesign plan's §8), not done here. These manifests are self-consistent
and buildable (verified with `kubectl kustomize` against a locally staged
copy of `config/galactic-nat66/base`'s nested `nat66/` directory — see
`base/kustomization.yaml`'s doc comment for why that directory isn't
checked into git) but standing them up live is out of scope for this
pass.
