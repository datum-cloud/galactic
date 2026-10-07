# Node Labeling Strategy

> How Galactic decides which DaemonSets run on which nodes.

_Last updated: 2026-10-06_

This document is cross-cutting — it covers the node-selection contract shared
by `galactic-cni`, `galactic-router`, `galactic-gateway`, `galactic-nat`,
and `fabric-router`, none of which owns it individually. See
[AGENTS.md](../AGENTS.md) for which per-component architecture doc to read
for everything else about a given binary.

---

## The labels

| Label                                     | Deploys                                                                        | Kind                    |
|-------------------------------------------|--------------------------------------------------------------------------------|-------------------------|
| `galactic.datumapis.com/node=compute`     | nothing exclusively (see below)                                                | primary role enum       |
| `galactic.datumapis.com/node=edge`        | `galactic-vrf` (ingress sidecar pods); hosts `galactic-gateway`/`galactic-nat` | primary role enum       |
| `galactic.datumapis.com/gateway=enabled`  | `galactic-gateway`, on a `node=edge` node only                                 | opt-in flag (edge only) |
| `galactic.datumapis.com/nat=enabled`      | `galactic-nat`, on a `node=edge` node only                                     | opt-in flag (edge only) |
| `galactic.datumapis.com/galactic=router`  | `galactic-cni`, `galactic-router` (plain/tenant mode)                          | mode enum               |
| `galactic.datumapis.com/galactic=control` | `galactic-router-rr`                                                           | mode enum               |
| `galactic.datumapis.com/fabric=router`    | `fabric-router` (plain mode)                                                   | mode enum               |
| `galactic.datumapis.com/fabric=control`   | `fabric-router` (reflector mode, same image)                                   | mode enum               |

`galactic-gateway` and `galactic-nat` are **never deployed automatically**: a
node runs one only after an operator labels it, and their manifests live in
`base/` directories no default kustomization applies. Each requires
`galactic.datumapis.com/node=edge` *and* its own opt-in label, so they run
on edge nodes alongside `galactic-vrf`, and only on the edge nodes an
operator picks. They are independent of each other, so an edge node can
carry either opt-in label or both.

Every affinity also excludes Kubernetes control-plane nodes
(`node-role.kubernetes.io/control-plane: DoesNotExist`), independently of
which of the above a node carries.

---

## Two label families, each an enum, for two different reasons

**`galactic.datumapis.com/node` is a primary-role enum.** A node has exactly
one value — `compute` or `edge` — because a Kubernetes label key is
single-valued, and these two are genuinely mutually exclusive by design:
`edge` nodes are tainted specifically to keep tenant workloads off them (see
`deploy/containerlab/node_files/iad/config.yaml`'s NAT-node taints), so a
node is never both at once. Each value deploys only what actually differs
between the two roles, not everything that role runs (see the worked example
below for the full per-node picture). Today that is all on the `edge` side:
`galactic-gateway` (ingress) and `galactic-nat` (egress). `compute` deploys
nothing exclusively since `galactic-nat` moved to `edge`, but the label stays:
it is still the tenant-serving role, it keeps `edge`'s mutual exclusivity
meaningful, and it is where the next compute-only component would key.

**`galactic.datumapis.com/galactic` and `galactic.datumapis.com/fabric` are
each a mode enum: "plain" vs. "control."** `galactic-cni` and
`galactic-router` (plain mode) are needed by *both* primary roles — every
`compute` node and every `edge` node runs both, unconditionally. Modeling
that as two independent boolean flags (as an earlier version of this scheme
did) or as an enumerated `In: [compute, edge]` list on each of their own
affinities both have the same failure mode this scheme has already been
bitten by once (see the bugs list below): a list of roles that has to be
kept in sync by hand every time a role is added, and silently goes stale
when it isn't. A single key with `router`/`control` values sidesteps that:
`galactic-router-rr` (the EVPN route reflector) and plain `galactic-router`
are genuinely mutually exclusive on one node — a route-reflector node never
also runs plain-mode `galactic-router`, and vice versa — so encoding them as
values of one key, rather than two separately-settable booleans, makes that
exclusivity structural instead of a convention someone has to maintain.
`galactic.datumapis.com/fabric` mirrors the same shape for the underlay:
`router` is the ordinary underlay eBGP participant (every current role),
`control` is the underlay's own route reflector — distinct from the EVPN
reflector above, and on the standard BGP port rather than a dedicated one,
since `fabric-router` and `galactic-router-rr` are already two independent
processes on any node that runs both.

`galactic.datumapis.com/galactic` and `galactic.datumapis.com/fabric` are
independent keys, so a node can mix values across them — e.g. an EVPN route
reflector (`galactic=control`) that is just an ordinary underlay participant,
not the underlay's own reflector (`fabric=router`).

**The rule of thumb**: if two things can never legitimately coexist on one
node, encode the difference as one key's enum value — whether that's a
primary role (`node`) or a mode within a family (`galactic`, `fabric`). If
they *can* coexist, or you're not sure, give the capability its own
independent flag instead. Getting this wrong is a real, previously-shipped
bug, not a hypothetical:

- `fabric-router`'s affinity used to enumerate roles via `In: [edge,
  route-reflector, gateway]`. `nat66` was never added to that list, so a
  NAT66 shard node silently never got the underlay BGP session its own SID
  advertisement depends on. Fixed by making `fabric` its own label that any
  role opts into, rather than a list `fabric-router` has to keep in sync
  with every other component's roles.
- `galactic-nat` used to require `galactic.datumapis.com/node: nat66` as a
  dedicated enum value. Since a node can only have one `node` value, that
  made it impossible for a node to be both `edge` (i.e. `compute`, in
  today's naming — see below) and a NAT66 shard at once, which is the only
  configuration that's ever actually used. Fixed by dropping `nat66` from
  the enum and folding shard duty into `node=compute` directly. It has since
  moved to `node=edge`, where a shard is one hop from the transit its
  masquerade addresses are originated into. An edge node runs it once it
  carries `galactic.datumapis.com/nat=enabled`, sharing each uplink's XDP
  hook with `galactic-gateway` through the node's XDP dispatcher.
- `galactic-router-rr` used to require a dedicated
  `galactic.datumapis.com/galactic-route-reflector=true` boolean flag,
  independent of everything else. Once `galactic-cni`/`galactic-router`
  needed to run on *both* `compute` and `edge` nodes, that would have meant
  *three* independent flags (`galactic-cni`, `galactic-router`,
  `galactic-route-reflector`) with an unenforced rule that the last one
  must never coexist with the second. Fixed by folding the first two into
  one `galactic=router` value and the third into the mutually-exclusive
  `galactic=control` value of that same key — see above.

---

## What `edge` means, and how gateway and NAT opt in

**`galactic.datumapis.com/node=edge` marks the nodes that host
`galactic-vrf`** — the ingress sidecar that runs next to Envoy and wires a
tenant VRF into the pod — **and the only nodes that may host
`galactic-gateway` and `galactic-nat`.** Like `compute`, an `edge` node also
runs `galactic-cni`, `galactic-router` and `fabric-router`, through their own
labels (`galactic=router`, `fabric=router`).

`node=edge` alone does not deploy the gateway or a shard. Each needs its own
opt-in label on top (`gateway=enabled`, `nat=enabled`), so an operator picks
which edge nodes run which, and a cluster can have edge nodes that run
neither. Their affinities require both labels, so neither ever lands on a
`compute` node, a node with no `node` value, or a control-plane node.

Earlier versions of this scheme went the other way twice. First `node=edge`
alone selected both, so they could never be placed independently (one label,
one value). Then they got their own labels but refused any node that carried
a `node` value at all, which kept them off `galactic-vrf`'s nodes. No
datapath reason required that: `galactic-vrf` claims nothing on the uplinks
(its replies arrive encapsulated to the node's own uSID, which the gateway
and the shard pass untouched), and egress shards are meant to run on edge
nodes. So all three now share the edge node. One configuration hazard
remains: an `EgressShard` whose SID reuses its node's router Block and
Node-ID captures that node's tenant ingress
([#711](https://github.com/datum-cloud/galactic/issues/711)).

Note the historical wording elsewhere in this repo: "edge XDP" describes
`galactic-gateway`'s datapath and predates this scheme; it is unrelated to
`node=edge`.

**Placement of `galactic-vrf` itself** is not defined in this repo yet (no
`config/galactic-vrf/`; see the note above `publish-galactic-vrf-image` in
`.github/workflows/publish.yaml`). Whatever defines its pods must require
`galactic.datumapis.com/node=edge`.

---

## Per-role reference

### `galactic.datumapis.com/node=compute`

The ordinary tenant-serving node. Runs (via
`galactic.datumapis.com/galactic=router`, below) `galactic-cni` and
`galactic-router`, and nothing keyed on this label itself.

`galactic-nat` used to run here, one egress shard per compute node. It now
runs on `nat=enabled` nodes (below): a compute node's tenant egress is
encapsulated toward its own site's shards instead
(`GALACTIC_CNI_EGRESS_SHARD_SIDS`, set per site, with no other site's shard as
a fallback).

### `galactic.datumapis.com/node=edge`

The nodes that host `galactic-vrf`. Runs (via
`galactic.datumapis.com/galactic=router` and
`galactic.datumapis.com/fabric=router`) `galactic-cni`, `galactic-router` and
`fabric-router`. A manifest in this repo deploys nothing on this label alone,
but it is required by `galactic-gateway` and `galactic-nat`, which run here
when the node also carries `gateway=enabled` or `nat=enabled` (below).

### `galactic.datumapis.com/gateway=enabled`

Runs `galactic-gateway`'s standalone, single-container pod
(`config/galactic-gateway/base/daemonset.yaml`). Opt-in, never automatic, and
independent of `nat`. The node must also carry
`galactic.datumapis.com/node=edge`. `galactic-router` and `galactic-cni` run
here too if the node also has `galactic=router`, as their own independent
DaemonSets.

### `galactic.datumapis.com/nat=enabled`

Runs `galactic-nat`, the egress shard
(`config/galactic-nat/base/daemonset.yaml`). Opt-in, never automatic, and
independent of `gateway`. The node must also carry
`galactic.datumapis.com/node=edge`.

A node with no gateway can use the base, whose `GALACTIC_NAT_XDP_ATTACH`
defaults to `direct`: the shard attaches its own XDP program to its uplinks.
A node that also carries `gateway=enabled` must set
`GALACTIC_NAT_XDP_ATTACH=dispatch`. An interface takes one program, so the
shard and the gateway, which runs in dispatch mode by default, each run from
their own slot of the node's shared, pinned XDP dispatcher, and either can
restart without detaching the other (see
[docs/nat/configuration.md](nat/configuration.md)). Compute nodes reach their
site's shards over SRv6 (`GALACTIC_CNI_EGRESS_SHARD_SIDS`).

### `galactic.datumapis.com/galactic=router`

Runs `galactic-cni` and `galactic-router` in its plain (non-reflector)
mode, together, on every `compute` and every `edge` node.

- `config/galactic-cni/daemonset.yaml`
- `config/galactic-router/overlays/router/daemonset-patch.yaml`

### `galactic.datumapis.com/galactic=control`

Runs `galactic-router-rr` (`GALACTIC_ROUTER_REFLECTOR=true`), the EVPN
route reflector every `galactic=router` node's `galactic-router` peers into
over iBGP. Mutually exclusive with `galactic=router` on the same node (one
label key, one value) — a route-reflector node never also runs plain-mode
`galactic-router`, and never runs `galactic-cni` either (a dedicated
route-reflector node hosts no tenant pods). See
`config/galactic-router/overlays/control/daemonset-patch.yaml`.

### `galactic.datumapis.com/fabric=router`

Runs `fabric-router`, the FRR underlay eBGP DaemonSet, independently of
whatever `node` or `galactic` value a node also carries. See
`config/fabric-router/daemonset.yaml`'s own affinity comment for the full
history of why this is a dedicated label rather than an enumerated list.

### `galactic.datumapis.com/fabric=control`

The underlay's own iBGP route reflector, distinct from the EVPN one above.
Unlike `galactic=control`, this has no separate binary or overlay to run --
`fabric-router` has no Go code of its own at all (it's a plain FRR
container), so `control` runs the identical image `router` does. The
reflector-vs-plain distinction lives entirely in the per-node `frr.conf`
`infra`'s own renderer produces for this node: a `route-reflector-client`
peer-group instead of the four canonical ones. This DaemonSet's affinity
matches both values identically; only the rendered config differs.
Mutually exclusive with `fabric=router` on the same node, the same way
`galactic`'s two values are.

---

## Worked example: the containerlab lab

| Node                                                       | `node`    | `galactic` | `fabric` | Runs                                                                                                                       |
|------------------------------------------------------------|-----------|------------|----------|----------------------------------------------------------------------------------------------------------------------------|
| `dfw-worker`, `sjc-worker`, `iad-worker`                   | `compute` | `router`   | `router` | `galactic-cni`, `galactic-router`, `fabric-router`                                                                         |
| `dfw-worker2`, `dfw-worker3`, `sjc-worker2`, `iad-worker2` | `edge`    | `router`   | `router` | `galactic-gateway` (`gateway=enabled`), `galactic-nat` (`nat=enabled`), `galactic-cni`, `galactic-router`, `fabric-router` |
| `iad-worker3`                                              | —         | `control`  | `router` | `galactic-router-rr`, `fabric-router`                                                                                      |

The lab's edge workers carry `node=edge` plus both `gateway=enabled` and
`nat=enabled`, which place a `galactic-gateway` and a `galactic-nat` shard on
each; the lab deploys no `galactic-vrf` yet. The shard runs with
`GALACTIC_NAT_XDP_ATTACH=dispatch`, so it and the gateway share the uplinks
through the node's XDP dispatcher.

The reflector row is the one that shows why `galactic` is a mode enum rather
than a boolean: `iad-worker3` carries no `node` value at all. Both `node`
roles imply `galactic=router`, and `router`/`control` are mutually exclusive
values of one key, so a reflector structurally cannot also be a compute or
edge node — it needs a worker of its own.

Every worker in the lab carries `fabric=router` today (see
`deploy/containerlab/node_files/{dfw,iad,sjc}/config.yaml`), since every
role in this topology needs the underlay. That's a property of this
particular lab's topology, not a rule the label scheme enforces — a real
deployment is free to have nodes with no galactic role at all (GPU,
monitoring, etc.), which correctly get none of these labels and none of
these DaemonSets.

---

## Migrating gateway and NAT nodes onto `node=edge`

The DaemonSet controller removes a pod from any node its affinity stops
matching, whether the node's labels or the DaemonSet's affinity changed. The
old manifests refuse a node carrying `galactic.datumapis.com/node` and the new
ones require `node=edge`, so no order avoids one restart of each gateway and
shard. Keep the gap to that restart:

1. On each gateway or NAT node, add `galactic.datumapis.com/node=edge`,
   keeping `galactic.datumapis.com/gateway=enabled` and/or
   `galactic.datumapis.com/nat=enabled`. The old manifests remove the gateway
   and shard pods from the node at once, and anything placed on `node=edge`,
   such as `galactic-vrf` and the Envoy it serves, can now land on it.
2. Apply the new manifests straight away. They place the pods back on the
   node.

Production is not affected: infra sets its own placement and already requires
`node=edge`. A gateway or NAT node that should not become an edge node has no
place in the new scheme: move its role to an edge node instead.

---

## Adding a new role

1. Decide whether it's mutually exclusive with an existing enum value in
   the same family (→ a new value of that key) or can coexist with an
   existing role (→ its own independent label). Default to the independent
   label unless you're certain the exclusivity is real and permanent — see
   the bugs list above for what happens when that assumption turns out to
   be wrong later.
2. If it needs the underlay, it still needs
   `galactic.datumapis.com/fabric=router` set explicitly — nothing infers
   this from the new label automatically.
3. If it needs `galactic-cni`/`galactic-router` (plain mode), set
   `galactic.datumapis.com/galactic=router` — don't add it to an enumerated
   list on `galactic-cni`'s or `galactic-router`'s own affinity.
4. Update the reference table at the top of this document and in
   [AGENTS.md](../AGENTS.md)'s "Node label strategy" section.
