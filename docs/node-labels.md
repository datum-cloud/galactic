# Node Labeling Strategy

> How Galactic decides which DaemonSets run on which nodes.

_Last updated: 2026-08-28_

This document is cross-cutting — it covers the node-selection contract shared
by `galactic-cni`, `galactic-router`, `galactic-gateway`, `galactic-nat66`,
and `fabric-router`, none of which owns it individually. See
[AGENTS.md](../AGENTS.md) for which per-component architecture doc to read
for everything else about a given binary.

---

## The four labels

| Label                                            | Deploys                                               | Kind              |
|--------------------------------------------------|-------------------------------------------------------|-------------------|
| `galactic.datumapis.com/node=compute`            | `galactic-nat66`                                      | primary role enum |
| `galactic.datumapis.com/node=edge`               | `galactic-gateway` (standalone — see below)           | primary role enum |
| `galactic.datumapis.com/galactic=router`         | `galactic-cni`, `galactic-router` (plain/tenant mode) | mode enum         |
| `galactic.datumapis.com/galactic=control`        | `galactic-router-rr`                                  | mode enum         |
| `galactic.datumapis.com/fabric=router`           | `fabric-router`                                       | mode enum         |
| `galactic.datumapis.com/fabric=control` (future) | `fabric-router-rr` — not yet implemented              | mode enum         |

Every affinity also excludes Kubernetes control-plane nodes
(`node-role.kubernetes.io/control-plane: DoesNotExist`), independently of
which of the above a node carries.

---

## Two label families, each an enum, for two different reasons

**`galactic.datumapis.com/node` is a primary-role enum.** A node has exactly
one value — `compute` or `edge` — because a Kubernetes label key is
single-valued, and these two are genuinely mutually exclusive by design:
`edge` nodes are tainted specifically to keep tenant workloads off them (see
`deploy/containerlab/node_files/iad/config.yaml`'s gateway-node taints), so a
node is never both at once. Each value now deploys only the one component
that actually differs between the two roles — `galactic-nat66` for
`compute`, `galactic-gateway` for `edge` — not everything that role runs
(see the worked example below for the full per-node picture).

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
`control` is reserved for the underlay's own route reflector
(`fabric-router-rr`, distinct from the EVPN reflector above — see the two
separate listener ports, 1179 vs. 2179, in the production POP architecture
this mirrors) — not yet implemented.

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
- `galactic-nat66` used to require `galactic.datumapis.com/node: nat66` as a
  dedicated enum value. Since a node can only have one `node` value, that
  made it impossible for a node to be both `edge` (i.e. `compute`, in
  today's naming — see below) and a NAT66 shard at once, which is the only
  configuration that's ever actually used. Fixed by dropping `nat66` from
  the enum and folding shard duty into `node=compute` directly — every
  compute node now runs `galactic-nat66` unconditionally.
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

## Naming collision, read this before anything else

**`galactic.datumapis.com/node=edge` deploys `galactic-gateway` — it does
*not* mean "the per-node tenant/compute role."** That's `node=compute`.

This is a deliberate rename, not an inconsistency to double-check: "edge"
now means the actual network edge — the ingress/egress boundary
`galactic-gateway`'s XDP NAT+LB datapath sits on — which is also why
`galactic-gateway` has always been described elsewhere in this repo as "the
edge XDP NAT+LB gateway," independently of and predating this label scheme.
Before this rename, the *tenant-serving* role was called `edge` and the
*gateway* role was called `gateway`, which collided with that existing
"edge XDP" terminology. Calling the tenant role `compute` and reserving
`edge` for the actual network-edge role resolves that collision instead of
perpetuating it.

If you're reading an older comment, commit, or diagram that says
`galactic.datumapis.com/node: edge` and shows `galactic-router`/
`galactic-cni` attached to it, it predates this rename and means what
`compute` means today.

---

## Per-role reference

### `galactic.datumapis.com/node=compute`

The ordinary tenant-serving node. Runs `galactic-nat66` — the one component
that differs between `compute` and `edge` — plus (via
`galactic.datumapis.com/galactic=router`, below) `galactic-cni` and
`galactic-router`.

- `config/galactic-nat66/base/daemonset.yaml`

### `galactic.datumapis.com/node=edge`

Runs `galactic-gateway`'s standalone, single-container pod — the other
component that differs between `compute` and `edge` — plus (via
`galactic.datumapis.com/galactic=router`) `galactic-cni` and
`galactic-router`. Dedicated, opt-in, tainted to keep ordinary tenant pods
off — see `config/galactic-gateway/base/daemonset.yaml`.

`galactic-router` used to run as a second container inside this same pod
(`galactic-router` + `galactic-gateway`, sharing one ServiceAccount). It's
now a fully independent DaemonSet, deployed the same way on `edge` as on
`compute` — a crash in one no longer risks the other's pod, not just the
other's binary.

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

### `galactic.datumapis.com/fabric=control` (future)

Reserved for `fabric-router-rr` — the underlay's own iBGP route reflector,
distinct from the EVPN one above (see the two separate listener ports, 1179
vs. 2179, in the production POP architecture this mirrors). Not implemented:
`fabric-router` today has no route-reflector variant, and `config/` has no
`fabric-router-rr` overlay. Mutually exclusive with `fabric=router` on the
same node, the same way `galactic`'s two values are, once implemented.

---

## Worked example: the containerlab lab

| Node | `node` | `galactic` | `fabric` | Runs |
|---|---|---|---|---|
| `dfw-worker`, `sjc-worker`, `iad-worker` | `compute` | `router` | `router` | `galactic-nat66`, `galactic-cni`, `galactic-router`, `fabric-router` |
| `iad-worker-rr` | — | `control` | `router` | `galactic-router-rr`, `fabric-router` |
| `iad-gateway1`, `iad-gateway2` | `edge` | `router` | `router` | `galactic-gateway`, `galactic-cni`, `galactic-router`, `fabric-router` |

Every worker in the lab carries `fabric=router` today (see
`deploy/containerlab/node_files/{dfw,iad,sjc}/config.yaml`), since every
role in this topology needs the underlay. That's a property of this
particular lab's topology, not a rule the label scheme enforces — a real
deployment is free to have nodes with no galactic role at all (GPU,
monitoring, etc.), which correctly get none of these labels and none of
these DaemonSets.

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
