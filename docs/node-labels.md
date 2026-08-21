# Node Labeling Strategy

> How Galactic decides which DaemonSets run on which nodes.

_Last updated: 2026-08-21_

This document is cross-cutting — it covers the node-selection contract shared
by `galactic-cni`, `galactic-router`, `galactic-gateway`, `galactic-nat66`,
and `fabric-router`, none of which owns it individually. See
[AGENTS.md](../AGENTS.md) for which per-component architecture doc to read
for everything else about a given binary.

---

## The five labels

| Label                                                  | Deploys                                                            | Kind                                                       |
|--------------------------------------------------------|--------------------------------------------------------------------|------------------------------------------------------------|
| `galactic.datumapis.com/fabric=true`                   | `fabric-router`                                                    | independent boolean flag                                   |
| `galactic.datumapis.com/node=compute`                  | `galactic-router` (default role), `galactic-nat66`, `galactic-cni` | primary role (enum value)                                  |
| `galactic.datumapis.com/node=edge`                     | `galactic-gateway`                                                 | primary role (enum value)                                  |
| `galactic.datumapis.com/galactic-route-reflector=true` | `galactic-router-rr`                                               | independent boolean flag                                   |
| `galactic.datumapis.com/fabric-route-reflector=true`   | `fabric-router-rr`                                                 | independent boolean flag — **future**, not yet implemented |

Every affinity also excludes Kubernetes control-plane nodes
(`node-role.kubernetes.io/control-plane: DoesNotExist`), independently of
which of the above a node carries.

---

## Two different kinds of label, on purpose

**`galactic.datumapis.com/node` is a primary-role enum.** A node has exactly
one value for it — `compute` or `edge` — because a Kubernetes label key is
single-valued, and these two are genuinely mutually exclusive by design:
`edge` nodes are tainted specifically to keep tenant workloads and the
`compute` role off them (see
`deploy/containerlab/node_files/iad/config.yaml`'s gateway-node taints), so a
node is never both at once.

**Everything else is an independent boolean-style flag**, not a fifth/sixth
enum value, because the thing it gates is *not* mutually exclusive with a
node's primary role:

- `fabric` applies to every role that needs underlay BGP connectivity —
  which today is all of them.
- `galactic-route-reflector` can, in principle, coexist with `node=compute`
  on the same node (a route reflector doesn't have to be a dedicated node);
  encoding it as `node=route-reflector` would have made that impossible,
  since the node would have had to give up being `compute` to become a
  reflector.
- `fabric-route-reflector` (future) follows the same reasoning for the
  underlay's own route reflector, independently of the EVPN one.

**The rule of thumb**: if two roles can never legitimately coexist on one
node, encode the difference as `galactic.datumapis.com/node`'s value. If
they can — or if you're not sure yet — give the capability its own
independent label instead. Getting this wrong is a real, previously-shipped
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
- `galactic-router-rr` used to require `galactic.datumapis.com/node:
  route-reflector`. Fixed the same way as `nat66`, for the same underlying
  reason: a route reflector shouldn't have to stop being anything else it
  might also need to be.

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

Runs `galactic-router` (default role), `galactic-nat66`, and `galactic-cni`
together, unconditionally — this is the ordinary tenant-serving node.

- `config/galactic-router/overlays/default/daemonset-patch.yaml`
- `config/galactic-nat66/base/daemonset.yaml`
- `config/galactic-cni/daemonset.yaml`

### `galactic.datumapis.com/node=edge`

Runs `galactic-gateway`'s two-container pod (`galactic-gateway` +
`galactic-router`, the latter carrying no gateway-specific code of its own —
see [ARCHITECTURE-GATEWAY.md](agents/ARCHITECTURE-GATEWAY.md)). Dedicated,
opt-in, tainted to keep ordinary tenant pods off — see
`config/galactic-gateway/base/daemonset.yaml`.

### `galactic.datumapis.com/fabric=true`

Runs `fabric-router`, the FRR underlay eBGP DaemonSet, independently of
whatever `node` value or route-reflector flag a node also carries. See
`config/fabric-router/daemonset.yaml`'s own affinity comment for the full
history of why this is a dedicated label rather than an enumerated list.

### `galactic.datumapis.com/galactic-route-reflector=true`

Runs `galactic-router-rr` (`GALACTIC_ROUTER_REFLECTOR=true`), the EVPN route
reflector every compute node's `galactic-router` peers into over iBGP. See
`config/galactic-router/overlays/rr/daemonset-patch.yaml`.

### `galactic.datumapis.com/fabric-route-reflector=true` (future)

Reserved for `fabric-router-rr` — the underlay's own iBGP route reflector,
distinct from the EVPN one above (see the two separate listener ports, 1179
vs. 2179, in the production POP architecture this mirrors). Not implemented:
`fabric-router` today has no route-reflector variant, and `config/` has no
`fabric-router-rr` overlay.

---

## Worked example: the containerlab lab

| Node                                     | `node`    | `galactic-route-reflector` | `fabric` | Runs                                                                           |
|------------------------------------------|-----------|----------------------------|----------|--------------------------------------------------------------------------------|
| `dfw-worker`, `sjc-worker`, `iad-worker` | `compute` | —                          | `true`   | `galactic-router` (default), `galactic-nat66`, `galactic-cni`, `fabric-router` |
| `iad-worker-rr`                          | —         | `true`                     | `true`   | `galactic-router-rr`, `fabric-router`                                          |
| `iad-gateway1`, `iad-gateway2`           | `edge`    | —                          | `true`   | `galactic-gateway` + `galactic-router`, `fabric-router`                        |

Every worker in the lab carries `fabric=true` today (see
`deploy/containerlab/node_files/{dfw,iad,sjc}/config.yaml`), since every
role in this topology needs the underlay. That's a property of this
particular lab's topology, not a rule the label scheme enforces — a real
deployment is free to have nodes with no galactic role at all (GPU,
monitoring, etc.), which correctly get none of these labels and none of
these DaemonSets.

---

## Adding a new role

1. Decide whether it's mutually exclusive with `compute`/`edge` (→ a new
   `galactic.datumapis.com/node` value) or can coexist with an existing
   role (→ its own independent label, `galactic.datumapis.com/<name>=true`).
   Default to the independent label unless you're certain the exclusivity
   is real and permanent — see the bugs list above for what happens when
   that assumption turns out to be wrong later.
2. If it needs the underlay, it still needs `galactic.datumapis.com/fabric`
   set explicitly — nothing infers this from the new label automatically.
3. Update the reference table at the top of this document and in
   [AGENTS.md](../AGENTS.md)'s "Node label strategy" section.
