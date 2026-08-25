# Getting Started with NAT66

This is a hands-on walkthrough for standing up the sharded, stateful NAT66
egress tier (`galactic-nat66`) from nothing. For the full environment
variable/CLI flag/CRD field reference, see
[docs/nat66/configuration.md](configuration.md). There is no dedicated
architecture doc for this component yet — `docs/agents/ARCHITECTURE-GATEWAY.md`
explicitly calls it "out of this document's scope"; the closest thing to a
design record is the (now-deleted, but git-history-recoverable) plan that
introduced it alongside the DSR/Maglev gateway rewrite.

> Last verified: 2026-08-25 against the current working tree of
> `cmd/galactic-nat66/`, `internal/config/nat66.go`,
> `config/galactic-nat66/`, and
> `deploy/containerlab/resources/galactic-nat66/`.

## What NAT66 is, and when you need it

A VPC-attached workload is addressed from its tenant's ULA (`fd00::/8`)
range. ULA addresses aren't routable on the public internet, and — unlike a
1:1 stateless prefix swap (NPTv6) — nothing structurally guarantees two
tenants' ULA space is unique, since independently self-generated RFC 4193
prefixes can collide. `galactic-nat66` solves this with **stateful**
translation: a dedicated, standalone tier of shard nodes that SNAT a
tenant's egress flow to a shard's own public address:port, track it in a
per-flow connection table, and reverse the translation on the reply — safe
even when two tenants present the exact same internal ULA address, because
every table is keyed by tenant VRF identity, not just address.

You need this component only if tenant workloads must reach the public
internet from a ULA-addressed VPC. It is a **separate binary, DaemonSet,
and eBPF program** from both `galactic-router` and `galactic-gateway` —
deliberately not folded into the ingress load-balancer, because egress
traffic is a different pattern needing its own hash ring, its own state,
and its own tier (see `internal/controller/nat66shard_controller.go`'s
package doc comment).

## Before you begin

- **A working fabric underlay and tenant BGP mesh.** `galactic-nat66`
  advertises its shard identity over BGP the same way any other node does
  — it needs `fabric-router` running and a `BGPRouter`/`BGPPeer` pair for
  the node it runs on, exactly like any other compute node. See
  [docs/router/configuration.md](../router/configuration.md) if that isn't
  already set up.
- **The `go.datum.net/network` CRDs installed**, specifically `NAT66Shard`
  and `BGPAdvertisement`.
- **A shard SID that does not collide with that node's own uSID Node-ID.**
  A NAT66 shard's own SRv6 address only has its top 64 bits (Block +
  Node-ID) checked by the datapath — reusing the same node's *own* real
  `BGPRouter.Spec.NodeID` for the shard's SID means the shard's XDP program
  silently hijacks that node's ordinary tenant ingress traffic before
  `usid_ingress` ever sees it (a real bug this codebase's own containerlab
  lab hit once — see `deploy/containerlab/resources/galactic-nat66/dfw/node-patch.yaml`'s
  comment for the full story). Pick a Node-ID nothing else on that
  locator uses.
- **A node labeled `galactic.datumapis.com/node: compute` and
  `galactic.datumapis.com/fabric=true`.** NAT66 isn't an opt-in capability
  on top of the compute role — every compute node is expected to run it
  (`config/galactic-nat66/base/daemonset.yaml`'s own affinity). See
  [docs/node-labels.md](../node-labels.md) for the full labeling strategy.

## Step 1 — Apply the shared RBAC/ServiceAccount

```sh
kubectl apply -k config/galactic-nat66/
```

This applies only `serviceaccount.yaml` and `rbac.yaml` — safe and
idempotent regardless of how many shard nodes you end up with. It is
**not** part of the root `config/kustomization.yaml`'s default resource
list (this role is opt-in), and it deliberately excludes
`config/galactic-nat66/base/` — see Step 2 for why.

## Step 2 — Instantiate a shard on one node

`config/galactic-nat66/base/` has **no working defaults**: three env vars
are required and must be unique per shard node, so applying it as-is
produces a crash-looping container. Write a small per-node kustomize
overlay instead. The pattern below mirrors
`deploy/containerlab/resources/galactic-nat66/dfw/` — copy that directory
for a real, worked reference.

`node-patch.yaml`, pinning to one node and setting its shard identity:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: galactic-nat66
spec:
  template:
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: node-role.kubernetes.io/control-plane
                    operator: DoesNotExist
                  - key: galactic.datumapis.com/node
                    operator: In
                    values: [compute]
                  - key: kubernetes.io/hostname
                    operator: In
                    values: [<your-node-name>]
      containers:
        - name: galactic-nat66
          env:
            - name: GALACTIC_NAT66_UPLINK_INTERFACE
              value: <fabric-facing-interface>   # e.g. eth1
            - name: GALACTIC_NAT66_SHARD_SID
              value: "<your-locator>:<reserved-node-id>:e001::"
            - name: GALACTIC_NAT66_SHARD_PUB_ADDR
              value: "<a-dedicated-publicly-routable-/128>"
```

`kustomization.yaml` for this overlay:

```yaml
resources:
  - ../../../../config/galactic-nat66/base
patches:
  - path: node-patch.yaml
```

Apply it:

```sh
kubectl apply -k <your-overlay-directory>/
```

Repeat this for every shard you want — each needs its own overlay
directory, its own `kubernetes.io/hostname` pin, and its own unique
`GALACTIC_NAT66_SHARD_SID`/`_SHARD_PUB_ADDR`.

## Step 3 — Register the shard as a `NAT66Shard`

```yaml
apiVersion: network.datumapis.com/v1alpha1
kind: NAT66Shard
metadata:
  name: <your-node-name>-nat66
  namespace: galactic-system
spec:
  targetRef:
    kind: Node
    name: <your-node-name>
```

Leave `status` empty — `NAT66ShardReconciler`, running inside that node's
own `galactic-nat66` pod, fills in `status.shardSID`/`status.shardAddress`
from the pod's own env config and publishes a `/128` `BGPAdvertisement`
for each so the rest of the fabric can route to it.

## Step 4 — Point every tenant node at the shard list

Every compute node's `galactic-cni` needs the full, fabric-wide list of
live shard SIDs so a pod's own CNI ADD can install its tenant VRF's
default egress route. Set this on `galactic-cni`'s **init** container
(the one that runs `internal/installer.Bootstrap` — not the long-running
`credential-refresh` container, which doesn't propagate its own env to
it):

```yaml
- name: GALACTIC_CNI_NAT66_SHARD_SIDS
  value: "<shard-1-sid>,<shard-2-sid>,<shard-3-sid>"
```

**Do this before any tenant pod using egress is scheduled.** A CNI ADD
that can't resolve at least one configured shard SID fails outright — see
[docs/nat66/configuration.md](configuration.md#nat66-shard-membership-galactic-cni-side)
for the exact mechanics and its own current limitation.

## Step 5 — Verify

```sh
kubectl get nat66shard -n galactic-system -o wide
kubectl get bgpadvertisement -n galactic-system | grep nat66
kubectl get pods -n galactic-system -l app.kubernetes.io/name=galactic-nat66 -o wide
```

`status.shardAddress`/`status.shardSID` should be populated and a
matching `BGPAdvertisement` should exist. Check the shard's own datapath
health and live flow count:

```sh
kubectl logs -n galactic-system <galactic-nat66-pod>
kubectl exec -n galactic-system <galactic-nat66-pod> -- \
  wget -qO- http://localhost:9182/metrics | grep galactic_nat66_
```

From a tenant pod, curl or `nc` an external IPv6 destination and confirm
the connection actually completes (not just that the SYN leaves the
node) — see [configuration.md](configuration.md#known-constraints) for
what to check if it doesn't.

## Where to go next

- [docs/nat66/configuration.md](configuration.md) — full environment
  variable, CLI flag, CRD field, and RBAC reference, plus this
  component's current known constraints.
- [docs/node-labels.md](../node-labels.md) — the node-labeling strategy
  this and every other Galactic component shares.
- `deploy/containerlab/resources/galactic-nat66/` — a complete, working
  3-shard reference deployment (`task deploy:galactic-nat66` in
  `deploy/containerlab/`).
