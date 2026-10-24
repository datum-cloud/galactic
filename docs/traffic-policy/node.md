# Traffic policy on the node

`galactic-router` programs interface traffic policy on each node. For every
VPCAttachment whose `status.node` is its node, it compiles the TrafficPolicy
each direction of the interface is bound to, publishes it into the uSID
datapath, reports what it applied in the TrafficPolicyBinding's
`status.nodes`, and exports the policy counters. It does the same for every
Galactic Edge attachment on its node (see [Edge attachments](#edge-attachments)). The cell side, which
validates policies and resolves bindings, is
[galactic-controller](controller.md); the design is in
[the traffic policy proposal](../enhancements/networking/interface-traffic-policy/README.md).

## Enabling it

Set `GALACTIC_ROUTER_TRAFFIC_POLICY=true` on the plain `galactic-router`
DaemonSet, never on the route reflector, which refuses it. Install first:

1. the `galactic.datumapis.com` CRDs (`config/crd/`), since an informer for
   a missing CRD never syncs;
2. the ClusterRole in `config/galactic-router/rbac.yaml`, which grants read
   access to policies, bindings, EdgeAttachments and EdgeServices and
   `patch` on the bindings' status.

Whether the datapath enforces, audits or ignores what galactic-router
publishes is galactic-cni's setting, `GALACTIC_CNI_TRAFFIC_POLICY`. With it
off, galactic-router still publishes and reports, and nothing is enforced.

## What it applies

| Binding                                       | The direction gets                                                                  |
| --------------------------------------------- | ----------------------------------------------------------------------------------- |
| No TrafficPolicyBinding                       | The built-in `default-deny-all`, which denies everything                            |
| A binding with no reference for a direction   | The built-in `default-deny-all`                                                     |
| A reference to a valid policy                 | That policy, at its current generation                                              |
| A reference to a missing policy               | Nothing: the direction denies as `policy_unavailable` and its status is `Pending`   |
| A reference to a policy that does not compile | The last snapshot of the same policy, if any, otherwise nothing; status is `Failed` |

A reference to a `default-deny-all` the controller does not own resolves to
nothing, as on the cell side.

Ingress policy is decided on the packet as it is delivered, after
decapsulation and any translation. A client of an IPv4 VIP reaches its
IPv6 backend translated to IPv6, from `64:ff9b::<client address>` (RFC
6052), so an ingress rule must match that client as an IPv6 source in
`64:ff9b::/96`. An IPv4 CIDR or an `ipFamily: IPv4` rule never matches an
IPv4 VIP's flows. See
[What an IPv4 VIP needs](../gateway/configuration.md#what-an-ipv4-vip-needs).

Each rule keeps its counter row while its name and action stay the same
within one policy and one interface lifetime, so editing a match does not
reset its counts. Renaming a rule, flipping its action, binding a different
policy or recreating the interface starts a new series.

galactic-router reconciles on every change and every five minutes. When it
restarts, it adopts each snapshot still bound in the datapath that holds
exactly what the current policy compiles to, for the same token, policy UID
and generation, so counts continue; a snapshot an older galactic-router
compiled differently is republished, starting its rules from zero. A
snapshot on an interface no attachment claims within one resync is unbound,
and its rows are freed.

To read a snapshot back, galactic-router pins each one it publishes under
`tp_snapshots/` in the datapath's pin directory, beside the policy maps, and
galactic-cni removes the pin when it unbinds the snapshot. On its first
reconcile and at most once every five minutes after, galactic-router removes
any pin that holds no bound snapshot, such as one left by a publish that an
interface's removal or a restart interrupted. Until then, such a pin holds its
snapshot's memory. The kernel opens a map
by ID only for `CAP_SYS_ADMIN`, which galactic-router does not have (it runs
with `NET_ADMIN` and `BPF`), so a snapshot without a matching pin, such as
one bound by a release that did not pin, cannot be read. galactic-router
adopts it as empty and logs it: it stays bound, so traffic keeps its
current verdict, until the next reconcile republishes it with fresh counter
rows or the sweep unbinds it. Until then its rules can count into rows
another snapshot was given, so those counters can over-count for that
window; verdicts are unaffected.

A rebind that cannot be installed, such as one that runs out of counter
rows, unbinds the direction rather than keeping the old policy's grants,
and reports `Failed`. A failed update of the same policy keeps its last
snapshot. Status is written only when this node's entry changes.

## Edge attachments

An EdgeAttachment's host link is enforced like a workload's interface.
`galactic-edge` writes the link's policy row and attaches the enforcement
programs before the link comes up, and `galactic-router` binds the policy
the attachment's EdgeService selects in `spec.trafficPolicy`:

```yaml
apiVersion: galactic.datumapis.com/v1alpha1
kind: EdgeService
metadata:
  name: connect
  namespace: tenant
spec:
  # providerRef, vpcRef, capabilities, ...
  trafficPolicy:
    ingressPolicyRef: {name: from-vpc} # traffic delivered to the provider
    egressPolicyRef: {name: to-vpc} # traffic the provider sends into the VPC
```

Both references resolve in the service's namespace, never in the provider's
namespace where the attachment lives, so a provider cannot choose its own
policy. The table above applies, with the service's `trafficPolicy` in
place of a binding. In addition, galactic-router binds nothing, and unbinds
both directions, while the attachment is not `Admitted` or its service is
gone, being deleted, replaced or granting another provider; the link then
denies everything as `policy_unavailable`. A change to the service or to a
referenced policy is republished to the attachments on the node.

galactic-router writes no status for an edge attachment. galactic-controller
reports whether the references resolve in the service's
`TrafficPolicyResolved` condition, with reason `Default` while both
directions take the built-in default and its attachments carry nothing, and
the counters below show what each direction applies. Their `namespace` and `attachment` labels name the
EdgeAttachment, `vpc` the service's VPC, and `interface` the host link.

## Status

Each node owns one entry in the binding's `status.nodes`, written with
server-side apply as field manager `galactic-router/<node>`:

```yaml
status:
  nodes:
    - node: worker-1
      ingress:
        state: Applied
        policy: {name: default-deny-all, uid: ..., generation: 1}
        observedGeneration: 3
        lastTransitionTime: "2026-10-15T12:00:00Z"
      egress:
        state: Applied
        policy: {name: web, uid: ..., generation: 7}
        observedGeneration: 3
        lastTransitionTime: "2026-10-15T12:00:00Z"
```

`Pending` means the interface's datapath state is not ready yet, or a
reference resolves to nothing. `Failed` carries the reason in `message`. The
entry disappears when the attachment leaves the node.

## Metrics

galactic-router serves the policy counters on its metrics port (`9179`),
which the `galactic-router` PodMonitor already scrapes, as
`galactic_cni_traffic_policy_*`: the prefix names the datapath that counts,
not the process that serves them. [docs/metrics.md](../metrics.md#traffic-policy--galactic_cni_traffic_policy_)
lists every series, its labels and example queries.

Every installed rule has a series from the moment it is published, at zero,
including the built-in default's deny-all rule, whose `policy_uid` is
`builtin:default-deny-all:v1`; an interface still on the default is visible
by that label. A hit is one evaluation, not one forwarded packet. The
supported budget is 27,200 series per node, 100 interfaces at the 64-rule
limit. After a restart, series return once galactic-router reconciles each
interface and adopts its snapshot, with their counts intact. A counter row
the collector cannot read is left out, never reported as zero, and counted
in `galactic_cni_traffic_policy_counter_read_errors`.

## Diagnostics

Run these in the galactic-router pod.

`galactic-router policy explain` decides one packet against a policy, from a
file or the cluster, without touching the datapath:

```console
$ galactic-router policy explain --policy tenant/web \
    --path Private --src 10.0.0.1 --dst 10.0.0.2 --proto tcp --dport 80
policy            web
path              Private
verdict           allow
reason            rule
rule              http (#0)
compiled entries  1
```

It decides with both the Go evaluator and the compiled entries the datapath
runs, and fails if they disagree. Leave `--path` out to see what an
unclassified packet gets.

`galactic-router policy show <namespace>/<attachment>` prints what this node
holds for one attachment: each direction's binding, status, bound snapshot
and every rule's counters, plus any fallback counts. Rules are named when the
policy in the cluster is still the generation the snapshot was compiled from,
and numbered otherwise.
