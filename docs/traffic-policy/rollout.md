# Rolling out interface traffic policy

Interface traffic policy denies by default: once a node enforces it, a tenant
interface forwards only what its bindings grant, in each direction. That is a
deliberate behavior change, so turning it on in a cell is a migration. This
guide is the order to do it in, what to check at each step, and how to back
out. The design is in
[the traffic policy proposal](../designs/interface-traffic-policy.md);
[controller.md](controller.md) and [node.md](node.md) are the component
references.

TrafficPolicy is not Kubernetes NetworkPolicy and is unrelated to BGPPolicy:
it filters a VPC workload's own interface, by forwarding path, address,
protocol and port, and neither reads nor replaces either of those.

## The three modes

`GALACTIC_CNI_TRAFFIC_POLICY` on `galactic-cni` sets each node's mode:

| Mode      | Decides | Counts | Drops | Use                                        |
| --------- | ------- | ------ | ----- | ------------------------------------------ |
| `off`     | no      | no     | no    | The default; the programs are loaded inert |
| `audit`   | yes     | yes    | no    | Measuring what enforcement would deny      |
| `enforce` | yes     | yes    | yes   | The steady state                           |

`audit` is for measuring a migration, not a compatibility mode: it forwards
everything, so a cell left in it enforces nothing. There is no legacy allow,
and nothing generates reverse rules: a workload that answers connections needs
an ingress grant for the requests and an egress grant for the replies.

In `audit` and `enforce`, a new interface's host side stays down until every
enforcement program is attached and verified, and CNI ADD fails on a node
whose kernel failed the preflight (Linux 6.8 or later, `HASH_OF_MAPS` and
`bpf_for_each_map_elem`).

## Before you start

Check every node of the cell:

- runs a galactic release that includes traffic policy, for `galactic-cni`,
  `galactic-router` and `galactic-controller`;
- has the `galactic.datumapis.com` CRDs (`config/crd/`), cert-manager, and the
  cloud operator's VPCAttachment CRD installed;
- publishes `status.node` and `status.hostInterface` on every VPCAttachment,
  which the cloud operator writes. An attachment without them is never bound
  on any node, and denies everything once enforced;
- grants `galactic-router` read access to EdgeAttachments and EdgeServices,
  which `config/galactic-router/rbac.yaml` includes, even in a cell without
  Galactic Edge. Without it galactic-router's edge attachment controller
  never syncs and galactic-router does not start. On an edge node, every
  edge attachment denies everything once enforced until its EdgeService
  selects a policy (see [Edge attachments](node.md#edge-attachments)).

`galactic-router` needs `NET_ADMIN` and `BPF`, as `config/galactic-router/`
grants, and not `CAP_SYS_ADMIN`: it reads back the snapshots it bound before
a restart from their pins (see
[Traffic policy on the node](node.md#what-it-applies)). The first restart
after upgrading from a release that did not pin snapshots republishes every
snapshot bound on the node, so their rule counters start again from zero.
Until each one is republished, its rules can count into rows another snapshot
was given.

## Steps

1. **Install the cell controller.** Apply `config/galactic-controller/` (its
   ServiceAccount and RBAC), then `config/galactic-controller/base/`. Its
   webhook fails closed, so wait until it admits a policy before anyone
   writes one: a server-side dry run of a valid TrafficPolicy succeeds. It
   provisions `default-deny-all` in every namespace that holds an attachment.

2. **Turn on the node reconciler.** Set `GALACTIC_ROUTER_TRAFFIC_POLICY=true`
   on the plain `galactic-router` DaemonSet, never the route reflector. With
   the mode still `off`, nothing changes for any packet, but every binding
   now reports what each node would install in `status.nodes`, and
   `galactic_cni_traffic_policy_*` appears on each router's metrics port.

3. **Write the grants.** For every VPCAttachment, create a
   TrafficPolicyBinding of the same name with an ingress and an egress
   reference, and the policies they name. A direction without a reference
   gets the built-in `default-deny-all`, which denies everything. Grant by
   path (`Private`, `PublicNAT`, `PublicService`) as well as by address and
   port, so a rule for one path never opens another. Check that every
   binding's `status.nodes` shows both directions `Applied`:

   ```sh
   kubectl get trafficpolicybindings -A -o json | jq -r '
     .items[] | . as $b | .status.nodes[]?
     | select(.ingress.state != "Applied" or .egress.state != "Applied")
     | "\($b.metadata.namespace)/\($b.metadata.name) on \(.node): \(.ingress.state)/\(.egress.state)"'
   ```

4. **Recreate workloads that predate the release.** An interface created
   before the release gets its policy state from `galactic-cni` at startup,
   but not its addresses, so its ARP and its neighbor discovery from a
   global address count as ordinary traffic rather than link operations, and
   are denied unless a rule grants them. Recreate those workloads; a new
   interface records its addresses at ADD.

5. **Audit.** Set `GALACTIC_CNI_TRAFFIC_POLICY=audit` on `galactic-cni`, one
   node or one site at a time. Every decision is now counted, and nothing is
   dropped. Leave it long enough to see each workload's normal traffic,
   including periodic jobs, then find what enforcement would deny:

   ```promql
   # Would be denied by no matching rule, or by a missing binding.
   sum by (resource_namespace, attachment, direction, reason) (
     increase(galactic_cni_traffic_policy_fallback_packets_total[1h])
   ) > 0

   # Would be denied by a rule, including the built-in default.
   sum by (resource_namespace, attachment, direction, policy, rule) (
     increase(galactic_cni_traffic_policy_rule_hits_total{action="deny"}[1h])
   ) > 0

   # Interfaces still on the built-in default.
   count by (resource_namespace, attachment, direction) (
     galactic_cni_traffic_policy_rule_hits_total{policy_uid="builtin:default-deny-all:v1"}
   )
   ```

   `policy_unavailable` means an interface has no installed policy at all:
   its attachment is not bound on its node yet, or its binding's reference is
   missing. `classification_error` means a packet's path could not be
   determined, typically because the node's NAT shard locators have not
   synced. Fix the grants and repeat until each query is empty, or shows only
   traffic you mean to deny. `galactic-router policy explain` decides a
   packet against a policy offline, to check a rule before relying on it.

6. **Enforce.** Set `GALACTIC_CNI_TRAFFIC_POLICY=enforce`, again a node or a
   site at a time, and watch the same queries: they now count drops.
   Changing the mode takes effect at once on every existing interface and
   needs no workload restart.

## Backing out

Set `GALACTIC_CNI_TRAFFIC_POLICY=off`. The datapath stops deciding at once and
forwards as before; bindings, status and counters stay, so moving forward
again resumes where it stopped. Turning the reconciler off
(`GALACTIC_ROUTER_TRAFFIC_POLICY=false`) leaves the installed snapshots in
place but stops updating them, so do that only with the mode `off`.

## In the containerlab lab

The lab in `deploy/containerlab/` enforces from the start: its `galactic-cni`
sets `enforce`, its routers run the reconciler, and every tenant fixture
binds both directions to a policy set granting only the paths its checks use
(`resources/tenants/policies/`). `task verify:traffic-policy` checks that
every binding is installed, and that each path forwards what it grants and
drops, and counts, what it does not. It is the place to try a policy change
before writing it for a cell.
