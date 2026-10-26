# Deploying and upgrading gateways

This guide installs the edge gateway and verifies its traffic path. [Configuration](configuration.md) lists settings and service APIs; [architecture](architecture.md) explains component ownership.

## What `galactic-gateway` is, and when you need it

`galactic-gateway` gives external clients a stable VIP:port that
load-balances into a tenant VPC's backend Pods, using a stateless DSR
(Direct Server Return) datapath over a Maglev consistent-hash ring — no
address/port rewriting on the gateway itself, no VRF or Geneve dependency. It is a **separate
binary, container, and DaemonSet from `galactic-router`** —
`config/galactic-gateway/base/daemonset.yaml` is a single-container pod —
deployed on dedicated gateway-role nodes only, alongside `galactic-router`'s
own standalone DaemonSet on those same nodes (opted in via
`galactic.datumapis.com/galactic=router`, the same flag `compute` nodes use;
see `config/galactic-router/overlays/router/`). `galactic-router` used to
run as a second container inside this same pod; it now runs as its own pod,
so a crash on either side no longer takes the other's *pod* down with it,
not just the other's binary. You need `galactic-gateway` only on nodes that
terminate external ingress traffic for tenant VPCs — every other node in the
fleet (`galactic-router` default role, `galactic-cni`) has no dependency on
it. `galactic-nat` is the exception: it can run on the same edge nodes, and
the two share each uplink's XDP hook through the node's shared dispatcher,
each from its own slot (`GALACTIC_GATEWAY_XDP_ATTACH=dispatch` here,
`GALACTIC_NAT_XDP_ATTACH=dispatch` there). See
[docs/nat/configuration.md](../nat/configuration.md). See
[ARCHITECTURE-GATEWAY.md](../gateway/architecture.md) for the full
design (why DSR, the anycast BGP model, the XDP packet path).

## Prerequisite: node labeling

`galactic-gateway`'s DaemonSet only schedules onto nodes labeled both
`galactic.datumapis.com/node: edge` and `galactic.datumapis.com/gateway:
enabled` (see `config/galactic-gateway/base/daemonset.yaml`'s node affinity,
which also excludes `node-role.kubernetes.io/control-plane` nodes outright).
It runs there alongside `galactic-vrf`, which `node=edge` also places, so
label an edge node `gateway=enabled` to opt it in. Read
[docs/node-labels.md](../node-labels.md) for the full node-labeling
strategy before doing anything else here.

A gateway node still needs the same underlay BGP connectivity every other
node needs — `galactic.datumapis.com/fabric=router` for `fabric-router` — and,
in a real (non-lab) deployment, is expected to be tainted to keep ordinary
tenant workloads off it (see `deploy/containerlab/node_files/iad/config.yaml`
for the lab's own taint).

## Step 1: Deploy the shared RBAC/ServiceAccount

```sh
kubectl apply -k config/galactic-gateway/
```

This kustomization covers exactly two resources —
`config/galactic-gateway/serviceaccount.yaml` (the `galactic-gateway`
ServiceAccount in `galactic-system`) and `config/galactic-gateway/rbac.yaml`
(a `ClusterRole`/`ClusterRoleBinding` pair granting that ServiceAccount
`get`/`list`/`watch`/`update`/`patch` on `networkgateways`/`networkservices`
(+`/status`), full CRUD on `bgpadvertisements`, and read-only
`get`/`list`/`watch` on both `bgprouters` and `bgpvrfinstances` — the latter
so `NetworkGatewayReconciler`'s `BGPVRFInstance` watch has an informer it's
actually allowed to list/watch; omitting it once left the manager's cache
sync hanging forever behind a silent `forbidden` reflector error, so it's
called out explicitly in `config/galactic-gateway/rbac.yaml`'s own
comments). It deliberately does **not** include
`config/galactic-gateway/base/` (the DaemonSet itself) — see Step 2. It's
safe and idempotent to apply cluster-wide regardless of how many gateway
nodes exist, and is **not** part of the root `config/kustomization.yaml`'s
default resource list: this role is opt-in, not "batteries included"
cluster bring-up.

`galactic-gateway` is a single-container pod with its own ServiceAccount and
ClusterRole — it carries none of `galactic-router`'s RBAC, and none is
bound to it. But a gateway node still needs a co-located `galactic-router`
**pod** (its own DaemonSet, not a container in this one) advertising that
node's tenant BGP session, since the gateway datapath itself publishes no
routes — so `config/galactic-router/` must also be applied to every gateway
node, opted in the same way a `compute` node is
(`galactic.datumapis.com/galactic=router`; see
[docs/router/configuration.md](../router/configuration.md)). If you already
run `kubectl apply -k config/galactic-router/` for your compute nodes, this
is already satisfied — the same DaemonSet's affinity matches both roles. A
bare `galactic-gateway` pod with no co-located `galactic-router` pod on that
node is not a supported configuration.

## Step 2: Why `config/galactic-gateway/base/` isn't applied as-is

`config/galactic-gateway/base/` is intentionally excluded from
`config/galactic-gateway/`'s own kustomization and must never be applied
directly — doing so produces a crash-looping `galactic-gateway` container. The
reason is `GALACTIC_GATEWAY_PUBLIC_INTERFACE`: every node's public,
underlay-facing uplink interface name can differ, so the base has no default
for it.

`GALACTIC_GATEWAY_SRV6_ADDRESS` no longer needs a per-node value (#707). It
is the source address of every outer header the node's `edge_lb` XDP program
pushes (`edgedsr.c`'s `encap_config_table`), never a translation source and
with no return-path role. Left unset, the gateway derives it at startup from
the `BGPRouter` targeting its node: the node's locator address, its
`srv6Locator` Block followed by its `nodeID` (`2001:db8:ff01::/48` and
`nodeID: 4098` give `2001:db8:ff01:1002::`). Until that router exists with a
locator and node ID, the gateway waits and stays not ready. A failed read
of BGPRouters from the API server is waited on the same way and logged as a
warning on every retry (#797), so a brief API outage does not restart the
gateway and a lasting one stays visible in its logs. The wait counts
against the startup probe, which the base DaemonSet sets to 10 minutes: past
that, the kubelet restarts the container and the wait starts over, so a
router that is still missing shows up as restarts (#796). Setting the
variable overrides the derived value, for a node that needs a different
source.

> See `internal/config/gateway.go`'s `EnvGatewaySRv6Address` doc comment and
> ARCHITECTURE-GATEWAY.md's ["SRv6 encap-source address"](architecture.md#constraints)
> section.

`config/galactic-gateway/base/` is designed to be instantiated **once per
gateway node** by a further overlay that pins the DaemonSet to one node
(`kubernetes.io/hostname`) and sets that node's own
`GALACTIC_GATEWAY_PUBLIC_INTERFACE` value. See the
[worked example](#step-3-worked-example-a-per-node-overlay) below.

See [the configuration reference](configuration.md#process-configuration) for process settings.

### Capabilities across the two co-located pods

`galactic-gateway` and the `galactic-router` pod it's co-located with on the
same gateway node both run with `runAsUser: 0`,
`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, and
`drop: ["ALL"]` on their Linux capabilities, adding back only what each
needs — each in its own pod's `securityContext`, not shared:

| Pod                | Added capabilities            | Why                                                                                                                                                                 |
| ------------------ | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic-router`  | `NET_ADMIN`                   | Same as the plain `default`/`rr` roles — no BPF/PERFMON, since gateway-specific eBPF is confined to the `galactic-gateway` pod                                      |
| `galactic-gateway` | `NET_ADMIN`, `BPF`, `PERFMON` | `BPF` for program/map creation; `PERFMON` because the verifier only allows pointer+scalar arithmetic on packet data when the loading process is `perfmon_capable()` |

`galactic-gateway` also requires `/sys/fs/bpf` mounted from the host as a
real bpffs (`type: Directory`, not `DirectoryOrCreate` — a missing mount
fails loudly rather than silently pinning maps to a plain directory);
`edgeattach.PinDir` pins every map under `/sys/fs/bpf/galactic-edge`. The
`galactic-router` pod separately mounts `/var/run/netns` read-only for its
own GC netns-liveness check (unrelated
to the gateway datapath — see
[ARCHITECTURE-ROUTER.md](../router/architecture.md)).

## Step 3: Worked example, a per-node overlay

`deploy/containerlab/resources/galactic-gateway/` is a real, working
instantiation pattern to copy for production: four edge nodes across three
lab clusters, each with its own overlay directory named for the node.

```
deploy/containerlab/resources/galactic-gateway/
├── base/                 # kustomize base pointing at config/galactic-gateway/base,
│                         #   plus a lab-only image-tag patch (gateway-lab-patch.yaml)
├── dfw-worker2/
│   ├── kustomization.yaml   # pins to one node, renames the DaemonSet
│   ├── node-patch.yaml      # sets PUBLIC_INTERFACE/INTERNAL_INTERFACES
│   └── networkgateway.yaml  # the NetworkGateway object itself
├── dfw-worker3/             # same shape, this node's own values
├── sjc-worker2/             #   "
├── iad-worker2/             #   "
├── dfw/
│   ├── kustomization.yaml        # composes this site's edge nodes + its rules
│   └── networkservices.yaml         # ns60-tcp and ns60-udp, port 80, selecting ns60's backends
├── sjc/                     # same shape, one edge node
└── iad/                     #   "
```

Each site has its own VIP, in a `/64` only that site's edge nodes originate
(`2001:db8:6060:1::/64` for dfw, `:2::` for sjc, `:3::` for iad), and two
`ns60` backends of its own on its compute node, so the per-site directories
differ in both. The backends' `ServiceVIPBinding`s are generated by the
compute node's `galactic-router`, so no site directory carries any.

### `kustomization.yaml` and `node-patch.yaml` — pin to one node, set the per-node values

`dfw-worker2/kustomization.yaml` adds a `kubernetes.io/hostname` match to
the DaemonSet's node affinity, on top of the base's own `node=edge` and
`gateway=enabled` terms, so this overlay's copy of the DaemonSet only ever
schedules onto exactly one node. It also renames the DaemonSet to
`galactic-gateway-dfw-worker2` (a strategic-merge patch can't rename a
resource), so two gateway nodes in the same cluster don't collide under one
name in one namespace:

```yaml
# dfw-worker2's galactic-gateway: one DaemonSet pinned to this node, and the
# NetworkGateway that tells the gateway controller to serve VIPs here.
namespace: galactic-system
resources:
  - ../base
  - networkgateway.yaml
patches:
  - path: node-patch.yaml
    target:
      kind: DaemonSet
      name: galactic-gateway
  # Pins this instance to dfw-worker2, on top of the base's own edge-node and
  # opt-in terms.
  - target:
      kind: DaemonSet
      name: galactic-gateway
    patch: |-
      - op: add
        path: /spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/0/matchExpressions/-
        value:
          key: kubernetes.io/hostname
          operator: In
          values:
            - dfw-worker2
      - op: replace
        path: /metadata/name
        value: galactic-gateway-dfw-worker2
```

`dfw-worker2/node-patch.yaml` sets the gateway container's per-node env
vars:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: galactic-gateway
spec:
  template:
    spec:
      containers:
        - name: galactic-gateway
          env:
            # Transit-facing uplink, where VIP traffic arrives: an LACP bond,
            # so edge_lb runs on each of its members.
            - name: GALACTIC_GATEWAY_PUBLIC_INTERFACE
              value: bond0
            # Compute-facing bond, where backends' VIP-sourced replies cross
            # this node; edge_return runs on its members.
            - name: GALACTIC_GATEWAY_INTERNAL_INTERFACES
              value: bond1
            # GALACTIC_GATEWAY_SRV6_ADDRESS is left unset: the gateway
            # derives this node's encapsulation source from its BGPRouter
            # (resources/galactic-router/dfw/).
```

`dfw-worker3`'s own overlay repeats this shape with its own hostname.

**To generalize this to a real deployment:** create one overlay directory
per gateway node, each pinning `kubernetes.io/hostname` to that node and
setting that node's own public uplink interface name. Give each gateway node
a `BGPRouter` with an `srv6Locator` and `nodeID`, which its co-located
`galactic-router` needs anyway, and the gateway derives its SRv6
encapsulation source from it. Set `GALACTIC_GATEWAY_SRV6_ADDRESS` only to
override that.

### The node's tenant BGP

The co-located `galactic-router` pod needs its own `BGPRouter`/
`BGPPeer` CRDs, exactly like every other `galactic-router` node — a gateway
node is not exempt from the normal tenant-BGP setup. The lab keeps them with
the rest of the router config, in
`deploy/containerlab/resources/galactic-router/dfw/bgprouter-dfw-worker2.yaml`
and `bgppeer-dfw-worker2.yaml`:

```yaml
apiVersion: galactic.datumapis.com/v1alpha1
kind: BGPRouter
metadata:
  name: galactic-router-dfw-worker2
  namespace: galactic-system
spec:
  targetRef:
    kind: Node
    name: dfw-worker2
  localASN: 65000
  routerID: "10.0.1.2"
  srv6Locator: "2001:db8:ff01::/48"
  nodeID: 4098
  addressFamilies:
    - afi: l2vpn
      safi: evpn
---
apiVersion: galactic.datumapis.com/v1alpha1
kind: BGPPeer
metadata:
  name: galactic-control-dfw-worker2
  namespace: galactic-system
spec:
  routerRef:
    name: galactic-router-dfw-worker2
  peerASN: 65000
  address: "fc00:0:8::1"
  remotePort: 1790
  addressFamilies:
    - afi: l2vpn
      safi: evpn
```

See [docs/router/configuration.md](../router/configuration.md) and
[ARCHITECTURE-ROUTER.md](../router/architecture.md) for the full
`BGPRouter`/`BGPPeer` field reference — nothing about these two objects is
gateway-specific.

### `networkgateway.yaml` — register this node as a gateway node

```yaml
apiVersion: galactic.datumapis.com/v1alpha1
kind: NetworkGateway
metadata:
  name: dfw-worker2
  namespace: galactic-system
spec:
  targetRef:
    kind: Node
    name: dfw-worker2
```

| `spec.targetRef.name` must equal the Kubernetes node name — by this repo's |
own convention every `NetworkGateway` fixture and overlay names the object
after the node it targets. `NetworkGatewayReconciler` matches this against
`--node-name`/`GALACTIC_GATEWAY_NODE_NAME` to decide whether it owns this
object.

### Rolling out and rolling back IPv4 VIPs

Roll out in this order:

1. The `NetworkService` CRD, which admits one IPv4 VIP per rule. The API
   server must run Kubernetes 1.30 or later, so that rules stored with two
   VIPs of a family stay editable outside `vipAddresses`.
2. On every backend node, `galactic-cni`, whose datapath translates IPv4
   VIPs to IPv6, and then `galactic-router`, which writes their bindings.
   Roll the two together on each node, and finish every backend node before
   step 6 turns the switch on anywhere. The order matters: a binding reports `Bound`
   once its `vip_xlat_table` rows are written, and the gate cannot see either
   component's version, so a mismatched pair can report a binding `Bound`
   that does not work (see below).
3. `get`, `list` and `watch` on `servicevipbindings` in the
   `galactic-gateway` ClusterRole, infra's copy of
   `config/galactic-gateway/rbac.yaml`.
4. `galactic-gateway` on every gateway node. With the switch off, its
   default, an upgraded gateway serves IPv4 VIPs no more than before.
5. Underlay origination of each IPv4 VIP's prefix from the site's edge
   nodes, as for the IPv6 VIPs.
6. `GALACTIC_GATEWAY_IPV4_VIPS=true`, one gateway node at a time. The backend
   nodes write IPv4 bindings once a gateway reports an IPv4 VIP loaded, so
   turning the switch on is what brings them in. Each node then advertises
   the VIP once its bindings are `Bound`. Check that node's
   `<gateway-node>/IPv4Served`, and that a client off the fabric reaches the
   VIP through it, before moving to the next.

Upgrading `galactic-router` (step 2) before the switch goes on (step 6) is
the safe order. Until a backend node's binding reports `Bound`, a gateway
with the switch on loads the rule's IPv4 VIP but reports `BindingsNotBound`
and advertises nothing, so no IPv4 traffic is drawn to a backend that cannot
translate it yet.

Two things about the gateway's access check at startup matter when the
switch goes on. With the switch on, startup waits up to 30 seconds for the
`servicevipbindings` access review and exits if the review cannot be made,
so a gateway that starts while the API server is unreachable restarts
rather than coming up. And the check runs only at startup: a gateway that
started with the switch on before step 3's grant landed stays with IPv4 VIPs
off, reporting `Unsupported`, until its pod is restarted.

Skew to watch for during the rollout. It fails closed at every step:

- An older gateway leaves IPv4 VIPs out and never advertises them.
- A `galactic-router` that predates IPv4 bindings writes none, so no binding
  is ever `Bound` and the gate never opens.
- A `galactic-router` built from `main` with the native IPv4 path (merged
  2026-10-20, before translation, and possibly running on the staging labs)
  counts only `NotAdvertised` and `Advertised` as loaded. This gateway
  reports those only once some backend's binding is `Bound`, so on its own
  that router writes nothing. Beside upgraded backend nodes it can see one,
  and it then writes bindings with an IPv4 `backendAddress`, and rows that
  rewrite the VIP to that IPv4 address, which it reports `Bound`. The gateway
  never balances over them, since they are not the binding it expects, and
  this release's `galactic-cni` drops any packet that reaches such a row and
  counts it as `vip_ipv4_backend`, rather than delivering untranslated IPv4
  to an IPv6-only workload. Do not run that router beside this release's
  `galactic-cni` while any gateway has the switch on: its backends serve no
  IPv4 VIP traffic. Rolling the two together, as step 2 says, avoids it.
- A `galactic-cni` from before translation ignores an IPv4 VIP's
  `vip_xlat_table` rows, so a newer router beside it reports a binding
  `Bound` that cannot translate. That is why step 2 upgrades the CNI first.

Before turning the switch on, make sure the backends accept `64:ff9b::/96`
sources and that traffic policy allows them (see [What an IPv4 VIP
needs](configuration.md#what-an-ipv4-vip-needs)). Restarts are safe too: a gateway rebuilds
its gate from the API on its first pass, and a backend node's router
re-verifies its bindings when it restarts, so a binding that is no longer
`Bound` takes its backend out of the table and, if it was the last, closes the
gate.

The gateway shares the edge node's XDP dispatcher with the `galactic-nat`
egress shard, and `edge_lb` runs before the shard's slot. It claims an IPv4
packet only when its destination is a loaded IPv4 VIP, and passes every
other IPv4 packet, NAT64's replies included, to the next slot. An IPv4 VIP
must therefore never be one of an egress shard's IPv4 masquerade addresses,
or the gateway would take that address's NAT64 replies.

To roll back, turn `GALACTIC_GATEWAY_IPV4_VIPS` off on every gateway first.
The IPv4 forwarding the gateway turned on, `net.ipv4.ip_forward` included,
stays on after the switch goes off, until the node reboots.
Each node withdraws its `-v4` advertisements on its next pass and reports
`Unsupported`, the backend nodes delete their IPv4 bindings, and the bindings'
finalizers remove their `vip_xlat_table` rows. Once no IPv4
`ServiceVIPBinding` is left, downgrade the gateways, then `galactic-router`
and `galactic-cni`. An earlier `galactic-router` can remove neither of an IPv4
VIP's rows: its `vipxlatmap` refuses the ingress row's IPv4-mapped key, and it
does not know the egress-translated row's direction. If any is left
(`galactic-router vip xlat list` shows them), remove the binding's two rows
with this release's `galactic-router vip xlat remove` before downgrading that
node's router. Roll the CRD back last, if at all. The earlier CRD refuses IPv4
VIPs, so a rule that holds one keeps validating only while its `vipAddresses`
is unchanged, and any edit to the list must drop the IPv4 VIP.

Bindings and rows written by the native IPv4 path go away on their own once
this release's `galactic-router` runs. Its binding writer deletes the
generated bindings with an IPv4 `backendAddress`, since it writes the IPv6
backend's binding instead. Until they are gone they report `BindFailed`,
since an IPv4 `backendAddress` is refused, and their deletion removes no row.
The periodic `vip_xlat_table` sweep then deletes their rows, which no binding
claims. Meanwhile the datapath drops their traffic as `vip_ipv4_backend`.

`galactic-cni` adds the `vip_xlat_failed`, `vip_ipv4_fragment`,
`vip_udp_no_checksum`, `vip_ipv4_backend` and `vip_ttl_exceeded` slots to its
`drop_reasons` map, so the upgrade, and a downgrade past it, recreate that
map and restart every `galactic_usid_drops_total` counter from zero on each
node. No other map changes, and `vip_xlat_table`'s rows survive both.

### Upgrading past the flow hash change

The release that fixes #958 changes the hash `edge_lb` picks a backend
with. The old hash sent a client's consecutive source ports to one backend
far more often than chance. The new one adds a finalizer and spreads them
like random ports. No map, CRD or configuration changes, but the upgrade
moves established flows, because the gateway keeps no connection table: a
flow's backend is whatever the hash picks for it.

What moves, and for how long:

- Once every gateway node runs the new hash, a flow lands on a different
  backend with odds of (N-1)/N for a rule with N backends, so half of all
  flows for two backends. Each moved TCP connection is reset by its new
  backend, and a moved UDP flow reaches a backend holding none of its
  state.
- While the DaemonSet rolls, one node at a time (`maxUnavailable: 1`), the
  old and new nodes pick different backends for the same flow. Each node's
  restart withdraws and re-advertises its VIPs, so the fabric shifts flows
  between gateways, and a flow that crosses between an old and a new node
  can move more than once. This lasts from the first gateway node's
  restart until the last one serves again.
- Rolling back to an earlier release moves the same flows again.

No drain keeps a flow on its backend through this change. Draining a
backend only adds to what moves. To limit the impact:

1. Upgrade during a maintenance window, and tell the owners of services
   with long-lived connections, such as MQTT or WebSocket clients, to
   expect one reconnect.
2. Roll every gateway node in one pass, so the window where nodes disagree
   is as short as the roll itself.
3. After the last node serves, check each node's health and VIP counters
   as [Verifying the deployment](#verifying-the-deployment) describes, and
   that a client off the fabric reaches every VIP.

## Verifying the deployment

Confirm the DaemonSet and CRDs exist and are healthy:

```sh
kubectl get daemonset -n galactic-system -l app.kubernetes.io/name=galactic-gateway
kubectl get networkgateways,networkservices -n galactic-system
kubectl get pods -n galactic-system -l app.kubernetes.io/name=galactic-gateway -o wide
```

Inspect a specific `NetworkGateway`'s `Ready` condition (`EngineHealthy`,
`AdvertisementFailed`, or `Terminating` — see the field reference above)
and a `NetworkService`'s `Accepted` condition:

```sh
kubectl get networkgateway <node-name> -n galactic-system -o yaml
kubectl get networkservice <rule-name> -n galactic-system -o yaml
```

Check both pods' logs — `galactic-gateway`'s own gRPC health check only
reports `SERVING` once the XDP datapath is attached and its VIP table is
reachable (it's forced to `NOT_SERVING` at process start specifically so a
probe never reports healthy before that point):

```sh
kubectl logs -n galactic-system <galactic-gateway-pod>
kubectl logs -n galactic-system -l app.kubernetes.io/name=galactic-router --field-selector spec.nodeName=<node-name>
```

Check this node's tenant BGP session state — the co-located `galactic-router`
pod advertises this node's own `BGPRouter`/`BGPPeer` exactly like any other
node; `STATE` should read `Established`:

```sh
kubectl get bgppeer -n galactic-system -o wide
```

Check the datapath is actually attached and serving traffic via the
Prometheus metrics `galactic-gateway` exposes on its metrics port
(`8081` by default) — `edgemetrics`'s pull-based collector reads
`vip_table`/`vip_stats_table`/`drop_reasons` live on every scrape, and
`internal/gateway/telemetry.go` exposes control-plane-level rejections
separately:

```sh
kubectl exec -n galactic-system <galactic-gateway-pod> -- \
  wget -qO- http://localhost:8081/metrics | grep galactic_edge_
```

Relevant series: `galactic_edge_rule_packets_total`,
`galactic_edge_rule_bytes_total`, `galactic_edge_rule_dropped_packets_total`,
`galactic_edge_rule_backends`, `galactic_edge_rule_seconds_since_last_packet`
(all labeled by `proto`/`port`/`vip`/`vpc`),
`galactic_edge_return_packets_total`, `galactic_edge_return_bytes_total` and
`galactic_edge_return_dropped_packets_total` (labeled by `vip`/`vpc`),
`galactic_edge_drops_total` (labeled
by `reason`; `ipv4_fragment` counts IPv4 fragments addressed to a VIP, which
are dropped because a later fragment has no ports to pick a backend by;
the drop applies to any TCP or UDP port on a VIP address, and it is not
counted in a VIP's own dropped packets because the port is unknown),
`galactic_edge_neigh_fallbacks_total` (load-balanced packets handed to the
kernel because the next hop toward the backend had no neighbor entry, for it
to resolve the neighbor and forward them; not counted as drops), and
`galactic_edge_control_plane_drops_total` (rule
applications rejected before ever reaching the datapath, e.g. quota
denials). In dispatch mode, `galactic_edge_dispatch_lease_renewals_total`
(labeled by `slot` and `result`) and
`galactic_edge_dispatch_lease_expiry_timestamp_seconds` (labeled by `slot`)
show each XDP dispatcher slot's lease: the dispatcher skips a slot once its
lease expires, so a slot whose renewals keep failing stops serving its VIPs. A rule with zero `rule_packets_total` and a client actually
sending traffic points at an upstream problem (BGP not carrying the route,
underlay reachability) rather than this node's own datapath; nonzero
`dropped_packets_total` for a rule with `rule_backends` at `0` means the
rule's own backend list is empty.

`vpc` is the owning rule's `spec.vpcRef`, the same identifier the CNI's
`galactic_usid_vrf_*` series carry, so a sum by `vpc` attributes load
balancer traffic to a tenant. It reads empty in three cases:

1. Right after a gateway restart, until the first reconcile re-applies
   every rule. The counters themselves survive the restart.
2. On a return series whose VIP address is shared by rules of more than one
   VPC, since return traffic is counted per address.
3. On an entry no current rule owns, which the orphan sweep removes.

Deleting a rule removes its series. There is no `vpc_attachment` label,
since a rule's backends can span many VPCAttachments.

Confirm the eBPF program is actually attached to the node's public
interface. `edgeattach.Attach` requests the host's XDP mode, native unless a
NIC on the host uses `bnxt_en` (see [XDP attach mode](../xdp-attach-mode.md)),
so a plain `ip -d link show dev <public-interface>` on the node itself should
show an attached `xdp` program, or `xdpgeneric` on a `bnxt_en` host, if this
step succeeded; the pod-level checks above (healthy gRPC health status, nonzero
metrics) are the primary signal and don't require node-level `ip`/`bpftool`
access.
