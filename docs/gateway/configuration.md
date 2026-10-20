# Gateway Deployment & Configuration

This is a how-to/reference guide for deploying and configuring
`galactic-gateway`, the edge XDP Maglev/DSR L4 load-balancer control plane. For
the design rationale (why DSR, why anycast, why no VRF dependency) see
[docs/agents/ARCHITECTURE-GATEWAY.md](../agents/ARCHITECTURE-GATEWAY.md) —
this document only covers the "how", not the "why", and cross-links back to
that doc wherever the mechanics matter.

> The worked example below is the lab's own gateway deployment in
> `deploy/containerlab/resources/galactic-gateway/`.

## What `galactic-gateway` is, and when you need it

`galactic-gateway` gives external clients a stable VIP:port that
load-balances into a tenant VPC's backend Pods, using a stateless DSR
(Direct Server Return) datapath over a Maglev consistent-hash ring — no
address/port rewriting, no VRF or Geneve dependency. It is a **separate
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
[ARCHITECTURE-GATEWAY.md](../agents/ARCHITECTURE-GATEWAY.md) for the full
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

**Do not confuse this label with the gateway's own "edge XDP" terminology.**
`galactic.datumapis.com/node=edge` is the *node role* label — it identifies an
edge node (which hosts `galactic-vrf`, and `galactic-gateway` or
`galactic-nat` where it carries their opt-in label), distinct from the
ordinary tenant-serving `galactic.datumapis.com/node=compute` role that runs
`galactic-router` (default role)/`galactic-cni`. "Edge XDP" is a separate,
pre-existing description of *what the datapath is* (an XDP program attached
at the actual network edge), used throughout
[ARCHITECTURE-GATEWAY.md](../agents/ARCHITECTURE-GATEWAY.md) independently
of this label scheme. The two happen to share the word "edge" for related
but distinct reasons; see node-labels.md's "Naming collision" section for
the full history of the rename this resolved (an older `node=edge` value
used to mean the tenant-serving role and would collide with a diagram or
comment using today's meaning).

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
> ARCHITECTURE-GATEWAY.md's ["SRv6 encap-source address"](../agents/ARCHITECTURE-GATEWAY.md#srv6-encap-source-address)
> section.

`config/galactic-gateway/base/` is designed to be instantiated **once per
gateway node** by a further overlay that pins the DaemonSet to one node
(`kubernetes.io/hostname`) and sets that node's own
`GALACTIC_GATEWAY_PUBLIC_INTERFACE` value. See the
[worked example](#step-3-worked-example-a-per-node-overlay) below.

### Configuration reference (`internal/config/gateway.go`)

`galactic-gateway` supports configuration via environment variables, CLI
flags, or a combination of both (CLI flags take precedence), with the
`GALACTIC_GATEWAY` env prefix — the same three-tier precedence pattern
`galactic-router` uses (see [docs/router/configuration.md](../router/configuration.md)).

| Option              | Environment Variable                   | CLI Flag                        | Default     | Required      |
| ------------------- | -------------------------------------- | ------------------------------- | ----------- | ------------- |
| Node name           | `GALACTIC_GATEWAY_NODE_NAME`           | `--node-name`, `-n`             | —           | Yes           |
| Public interface    | `GALACTIC_GATEWAY_PUBLIC_INTERFACE`    | `--gateway-public-interface`    | —           | While enabled |
| SRv6 address        | `GALACTIC_GATEWAY_SRV6_ADDRESS`        | `--gateway-srv6-address`        | Derived     | No            |
| Internal interfaces | `GALACTIC_GATEWAY_INTERNAL_INTERFACES` | `--gateway-internal-interfaces` | —           | No            |
| XDP attach mode     | `GALACTIC_GATEWAY_XDP_ATTACH`          | `--gateway-xdp-attach`          | `dispatch`  | No            |
| Datapath enabled    | `GALACTIC_GATEWAY_DATAPATH_ENABLED`    | `--gateway-datapath-enabled`    | `true`      | No            |
| IPv4 VIPs           | `GALACTIC_GATEWAY_IPV4_VIPS`           | `--gateway-ipv4-vips`           | `true`      | No            |
| Procfs sysctl root  | `GALACTIC_GATEWAY_PROC_SYS_PATH`       | `--gateway-proc-sys-path`       | `/proc/sys` | No            |
| Metrics port        | `GALACTIC_GATEWAY_METRICS_PORT`        | `--metrics-port`                | `8081`      | No            |
| gRPC health port    | `GALACTIC_GATEWAY_GRPC_HEALTH_PORT`    | `--grpc-health-port`            | `5181`      | No            |

`GALACTIC_GATEWAY_XDP_ATTACH` is `dispatch` or `direct`. `dispatch` runs
`edge_lb` and `edge_return` from the gateway slots of the node's shared,
pinned XDP dispatcher, so a restart swaps the programs in place without
detaching anything, and the egress shard can share the uplinks. `direct`
attaches the programs themselves, unpinned, so they detach when the process
exits. It first detaches an idle dispatcher from its interfaces, and refuses
to start while another datapath's slot is live there. See
[Sharing the XDP hook](../agents/ARCHITECTURE-GATEWAY.md#sharing-the-xdp-hook-xdpdispatch).

`GALACTIC_GATEWAY_IPV4_VIPS=true`, the default, serves IPv4 VIPs on this
node. It does three things:

- It turns on IPv4 forwarding on every public and internal interface for the
  datapath's FIB lookups, including the host-wide `net.ipv4.ip_forward`, so
  the node then routes IPv4 between all of its interfaces. It does so only
  when the node is about to load its first IPv4 VIP, not at startup, so
  upgrading a gateway on which no rule has an IPv4 VIP leaves its IPv4
  forwarding as it was. An interface the datapath picks up later, such as a
  replacement bond member, gets it too. Once on, it stays on until the node
  reboots, even after the last IPv4 VIP goes or the switch is turned off:
  `net.ipv4.ip_forward` is host-wide, and turning it back off could cut
  another datapath on the node. If it cannot be turned on, the pass that
  would load the IPv4 VIP is not applied at all, the `NetworkGateway`'s
  `Ready` reads `False` with reason `IPv4ForwardingFailed`, and the pass is
  retried; the rules the node already serves stay as they were.
- It loads each rule's IPv4 VIP into the datapath beside its IPv6 VIP,
  balanced over the rule's IPv6 backends, whose nodes translate its flows
  (see [What an IPv4 VIP needs](#what-an-ipv4-vip-needs)).
- It advertises the IPv4 VIP (the rule's `-v4` `BGPAdvertisement`) once the
  readiness gate below holds, and withdraws it as soon as the gate closes.

The gateway reads and watches `ServiceVIPBinding`s for the gate, so its
ClusterRole needs `get`, `list` and `watch` on `servicevipbindings`
(`config/galactic-gateway/rbac.yaml`). At startup, with the switch on, the
gateway checks that it can list and watch them. If the API server denies it,
the gateway logs an error naming the missing access and runs with IPv4 VIPs
off: it serves IPv6 as usual, loads and advertises no IPv4 VIP, and every rule
with an IPv4 VIP reports `Unsupported` for the node. Grant the access and
restart the pod to turn IPv4 VIPs on. If the check cannot be made at all, for
example while the API server is unreachable, the gateway retries it for 30
seconds and then exits, so the restart checks again. It does not turn IPv4 off
on a failed check, because a node reporting IPv4 unloaded lets backend nodes
remove their IPv4 bindings once no gateway reports it loaded. Without the
check, a watch the gateway may not make would keep its cache from syncing, and
the node would serve no rule at all.

The default is `true`, so upgrading a gateway to this release turns IPv4
VIPs on. Its ClusterRole must grant `get`, `list` and `watch` on
`servicevipbindings` before the release reaches a cluster. Infra deploys its
own copy of that ClusterRole, so the grant has to land there first.
Otherwise each gateway runs with IPv4 VIPs off and reports the missing
permission, as the paragraph above describes. The switch stays as a
per-node kill switch: setting it to `false` withdraws every IPv4 VIP the
node advertises and unloads them, and leaves IPv6 untouched. See
[Rolling out and rolling back IPv4 VIPs](#rolling-out-and-rolling-back-ipv4-vips).

`GALACTIC_GATEWAY_DATAPATH_ENABLED=false` keeps the process up and its pod
ready but loads nothing, empties the gateway's dispatcher slots, and
withdraws every one of this node's VIP advertisements. The NetworkGateway's
`Ready` reads `False` with reason `DatapathDisabled`. The public interface
is not required while it is off, and no SRv6 address is derived.

`GALACTIC_GATEWAY_PROC_SYS_PATH` is the procfs root the datapath writes its
forwarding sysctls under (`net.ipv6.conf.<iface>.forwarding` and
`net.ipv6.conf.all.forwarding`). `bpf_fib_lookup` refuses every lookup on an
interface with forwarding off, so a sysctl that does not read `1` after the
write stops the gateway at startup, and leaves an interface found later
without the datapath until it does. A pod that is not privileged gets
`/proc/sys` read-only, so `config/galactic-gateway/base/daemonset.yaml`
mounts the host's `/proc/sys/net` at `/host/proc/sys/net` and sets this to
`/host/proc/sys`. A node where something else already turned forwarding on
passes with the default too. SELinux policy on an enforcing node can still
refuse the write, and the gateway then says so at startup.

`GALACTIC_GATEWAY_INTERNAL_INTERFACES` is a comma-separated list of this
node's compute-facing interfaces, and it is what puts the return path in
place. Where the compute tier reaches the fabric through this node, a
backend's reply to a VIP crosses it as ordinary forwarded traffic, and the
kernel drops it: the request reached the backend encapsulated through XDP,
so connection tracking never saw the flow and marks the reply invalid, which
kube-proxy's `KUBE-FORWARD` chain drops. Naming the interfaces here attaches
the `edge_return` program to them, which forwards those replies before
netfilter runs. Leave it unset on a node with no compute tier behind it.

Never name the public uplink here. On the uplink, an external client could
source a packet from a VIP address and have this program forward it
unexamined; from the compute side that traffic is this gateway's own by
construction.

Both required fields are enforced by `GatewayConfig.Validate` at
startup — a node deployed without them crash-loops immediately with an
actionable message rather than running degraded. `Validate` additionally
rejects a set SRv6 address that isn't a native IPv6 address (an IPv4 or
4-in-6 value fails validation, per `internal/config/gateway.go`). An unset
one is derived from the node's `BGPRouter`; two `BGPRouter`s for the same
node that derive different addresses stop the gateway at startup.

The `8081`/`5181` metrics/gRPC-health port defaults deliberately differ
from `galactic-router`'s own `9179`/`5179` defaults, because on a gateway
node both run as separate `hostNetwork: true` pods — every port either one
binds shares that node's network namespace and must not collide, even
though the two are no longer co-located in the same pod:

| Pod                                                                                          | Metrics | gRPC health |
| --------------------------------------------------------------------------------------------- | ------- | ----------- |
| `galactic-router` (this node's tenant-BGP side, `config/galactic-router/overlays/router/`)     | `9179`  | `5179`      |
| `galactic-gateway`                                                                              | `8081`  | `5181`      |

The `galactic-router` pod on a gateway node is the exact same DaemonSet as
`galactic-router`'s default role on a `compute` node — it carries no
gateway-specific env of its own and sets
`GALACTIC_ROUTER_BGP_LISTEN_PORT=-1` (outbound-only — no inbound BGP
listener on this role). See
[docs/router/configuration.md](../router/configuration.md) for what every
`GALACTIC_ROUTER_*` variable does.

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
[ARCHITECTURE-ROUTER.md](../agents/ARCHITECTURE-ROUTER.md)).

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
[ARCHITECTURE-ROUTER.md](../agents/ARCHITECTURE-ROUTER.md) for the full
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

## Configuring `NetworkGateway` and `NetworkService`

`galactic-gateway` reconciles exactly two CRDs
(`api/network/v1alpha1`):

### `NetworkGateway` — one per gateway node

| Field                 | Required | Type     | Description                                                                                                                                                                                                                                                                                                                                     |
| --------------------- | -------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spec.targetRef.name` | Yes      | `string` | Kubernetes node name this gateway engine executes on.                                                                                                                                                                                                                                                                                           |
| `status.conditions`   | —        | —        | `Ready` condition, reason `EngineHealthy` (converged and fully advertised), `AdvertisementFailed` (converged but couldn't publish one or more rule routes), `DatapathDisabled`, `IPv4ForwardingFailed` (an IPv4 VIP is due to load but the node's IPv4 forwarding could not be turned on, so nothing in the pass is applied), or `Terminating`. |

There is deliberately **no** self-address or primary-node field on this
status — DSR has nothing analogous to publish. Create one object per
gateway node, named after that node (see the worked example above).

### `NetworkService` — internal ingress load-balancing spec

| Field                  | Required | Type                   | Description                                                                                                                                                                                                                                                                                  |
| ---------------------- | -------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spec.vpcRef`          | Yes      | `string`               | Opaque VPC identifier (owned by the Galactic cell controller, not validated here beyond non-emptiness). Only attachments whose `status.vpc` equals it can be backends.                                                                                                                       |
| `spec.vipAddresses`    | Yes      | `[]string` (1–8)       | Ingress VIP addresses this rule provisions: at most one IPv6 and at most one IPv4 address, an IPv4 address in dotted form. See below.                                                                                                                                                        |
| `spec.protocol`        | Yes      | `tcp` \| `udp`         | IP protocol load-balanced on `vipAddresses`. The API also accepts `sctp`, `esp`, `gre` and `icmp`, but refuses them as not served yet; see below.                                                                                                                                            |
| `spec.port`            | tcp, udp | `int32` (1–65535)      | Ingress port on `vipAddresses` this rule load-balances. Required for a protocol with ports, refused for one without.                                                                                                                                                                         |
| `spec.backendSelector` | Yes      | `metav1.LabelSelector` | Selects the `VPCAttachment`s (`galactic.datumapis.com`, any namespace) that serve the rule. Each contributes its IPv6 interface addresses as backends of both VIPs; its IPv4 addresses are never backends. Must not be empty.                                                                |
| `spec.backendPort`     | tcp, udp | `int32` (1–65535)      | Destination port on every selected backend. Required for a protocol with ports, refused for one without.                                                                                                                                                                                     |
| `status.conditions`    | —        | —                      | `Accepted` (set `True` once gateway nodes exist in the namespace; not an ownership check, see below), `<gateway-node>/Programmed` per gateway node, `<gateway-node>/IPv4Served` per gateway node for a rule with an IPv4 VIP, and `<backend-node>/BackendsBound` per node hosting a backend. |

Example, the TCP rule from `deploy/containerlab/resources/galactic-gateway/iad/networkservices.yaml`:

```yaml
apiVersion: galactic.datumapis.com/v1alpha1
kind: NetworkService
metadata:
  name: ns60-tcp
  namespace: galactic-system
spec:
  vpcRef: "60"
  vipAddresses:
    - 2001:db8:6060:3::1
  protocol: tcp
  port: 80
  backendSelector:
    matchLabels:
      app: backend
  backendPort: 80
```

The gateways serve `tcp` and `udp`. The API also lists `sctp`, which has
ports, and `esp`, `gre` and `icmp`, which have none, so that serving them
later needs no API change. Until then, creating or updating a rule with any of
them is refused with `protocol is not served yet: the gateway datapath serves
tcp and udp only`. Both ports are required for `tcp`, `udp` and `sctp`, and
must be unset for `esp`, `gre` and `icmp`, whose backends are chosen from the
client and VIP addresses alone (see
[ARCHITECTURE-GATEWAY.md](../agents/ARCHITECTURE-GATEWAY.md#protocols-without-ports-designed-not-served)).
The set of protocols is open-ended, so a client reading a rule must accept a
`protocol` value it does not recognise, keep it when writing the rule back, and
never treat it as `tcp` or `udp`. A rule that reaches the gateways with a protocol they do not serve,
for example one stored under a schema that admitted it, is not loaded or
advertised, and its `<gateway-node>/Programmed` condition reports
`UnservedProtocol`. One with an unset or out-of-range port reports
`InvalidRule`. Its backend nodes keep the bindings they already have and
report `InvalidRule` on `<backend-node>/BackendsBound`.

A rule may carry at most one VIP of each family: a backend node rewrites a
reply's source back to a single VIP of the client's family, so a backend
cannot answer for a second one. To serve another VIP of a family, create
another rule whose backends listen on a different `backendPort`. Admission
refuses a second VIP of either family, and an IPv4-mapped IPv6 address such
as `::ffff:203.0.113.5`; write an IPv4 VIP in dotted form. A rule stored with
two VIPs of a family before these limits keeps validating while its
`vipAddresses` is unchanged, because the API server ratchets validation of an
unchanged field on Kubernetes 1.30 and later. Any edit to the list must bring
it within the limits, and an older API server refuses every update to such a
rule. The controllers still handle one. A rule with two IPv6 VIPs fails to
load on the gateways and reports `InvalidRule` on its backend nodes. A rule
with two IPv4 VIPs keeps its IPv6 VIP: the gateways never load or advertise
either IPv4 VIP and report `MultipleVIPs`, and its backend nodes report
`InvalidRule` and write no IPv4 binding, while the IPv6 VIP's bindings stay
current.

A gateway node advertises a rule's IPv4 VIP only while all of these hold:

1. `GALACTIC_GATEWAY_IPV4_VIPS` is on.
2. The rule has exactly one IPv4 VIP, and the node's engine loaded the rule.
3. At least one selected attachment in the rule's VPC has an IPv6 address
   whose backend uSID resolves and that no older rule serves for an IPv4 VIP
   on the same `backendPort` and `protocol`.
4. That backend's `ServiceVIPBinding` for the IPv4 VIP reports `Bound` for
   its current generation and the rule's current spec, and is not being
   deleted.

The node balances the IPv4 VIP only over the eligible backends whose binding
is `Bound`. A backend whose binding is missing, failed, out of date or being
deleted is left out of the Maglev table and named in the node's
`<gateway-node>/Programmed` message, so no flow reaches a backend that cannot
answer it. That way every node that advertises the VIP serves it, and every
backend it sends a flow to can reply. A new backend joins once its binding is
`Bound`, without withdrawing the VIP. While none of the eligible backends is
`Bound`, the node still loads the VIP over all of them but does not advertise
it: the backend nodes write IPv4 bindings only while a gateway reports the VIP
loaded, so the VIP has to load before any binding can become `Bound`. The node
withdraws the `-v4` advertisement on the first pass where any condition stops
holding, even if writing the rule's `-v6` advertisement fails on that pass,
and the rule's IPv6 VIP and its `-v6` advertisement are not affected.

Each gateway node reports what it did with a rule's IPv4 VIPs as its
`<gateway-node>/IPv4Served` condition:

| Status  | Reason             | Meaning                                                                                                                         |
| ------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `True`  | `Advertised`       | loaded over the eligible backends whose bindings are `Bound`, at least one, and advertised                                      |
| `False` | `NotAdvertised`    | loaded over `Bound` backends, but the route is not published: no `BGPRouter` targets the node, or the advertisement failed      |
| `False` | `BindingsNotBound` | loaded over every eligible backend, but none of their bindings is `Bound` yet, so not advertised                                |
| `False` | `Unsupported`      | `GALACTIC_GATEWAY_IPV4_VIPS` is off, so they are left out of the datapath                                                       |
| `False` | `NoBackend`        | the switch is on, but no selected attachment has an IPv6 address that is a backend of this IPv4 VIP (none, unresolved, claimed) |
| `False` | `MultipleVIPs`     | the switch is on, but the rule has more than one IPv4 VIP, so none loads                                                        |
| `False` | `NotLoaded`        | the switch is on, but the node did not load the rule at all                                                                     |

`Advertised`, `NotAdvertised` and `BindingsNotBound` mean the node has the
IPv4 VIP loaded. The rule's IPv6 VIP keeps serving in every case. A rule whose
every VIP is IPv4 is not loaded where none of them can be, and its
`<gateway-node>/Programmed` condition reports `NoServedVIP` with the switch
off and `InvalidRule` with it on. An IPv4 VIP's backends are the selected
attachments' IPv6 addresses, the same ones as the IPv6 VIP's. Each backend
node writes a binding for each of them, pairing the IPv4 `vipAddress` with the
IPv6 `backendAddress`, but only while some gateway node reports one of the
three loaded reasons for the rule, and deletes them once none does, so a cell
whose gateways leave IPv4 VIPs out has no IPv4 bindings or rows. Each gateway
pass removes the `<node>/Programmed` and `<node>/IPv4Served` conditions of any
node that no `NetworkGateway` in the namespace targets, so a gateway that left
without clearing its conditions cannot keep the backend nodes' IPv4 bindings
alive. A node missing from the gateway's cache is confirmed missing with an
uncached read of the API server first, so a new gateway node's conditions are
never removed while the cache has yet to see its `NetworkGateway`.

#### What an IPv4 VIP needs

Workloads are IPv6 only. An IPv4 VIP needs nothing from its backends but an
IPv6 address in the rule's VPC, the same address that serves the IPv6 VIP;
admission takes no IPv4 backend, and an attachment's IPv4 address is never
one. The backend's node translates between the families statelessly (RFC
7915):

- A client's IPv4 packet reaches the workload as IPv6, addressed to the
  backend's IPv6 address and `backendPort`, from the client's address under
  the RFC 6052 well-known prefix `64:ff9b::/96`. A client at `192.0.2.10`
  appears as `64:ff9b::c000:20a`, so the client's own address is preserved,
  embedded in the low 32 bits. IPv4 options are dropped.
- The workload replies to that address as it would to any IPv6 client. Its
  node translates the reply back to IPv4, from the VIP and `port` to the
  client, with Don't Fragment set, and sends it straight out its fabric
  uplink.

So the workload must accept connections from `64:ff9b::/96` sources (check
any firewall or allow-list) and route replies to them through its default
route, which every Galactic attachment has. A reply that the node does not
recognize as the VIP's, from another port for example, is ordinary NAT64
egress traffic. The same backend socket can serve the rule's IPv4 and IPv6
VIPs at once. The node drops and counts an IPv4 UDP datagram with no
checksum (`vip_udp_no_checksum`), since IPv6 requires one, and an IPv4
fragment (`vip_ipv4_fragment`), which the gateway never sends. TCP's MSS is
clamped so a client's segments fit the fabric once the gateway encapsulates
them. A reply too big for the client's path is not fragmented; the ICMPv4
error it draws goes to the VIP and the backend never learns of it. The node
translates as a router does, decrementing the TTL or hop limit, and drops and
counts a packet that would reach zero (`vip_ttl_exceeded`).

Only a TCP or UDP reply with no extension header is translated. Anything
else the workload sends to `64:ff9b::/96`, such as an ICMPv6 Destination
Unreachable or Packet Too Big, a packet with an extension header, or an IPv6
fragment, leaves as ordinary NAT64 egress from the backend's own address, so
the client never receives it as traffic from the VIP. In particular a client
does not see the backend's port unreachable errors, and a large UDP reply the
backend fragments never reaches it.

Interface traffic policy sees an IPv4 VIP's flows after translation: an
ingress rule on the backend's attachment matches the client as its
`64:ff9b::/96` address, IPv6 and TCP or UDP, never as an IPv4 address. A rule
that allows IPv4 clients by an IPv4 CIDR, or with `ipFamily: IPv4`, does not
match them; write it for `64:ff9b::<client>/128`, or `64:ff9b::/96` for every
IPv4 client. See [Traffic policy on the node](../traffic-policy/node.md).
See [the CNI datapath](../agents/ARCHITECTURE-CNI.md#key-design-decisions).

For the same reason a backend serves only one rule on a given backend port.
The node rewrites a reply by its source, the backend's address, port and
protocol in its VPC, so two rules selecting the same backend on the same
`backendPort` and `protocol` cannot both get their replies back. The oldest
rule, by creation time and then namespace/name, serves the backend. Every
newer rule leaves it out: the gateways send it none of that rule's flows,
the rule's `<gateway-node>/Programmed` message names it as served by the
older rule, and its `<backend-node>/BackendsBound` condition reports
`BackendsClaimed`. A rule left with no backend at all is not loaded. To serve a
second VIP of one family from the same backends, give its rule a different
`backendPort` the backends also listen on. Deleting the older rule hands the
backend to the next oldest. The claim is per VIP family: replies to IPv4
clients and to IPv6 clients are rewritten by different rows, so an IPv6 rule
and an IPv4 rule on the same backend, `backendPort` and `protocol` both serve
it, while two rules with IPv4 VIPs there compete like two with IPv6 VIPs.

A selected attachment is a backend of both VIPs once its status names a node
and its interface has an IPv6 address. Two attachments claiming one address,
or two backends on one node whose slots (below) collide, keep only the first
in address order; the other is reported as unresolved rather than given flows
it could not answer. Until then it appears in the rule's
`<gateway-node>/Programmed` message with reason `BackendsUnresolved`, as does
a backend whose node advertises no route for it yet. A rule with no backend
at all is not loaded.

The Galactic cell controllers write attachment status.
One of them reads the `BGPAdvertisement` that `galactic-router` publishes for
the attachment and copies the node of that advertisement's `BGPRouter` into
`status.node`. Without them, an attachment with no `status.vpc` is never
selected, so the rule reports no backends and no pending entry for it. An
attachment whose `status.vpc` is set but whose `status.node` is not stays
pending with `status.node not set by the Galactic cell controller`. A rule whose
attachments are all pending or unselected does not load. The containerlab lab
runs none of these controllers, so
`deploy/containerlab/scripts/publish-attachments.sh` patches
`status.vpc` and `status.node` in by hand.

Every accepted, non-deleting `NetworkService` in the namespace is served by
**every** `NetworkGateway` node identically — there is no
`status.primaryNode`/placement field to set, and no per-node subset to
target. `galactic-gateway` resolves each backend to the SRv6 uSID of the
node its attachment reports, through that node's
`BGPAdvertisement`/`BGPRouter`/`BGPVRFInstance` CRDs, and verifies the rule's
own `vpcRef` owns the match before trusting it. It then writes the backend's
slot, a hash of its address and port, into bits 81–96 of that uSID, so a node
hosting several of the rule's backends can tell which one Maglev chose.
Placement across gateway nodes is Maglev's consistent-hash ring (built
identically on every node from the same `(VIP, backend list)` input) plus
anycast BGP at equal preference — not a control-plane assignment step you
configure here. The gateways watch `VPCAttachment`s, so a backend that
appears, moves to another node or changes address reconverges the rule
without an edit. See
[ARCHITECTURE-GATEWAY.md's Data Flow section](../agents/ARCHITECTURE-GATEWAY.md#data-flow)
for the full mechanics.

Deleting a `NetworkService` withdraws its VIP routes before any gateway node
stops serving it. The rule's finalizer deletes its `BGPAdvertisement`s,
and each node keeps the rule loaded until they are gone plus a 5-second
drain delay, so traffic already on its way to the VIP is not dropped.

> **Note:** `NetworkService` is not a tenant API. The platform API that serves
> tenants writes it, after checking that the tenant owns the VPC `vpcRef`
> names. Galactic does not repeat that check: `Accepted` means only that
> gateway nodes exist in the namespace. Anyone RBAC allows to write a
> `NetworkService` in `galactic-system` can provision ingress for any `vpcRef`,
> so grant that access only to platform controllers.

### `ServiceVIPBinding` — the backend-side half, generated by `galactic-router`

A `NetworkService` configures the gateway side of DSR. For a backend to
**answer the client directly** on the VIP, its own node also needs a
`ServiceVIPBinding` for each `(VIP, backend)` pair. Nobody writes these by
hand: `galactic-router` on every node runs `NetworkServiceBindingReconciler`
(`internal/controller/networkservice_binding_controller.go`), which writes one
for each VIP of each accepted rule, at most one per family, and each
selected backend whose attachment reports that node, and
deletes the ones that no longer apply. An IPv4 VIP gets bindings only while
a gateway node has it loaded (see above).
`ServiceVIPBindingReconciler`, in the same process, then programs the
node's `vip_xlat_table` from it. Example of a generated binding:

```yaml
apiVersion: galactic.datumapis.com/v1alpha1
kind: ServiceVIPBinding
metadata:
  name: ns60-tcp-iad-worker-3f0c9a1d6b2e4f57
  namespace: galactic-system
  labels:
    app.kubernetes.io/managed-by: galactic-router
    galactic.datum.net/network-rule: ns60-tcp
    galactic.datum.net/binding-node: iad-worker
  ownerReferences:
    - apiVersion: galactic.datumapis.com/v1alpha1
      kind: NetworkService
      name: ns60-tcp
spec:
  targetRef:
    kind: Node
    name: iad-worker
  vpcRef: "60"
  vipAddress: 2001:db8:6060:3::1
  port: 80
  protocol: tcp
  backendAddress: fd20:60:ff03:a::100
  backendPort: 80
  egressKind: veth
```

- `targetRef.name` is the **backend's own node**, from its attachment's
  `status.node`, not a gateway node.
- `vpcRef` is the rule's. It names the VRF the binding's rows go into
  (`BGPVRFInstance` `<vpc>-<node>`), so two tenants using the same backend
  address on one node never share a row.
- `egressKind` comes from the attachment's interface mode: `veth` for
  `Netns` (a container), `tap` for `Hypervisor` or `HypervisorDeclared` (a
  VM).
- The binding is owned by the rule, so deleting the rule removes it, after
  the gateways have drained the VIP. A rule that loses `Accepted`, as it
  does whenever its namespace briefly has no `NetworkGateway`, keeps its
  bindings, so the backend nodes' rows survive until the gateways return.
  A backend that moves to another node or changes address has its binding
  deleted on the old node and a new one written where it now runs.

The ingress row is keyed on the VIP, port and the backend's slot, the same
hash of the backend's address and port the gateway writes into the uSID. So
several backends of one VIP can share a node, each answering the flows
Maglev sent it. Two bindings conflict only when they claim the same row:
the same VIP, port, protocol and slot, or the same backend address, port
and protocol, in the same VPC. The older binding keeps serving. The newer
one is not programmed and reports `Bound=False` with reason `Conflict`,
naming the binding that holds the row.

`usid.c` matches only the slot the gateway sent, with no fallback to the
slot-0 ingress rows a `galactic-router` built before #799 wrote, so upgrade
`galactic-gateway` and `galactic-router` together. Each router rewrites its
bindings' rows with slots when it starts, and its periodic `vip_xlat_table`
sweep removes the old slot-0 rows.

A binding is programmed only once its VPC's VRF on the node advertises a
prefix containing `backendAddress`, through a `BGPAdvertisement` on that
node's `BGPRouter` with the VRF's ID. Until then it reports `Bound=False`
with reason `BindFailed`, naming the VPC, VRF, node and address, and claims
no row. This catches a hand-written binding for an address the node does not
serve, an attachment whose interface is not up yet, and a stale attachment
address. A new or changed advertisement on the node requeues its bindings,
so one written first binds as soon as the address is advertised. Deleting a
binding never needs the advertisement.

Each node summarizes its bindings on the rule as
`<backend-node>/BackendsBound`: `True` with reason `Bound` once every one
reports `Bound`, `False` with reason `BindingsNotBound` naming each that
does not, `BackendsClaimed` naming each backend on the node an older rule
serves, or `InvalidRule` if the selector cannot be parsed or the rule
has more than one VIP of a family. A node keeps the bindings it already wrote
for an invalid rule, so its `vip_xlat_table` rows survive an invalid edit
until the spec is fixed or the rule is deleted. Only a node that holds
bindings for the rule reports `InvalidRule`. Every other node writes
nothing and removes a condition left from when it served the rule, since
the gateways already report the error in their `Programmed` conditions. A
rule can be `Programmed` on every gateway and still fail to reach a
backend; this condition is where that shows.

A node's own `galactic-router` is the only one that clears its condition,
deletes its bindings and removes the teardown finalizer from bindings
targeting it. When a node is decommissioned and its `Node` object deleted,
the surviving routers do it instead: they remove its
`<backend-node>/BackendsBound` condition from every rule, delete its
generated bindings, and remove the finalizer from every binding targeting
it, hand-written ones included, so none stays `Terminating`. Its kernel
state went with the node. Each router checks at startup, on every `Node`
deletion and every `--gc-interval`, so one that was down when the node left
still cleans up. Delete the `Node` object only once the node is gone for
good: if the node is still running, its bindings are deleted without
teardown, and it writes them again on its next reconcile.

### Rolling out and rolling back IPv4 VIPs

Roll out in this order:

1. The `NetworkService` CRD, which admits one IPv4 VIP per rule. The API
   server must run Kubernetes 1.30 or later, so that rules stored with two
   VIPs of a family stay editable outside `vipAddresses`.
2. On every backend node, `galactic-cni`, whose datapath translates IPv4
   VIPs to IPv6, and then `galactic-router`, which writes their bindings.
   Roll the two together on each node, and finish every backend node before
   step 4 upgrades any gateway. The order matters: a binding reports `Bound`
   once its `vip_xlat_table` rows are written, and the gate cannot see either
   component's version, so a mismatched pair can report a binding `Bound`
   that does not work (see below).
3. `get`, `list` and `watch` on `servicevipbindings` in the
   `galactic-gateway` ClusterRole, infra's copy of
   `config/galactic-gateway/rbac.yaml`. This must land before this release
   of `galactic-gateway` reaches the cluster, because the release serves
   IPv4 VIPs by default.
4. `galactic-gateway`, one gateway node at a time. The switch is on by
   default, so each upgraded node loads every rule's IPv4 VIP. The backend
   nodes write IPv4 bindings once a gateway reports an IPv4 VIP loaded, so
   this is what brings them in. Each node then advertises the VIP once its
   bindings are `Bound`. Check that node's `<gateway-node>/IPv4Served`
   before moving to the next. To upgrade with IPv4 off and turn it on
   later, set `GALACTIC_GATEWAY_IPV4_VIPS=false` on the gateways for the
   upgrade, then remove the override one gateway node at a time.

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

Before the gateways are upgraded, make sure the backends accept `64:ff9b::/96`
sources and that traffic policy allows them (see [What an IPv4 VIP
needs](#what-an-ipv4-vip-needs)). Restarts are safe too: a gateway rebuilds
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

To roll back, set `GALACTIC_GATEWAY_IPV4_VIPS=false` on every gateway first.
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
counted in a VIP's own dropped packets because the port is unknown), and `galactic_edge_control_plane_drops_total` (rule
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

## See also

- [docs/agents/ARCHITECTURE-GATEWAY.md](../agents/ARCHITECTURE-GATEWAY.md) —
  design rationale, full data-flow walkthrough, module reference, known
  constraints.
- [docs/node-labels.md](../node-labels.md) — the full node-labeling
  strategy shared across every Galactic component.
- [docs/router/configuration.md](../router/configuration.md) — the
  `GALACTIC_ROUTER_*` environment variables the co-located `galactic-router`
  pod on the same gateway node also reads.
