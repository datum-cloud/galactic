# Gateway Deployment & Configuration

This is a how-to/reference guide for deploying and configuring
`galactic-gateway`, the edge XDP Maglev/DSR L4 load-balancer control plane. For
the design rationale (why DSR, why anycast, why no VRF dependency) see
[docs/agents/ARCHITECTURE-GATEWAY.md](../agents/ARCHITECTURE-GATEWAY.md) —
this document only covers the "how", not the "why", and cross-links back to
that doc wherever the mechanics matter.

> Last verified: 2026-09-09 against the current working tree of
> `cmd/galactic-gateway/`, `internal/config/gateway.go`, `config/galactic-gateway/`,
> `config/galactic-router/`, and `deploy/containerlab/resources/galactic-gateway/`.
> The worked example below is the lab's own gateway deployment in that
> directory.

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
`get`/`list`/`watch`/`update`/`patch` on `networkgateways`/`networkrules`
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
│   └── networkrules.yaml         # ns60-tcp and ns60-udp, port 80, selecting ns60's backends
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
apiVersion: network.datumapis.com/v1alpha1
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
apiVersion: network.datumapis.com/v1alpha1
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
apiVersion: network.datumapis.com/v1alpha1
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

## Configuring `NetworkGateway` and `NetworkRule`

`galactic-gateway` reconciles exactly two CRDs
(`go.datum.net/network`'s `api/v1alpha1` package):

### `NetworkGateway` — one per gateway node

| Field                 | Required | Type     | Description                                                                                                                                                                   |
| --------------------- | -------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spec.targetRef.name` | Yes      | `string` | Kubernetes node name this gateway engine executes on.                                                                                                                         |
| `status.conditions`   | —        | —        | `Ready` condition, reason `EngineHealthy` (converged and fully advertised), `AdvertisementFailed` (converged but couldn't publish one or more rule routes), `DatapathDisabled`, or `Terminating`. |

There is deliberately **no** self-address or primary-node field on this
status — DSR has nothing analogous to publish. Create one object per
gateway node, named after that node (see the worked example above).

### `NetworkRule` — tenant-writable ingress load-balancing spec

| Field                  | Required | Type                   | Description                                                                                                                                                                                            |
| ---------------------- | -------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `spec.vpcRef`          | Yes      | `string`               | Opaque VPC identifier (owned by the companion operator, not validated here beyond non-emptiness). Only attachments whose `status.vpc` equals it can be backends.                                       |
| `spec.vipAddresses`    | Yes      | `[]string` (1–8)       | Ingress VIP addresses this rule provisions. The backend nodes translate IPv6 VIPs only (#705).                                                                                                         |
| `spec.protocol`        | Yes      | `tcp` \| `udp`         | Transport protocol matched by `vipAddresses`/`port`.                                                                                                                                                   |
| `spec.port`            | Yes      | `int32` (1–65535)      | Ingress port on `vipAddresses` this rule load-balances.                                                                                                                                                |
| `spec.backendSelector` | Yes      | `metav1.LabelSelector` | Selects the `VPCAttachment`s (`cloud.datumapis.com`, any namespace) that serve the rule. Each contributes its IPv6 interface addresses as backends. Must not be empty.                                 |
| `spec.backendPort`     | Yes      | `int32` (1–65535)      | Destination port on every selected backend.                                                                                                                                                            |
| `status.conditions`    | —        | —                      | `Accepted` (set `True` once gateway nodes exist; see the admission-webhook caveat below), `<gateway-node>/Programmed` per gateway node, and `<backend-node>/BackendsBound` per node hosting a backend. |

Example, the TCP rule from `deploy/containerlab/resources/galactic-gateway/iad/networkrules.yaml`:

```yaml
apiVersion: network.datumapis.com/v1alpha1
kind: NetworkRule
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

A rule may carry at most one IPv6 VIP: a backend node rewrites a reply's
source back to a single VIP, so a backend cannot answer for a second one. A
rule with two fails to load on the gateways and reports `InvalidRule` on its
backend nodes. IPv4 VIPs are not translated on the backend side (#705).

For the same reason a backend serves only one rule on a given backend port.
The node rewrites a reply by its source, the backend's address, port and
protocol in its VPC, so two rules selecting the same backend on the same
`backendPort` and `protocol` cannot both get their replies back. The oldest
rule, by creation time and then namespace/name, serves the backend. Every
newer rule leaves it out: the gateways send it none of that rule's flows,
the rule's `<gateway-node>/Programmed` message names it as served by the
older rule, and its `<backend-node>/BackendsBound` condition reports
`BackendsClaimed`. A rule left with no backend at all is not loaded. To serve a
second IPv6 VIP from the same backends, give its rule a different
`backendPort` the backends also listen on. Deleting the older rule hands the
backend to the next oldest.

A selected attachment is a backend once its status names a node and its
interface has an IPv6 address. Two attachments claiming one address, or two
backends on one node whose slots (below) collide, keep only the first in
address order; the other is reported as unresolved rather than given flows
it could not answer. Until then it appears in the rule's
`<gateway-node>/Programmed` message with reason `BackendsUnresolved`, as does
a backend whose node advertises no route for it yet. A rule with no backend
at all is not loaded.

Galactic never writes an attachment's status.
[datum-cloud/cloud](https://github.com/datum-cloud/cloud)'s controllers do.
One of them reads the `BGPAdvertisement` that `galactic-router` publishes for
the attachment and copies the node of that advertisement's `BGPRouter` into
`status.node`. Without them, an attachment with no `status.vpc` is never
selected, so the rule reports no backends and no pending entry for it. An
attachment whose `status.vpc` is set but whose `status.node` is not stays
pending with `status.node not set by datum-cloud/cloud`. A rule whose
attachments are all pending or unselected does not load. The containerlab lab
runs none of these controllers, so
`deploy/containerlab/scripts/publish-ns60-attachments.sh` patches
`status.vpc` and `status.node` in by hand.

Every accepted, non-deleting `NetworkRule` in the namespace is served by
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

Deleting a `NetworkRule` withdraws its VIP routes before any gateway node
stops serving it. The rule's finalizer deletes its `BGPAdvertisement`s,
and each node keeps the rule loaded until they are gone plus a 5-second
drain delay, so traffic already on its way to the VIP is not dropped.

> **Known constraint:** no `NetworkRule` admission webhook is deployed in
> this repo today. `Accepted` is set `True` unconditionally once gateway
> nodes exist for the namespace — anyone who can create a `NetworkRule` in
> `galactic-system` can currently provision ingress for any `vpcRef`. See
> ARCHITECTURE-GATEWAY.md's Known Constraints for detail.

### `ServiceVIPBinding` — the backend-side half, generated by `galactic-router`

A `NetworkRule` configures the gateway side of DSR. For a backend to
**answer the client directly** on the VIP, its own node also needs a
`ServiceVIPBinding` for each `(VIP, backend)` pair. Nobody writes these by
hand: `galactic-router` on every node runs `NetworkRuleBindingReconciler`
(`internal/controller/networkrule_binding_controller.go`), which writes one
for each IPv6 VIP of each accepted rule and each selected backend whose
attachment reports that node, and deletes the ones that no longer apply.
`ServiceVIPBindingReconciler`, in the same process, then programs the
node's `vip_xlat_table` from it. Example of a generated binding:

```yaml
apiVersion: network.datumapis.com/v1alpha1
kind: ServiceVIPBinding
metadata:
  name: ns60-tcp-iad-worker-3f0c9a1d6b2e4f57
  namespace: galactic-system
  labels:
    app.kubernetes.io/managed-by: galactic-router
    galactic.datum.net/network-rule: ns60-tcp
    galactic.datum.net/binding-node: iad-worker
  ownerReferences:
    - apiVersion: network.datumapis.com/v1alpha1
      kind: NetworkRule
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

Each node summarizes its bindings on the rule as
`<backend-node>/BackendsBound`: `True` with reason `Bound` once every one
reports `Bound`, `False` with reason `BindingsNotBound` naming each that
does not, `BackendsClaimed` naming each backend on the node an older rule
serves, or `InvalidRule` if the selector cannot be parsed or the rule
has more than one IPv6 VIP. A node keeps the bindings it already wrote
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

## Verifying the deployment

Confirm the DaemonSet and CRDs exist and are healthy:

```sh
kubectl get daemonset -n galactic-system -l app.kubernetes.io/name=galactic-gateway
kubectl get networkgateways,networkrules -n galactic-system
kubectl get pods -n galactic-system -l app.kubernetes.io/name=galactic-gateway -o wide
```

Inspect a specific `NetworkGateway`'s `Ready` condition (`EngineHealthy`,
`AdvertisementFailed`, or `Terminating` — see the field reference above)
and a `NetworkRule`'s `Accepted` condition:

```sh
kubectl get networkgateway <node-name> -n galactic-system -o yaml
kubectl get networkrule <rule-name> -n galactic-system -o yaml
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
by `reason`), and `galactic_edge_control_plane_drops_total` (rule
applications rejected before ever reaching the datapath, e.g. quota
denials). A rule with zero `rule_packets_total` and a client actually
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
interface — `edgeattach.Attach` requests **native XDP driver mode only**
(never generic/SKB mode), so a plain `ip -d link show dev <public-interface>`
on the node itself should show an attached `xdp` program if this step
succeeded; the pod-level checks above (healthy gRPC health status, nonzero
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
