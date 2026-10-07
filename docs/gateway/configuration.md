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
locator and node ID, the gateway waits and stays not ready. Setting the
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
│   ├── networkrules.yaml         # ns60-tcp and ns60-udp, port 80
│   └── servicevipbindings.yaml   # one ServiceVIPBinding per rule for the backend
├── sjc/                     # same shape, one edge node
└── iad/                     #   "
```

Each site has its own VIP, in a `/64` only that site's edge nodes originate
(`2001:db8:6060:1::/64` for dfw, `:2::` for sjc, `:3::` for iad), and one
`ns60` backend of its own, so the per-site directories differ in both.

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

| Field                   | Required | Type                       | Description                                                                                                                                      |
| ----------------------- | -------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `spec.vpcRef`           | Yes      | `string`                   | Opaque VPC identifier (owned by the companion operator, not validated here beyond non-emptiness).                                                |
| `spec.vpcAttachmentRef` | Yes      | `string`                   | Opaque VPC attachment identifier, paired with `vpcRef`.                                                                                          |
| `spec.vipAddresses`     | Yes      | `[]string` (1–8)           | Ingress VIP addresses (IPv4 and/or IPv6) this rule provisions.                                                                                   |
| `spec.protocol`         | Yes      | `tcp` \| `udp`             | Transport protocol matched by `vipAddresses`/`port`.                                                                                             |
| `spec.port`             | Yes      | `int32` (1–65535)          | Ingress port on `vipAddresses` this rule load-balances.                                                                                          |
| `spec.backends`         | Yes      | `[]{address, port}` (1–64) | Backend `address:port` targets traffic is load-balanced to.                                                                                      |
| `status.conditions`     | —        | —                          | `Accepted` condition — currently set `True` unconditionally once gateway nodes exist for the namespace (see the admission-webhook caveat below). |

Example, the TCP rule from `deploy/containerlab/resources/galactic-gateway/iad/networkrules.yaml`:

```yaml
apiVersion: network.datumapis.com/v1alpha1
kind: NetworkRule
metadata:
  name: ns60-tcp
  namespace: galactic-system
spec:
  vpcRef: "60"
  vpcAttachmentRef: "60"
  vipAddresses:
    - 2001:db8:6060:3::1
  protocol: tcp
  port: 80
  backends:
    - address: fd20:60:ff03:a::100
      port: 80
```

Every accepted, non-deleting `NetworkRule` in the namespace is served by
**every** `NetworkGateway` node identically — there is no
`status.primaryNode`/placement field to set, and no per-node subset to
target. `galactic-gateway` resolves each backend address's SRv6 uSID by
matching it against `BGPAdvertisement`/`BGPRouter`/`BGPVRFInstance` CRDs
(read-only, not watched) and verifies the requesting rule's own `vpcRef`
owns that match before trusting it. Placement across gateway nodes is
Maglev's consistent-hash ring (built identically on every node from the
same `(VIP, backend list)` input) plus anycast BGP at equal preference —
not a control-plane assignment step you configure here. See
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

### `ServiceVIPBinding` — the backend-side half, not reconciled by `galactic-gateway`

A `NetworkRule` alone configures the gateway-side half of DSR. For a
backend to actually **answer the client directly** on the VIP (DSR's whole
premise), its own worker node also needs a `ServiceVIPBinding` object
naming that `(node, VIP, backend)` triple — this is reconciled by
`ServiceVIPBindingReconciler` running inside **`galactic-router`** (not
`galactic-gateway`), so it's out of this document's direct scope, but
worth knowing about since it's required for the datapath to work
end-to-end. Example, the TCP binding from
`deploy/containerlab/resources/galactic-gateway/iad/servicevipbindings.yaml`:

```yaml
apiVersion: network.datumapis.com/v1alpha1
kind: ServiceVIPBinding
metadata:
  name: ns60-tcp-backend
  namespace: galactic-system
spec:
  targetRef:
    kind: Node
    name: iad-worker
  vipAddress: 2001:db8:6060:3::1
  port: 80
  protocol: tcp
  backendAddress: fd20:60:ff03:a::100
  backendPort: 80
  egressKind: veth
```

`targetRef.name` is the **backend's own worker node**, not a gateway node.
`egressKind` is `veth` for a plain container backend or `tap` for a VM
backend, mirroring the same fork the SRv6 uSID datapath's `vrf_table`
already has. As of this writing there is no controller in this repo that
derives `ServiceVIPBinding` objects automatically from a `NetworkRule`'s
backend list — the lab example above is hand-authored, and a real
deployment must currently do the same for each backend. See
`internal/controller/servicevipbinding_controller.go`'s package doc
comment for the full mechanics of what happens once this object exists.

Bindings on one node may share a port. Two bindings conflict only when they
claim the same VIP, port and protocol, or the same backend address, port and
protocol, in the same VPC. The older binding keeps serving. The newer one is
not programmed and reports `Bound=False` with reason `Conflict`, naming the
binding that holds the row. It takes over once that binding is deleted.

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
(all labeled by `proto`/`port`/`vip`), `galactic_edge_drops_total` (labeled
by `reason`), and `galactic_edge_control_plane_drops_total` (rule
applications rejected before ever reaching the datapath, e.g. quota
denials). A rule with zero `rule_packets_total` and a client actually
sending traffic points at an upstream problem (BGP not carrying the route,
underlay reachability) rather than this node's own datapath; nonzero
`dropped_packets_total` for a rule with `rule_backends` at `0` means the
rule's own backend list is empty.

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
