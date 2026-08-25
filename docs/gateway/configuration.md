# Gateway Deployment & Configuration

This is a how-to/reference guide for deploying and configuring
`galactic-gateway`, the edge XDP Maglev/DSR NAT+LB gateway control plane. For
the design rationale (why DSR, why anycast, why no VRF dependency) see
[docs/agents/ARCHITECTURE-GATEWAY.md](../agents/ARCHITECTURE-GATEWAY.md) —
this document only covers the "how", not the "why", and cross-links back to
that doc wherever the mechanics matter.

> Last verified: 2026-08-25 against the current working tree of
> `cmd/galactic-gateway/`, `internal/config/gateway.go`, `config/galactic-gateway/`,
> and `deploy/containerlab/resources/galactic-gateway/`.

## What `galactic-gateway` is, and when you need it

`galactic-gateway` gives external clients a stable VIP:port that
load-balances into a tenant VPC's backend Pods, using a stateless DSR
(Direct Server Return) datapath over a Maglev consistent-hash ring — no
address/port rewriting, no VRF or Geneve dependency. It is a **separate
binary and container from `galactic-router`**, deployed as the second
container in a two-container pod (`galactic-router` + `galactic-gateway`,
`config/galactic-gateway/base/daemonset.yaml`) on dedicated gateway-role
nodes only, specifically so a crash on either side no longer takes the
other down with it. You need it only on nodes that terminate external
ingress traffic for tenant VPCs — every other node in the fleet
(`galactic-router` default role, `galactic-cni`, `galactic-nat66`) has no
dependency on it. See
[ARCHITECTURE-GATEWAY.md](../agents/ARCHITECTURE-GATEWAY.md) for the full
design (DSR vs. the removed Full-NAT design, the anycast BGP model, the
XDP packet path) and
[gateway-ingress-packet-trace.md](gateway-ingress-packet-trace.md) for a
packet-level sequence diagram (currently describing the earlier Full-NAT
datapath — see that file's own header for the caveat).

## Prerequisite: node labeling

`galactic-gateway`'s DaemonSet only schedules onto nodes labeled
`galactic.datumapis.com/node: edge` (see
`config/galactic-gateway/base/daemonset.yaml`'s node affinity, which also
excludes `node-role.kubernetes.io/control-plane` nodes outright). Read
[docs/node-labels.md](../node-labels.md) for the full node-labeling
strategy before doing anything else here.

**Do not confuse this label with the gateway's own "edge XDP" terminology.**
`galactic.datumapis.com/node=edge` is the *node role* label — it identifies a
dedicated gateway node, distinct from the ordinary tenant-serving
`galactic.datumapis.com/node=compute` role that runs `galactic-router`
(default role)/`galactic-cni`/`galactic-nat66`. "Edge XDP" is a separate,
pre-existing description of *what the datapath is* (an XDP program attached
at the actual network edge), used throughout
[ARCHITECTURE-GATEWAY.md](../agents/ARCHITECTURE-GATEWAY.md) independently
of this label scheme. The two happen to share the word "edge" for related
but distinct reasons; see node-labels.md's "Naming collision" section for
the full history of the rename this resolved (an older `node=edge` value
used to mean the tenant-serving role and would collide with a diagram or
comment using today's meaning).

A gateway node still needs the same underlay BGP connectivity every other
node needs — `galactic.datumapis.com/fabric=true` for `fabric-router` — and,
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
`get`/`list`/`watch` on `bgprouters`). It deliberately does **not** include
`config/galactic-gateway/base/` (the DaemonSet itself) — see Step 2. It's
safe and idempotent to apply cluster-wide regardless of how many gateway
nodes exist, and is **not** part of the root `config/kustomization.yaml`'s
default resource list: this role is opt-in, not "batteries included"
cluster bring-up.

Because the two-container pod has exactly one ServiceAccount identity, the
`galactic-gateway` ServiceAccount must **also** be bound to the
`galactic-router` `ClusterRole` from `config/galactic-router/rbac.yaml` (a
second `ClusterRoleBinding` inside `config/galactic-gateway/rbac.yaml`
already does this) — so `config/galactic-router/rbac.yaml` must be applied
too. If you already run `kubectl apply -k config/galactic-router/` for your
compute nodes, this is already satisfied; a gateway-only cluster with no
compute nodes yet must apply that RBAC on its own
(`kubectl apply -f config/galactic-router/rbac.yaml`). A bare
`galactic-gateway` container with no co-located `galactic-router` container
advertising the node's tenant BGP session is not a supported configuration.

## Step 2: Why `config/galactic-gateway/base/` isn't applied as-is

`config/galactic-gateway/base/` is intentionally excluded from
`config/galactic-gateway/`'s own kustomization and must never be applied
directly — doing so produces a crash-looping `galactic-gateway` container.
The reason is `GALACTIC_GATEWAY_SRV6_ADDRESS`: it is this node's own plain
SRv6-reachable IPv6 address, used purely as the source address of every
outer header the node's `edge_lb` XDP program pushes
(`edgedsr.c`'s `encap_config_table`) — it is **never** a NAT/SNAT source and
has no return-path significance, unlike the identically-named field in the
now-removed Full-NAT design. Because DSR rewrites nothing, there is no
reconcile step that derives or publishes this value automatically (no
analogue of a "self-address" status field exists on `NetworkGateway` at
all — see that CRD's own doc comment). It must be unique per gateway node
and is operator-supplied today, with no in-cluster derivation mechanism.
`GALACTIC_GATEWAY_PUBLIC_INTERFACE` is deployment-specific for the same
reason — every node's public/underlay-facing uplink interface name can
differ.

> A few older comments in this repo (`config/galactic-gateway/base/daemonset.yaml`,
> `AGENTS.md`, `README.md`) attribute this constraint to a `publishSelfAddress`
> doc comment on `internal/controller/networkgateway_controller.go`. That
> function was removed as part of the DSR/anycast rewrite — it belonged to
> the earlier Full-NAT design, which *did* publish a per-node self-address
> route. The underlying constraint (unique per-node SRv6 address, no
> in-cluster derivation) still holds; it's just no longer explained by a
> function of that name. The authoritative explanation today is
> `internal/config/gateway.go`'s `EnvGatewaySRv6Address` doc comment and
> ARCHITECTURE-GATEWAY.md's ["SRv6 encap-source address"](../agents/ARCHITECTURE-GATEWAY.md#srv6-encap-source-address)
> section.

`config/galactic-gateway/base/` is designed to be instantiated **once per
gateway node** by a further overlay that pins the DaemonSet to one node
(`kubernetes.io/hostname`) and sets that node's own
`GALACTIC_GATEWAY_PUBLIC_INTERFACE`/`GALACTIC_GATEWAY_SRV6_ADDRESS` values —
see the [worked example](#step-3-worked-example-a-per-node-overlay) below.

### Configuration reference (`internal/config/gateway.go`)

`galactic-gateway` supports configuration via environment variables, CLI
flags, or a combination of both (CLI flags take precedence), with the
`GALACTIC_GATEWAY` env prefix — the same three-tier precedence pattern
`galactic-router` uses (see [docs/router/configuration.md](../router/configuration.md)).

| Option           | Environment Variable                | CLI Flag                     | Default | Required |
| ---------------- | ----------------------------------- | ---------------------------- | ------- | -------- |
| Node name        | `GALACTIC_GATEWAY_NODE_NAME`        | `--node-name`, `-n`          | —       | Yes      |
| Public interface | `GALACTIC_GATEWAY_PUBLIC_INTERFACE` | `--gateway-public-interface` | —       | Yes      |
| SRv6 address     | `GALACTIC_GATEWAY_SRV6_ADDRESS`     | `--gateway-srv6-address`     | —       | Yes      |
| Metrics port     | `GALACTIC_GATEWAY_METRICS_PORT`     | `--metrics-port`             | `8081`  | No       |
| gRPC health port | `GALACTIC_GATEWAY_GRPC_HEALTH_PORT` | `--grpc-health-port`         | `5181`  | No       |

All three required fields are enforced by `GatewayConfig.Validate` at
startup — a node deployed without them crash-loops immediately with an
actionable message rather than running degraded. `Validate` additionally
rejects an SRv6 address that isn't a native IPv6 address (an IPv4 or
4-in-6 value fails validation, per `internal/config/gateway.go`).

The `8081`/`5181` metrics/gRPC-health port defaults deliberately differ
from `galactic-router`'s own `9179`/`5179` defaults, because
`galactic-gateway` runs as a second container in the same
`hostNetwork: true` pod — every port it binds shares that node's network
namespace with the co-located `galactic-router` container and must not
collide with it:

| Container                                      | Metrics | gRPC health |
| ---------------------------------------------- | ------- | ----------- |
| `galactic-router` (this pod's tenant-BGP side) | `9179`  | `5179`      |
| `galactic-gateway`                             | `8081`  | `5181`      |

The co-located `galactic-router` container carries no gateway-specific
env of its own; `config/galactic-gateway/base/daemonset.yaml` sets it up
identically to `galactic-router`'s default role, plus an explicit
`GALACTIC_ROUTER_GRPC_HEALTH_PORT=5179` (so it can never silently drift
into colliding with `galactic-gateway`'s own `5181`) and
`GALACTIC_ROUTER_BGP_LISTEN_PORT=-1` (outbound-only — no inbound BGP
listener on this role, same as `galactic-router`'s default overlay). See
[docs/router/configuration.md](../router/configuration.md) for what every
`GALACTIC_ROUTER_*` variable does.

### Two-container pod capabilities

Both containers run with `runAsUser: 0`, `allowPrivilegeEscalation: false`,
`readOnlyRootFilesystem: true`, and `drop: ["ALL"]` on their Linux
capabilities, adding back only what each needs:

| Container          | Added capabilities            | Why                                                                                                                                                                 |
| ------------------ | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic-router`  | `NET_ADMIN`                   | Same as the plain `default`/`rr` roles — no BPF/PERFMON, since gateway-specific eBPF is confined to the other container                                             |
| `galactic-gateway` | `NET_ADMIN`, `BPF`, `PERFMON` | `BPF` for program/map creation; `PERFMON` because the verifier only allows pointer+scalar arithmetic on packet data when the loading process is `perfmon_capable()` |

The `galactic-gateway` container also requires `/sys/fs/bpf` mounted from
the host as a real bpffs (`type: Directory`, not `DirectoryOrCreate` — a
missing mount fails loudly rather than silently pinning maps to a plain
directory); `edgeattach.PinDir` pins every map under
`/sys/fs/bpf/galactic-edge`. The `galactic-router` container mounts
`/var/run/netns` read-only for its own GC netns-liveness check (unrelated
to the gateway datapath — see
[ARCHITECTURE-ROUTER.md](../agents/ARCHITECTURE-ROUTER.md)).

## Step 3: Worked example, a per-node overlay

`deploy/containerlab/resources/galactic-gateway/` is a real, working
instantiation pattern to copy for production — two gateway nodes
(`iad-gateway1`/`iad-gateway2`) in the `iad` lab cluster, each with its own
overlay directory:

```
deploy/containerlab/resources/galactic-gateway/
├── base/                 # kustomize base pointing at config/galactic-gateway/base,
│                         #   plus a lab-only image-tag patch (router-lab-patch.yaml)
├── iad-gateway1/
│   ├── kustomization.yaml
│   ├── node-patch.yaml      # pins to one node, sets PUBLIC_INTERFACE/SRV6_ADDRESS
│   ├── bgprouter.yaml       # this node's tenant BGPRouter
│   ├── bgppeer.yaml         # this node's iBGP session to the route reflector
│   └── networkgateway.yaml  # the NetworkGateway object itself
├── iad-gateway2/            # same shape, this node's own values
└── iad/
    ├── kustomization.yaml       # composes both gateway nodes + sample rule
    ├── networkrule-ns60.yaml    # sample NetworkRule
    └── servicevipbinding-ns60.yaml  # sample ServiceVIPBinding for the backend
```

### `node-patch.yaml` — pin to one node, set the per-node values

`iad-gateway1/node-patch.yaml` adds a `kubernetes.io/hostname` match to the
DaemonSet's node affinity (so this overlay's copy of the DaemonSet only
ever schedules onto exactly one node) and sets the two required
gateway-container env vars:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: galactic-gateway
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
                    values: [edge]
                  - key: kubernetes.io/hostname
                    operator: In
                    values: [iad-gateway1]
      containers:
        - name: galactic-gateway
          env:
            - name: GALACTIC_GATEWAY_PUBLIC_INTERFACE
              value: eth1
            - name: GALACTIC_GATEWAY_SRV6_ADDRESS
              value: "2001:db8:ff03:2:e000::"
```

`iad-gateway2`'s own `node-patch.yaml` repeats this shape with its own
hostname and a distinct `GALACTIC_GATEWAY_SRV6_ADDRESS`
(`2001:db8:ff03:3:e000::`) — every gateway node needs its own unique value.
`iad-gateway1/kustomization.yaml` additionally JSON6902-patches the
DaemonSet's own `metadata.name` to `galactic-gateway1` (a strategic-merge
patch can't rename a resource), so the two nodes' DaemonSets don't collide
under the same name in the same namespace.

**To generalize this to a real deployment:** create one overlay directory
per gateway node, each with its own `node-patch.yaml` pinning
`kubernetes.io/hostname` to that node and setting that node's own public
uplink interface name and a unique SRv6-reachable IPv6 address (a uSID
computed the same way `internal/plumbing/ebpf/uformat.Encode` derives one
for this node's `BGPRouter`'s locator/nodeID — see the lab's own
`node-patch.yaml` comment for the exact encoding used there). There is no
generic default for either value and nothing in this repo computes them
for you.

### `bgprouter.yaml`/`bgppeer.yaml` — this node's tenant BGP

The co-located `galactic-router` container needs its own `BGPRouter`/
`BGPPeer` CRDs, exactly like every other `galactic-router` node — a gateway
node is not exempt from the normal tenant-BGP setup:

```yaml
apiVersion: network.datumapis.com/v1alpha1
kind: BGPRouter
metadata:
  name: iad-gateway1-tenant
  namespace: galactic-system
spec:
  targetRef:
    kind: Node
    name: iad-gateway1
  roles: [tenant]
  localASN: 65000
  routerID: "10.0.2.2"
  srv6Locator: "2001:db8:ff03::/48"
  nodeID: 2
  addressFamilies:
    - afi: l2vpn
      safi: evpn
---
apiVersion: network.datumapis.com/v1alpha1
kind: BGPPeer
metadata:
  name: iad-gateway1-tenant-to-rr
  namespace: galactic-system
spec:
  routerRef:
    name: iad-gateway1-tenant
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
  name: iad-gateway1
  namespace: galactic-system
spec:
  targetRef:
    kind: Node
    name: iad-gateway1
```

`spec.targetRef.name` must equal the Kubernetes node name — by this repo's
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
| `status.conditions`   | —        | —        | `Ready` condition, reason `EngineHealthy` (converged and fully advertised), `AdvertisementFailed` (converged but couldn't publish one or more rule routes), or `Terminating`. |

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

Example, from `deploy/containerlab/resources/galactic-gateway/iad/networkrule-ns60.yaml`:

```yaml
apiVersion: network.datumapis.com/v1alpha1
kind: NetworkRule
metadata:
  name: ns60-web
  namespace: galactic-system
spec:
  vpcRef: "60"
  vpcAttachmentRef: "60"
  vipAddresses:
    - 2001:db8:6060::1
  protocol: tcp
  port: 80
  backends:
    - address: fd20:60:ff03::100:0
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
end-to-end. Example, from
`deploy/containerlab/resources/galactic-gateway/iad/servicevipbinding-ns60.yaml`:

```yaml
apiVersion: network.datumapis.com/v1alpha1
kind: ServiceVIPBinding
metadata:
  name: ns60-web-iad-worker
  namespace: galactic-system
spec:
  targetRef:
    kind: Node
    name: iad-worker
  vipAddress: 2001:db8:6060::1
  port: 80
  protocol: tcp
  backendAddress: fd20:60:ff03::100:0
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

Check both containers' logs — `galactic-gateway`'s own gRPC health check
only reports `SERVING` once the XDP datapath is attached and its VIP table
is reachable (it's forced to `NOT_SERVING` at process start specifically
so a probe never reports healthy before that point):

```sh
kubectl logs -n galactic-system <pod> -c galactic-gateway
kubectl logs -n galactic-system <pod> -c galactic-router
```

Check this node's tenant BGP session state — `galactic-router`'s
co-located container advertises this node's own `BGPRouter`/`BGPPeer`
exactly like any other node; `STATE` should read `Established`:

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
kubectl exec -n galactic-system <pod> -c galactic-gateway -- \
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
- [docs/gateway/gateway-ingress-packet-trace.md](gateway-ingress-packet-trace.md) —
  packet-level sequence diagrams (currently describing the earlier
  Full-NAT datapath).
- [docs/router/configuration.md](../router/configuration.md) — the
  `GALACTIC_ROUTER_*` environment variables the co-located `galactic-router`
  container in this same pod also reads.
