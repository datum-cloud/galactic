# Gateway configuration

Use [deployment](deployment.md) for prerequisites, manifests, verification and upgrades; [architecture](architecture.md) describes ownership and [backend health](backend-health.md) explains probes. This reference covers process settings and the service API.

## Process configuration

`galactic-gateway` supports configuration via environment variables, CLI
flags, or a combination of both (CLI flags take precedence), with the
`GALACTIC_GATEWAY` env prefix — the same three-tier precedence pattern
`galactic-router` uses (see [docs/router/configuration.md](../router/configuration.md)).

Logging takes `--log-level` (`LOG_LEVEL`), without the `GALACTIC_GATEWAY` prefix and the standard `--zap-*` flags; see [Logging](../observability/logging.md).

| Option               | Environment Variable                    | CLI Flag                         | Default     | Required              |
| -------------------- | --------------------------------------- | -------------------------------- | ----------- | --------------------- |
| Node name            | `GALACTIC_GATEWAY_NODE_NAME`            | `--node-name`, `-n`              | —           | Yes                   |
| Public interface     | `GALACTIC_GATEWAY_PUBLIC_INTERFACE`     | `--gateway-public-interface`     | —           | While enabled         |
| SRv6 address         | `GALACTIC_GATEWAY_SRV6_ADDRESS`         | `--gateway-srv6-address`         | Derived     | No                    |
| Internal interfaces  | `GALACTIC_GATEWAY_INTERNAL_INTERFACES`  | `--gateway-internal-interfaces`  | —           | No                    |
| XDP attach mode      | `GALACTIC_GATEWAY_XDP_ATTACH`           | `--gateway-xdp-attach`           | `dispatch`  | No                    |
| Datapath enabled     | `GALACTIC_GATEWAY_DATAPATH_ENABLED`     | `--gateway-datapath-enabled`     | `true`      | No                    |
| IPv4 VIPs            | `GALACTIC_GATEWAY_IPV4_VIPS`            | `--gateway-ipv4-vips`            | `false`     | No                    |
| Backend health       | `GALACTIC_GATEWAY_BACKEND_HEALTH`       | `--gateway-backend-health`       | `false`     | No                    |
| Procfs sysctl root   | `GALACTIC_GATEWAY_PROC_SYS_PATH`        | `--gateway-proc-sys-path`        | `/proc/sys` | No                    |
| Project services     | `GALACTIC_GATEWAY_PROJECT_SERVICES`     | `--gateway-project-services`     | `false`     | No                    |
| Gateway namespace    | `GALACTIC_GATEWAY_NAMESPACE`            | `--gateway-namespace`            | —           | With project services |
| Project VIP prefixes | `GALACTIC_GATEWAY_PROJECT_VIP_PREFIXES` | `--gateway-project-vip-prefixes` | —           | With project services |
| Metrics port         | `GALACTIC_GATEWAY_METRICS_PORT`         | `--metrics-port`                 | `8081`      | No                    |
| gRPC health port     | `GALACTIC_GATEWAY_GRPC_HEALTH_PORT`     | `--grpc-health-port`             | `5181`      | No                    |

`GALACTIC_GATEWAY_XDP_ATTACH` is `dispatch` or `direct`. `dispatch` runs
`edge_lb` and `edge_return` from the gateway slots of the node's shared,
pinned XDP dispatcher, so a restart swaps the programs in place without
detaching anything, and the egress shard can share the uplinks. `direct`
attaches the programs themselves, unpinned, so they detach when the process
exits. It first detaches an idle dispatcher from its interfaces, and refuses
to start while another datapath's slot is live there. See
[Sharing the XDP hook](packet-paths.md#sharing-the-xdp-hook-xdpdispatch).

`GALACTIC_GATEWAY_IPV4_VIPS=true` serves IPv4 VIPs on this node. It is off by
default and is set per gateway node. It does three things:

- It turns on IPv4 forwarding on every public and internal interface for the
  datapath's FIB lookups, including the host-wide `net.ipv4.ip_forward`, so
  the node then routes IPv4 between all of its interfaces. It does so only
  when the node is about to load its first IPv4 VIP, not at startup, so
  turning the switch on where no rule has an IPv4 VIP leaves the node's IPv4
  forwarding as it was. An interface the datapath picks up later, such as a
  replacement bond member, gets it too. Once on, it stays on until the node
  reboots, even after the last IPv4 VIP goes or the switch is turned off:
  `net.ipv4.ip_forward` is host-wide, and turning it back off could cut
  another datapath on the node. If it cannot be turned on, IPv4 fails closed
  for that pass only: every IPv4 VIP is left out, none is loaded or
  advertised, and each affected rule's `<gateway-node>/IPv4Served` and the
  `NetworkGateway`'s `Ready` read `False` with reason `IPv4ForwardingFailed`.
  IPv6 VIPs are loaded, updated and advertised as usual, and the pass is
  retried until forwarding can be turned on.
- It loads each rule's IPv4 VIP into the datapath beside its IPv6 VIP,
  balanced over the rule's IPv6 backends, whose nodes translate its flows
  (see [What an IPv4 VIP needs](#what-an-ipv4-vip-needs)).
- It advertises the IPv4 VIP (the rule's `-v4` `BGPAdvertisement`) once the
  readiness gate below holds, and withdraws it as soon as the gate closes.

The gateway reads and watches `ServiceVIPBinding`s for the gate, and for
shared address and port range rules whatever the switch says, so its
ClusterRole needs `get`, `list` and `watch` on `servicevipbindings`
(`config/galactic-gateway/rbac.yaml`). Without list and watch the gateway
fails startup with an error naming the missing access, as it does for every
type it watches. If the check cannot be made at all, for example while the API
server is unreachable, the gateway exits, so the restart checks again. It does
not turn IPv4 off on a failed check, because a node reporting IPv4 unloaded
lets backend nodes remove their IPv4 bindings once no gateway reports it
loaded.

Before turning the switch on for a gateway node:

- Its ClusterRole must grant `get`, `list` and `watch` on
  `servicevipbindings`. Infra deploys its own copy of that ClusterRole, so
  the grant has to land there. Otherwise the gateway fails startup and
  names the missing permission, as the paragraph above describes.
- The underlay must originate the prefix each IPv4 VIP sits in, from the
  site's edge nodes, as it does each IPv6 VIP's. The gateway's `-v4`
  advertisement is an EVPN path inside Galactic's own mesh, which the
  transit never sees. Without the underlay route the node reports
  `Advertised` while no client off the fabric can reach the VIP. The
  containerlab lab originates each site's IPv4 VIP `/26` from its edge
  nodes' `frr.conf`.

Turning the switch back off withdraws every IPv4 VIP the node advertises and
unloads them, and leaves IPv6 untouched. See
[Rolling out and rolling back IPv4 VIPs](#rolling-out-and-rolling-back-ipv4-vips).

`GALACTIC_GATEWAY_BACKEND_HEALTH=true` lets this node take a backend its node
reports `Unhealthy` out of a `NetworkService`'s Maglev table. It applies only
to a service with `spec.healthCheck`, and only while every `NetworkGateway` in
the namespace reports `status.backendHealthFiltering: true`, which each node
sets when the switch is on. A single node without it, not yet upgraded, rolled
back or with the switch off, turns health off on every node, so they keep
building the same table. Health is read from `ServiceVIPBinding`s, so the
switch needs the same `servicevipbindings` access, and the same startup check,
as IPv4 VIPs above: without the access the node runs with the switch off and
logs why. See [Backend health checks](backend-health.md).

`GALACTIC_GATEWAY_DATAPATH_ENABLED=false` keeps the process up and its pod
ready, empties the gateway's load-balancing dispatcher slot, and withdraws
every one of this node's VIP advertisements. The NetworkGateway's `Ready`
reads `False` with reason `DatapathDisabled`. The public interface is not
required while it is off, and no SRv6 address is derived.

A node with its datapath off can still carry replies: a backend node sends
every VIP reply out one uplink, whichever gateway node took the request. So
with `GALACTIC_GATEWAY_INTERNAL_INTERFACES` set, the node keeps `edge_return`
on those interfaces and claims replies from every VIP that any NetworkService
in its namespace lists. IPv4 VIPs are included only with
`GALACTIC_GATEWAY_IPV4_VIPS` on. With no internal interfaces set it loads
nothing. Turning the datapath off is therefore not a way to stop a node that
cannot load XDP programs at all. Take such a node out of the fabric's
forwarding path instead.

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

| Pod                                                                                           | Metrics | gRPC health |
| --------------------------------------------------------------------------------------------- | ------- | ----------- |
| `galactic-router` (this node's tenant-BGP side, `config/galactic-router/overlays/router/`)    | `9179`  | `5179`      |
| `galactic-gateway`                                                                            | `8081`  | `5181`      |

The `galactic-router` pod on a gateway node is the exact same DaemonSet as
`galactic-router`'s default role on a `compute` node — it carries no
gateway-specific env of its own and sets
`GALACTIC_ROUTER_BGP_LISTEN_PORT=-1` (outbound-only — no inbound BGP
listener on this role). See
[docs/router/configuration.md](../router/configuration.md) for what every
`GALACTIC_ROUTER_*` variable does.

## Configuring `NetworkGateway` and `NetworkService`

`galactic-gateway` reconciles exactly two CRDs
(`api/network/v1alpha1`):

### `NetworkGateway` — one per gateway node

| Field                           | Required | Type     | Description                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------- | -------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spec.targetRef.name`           | Yes      | `string` | Kubernetes node name this gateway engine executes on.                                                                                                                                                                                                                                                                                                      |
| `status.conditions`             | —        | —        | `Ready` condition, reason `EngineHealthy` (converged and fully advertised), `AdvertisementFailed` (converged but couldn't publish one or more rule routes), `DatapathDisabled`, `IPv4ForwardingFailed` (an IPv4 VIP is due to load but the node's IPv4 forwarding could not be turned on, so IPv4 VIPs are left out and IPv6 is served), or `Terminating`. |
| `status.backendHealthFiltering` | —        | `bool`   | `true` while this node can take `Unhealthy` backends out of a rule's Maglev table (`GALACTIC_GATEWAY_BACKEND_HEALTH`). Health applies only while every `NetworkGateway` in the namespace reports it.                                                                                                                                                       |

There is deliberately **no** self-address or primary-node field on this
status — DSR has nothing analogous to publish. Create one object per
gateway node, named after that node (see the worked example above).

### `NetworkService` — internal ingress load-balancing spec

| Field                  | Required | Type                   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---------------------- | -------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spec.vpcRef`          | Yes      | `string`               | Opaque VPC identifier (owned by the Galactic cell controller, not validated here beyond non-emptiness). Only attachments whose `status.vpc` equals it can be backends.                                                                                                                                                                                                                                                                                                                        |
| `spec.vipAddresses`    | Yes      | `[]string` (1–8)       | Ingress VIP addresses this rule provisions: at most one IPv6 and at most one IPv4 address, an IPv4 address in dotted form. See below.                                                                                                                                                                                                                                                                                                                                                         |
| `spec.protocol`        | Yes      | `tcp` \| `udp`         | IP protocol load-balanced on `vipAddresses`. The API also accepts `sctp`, `esp`, `gre` and `icmp`, but refuses them as not served yet; see below.                                                                                                                                                                                                                                                                                                                                             |
| `spec.port`            | tcp, udp | `int32` (1–65535)      | Ingress port on `vipAddresses` this rule load-balances. Required for a protocol with ports, refused for one without.                                                                                                                                                                                                                                                                                                                                                                          |
| `spec.backendSelector` | Yes      | `metav1.LabelSelector` | Selects the `VPCAttachment`s (`galactic.datumapis.com`, any namespace) that serve the rule. Each contributes its IPv6 interface addresses as backends of both VIPs; its IPv4 addresses are never backends. Must not be empty.                                                                                                                                                                                                                                                                 |
| `spec.backendPort`     | tcp, udp | `int32` (1–65535)      | Destination port on every selected backend. Required for a protocol with ports, refused for one without.                                                                                                                                                                                                                                                                                                                                                                                      |
| `spec.sessionAffinity` | No       | `string` enum          | `None` (default), `ClientIP` or `ClientIPAndProtocol`: which connections from one client share a backend. See [Session affinity](#session-affinity).                                                                                                                                                                                                                                                                                                                                          |
| `spec.healthCheck`     | No       | object                 | Turns on TCP health checks of the backends: `port` (default `backendPort`, required for `udp`), `intervalSeconds` (5), `timeoutSeconds` (2), `unhealthyThreshold` (3), `healthyThreshold` (3). See [Backend health checks](backend-health.md).                                                                                                                                                                                                                                                |
| `status.conditions`    | —        | —                      | `Accepted` (set `True` once gateway nodes serve the rule; for a rule in a project namespace, also an ownership check, see [Services in a project namespace](#services-in-a-project-namespace)); the rule-wide `Programmed`, `Advertised`, `BackendsReady`, `Ready` and, with an IPv4 VIP, `IPv4Served` (see [Reading a rule's status](#reading-a-rules-status)); `<gateway-node>/Programmed` and `<gateway-node>/Advertised` per gateway node, `<gateway-node>/IPv4Served` per gateway node for a rule with an IPv4 VIP, and `<backend-node>/BackendsBound` per node hosting a backend. |

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
[ARCHITECTURE-GATEWAY.md](architecture.md#datapath)).
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

| Status  | Reason                 | Meaning                                                                                                                         |
| ------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `True`  | `Advertised`           | loaded over the eligible backends whose bindings are `Bound`, at least one, and advertised                                      |
| `False` | `NotAdvertised`        | loaded over `Bound` backends, but the route is not published: no `BGPRouter` targets the node, or the advertisement failed      |
| `False` | `BindingsNotBound`     | loaded over every eligible backend, but none of their bindings is `Bound` yet, so not advertised                                |
| `False` | `NoHealthyBackends`    | left out: the rule's health check is `FailClosed` and no backend has a current `Healthy` result                                 |
| `False` | `Unsupported`          | `GALACTIC_GATEWAY_IPV4_VIPS` is off, so they are left out of the datapath                                                       |
| `False` | `NoBackend`            | the switch is on, but no selected attachment has an IPv6 address that is a backend of this IPv4 VIP (none, unresolved, claimed) |
| `False` | `MultipleVIPs`         | the switch is on, but the rule has more than one IPv4 VIP, so none loads                                                        |
| `False` | `NotLoaded`            | the switch is on, but the node did not load the rule at all                                                                     |
| `False` | `IPv4ForwardingFailed` | the switch is on, but the node's IPv4 forwarding could not be turned on, so they are left out this pass                         |

`Advertised`, `NotAdvertised` and `BindingsNotBound` mean the node has the
IPv4 VIP loaded, and `NoHealthyBackends` that it would load it once a
backend is `Healthy`. The rule's IPv6 VIP keeps serving in every case. A
rule whose every VIP is IPv4 is not loaded where none of them can be, and its
`<gateway-node>/Programmed` condition reports `NoServedVIP` with the switch
off and `InvalidRule` with it on. An IPv4 VIP's backends are the selected
attachments' IPv6 addresses, the same ones as the IPv6 VIP's. Each backend
node writes a binding for each of them, pairing the IPv4 `vipAddress` with the
IPv6 `backendAddress`, but only while some gateway node reports one of the
four reasons above for the rule, and deletes them once none does, so a cell
whose gateways leave IPv4 VIPs out has no IPv4 bindings or rows. Each gateway
pass removes the `<node>/Programmed`, `<node>/Advertised` and
`<node>/IPv4Served` conditions of any node that no `NetworkGateway` in the
namespace targets, so a gateway that left without clearing its conditions
cannot keep the backend nodes' IPv4 bindings alive. A node missing from the gateway's cache is confirmed missing with an
uncached read of the API server first, so a new gateway node's conditions are
never removed while the cache has yet to see its `NetworkGateway`.

#### Session affinity

`spec.sessionAffinity` selects what a gateway hashes, besides the client's
address, to pick a backend:

| Value                 | Hashed                      | Connections from one client that share a backend        |
| --------------------- | --------------------------- | ------------------------------------------------------- |
| `None` (default)      | Address and source port     | None: each connection is balanced on its own            |
| `ClientIP`            | Address                     | All, whatever their port, protocol or service           |
| `ClientIPAndProtocol` | Address and the IP protocol | Those over one protocol, whatever their port or service |

Affinity keeps no state. Every gateway node hashes the same inputs over the
same Maglev table, so a client's flows reach the same backend whichever node
receives them. Under `ClientIP` and `ClientIPAndProtocol` the table depends
only on the backends' addresses, so services that set the same affinity and
select the same backend addresses pin a client to the same backend, even with
different `port`s and `backendPort`s. A rule's IPv4 and IPv6 VIPs are
separate tables over each family's backends, and a client's IPv4 and IPv6
addresses are different clients.

Affinity holds only while the backend set is unchanged. Adding or removing a
backend moves about 1 in N clients to another backend, N being the number of
backends, and each moved TCP connection is reset by its new backend. Clients
behind one NAT address share a backend under either client-IP mode.

A change to `sessionAffinity` takes effect on every gateway node at the next
reconcile, with no restart. It rehashes every connection of the service, so a
connection reaches a different backend afterwards with odds of (N-1)/N; change
it when the service can take that. Set it only once every gateway node runs a
release that serves it: a gateway without affinity support ignores the field
and balances by source port, so nodes would disagree on a client's backend.

#### Reading a rule's status

Rule-wide conditions say whether a rule serves, without reading
`NetworkGateway` or knowing which nodes exist. Every gateway node computes them
from the per-node conditions and writes them only when they change. A per-node
condition, or `Accepted`, from an older generation counts as not reported yet.

| Condition       | `True` when                                                                                                                                                                                                                                   |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Programmed`    | every gateway node that reports on the rule loaded it                                                                                                                                                                                         |
| `Advertised`    | every gateway node that loaded the rule published its routes, and `galactic-router` reports each one advertised                                                                                                                               |
| `BackendsReady` | every backend node bound its backends, and no gateway node left a backend out because its uSID did not resolve or its node reports it `Unhealthy`, kept every backend because all are `Unhealthy`, or could not apply the rule's health check |
| `IPv4Served`    | every gateway node that loaded the rule serves its IPv4 VIP. Present only on a rule with an IPv4 VIP                                                                                                                                          |
| `Ready`         | `Accepted`, `Programmed`, `Advertised` and `BackendsReady` are `True`, and so is `IPv4Served` on a rule whose only VIP is IPv4. Otherwise it carries the reason and message of the first one that isn't                                       |

Only gateway nodes with a `<gateway-node>/Programmed` condition count. A node
that has not reported, for example one whose datapath is turned off,
advertises none of the rule's VIPs, so clients never reach it. The
`Programmed` and `Ready` messages say how many registered gateway nodes have
not reported.

`Ready` leaves out `IPv4Served` while the rule has an IPv6 VIP. IPv4 VIPs are
off on most gateways, and a rule whose IPv6 VIP serves is not down because its
IPv4 VIP is not served. Read `IPv4Served` to see whether the IPv4 VIP serves.

A condition that is not `True` takes the reason every failing node reports,
and its message names each failing node with its reason. When the nodes
disagree, it takes the generic reason in this table instead.

| Reason                   | On                            | What to do                                                                                                                                               |
| ------------------------ | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Pending`                | any                           | Nothing. No node has reported on the current generation yet.                                                                                             |
| `NoGatewayNodes`         | `Programmed`                  | Platform: no `NetworkGateway` is registered in the namespace.                                                                                            |
| `InvalidRule`            | `Programmed`, `BackendsReady` | Fix the spec. The message says what could not be built, such as a port or a backend set that resolves to nothing.                                        |
| `UnservedProtocol`       | `Programmed`                  | Use `tcp` or `udp`.                                                                                                                                      |
| `NoServedVIP`            | `Programmed`                  | Add an IPv6 VIP, or ask for IPv4 VIPs to be turned on.                                                                                                   |
| `LoadFailed`             | `Programmed`                  | Platform: the gateway refused the rule, for example over quota. The message carries the error.                                                           |
| `NotProgrammed`          | `Programmed`, `Advertised`    | Gateway nodes failed for different reasons, or none loaded the rule. Read the message.                                                                   |
| `AdvertisementFailed`    | `Advertised`                  | Platform: writing the route failed. It is retried.                                                                                                       |
| `AdvertisementPending`   | `Advertised`                  | Wait. The route is written, but `galactic-router` does not report it advertised yet. If it persists, the route's own `BGPAdvertisement` status says why. |
| `NoRouter`               | `Advertised`                  | Platform: no single `BGPRouter` targets the gateway node.                                                                                                |
| `<IPv4Served reason>`    | `IPv4Served`                  | The IPv4 VIP is not served. See the `IPv4Served` table above for the reason.                                                                             |
| `NotAdvertised`          | `Advertised`                  | Gateway nodes failed for different reasons. Read the message.                                                                                            |
| `NotServed`              | `IPv4Served`                  | Gateway nodes failed for different reasons. Read the message.                                                                                            |
| `BackendsClaimed`        | `BackendsReady`               | Another rule already serves these backends on the same port. Change `backendPort`, or move the backends off the other rule.                              |
| `BindingsNotBound`       | `BackendsReady`               | Wait. If it persists, the backend nodes' `BackendsBound` messages name each binding and why it is not bound.                                             |
| `BackendsUnresolved`     | `BackendsReady`               | A backend's node has no route yet, usually while its pod is recreated. The rule serves through the rest.                                                 |
| `BackendsUnhealthy`      | `BackendsReady`               | Backends failed their health check and are out of the table; the message names them. Fix the backends. The rule serves through the rest.                 |
| `NoHealthyBackends`      | `BackendsReady`               | Every backend fails its health check, so all of them are kept. Check the backends, and that traffic policy allows the probe.                             |
| `HealthChecksNotApplied` | `BackendsReady`               | Platform: some gateway node does not apply health, so none does. The message names the nodes.                                                            |
| `BackendsNotReady`       | `BackendsReady`               | Nodes reported different backend problems. Read the message.                                                                                             |

`BackendsReady` will also cover a backend cluster that lacks the rule, so
replies have no path back (#706), once that is built.

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
See [the CNI datapath](../cni/architecture.md#key-design-decisions).

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
[ARCHITECTURE-GATEWAY.md's Data Flow section](packet-paths.md)
for the full mechanics.

Deleting a `NetworkService` withdraws its VIP routes before any gateway node
stops serving it. The rule's finalizer deletes its `BGPAdvertisement`s,
and each node keeps the rule loaded until they are gone plus a 5-second
drain delay, so traffic already on its way to the VIP is not dropped.

#### Services in a project namespace

A `NetworkService` can live in the gateway namespace (`galactic-system`) or in
a project namespace, any other. A cluster runs one gateway namespace, the one
`galactic-router`'s BGP objects live in (`GALACTIC_ROUTER_GC_NAMESPACE`), and
the `BGPAdvertisement`s and `ServiceVIPBinding`s made for every service live
there, whatever namespace the service is in.

The gateways serve project namespaces only with
`GALACTIC_GATEWAY_PROJECT_SERVICES=true`, so a location can turn it on before
others. It needs two more settings, and the gateway refuses to start without
them:

- `GALACTIC_GATEWAY_NAMESPACE` names the gateway namespace. The DaemonSet sets
  it to the pod's own namespace. Whenever it is set, with the switch on or
  off, only `NetworkGateway`s there are trusted: one created in any other
  namespace is ignored, so it neither serves anything nor makes its
  namespace's services trusted.
- `GALACTIC_GATEWAY_PROJECT_VIP_PREFIXES` lists, comma-separated, the prefixes
  the platform allocates load balancer addresses from.

With the switch on, the gateway's role also needs `watch` on `vpcs`. A watch
the role denies stops the gateway at startup. With the switch off, a gateway
serves only the services in its own `NetworkGateway`'s namespace. It sets no
finalizer or condition on any other service. A project service it accepted
while the switch was on gets `Accepted=False` with reason
`ProjectServicesOff`, and its routes are withdrawn.

A service in the gateway namespace is trusted: the platform API that serves
tenants writes it after checking that the tenant owns the VPC `vpcRef` names,
and `Accepted` means only that gateway nodes exist. Anyone RBAC allows to
write a `NetworkService` in `galactic-system` can provision ingress for any
`vpcRef`, so grant that access only to platform controllers.

A service in a project namespace is trusted for nothing, and the gateways
check it themselves:

| Check                                                                                                                                       | Outcome when it fails                               |
| ------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| Every VIP address falls in `GALACTIC_GATEWAY_PROJECT_VIP_PREFIXES`                                                                          | `Accepted=False`, reason `VIPOutsidePool`           |
| A `VPC` in the service's namespace has `status.vpc` equal to `vpcRef`                                                                       | `Accepted=False`, reason `OwnershipDenied`          |
| No other service serves one of its VIP addresses on its protocol and port (a service in the gateway namespace always wins, then the oldest) | `Accepted=False`, reason `VIPClaimed`               |
| Its backends are `VPCAttachment`s in its own namespace                                                                                      | Attachments elsewhere are never selected or claimed |

Once accepted it reports `Accepted=True` with reason `OwnershipVerified`. A
service that loses `Accepted` is unloaded and its routes withdrawn. Its
generated objects carry the `galactic.datum.net/network-rule-namespace` label
naming its namespace, and no owner reference, since one cannot cross
namespaces: the service's finalizer and each gateway's sweep remove its
advertisements, and each backend node removes its bindings. A service deleted
when no `NetworkGateway` is left to serve it is torn down by any running
gateway process, so its namespace does not stay `Terminating`.

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

For a rule with `spec.healthCheck`, the same node also probes each backend and
writes the result to `status.health` of the backend's bindings:

```yaml
status:
  health:
    state: Unhealthy # Healthy, Unhealthy or Unknown
    reason: ProbeFailed # ProbeSucceeded, ProbeFailed, Pending or ProbeUnavailable
    message: dial tcp6 [fe80::a060:bbff:fe37:4f09%G00000006060aH]:0->[fd20:60:ff01:a::100]:80: connect: connection refused
    attachmentUID: 6d0f6f9e-0c4e-4b6d-9a4c-1c2f3e4d5a6b
    port: 80
    lastTransitionTime: "2026-10-22T18:00:00Z"
```

`state` is the damped decision, not the last probe. It is written only when it
changes, and every binding of one backend carries the same one. A gateway
reads it only while `attachmentUID` and `port` match the backend's current
attachment and the rule's health check port. See
[Backend health checks](backend-health.md).

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

## Deployment and upgrades

<a id="prerequisite-node-labeling"></a>

See [Prerequisite: node labeling](deployment.md#prerequisite-node-labeling).

<a id="step-1-deploy-the-shared-rbacserviceaccount"></a>

See [Step 1: Deploy the shared RBAC/ServiceAccount](deployment.md#step-1-deploy-the-shared-rbacserviceaccount).

<a id="step-2-why-configgalactic-gatewaybase-isnt-applied-as-is"></a>

See [Step 2: Why `config/galactic-gateway/base/` isn't applied as-is](deployment.md#step-2-why-configgalactic-gatewaybase-isnt-applied-as-is).

<a id="step-3-worked-example-a-per-node-overlay"></a>

See [Step 3: Worked example, a per-node overlay](deployment.md#step-3-worked-example-a-per-node-overlay).

<a id="rolling-out-and-rolling-back-ipv4-vips"></a>

See [Rolling out and rolling back IPv4 VIPs](deployment.md#rolling-out-and-rolling-back-ipv4-vips).

<a id="upgrading-past-the-flow-hash-change"></a>

See [Upgrading past the flow hash change](deployment.md#upgrading-past-the-flow-hash-change).

<a id="verifying-the-deployment"></a>

See [Verifying the deployment](deployment.md#verifying-the-deployment).
