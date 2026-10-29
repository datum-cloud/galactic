# Troubleshooting Galactic Edge

How to find where an edge attachment or route stopped, which objects are
involved, and who forwards a prefix now, from the conditions, Events and
metrics the foundation emits. The lifecycle itself is defined in
[the provider contract](provider-contract.md);
the metrics are listed in
[the metrics reference](../observability/edge.md#galactic-edge-foundation--galactic_edge_foundation_).

## Lifecycle stages

An attachment passes each stage in this order. Each stage has one writer of
its condition. Core is `galactic-controller --role=cell --edge`. The node is
`galactic-edge` on the attachment's node.

| Stage       | Object           | Condition, writer              | Warning Event (action), emitter     | State metric                                                |
| ----------- | ---------------- | ------------------------------ | ----------------------------------- | ----------------------------------------------------------- |
| Admission   | `EdgeAttachment` | `Admitted`, core               | `Admission`, `galactic-controller`  | `galactic_edge_foundation_attachments{state="Admission"}`   |
| Admission   | `EdgeService`    | `Admitted`, core               | `Admission`, `galactic-controller`  | none                                                        |
| Allocation  | `EdgeAttachment` | `Allocated`, core              | `Allocation`, `galactic-controller` | `galactic_edge_foundation_attachments{state="Allocation"}`  |
| Programming | `EdgeAttachment` | `Programmed`, node             | `Programming`, `galactic-edge`      | `galactic_edge_foundation_attachments{state="Programming"}` |
| Ready       | `EdgeAttachment` | `Ready`, provider              | none                                | `galactic_edge_foundation_attachments{state="Ready"}`       |
| Policy      | `EdgeService`    | `TrafficPolicyResolved`, core  | `Policy`, `galactic-controller`     | `galactic_edge_foundation_services{policy="Unresolved"}`    |
| Route       | `EdgeRoute`      | `Claimed` and `Accepted`, core | `Route`, `galactic-controller`      | `galactic_edge_foundation_routes`                           |
| Publication | `EdgeRoute`      | `Published`, core              | none                                | `galactic_edge_foundation_routes{state="Accepted"}`         |
| Ownership   | `EdgeRoute`      | `status.closedEpoch`, node     | `Ownership`, `galactic-edge`        | `galactic_edge_foundation_gate_closures_total`              |

An admitted attachment whose authority ends, because its service, pod,
instance or grant went away, gets `Draining` True and an `Admission` Event
that names the reason and the drain deadline. Core deletes it at that
deadline and holds it with its finalizer until its node reports `Released`.

Each failure records one Event when it starts, not one per retry, and adds
one to `galactic_edge_foundation_failures_total{stage, reason}`. A claim waiting to
fence the previous holder (`WaitingForFencing`, `IndexRebuilt`) is the
claim's normal path and records nothing.

## Correlation fields

Every foundation Event's note is the message, then ` | `, then these
fields as `key=value`, in this order, leaving out those that do not apply:

| Field               | Value                                                 |
| ------------------- | ----------------------------------------------------- |
| `provider`          | The `EdgeProvider`'s name                             |
| `service`           | The granting `EdgeService`, as `namespace/name`       |
| `serviceUID`        | The granting service's UID                            |
| `serviceGeneration` | The service generation core decided on                |
| `attachment`        | The `EdgeAttachment`, as `namespace/name`             |
| `attachmentUID`     | The attachment's UID                                  |
| `podUID`            | The provider pod's UID                                |
| `node`              | The node that programs the attachment or holds a gate |
| `route`             | The `EdgeRoute`, as `namespace/name`                  |
| `prefix`            | The route's prefix                                    |
| `epoch`             | The route's accepted claim epoch, or its pending one  |

The same attachment UID appears in core's and the node's Events, so one
query follows an attachment through every stage. No Event or metric carries
a credential: the foundation's objects hold none.

## Workflow

### 1. Find the attachment

```sh
kubectl get edgeattachments -A -o custom-columns=\
NS:.metadata.namespace,NAME:.metadata.name,UID:.metadata.uid,\
PROVIDER:.spec.providerRef.name,NODE:.status.nodeName,ADDRESS:.status.address
```

For a provider pod, its attachments carry its UID in `spec.podUID`.

### 2. Find the stage it stopped at

```sh
kubectl get edgeattachment -n NS NAME -o jsonpath=\
'{range .status.conditions[*]}{.type}={.status} {.reason}: {.message}{"\n"}{end}'
```

The first stage in the table above whose condition is not True is where it
stopped. Its reason and message say why. No `Admitted` condition at all
means core has not decided yet: check that `galactic-controller` runs with
`--edge`.

### 3. Read its Events

```sh
kubectl events -n NS --for edgeattachment/NAME
```

For everything about one attachment across services, routes and nodes,
match its UID in the notes:

```sh
kubectl get events -A -o json | jq -r --arg uid ATTACHMENT_UID '
  .items[] | select(.message | contains("attachmentUID=" + $uid))
  | [.eventTime // .lastTimestamp, .reportingComponent, .action, .reason, .message] | @tsv'
```

Events expire with the API server's event TTL, one hour by default. After
that the conditions and `galactic_edge_foundation_failures_total` remain.

### 4. Find who forwards a prefix

```sh
kubectl get edgeroutes -n NS -o custom-columns=\
NAME:.metadata.name,PREFIX:.spec.prefix,EPOCH:.status.accepted.epoch,\
ATTACHMENT:.status.accepted.attachment,NODE:.status.accepted.node,\
CLOSED:.status.closedEpoch,ACCEPTED:.status.conditions[?(@.type=="Accepted")].status
```

The accepted holder is `status.accepted`: its attachment, node and epoch.
It may forward only while `Accepted` is True and its epoch is above
`closedEpoch`, and on its node only until its gate's deadline. The VPC's
`EdgeRouteIndex`, named after the VPC's UID in the service's namespace,
lists every route core accepted there and any holder still being fenced:

```sh
kubectl get edgerouteindex -n SERVICE_NS VPC_UID -o yaml
```

### 5. Check the node

On the holder's node, `galactic_edge_foundation_gates{state}` counts open, expired
and closed gates, and `galactic_edge_foundation_gate_drops_total` counts packets
dropped for want of an open gate. Each gate the agent closes while open
records an `Ownership` Event on the route whose reason is the cause.

#### Node requirements

The agent creates a `PacketAccess` attachment's TUN device from its own
container, through the node's `/dev/net/tun`, which the DaemonSet mounts as a
`CharDevice` hostPath volume. The node needs:

- The kernel's `tun` driver, with its device node at `/dev/net/tun`. Without
  it the agent pod does not start, and its Events report the failed
  hostPath check for `/dev/net/tun`.
- A container runtime that lets unprivileged containers open character device
  `10:200`. runc allows it by default in every release except 1.2.0 to 1.2.3.
  A runtime that refuses it fails each `PacketAccess` attachment with
  `Programmed` False, reason `ProvisionFailed`, and a `hostattach: create TUN`
  message reporting the denied open.

The agent's `--mtu` must be no larger than the fabric uplink MTU less the
40-byte encapsulation header, the limit `galactic-cni` writes to
`encap_mtu_table`. A larger one fails every attachment on the node with
`Programmed` False, reason `MTUExceedsUnderlay`, and a message naming both
values. The [provider contract](provider-contract.md#attachment) gives the
bounds.

## Telling failures apart

| What happened                 | Where it shows                                                                                                                                                          | What sets it apart                                                                                               |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Unauthorized request          | `Admission` Event on the attachment or service, or `Route` Event on a claim; reasons such as `UnknownProvider`, `VPCNotGranted`, `PrefixNotGranted`, `IdentityMismatch` | No address allocated, no host state, no gate. Fix the grant or provider, not the node                            |
| Unready attachment            | `Programming` Event and `Programmed` False on the attachment; or `Ready` False with no foundation Event                                                                 | `Programmed` False is the node's failure, its reason naming the step. `Ready` False is the provider's own report |
| Policy denial, configuration  | `Policy` Event on the service; `TrafficPolicyResolved` False                                                                                                            | The attachment is programmed but carries only neighbor discovery until the policy resolves                       |
| Policy denial, packets        | `galactic_cni_traffic_policy_fallback_packets_total` and `_rule_hits_total{action="deny"}` from `galactic-router`, labeled with the attachment                          | The policy resolved and is enforced; the traffic is not allowed by it                                            |
| Ownership expired             | `Ownership` Event with reason `Expired`                                                                                                                                 | The provider stopped renewing its instance lease, or the API server was out of reach                             |
| Grant ended                   | `Ownership` Event with reason `GrantCeiling`, or `AuthorityEnded`                                                                                                       | The grant's `validUntil` passed, or the grant, provider or attachment stopped authorizing the route              |
| Ownership revoked or released | `Route` Event (revocation) and `Ownership` Event with reason `Revoked`, or `Released`                                                                                   | Core revoked the claim, or the holder released it                                                                |
| Routing convergence           | Route `Accepted` True, `Published` False with `AttachmentNotProgrammed`, `VRFNotReady` or `AwaitingRouter`                                                              | Forwarding on the node is allowed; remote nodes have not learned the prefix yet                                  |

Forwarding cutoff, local route withdrawal and remote convergence are
separate events. An expired gate whose grant has also lapsed by the time the agent closes it
is reported as `GrantCeiling` or `AuthorityEnded`, not `Expired`, even when
the provider stopped renewing first. `Expired` alone means the grant was
still valid.

The datapath stops forwarding at the gate's deadline on
its own; the `Ownership` Event records when the agent observed and closed
the gate, at or after that. `galactic-router` withdraws the local
advertisement within its 250 ms gate poll. Remote convergence then depends
on the route reflectors and the hold time, which the contract's Timing
section bounds.

## Diagnose a MASQUE connector

The [MASQUE service](masque-service.md) adds per-request telemetry on top of the foundation's. Its metrics are in [the MASQUE metrics reference](../observability/masque.md). Two log lines of `masque-provider` name every identity of one request, and share its session ID:

- `request admitted` from the adapter: `session`, `connector`, `principal`, `serviceUID`, `attachment`, `attachmentUID`, `route`, `claimEpoch` and `instanceEpoch`.
- `CONNECT-IP request accepted` from the server: `transport`, `session`, `connector`, `vpc`, `prefix`, `attachment`, `claim` and `epoch`.

Their ends are `request ended` (with `endReason`) and `CONNECT-IP request ended` (with `cause` and `duration`). A refused request logs `CONNECT-IP request rejected` with `transport` and `outcome`, and `admission refused` with the adapter's `outcome`. No log line or metric carries a credential or packet contents.

1. Find the connector's latest request:

   ```sh
   kubectl logs -n masque-system deploy/masque-provider | grep 'connector=<connector>'
   ```

2. If it was refused, the outcome says who refused it:

   | Outcome                         | Refused by                            | Next step                                                                                  |
   | ------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------ |
   | `unauthenticated`, `forbidden`  | The authority: the client's grant     | Check the connector's credential and VPC with the authority, not the node                  |
   | `limited`, `max_connections*`   | The server's limits                   | `galactic_connectip_tunnels`, `_admissions` and `_connections` against the configured caps |
   | `no_lease`, `shutting_down`     | The provider instance                 | `galactic_masque_lease_held`; the pod's readiness                                          |
   | `attachment_failed`             | Core or the node: the attachment      | Steps 1 to 3 of [the workflow](#workflow) with the attachment the adapter logged           |
   | `route_refused`, `route_failed` | Core: the connector's /96 route claim | [Find who forwards the prefix](#4-find-who-forwards-a-prefix) and read the route's Events  |
   | `mtu`                           | The path                              | The client's path cannot carry a 1280-byte inner packet over HTTP/3; HTTP/2 can            |

3. If it was admitted but does not forward, `galactic_masque_requests` says how far it got. `programmed` with `galactic_masque_lease_held` at 0 is a lost lease. `programmed` with the lease held is a grant past its deadline, or a packet path not yet open. `admitted` is an attachment or route claim no longer current; follow [the workflow](#workflow) with the logged `attachmentUID` and `route`.
4. If it ended, read both end lines. The server's `cause` says what broke the tunnel and the adapter's `endReason` says why:

   | `cause`         | `endReason`                                                                   | Meaning                                                              |
   | --------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------- |
   | `lease_ended`   | `grant_expired`, `grant_revoked`, `grant_changed`, `grant_invalid`, `revoked` | The client's authority ended                                         |
   | `lease_ended`   | `replaced`                                                                    | The connector reconnected, possibly over the other transport         |
   | `lease_ended`   | `lease_lost`                                                                  | The provider instance lost its Lease; every request on the pod ended |
   | `lease_ended`   | `route_revoked`, `route_moved`                                                | Core stopped accepting the /96 claim; see the route's `Route` Event  |
   | `lease_ended`   | `attachment_*`                                                                | The attachment was drained, deleted or reprogrammed                  |
   | `path_mtu`      | `closed`                                                                      | The client's path no longer carries a 1280-byte packet               |
   | `slow_client`   | `closed`                                                                      | The client stopped receiving for 5 seconds                           |
   | `backend_error` | `closed`                                                                      | The packet device failed a read or write                             |
   | `client_closed` | `closed`                                                                      | The client or its connection ended the request                       |

5. If it forwards but traffic is lost, check `galactic_connectip_packets_denied_total` for packet policy drops, `galactic_masque_device_drops_total` for a full device, and the traffic policy and route publication rows of [Telling failures apart](#telling-failures-apart) for the gVPC side.

## Alerts

`config/monitoring/` ships the PodMonitors for both components and the
`galactic-edge` alert group, listed in
[the metrics reference](../observability/alerts.md#shipped-alerts). They fire on what the
foundation itself stopped doing: attachments not programmed, services
without a resolvable policy, lost ownership scopes, failing cleanup and
unreachable metrics. A refused admission is a tenant or provider decision
and alerts nothing.

The `masque-provider` alert group fires on a MASQUE provider pod failing
requests on its own side. A request the client or its grant gets wrong
alerts nothing. Each alert names the pod; start from its logs as in
[Diagnose a MASQUE connector](#diagnose-a-masque-connector).

### GalacticMasqueRequestsFailing

Over a quarter of the pod's requests fail on the provider's side. Find the
stage that refuses them:

```promql
sum by (outcome) (increase(galactic_masque_admissions_total{pod="<pod>"}[30m]))
```

- `authorizer_failed`: the pod cannot reach the grant authority, or it times out. Check the `masque-authority` pods and the provider's projected token.
- `attachment_failed`: follow [the workflow](#workflow) from the attachment in the `admission refused` log line.
- `route_refused`, `route_failed`: see [GalacticMasqueRouteClaimsFailing](#galacticmasquerouteclaimsfailing).
- `replace_failed`: the connector's previous request did not stop in time. Read that request's log lines by its session ID.

When admissions succeed, `galactic_connectip_tunnel_ends_total` with `cause` `backend_error` or `setup_failed` points at the packet device or address assignment. Read the `CONNECT-IP request ended` lines and check the node as in [step 5](#5-check-the-node).

### GalacticMasqueRouteClaimsFailing

Core keeps refusing connector /96 claims (`refused`) or not accepting them
in time (`failed`). For a refusal, [find who forwards the
prefix](#4-find-who-forwards-a-prefix) named in the `admission refused`
line; another forwarder holds it. For a failure, check that the core
controller (`galactic-controller --role=cell --edge`) runs, and read the
route's Events with `kubectl describe edgeroutes -n masque-system`.

### GalacticMasqueLeaseNotHeld

The pod holds no instance Lease, so it admits nothing and is not ready.
Read its `lease` log lines for the error. Its Lease writes can be refused
by the provider's RBAC or the `galactic-edge-lease` admission policy, or
fail when the API server is unhealthy.

### GalacticMasqueLeaseLost

The pod keeps losing and reacquiring its Lease, ending every request each
time. Its `lease renewal failed` and `lease lost` lines give the error,
such as Lease writes the API server refused or timed out.

### GalacticMasquePathMTUTooSmall

The HTTP/3 path of many requests cannot carry a 1280-byte inner packet.
When it affects most clients, the cut is in front of the pod: check the
MTU of the load balancer, any tunnel and the node's uplink. Clients can
still connect over HTTP/2.

### GalacticMasqueMetricsDown

Prometheus cannot scrape the pod's `health` port (9188). Check that the
pod runs and that the `masque-provider` PodMonitor from
`config/monitoring/` is applied and can reach the `masque-system`
namespace.
