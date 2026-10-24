# Troubleshooting Galactic Edge

How to find where an edge attachment or route stopped, which objects are
involved, and who forwards a prefix now, from the conditions, Events and
metrics the foundation emits. The lifecycle itself is defined in
[the provider contract](../enhancements/networking/galactic-edge/contract.md);
the metrics are listed in
[the metrics reference](../metrics.md#galactic-edge-foundation--galactic_edge_foundation_).

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

## Alerts

`config/monitoring/` ships the PodMonitors for both components and the
`galactic-edge` alert group, listed in
[the metrics reference](../metrics.md#shipped-alerts). They fire on what the
foundation itself stopped doing: attachments not programmed, services
without a resolvable policy, lost ownership scopes, failing cleanup and
unreachable metrics. A refused admission is a tenant or provider decision
and alerts nothing.
