# Backend health checks

A `NetworkService` balances flows over the backends its `backendSelector`
picks. A backend that resolves and advertises but has stopped serving keeps
its slots in the Maglev table, so every flow hashed to it fails. Health checks
take such a backend out of the table on every gateway node, and put it back
once it serves again.

Health checks are opt-in per service. A service without `spec.healthCheck`
behaves exactly as it does without this feature.

## What stays the same

- **The edge datapath.** `edge_lb` stays stateless: a packet's backend comes
  from a fixed flow hash looked up in the Maglev table. Health changes only
  the backend list the control plane builds the table from. No eBPF program
  or map changes.
- **Table determinism.** Every gateway node builds a rule's table from API
  objects alone. Health adds API objects to that input. It adds no probe
  result, timer or clock a gateway reads locally.

The one datapath change is on the backend's node, in the uSID program, so a
probe's reply reaches the prober (see [Reply path](#reply-path)).

## Who probes

`galactic-router` on the backend's own node probes the backend. It already
writes the backend's `ServiceVIPBinding`s, so it is already the one writer for
per-backend state.

- One prober per backend, however many gateway nodes there are.
- The probe never crosses the fabric, so a fabric fault shows up as a fabric
  fault, not as every backend failing at once.
- It works the same for a container (veth) and a VM (tap) backend: the probe
  reaches the guest's own TCP stack.

Gateway nodes do not probe. With DSR they never see a backend's replies, and
probes from each gateway node would give each node its own view, which breaks
table determinism.

## What the probe is

A TCP connect to `backendAddress` on the health check port, from the backend
node's root namespace, over the backend's own host-side interface
(`status.hostInterface` of its `VPCAttachment`, a veth or a tap enslaved to the
VPC's VRF). The socket is bound to that interface and to the interface's
link-local address.

- **Success** is a completed handshake within `timeoutSeconds`. The prober
  closes the connection at once and sends no data.
- **Cold starts.** A connection refusal is retried at most twice, 250 ms
  apart, within the same `timeoutSeconds` budget. All attempts produce one
  health observation; the next probe still waits the configured interval.
- **Failure** is a refusal after those attempts, another connection error,
  or no handshake within the timeout. Cancellation stops retries immediately.
- **Port.** The health check port defaults to `backendPort`, so the probe
  reaches the socket that serves the VIP. A UDP service must name a TCP port
  the backend listens on: a UDP send that does not fail proves nothing, and
  there is no reply a generic prober can expect. The API refuses a UDP service
  with a health check and no port.

### Reply path

The backend's node rewrites every packet the backend sends from
`backendAddress:backendPort` to come from the VIP, and sends it out the fabric
uplink, because that is how a DSR reply reaches its client. A probe's
SYN-ACK leaves from the same address and port, so without a carve-out it would
be rewritten and sent away, and no probe on `backendPort` could ever
succeed.

The uSID program (`usid_egress`) therefore hands a packet addressed to a
link-local destination to the kernel before the VIP rewrite and NPTv6, as it
already does after them. A DSR client is never link-local, and a link-local
packet never leaves the link, so neither rewrite has anything to do with it.
The probe's reply goes to the prober's link-local address on the same link
and never leaves the node.

The source is the link-local address rather than the attachment's gateway
address for this reason: a reply to the gateway address is an ordinary unicast
reply, and the datapath cannot tell it from a VIP reply without a lookup on
every packet.

### Traffic policy

A probe is tenant traffic on the private path, so interface traffic policy
applies to it like any other packet the host sends to the backend. Where
policy is enforced, the backend's ingress policy must allow TCP from
`fe80::/10` to the health check port on the `Private` path, and its egress
policy the replies to `fe80::/10`. Without that, every probe fails and the
all-unhealthy rule below keeps the backends in the table.

## Where the result lives

On each of the backend's `ServiceVIPBinding`s, in `status.health`, written
only by `galactic-router` on the backend's node:

| Field                | Meaning                                                                          |
| -------------------- | -------------------------------------------------------------------------------- |
| `state`              | `Healthy`, `Unhealthy` or `Unknown`: the damped decision, not the last probe     |
| `reason`             | `ProbeSucceeded`, `ProbeFailed`, `Pending` or `ProbeUnavailable`                 |
| `message`            | The last probe error, when there is one                                          |
| `attachmentUID`      | The `VPCAttachment` incarnation the decision is about                            |
| `port`               | The port that was probed                                                         |
| `lastTransitionTime` | When `state` last changed                                                        |

A backend has one binding per VIP family it serves, and each carries the same
decision. A gateway reads a family's decision from that family's binding.

The router writes `status.health` only when the decision changes, with a merge
patch of that field alone, so it never rewrites the `Bound` condition the same
process sets. The write volume is one patch per binding per transition.

### Identity

A decision applies only to the backend it was made for. A gateway ignores
`status.health`, treating it as `Unknown`, unless:

- the binding is the current generated binding for the rule and backend, the
  same check the IPv4 VIP gate makes today;
- `attachmentUID` is the UID of the `VPCAttachment` that holds the address now;
- `port` is the rule's current health check port.

So a recreated attachment that reuses an address, or a port change, starts from
`Unknown`.

### States

| State       | Reason             | When                                                                   | In the table |
| ----------- | ------------------ | ---------------------------------------------------------------------- | ------------ |
| `Unknown`   | `Pending`          | Too few probes since the backend, or its health check, appeared        | Yes          |
| `Healthy`   | `ProbeSucceeded`   | `healthyThreshold` consecutive successes                               | Yes          |
| `Unhealthy` | `ProbeFailed`      | `unhealthyThreshold` consecutive failures                              | No           |
| `Unknown`   | `ProbeUnavailable` | `unhealthyThreshold` consecutive probes that could not run             | Yes          |

A probe cannot run when the backend's host-side interface, or its link-local
address, is missing on the node.

Only an observed failure takes a backend out. `Unknown` keeps it in, so
turning health checks on never shrinks a pool before the first probes finish,
and a prober that cannot run removes nothing.

## Flap damping

The decision moves only after `unhealthyThreshold` consecutive failures or
`healthyThreshold` consecutive successes. A backend that alternates between
passing and failing never reaches either threshold, so it keeps its current
state. There is no other hold-down, and no slow start: a recovered backend gets
its full share of slots at once.

The prober publishes the decision. Gateways apply no recovery timer of their
own, so two gateways never disagree because their clocks or start times
differ.

## Every backend unhealthy

If every backend of a family is `Unhealthy`, the gateway keeps all of them in
the table and keeps advertising the VIP. An empty table drops every packet, and
a withdrawn VIP leaves clients with no route at all. Neither helps when the
cause is often the probe itself, such as a traffic policy that denies it. The
rule's status says so (see below), so the condition is visible.

## Flow disruption

Damping limits how often the backend set changes. It does nothing for the cost
of a single change. Removing one of N backends reassigns the slots it held,
and Maglev also reassigns a few slots between the backends that stay. Every
connection whose slot changes breaks, because the datapath keeps no connection
state. Recovery is the inverse change and breaks the same share of
connections again, including those that moved off the backend while it was
out.

Measured on the gateway's 1021-slot table, worst case over which backend
leaves:

| Backends | Slots changed | Slots moved between remaining backends | 1/N    |
| -------- | ------------- | -------------------------------------- | ------ |
| 2        | 50.05%        | 0.00%                                  | 50.00% |
| 3        | 34.67%        | 1.27%                                  | 33.33% |
| 4        | 25.76%        | 0.78%                                  | 25.00% |
| 8        | 15.08%        | 2.55%                                  | 12.50% |
| 16       | 9.89%         | 3.62%                                  | 6.25%  |

## Consistency

The consistency domain is one namespace of one cluster: the gateway nodes
whose `NetworkGateway`s live in the namespace of the service. Each cluster's
gateways read only their own cluster's objects. A backend in another cluster
is outside this design.

- **Decision version.** A gateway's input is the bindings' `status.health` as
  its informer cache holds them. Two gateways with the same cache contents
  build the same table.
- **Disagreement window.** After a decision changes, gateways disagree until
  each has seen the write and finished a pass: normally the watch latency plus
  one reconcile. The target is every gateway in the namespace serving the new
  table within 5 seconds of the write, measured in the lab.
- **Delayed watch, failed reconcile or partition.** A gateway that has not seen
  the write keeps its last table and converges when it does. There is no bound
  while a gateway is cut off from the API server.
- **Prober restart.** `galactic-router` resumes from each binding's persisted
  decision, so a restart changes no table. Only a backend whose identity no
  longer matches starts again from `Unknown`.
- **Prober down.** The last decision stays. A backend that fails while its
  node's `galactic-router` is down stays in the table until the router
  returns.
- **Gateway restart.** A gateway rebuilds its table from the same objects and
  gets the same result.

### Mixed versions

A gateway that predates health checks would ignore `status.health` and keep
an unhealthy backend that the other gateways drop. To prevent that, a gateway
with `GALACTIC_GATEWAY_BACKEND_HEALTH` on reports
`status.backendHealthFiltering: true` on its own `NetworkGateway`, and applies
health only while every `NetworkGateway` in the namespace reports it. An older
gateway never writes the field, and its status update removes it, so a single
gateway that does not filter, whether not yet upgraded, rolled back or with the
switch off, turns filtering off on all of them.

The rule's status says when filtering is off for this reason
(`HealthChecksNotApplied`).

## API

```yaml
spec:
  healthCheck:
    port: 8080             # optional for tcp (default: backendPort), required for udp
    intervalSeconds: 5     # 1-300
    timeoutSeconds: 2      # 1-60, at most intervalSeconds
    unhealthyThreshold: 3  # 1-10
    healthyThreshold: 3    # 1-10
```

With the defaults a dead backend leaves the table 10 to 15 seconds after it
stops answering, and returns 10 to 15 seconds after it answers again.

### Status

Per backend, `status.health` on each `ServiceVIPBinding`, as above.

Per rule, each gateway node's `<node>/Programmed` condition, which stays
`True` while the rule is loaded, takes one of these reasons:

| Reason                   | Meaning                                                                       |
| ------------------------ | ----------------------------------------------------------------------------- |
| `BackendsUnhealthy`      | Loaded without the unhealthy backends; the message names them                 |
| `NoHealthyBackends`      | Every backend is unhealthy, so all of them are kept                           |
| `HealthChecksNotApplied` | A gateway node in the namespace does not apply health, so none of them does   |

The rule-wide `BackendsReady` condition reports each of them as a backend
problem, as it reports `BackendsUnresolved`.

## Rollout and rollback

1. Install the CRDs that carry `spec.healthCheck`,
   `ServiceVIPBinding.status.health` and
   `NetworkGateway.status.backendHealthFiltering`.
2. Upgrade `galactic-cni` on every node, so the uSID program hands
   link-local replies to the kernel. Without it every probe on `backendPort`
   fails.
3. Upgrade `galactic-router` on every node. It probes only services with a
   health check, so this changes nothing yet.
4. Upgrade `galactic-gateway` on every gateway node, with
   `GALACTIC_GATEWAY_BACKEND_HEALTH=true` and a ClusterRole that grants
   `get`, `list` and `watch` on `servicevipbindings`. Filtering starts once
   the last one reports `backendHealthFiltering`.
5. Set `spec.healthCheck` on a service, and allow the probes in its traffic
   policy where policy is enforced.

To turn health checks off for one service, remove `spec.healthCheck`. The
routers clear `status.health` and stop probing, and the gateways put every
backend back.

To roll back, turn `GALACTIC_GATEWAY_BACKEND_HEALTH` off on any gateway, or
downgrade the gateways, first: the first gateway that stops reporting
`backendHealthFiltering` turns filtering off on all of them. Then downgrade the routers, then `galactic-cni`.
A router downgraded first drops `status.health` from its bindings on its next
status write, which returns its backends to the table. `galactic-cni`
downgraded while gateways still filter makes every probe on its node's
backends fail, and takes those backends out.
