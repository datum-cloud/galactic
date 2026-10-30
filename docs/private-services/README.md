# Private service routes

`ServiceEndpoint` declares the producer destination. Its declared
`spec.address`, `spec.protocol`, and `spec.port` are the exact destination tuple
that the selected producer attachment must accept. Galactic does not interpret
the address as a Kubernetes Service frontend: it does not discover
EndpointSlices or select a Kubernetes backend. A translated policy uses
`spec.frontend.address` inside the consumer VPC and translates it to the
endpoint address before delivery.

The controller that publishes the `ServiceEndpoint` owns the service
implementation. Unless the endpoint spreads traffic (see
[Several producers on one node](#several-producers-on-one-node)), it also owns
their health: it must ensure every attachment selected by `attachmentRef` or
`attachmentSelector` is ready to receive the declared tuple.
`VPCAttachment`'s `Ready` and `Programmed` conditions are necessary networking
prerequisites; they do not attest that a service listener is healthy. A
listener may bind or configure the address in the producer, use a transparent
socket, or use another service-owned mechanism. Galactic does not configure the
producer VIP; that mechanism and its lifecycle are owned by the service.
Whatever mechanism is used must make the exact VIP routable through the
selected producer attachment and neighbor-resolvable on that attachment. A
transparent socket bind by itself is insufficient when the producer VPC's FIB
or neighbor discovery cannot deliver the VIP to that interface.

Galactic treats an attachment as ready only when its status has
`observedGeneration` equal to its generation, non-empty `node`, `vpc` and
`vpcAttachment`, and `Ready` and `Programmed` both `True`. The Galactic cell controllers in `internal/cloud/controller` write these, partly
from the `BGPAdvertisement` that `galactic-router` publishes for the
attachment. Without them no attachment is ready and no route is programmed.

By default (`spec.distribution` unset or `Single`), Galactic selects one ready
producer for each consumer. A node-local producer is preferred and ties are
resolved deterministically by attachment namespace and name. More than one
ready producer in the same node and VPC is rejected because the single-target
route cannot distinguish those replicas. Replicas on different nodes or in
distinct VPCs remain valid. `NodeLocal` stops there when no local producer is
ready; `PreferNodeLocal` may select a remote producer and carries the original
packet through the SRv6 service tunnel. In both cases the producer receives the
declared destination and the original consumer source unchanged.

## Several producers on one node

`spec.distribution: Spread` sends each consumer's traffic to every ready
producer on the consumer's node, up to 16 of them, through the one service
address. It requires `spec.healthCheck`, and `healthCheck` is refused without
it:

```yaml
spec:
  address: fd53::53
  port: 53
  protocol: udp
  deliveryMode: PreferNodeLocal
  attachmentSelector:
    matchLabels:
      role: resolver
  distribution: Spread
  healthCheck:
    port: 8053          # required for a udp endpoint: a TCP port the producers listen on
    intervalSeconds: 5
    timeoutSeconds: 2
    unhealthyThreshold: 3
    healthyThreshold: 3
```

How flows are spread:

- A TCP connection goes to the producer that received its first packet and
  stays there while that producer is in the node's set, even after its health
  check fails. A new connection goes to a producer chosen by its flow hash.
- Each UDP datagram picks a producer at random, so the requests of one socket
  spread too. This suits request/response protocols such as DNS. It does not
  suit a protocol that needs a UDP flow to stay on one producer, such as QUIC;
  keep such endpoints on `Single`.
- Replies reach the consumer from whichever producer answered.

Each producer's own node probes it: `galactic-router` opens a TCP connection to
the producer attachment's first IPv6 address, or its pod subnet's address,
on `healthCheck.port` (the endpoint's port when unset), through the producer's
host-side interface and from that interface's link-local address. Where
interface traffic policy is enforced, the producer's policy must allow that
TCP connection from `fe80::/10` on the Private path. The node publishes the
decision for each of its producers in its own `ServiceEndpointProducerReport`
for the endpoint, in the endpoint's namespace and owned by it:

```console
$ kubectl get svcproducerreport
NAME                        ENDPOINT   NODE     AGE
resolver-3f1c2a9d8e7b6a50   resolver   node-1   2d
resolver-9b0e4d7c6a5f4e31   resolver   node-2   2d
$ kubectl get svcproducerreport resolver-3f1c2a9d8e7b6a50 -o jsonpath='{range .spec.producers[*]}{.name}{"\t"}{.state}{"\t"}{.reason}{"\t"}{.renewTime}{"\n"}{end}'
resolver-a   Healthy     ProbeSucceeded   2026-01-01T12:00:45Z
resolver-b   Unhealthy   ProbeFailed      2026-01-01T12:00:45Z
```

Each report holds at most the 16 producers one node may have, so an
endpoint's producers can span any number of nodes. A node deletes its report
when it has no producers of the endpoint left. A node that has producers of
the endpoint deletes any other node's report whose newest entry was last
renewed more than 10 minutes ago, because that node is gone.

The node renews its entries every 15 seconds, whether or not a decision
changed, and sets each entry's `renewTime`. An entry is current for 60 seconds
after its `renewTime`. After that it is expired: its node is down, or its
`galactic-router` has stopped, and its `state` may no longer be true. An entry
with no `renewTime` is expired too.

What a current decision does:

| State       | New flows | Existing TCP connections and replies |
| ----------- | --------- | ------------------------------------ |
| `Healthy`   | yes       | yes                                  |
| `Unknown`   | yes       | yes                                  |
| `Unhealthy` | no        | yes                                  |

An expired entry never drains a producer on its own node, so a producer
reported `Unhealthy` just before its node's router stopped takes new flows
again once the entry expires.

When every producer on a node is `Unhealthy`, all of them keep taking new
flows, because an empty set would drop every request. A producer that crashes
stops getting new flows within `intervalSeconds × unhealthyThreshold` plus
`timeoutSeconds`, plus the time its node takes to publish the decision and the
consumer's node to program it. One whose attachment stops being ready leaves
the set as soon as its node sees the change. Either way only its own
connections move.

For a rollout or shutdown that loses no requests, make the producer fail its
health check first and keep serving for at least that detection time plus its
longest request, then stop it. Its in-flight requests and open connections
finish while new ones go to the other producers.

When the consumer's node has no producer, `PreferNodeLocal` sends the consumer
to one remote producer, through the SRv6 service tunnel as with `Single`. It is
the first producer by namespace and name whose node currently reports it
`Healthy` or `Unknown`, or has no entry for it. If there is none, it is the
first producer whose entry expired, and failing that the first producer. So
when a node goes down while its producers' attachments still read ready,
consumers on other nodes move off those producers within 60 seconds of the
node's last renewal, as long as another node currently reports a producer that
can take them. A remote consumer does not spread. While a health change reaches the
consumer's node and the producer's node at different moments, the two can
briefly disagree on that producer, and its requests are refused until they
agree.

A TCP connection keeps its producer only while its pin lasts. A pin ends after
300 seconds without traffic, the same idle limit replies already have, or when
the node evicts it under load or reloads the datapath. A packet of an
established connection with no pin goes to the producer its hash picks among
the current eligible ones, so if that set changed since the connection opened,
the connection resets. Changing an endpoint between `Single` and `Spread`
replaces its routes, which can drop a request in flight and moves existing TCP
connections.

Apply the `ServiceEndpointProducerReport` CRD and the `galactic-router`
RBAC for it before upgrading `galactic-router` to a version that writes
reports. Without the CRD that router cannot start its watches and does not
start. A `galactic-router` that predates reports writes its entries into
the endpoint's `status.producers` instead. An upgraded router removes its own
entries there only once its report holds their replacements. While routers
are being upgraded or rolled back, an upgraded router reads both, and for each
producer keeps whichever entry its node renewed last, so producers on nodes
that run the older router keep draining. A rolled-back router reads only
`status.producers`, so it treats producers on nodes that still run the newer
router as having no entry, and does not drain them, until those nodes are
rolled back too.

A `galactic-router` without report renewal writes no `renewTime`, so while
routers are being upgraded, consumers on upgraded nodes treat the entries of
nodes that are not yet upgraded as expired, and send remote consumers to
them only when no current entry offers a producer. This lasts until the
rollout finishes. A rolled-back router ignores `renewTime`.

Apply the `ServiceEndpoint` CRD with `renewTime` before upgrading
`galactic-router`. Without it the API server prunes the field from every
report, so every entry reads as expired and no `Unhealthy` producer drains.
Nodes compare `renewTime` with their own clock, so keep node clocks in sync:
a skew near 45 seconds expires live reports early or keeps a lost node's
reports current for that much longer.

Spread needs a `galactic-cni` whose datapath has the producer set map. A
`galactic-router` that finds the map missing refuses the endpoint's Spread
routes on that node, retrying, and keeps every other route working. Roll out
`galactic-cni` before setting `Spread`. Before rolling back either
`galactic-router` or `galactic-cni` to a version without Spread, set every
endpoint back to `Single`: an older router refuses an endpoint with several
producers on one node, and an older datapath drops the Spread routes a newer
router still writes, since the producer set map's pin outlives the rollback.

## No consumer-visible route

Galactic does not add the service address or a service-specific route to a
consumer, and does not inject a route into a consumer guest. Consumers send the
packet through their ordinary default gateway. The attachment's TC-eBPF
classifier matches the exact service or frontend tuple and redirects it to the selected
producer; unauthorized ports are dropped. Galactic also does not install a
host route for the service address. The producer service may still need to
configure or bind the address locally so its own network stack or listener
accepts the packet; that producer-side configuration is not consumer-visible.

For direct endpoint access with no frontend translation, operators should expect
all of the following. When [consumer service frontends](#consumer-service-frontends)
are enabled, the classifier translates the frontend address to the declared
producer destination; the absence of guest and host service routes still holds:

- `ip route` inside a consumer contains no route for the service address;
- the node has no service-address route created by the service-route
  controller;
- the producer receives the original service destination rather than a hidden
  backend address; and
- publishing an address that the producer does not accept produces an
  unavailable service. Publishing the endpoint alone does not enable frontend
  translation or discover a backend.

## Not a ServiceVIPBinding

`ServiceVIPBinding` belongs to Galactic's gateway DSR dataplane. It explicitly
maps a gateway frontend VIP and port to a real backend address and port, and its
controller programs the separate VIP translation table. A `ServiceEndpoint`
does not reference a `ServiceVIPBinding`, and the private service-route
dataplane does not consult that translation to discover a backend. Reusing the
same address in both APIs does not connect the two mechanisms.

## Consumer service frontends

Frontend translation is disabled by default. Enable it on participating routers
with `--service-frontend-enabled` or `GALACTIC_ROUTER_SERVICE_FRONTEND_ENABLED=true`.
The publishing controller supplies the producer address in `ServiceEndpoint`;
`ServiceRoutePolicy.spec.frontend.address` supplies the consumer address.
Both addresses must use the same IP family. Ports are not translated.

A translated policy pins the consumer VPC by name and UID. Selected attachments
must match that VPC's allocated network identity. Persistent access remains
active during control plane outages and ends when the policy is withdrawn or
the VPC lifetime changes.

```yaml
spec:
  authorization:
    # Keep connectivity until an explicit policy or VPC lifetime change.
    persistent: true
```

Time-bounded access sets `authorization.validUntil` within the next two minutes
and omits `persistent`. Kernel checks enforce its deadline on requests and
established replies. Persistent access must omit the deadline.

Policies claiming the same frontend address, protocol, and port on one consumer
attachment are rejected together. Separate VPC attachments can reuse that tuple.
The publisher owns access policy and, for `Single` endpoints, service health;
Galactic enforces network access and forwards packets. It does not interpret DNS records or zones.

## Node programming reports

`ServiceRoutePolicy.status.nodes` reports whether each participating node
programmed the current path. A report identifies the policy UID, generation,
and input digest. It expires within 60 seconds or when authorization expires,
whichever comes first. Consumer and producer nodes report independently for
remote delivery.

Controllers require the current topology digest and all required nodes to
establish a new path. Expired reports indicate unknown observation health; they
do not revoke a persistent path. `Accepted=True` means the policy is valid; it does not prove
that forwarding is installed. Reports cover network programming, not the
health of the producer application. Startup withdraws previous local readiness
before rebuilding the node's state.
