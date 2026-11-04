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
Galactic delivers the packet to the selected producer attachment through
the attachment's own address of the VIP's family, from the producer's subnet,
on the producer's node and from a consumer on another node alike. The
producer VPC then needs no route for the VIP and the producer need not answer
neighbor discovery for it, but it must still accept a packet addressed to the
VIP, for example by binding it or through a transparent socket. An attachment
with no subnet of the VIP's family is delivered the VIP itself as the next
hop, so it must answer neighbor discovery for the VIP. While the CNI or router
is older than the remote target map (see
[Remote target map roll order](#remote-target-map-roll-order)), a request from
another node reaches the producer only if its VPC routes the VIP to it.

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
  check fails. A new connection goes to the eligible producer that rendezvous
  hashing of its flow ranks first, so a producer joining or leaving moves only
  the connections it gains or loses.
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

| State                 | New flows from its own node's consumers                                                        | Existing TCP connections and replies |
| --------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------ |
| `Healthy`             | yes                                                                                            | yes                                  |
| `Unknown` or no entry | only while no producer on its node is `Healthy` and its consumers have not moved               | yes, unless its consumers move       |
| `Unhealthy`           | only while every producer on its node is `Unhealthy` and its consumers have no remote producer | yes, unless its consumers move       |

A producer with no result yet, such as one just added, takes new flows only
once its health check passes, as long as another producer on its node is
`Healthy`. When none is, as right after a node's router restarts before any
probe completes, producers with no result keep taking new flows. A producer
whose probe cannot be sent at all (`ProbeUnavailable`) is `Unknown` too. An
expired entry never drains a producer on its own node, so a producer reported
`Unhealthy` just before its node's router stopped takes new flows again once
the entry expires.

A producer whose host-side interface is gone, as while a replacement pod
recreates it, leaves its node's set until the interface returns, and the other
producers keep serving throughout. If the producers left are all draining,
they take new flows until it returns, even those reported `Unhealthy`. Only a
set with no ready interface left stops serving.

A replacement pod that keeps its attachment does not inherit its predecessor's
health result. The node reports the producer `Unknown` while its interface is
missing and probes the recreated interface afresh, with no result. Until its
node reports a result reached after the interface was recreated, the
replacement takes no new flows while another producer in the set does.

With `PreferNodeLocal`, a consumer moves to a remote producer when the
producers on its node include an `Unhealthy` one and none that is `Healthy` or
whose entry expired, so every one of them failed or has no result yet, as
when a replacement starts while the producer it replaces fails. It moves only
while another node currently reports a producer `Healthy` or `Unknown`, or has
no entry for one. The remote producer is picked among the producers on other
nodes exactly as for a node with no producer (below), so a producer on the
consumer's own node, such as a replacement with no result yet, is never
picked. It returns once a producer on its node is `Healthy`.
Every node decides this from the same reports, so the consumer's node and the
remote producer's node agree on the path, apart from the moment a report
reaches one before the other (below). Moving between the local set and the
remote producer replaces the consumer's route: UDP requests follow at once,
and a TCP connection opened before the move does not survive it.

While routers are being upgraded to a version that moves such consumers, a
remote producer whose node still runs an older router does not accept them,
so their requests are refused until that node is upgraded too, or a producer
on their own node recovers.

When no other node has such a producer, or the endpoint is `NodeLocal`, a
node whose producers are all `Unhealthy` keeps sending new flows to all of
them, because an empty set would drop every request. A producer that crashes
stops getting new flows within `intervalSeconds × unhealthyThreshold` plus
`timeoutSeconds`, plus the time its node takes to publish the decision and the
consumer's node to program it. One whose attachment stops being ready leaves
the set as soon as its node sees the change. Either way only its own
connections move.

For a rollout or shutdown that loses no requests, make the producer fail its
health check first and keep serving for at least that detection time plus its
longest request, then stop it. Its in-flight requests and open connections
finish while new ones go to the other producers.

When the consumer's node has no producer, or none it can use as described
above, `PreferNodeLocal` sends the consumer to one remote producer, through the SRv6 service tunnel as with `Single`. It
is picked among the producers whose node currently reports them `Healthy` or
`Unknown`, or has no entry for them. If there are none, it is picked among the
producers whose entry expired, and failing that among all producers. The
consumer's node picks by its `galactic-router` setting
[`--service-spread-pairing`](../router/configuration.md#--service-spread-pairing--galactic_router_service_spread_pairing).
With `first`, the default, it picks the first producer by namespace and name,
so every remote consumer goes to the same producer. With `rendezvous`,
rendezvous hashing of the consumer's and each producer's attachment UID picks
it, so consumers spread across the remote producers, and a producer joining,
leaving or turning `Unhealthy` moves only the consumers it gains or loses. A
producer's node installs the producer half for the producer each pairing
picks, whatever its own setting, so the consumer's traffic is accepted while
its node and the producer's node use different settings. Set `rendezvous` only
after every node runs a router that has the option, since an older router
accepts only the `first` pairing. With `first`, every consumer that moves off
its node goes to the same producer, so a failure that turns many nodes'
producers `Unhealthy` at once concentrates their consumers there; prefer
`rendezvous` for endpoints with many nodes. When a node
goes down while its producers' attachments still read ready, its consumers move
to other producers within 60 seconds of the node's last renewal, as long as
another node currently reports a producer that can take them. Each consumer's
requests all go to its one remote producer. While a health change reaches the
consumer's node and the producer's node at different moments, the two can
briefly disagree on that producer, and its requests are refused until they
agree.

A TCP connection's pin ends after 300 seconds without traffic, the same idle
limit replies have, or when the node evicts it under load or reloads the
datapath. A packet of an established connection with no pin stays with the
producer whose reply row, which the node keeps for four times as many flows,
shows it already carries the connection. Only a connection with neither is
placed by its hash again: it stays with its producer unless a producer that
joined since ranks first for it. Changing an endpoint between `Single` and
`Spread` replaces its routes, which can drop a request in flight and moves
existing TCP connections.

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
active during control plane outages, including a router restart (see
[Router restarts](#router-restarts)), and ends when the policy is withdrawn or
the VPC lifetime changes.

Persistent access removes the node-side deadline that otherwise bounds an
authorization, so nothing on the node revokes it while the control plane is
unreachable. The only limit on who can grant it is RBAC on
`ServiceRoutePolicy`. Galactic ships no role that lets tenants write these
policies. Grant create, update and patch on `serviceroutepolicies` only to
the network control plane that publishes the service. Any principal that can
write a policy can give a VPC persistent access to the selected endpoint.

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

A controller that waits for these reports computes the required nodes and the
input digest with `serviceplan.ProgrammingPlan` from the public
`go.datum.net/galactic/pkg/serviceplan` package, the same planner the routers
compile their routes with. It first passes the endpoint through
`serviceplan.WithProducerReports`, with the `ServiceEndpointProducerReport`
objects of the endpoint's namespace, so the plan reads the same producer
health the routers do; that needs permission to list those reports. For a
`Spread` endpoint the plan changes when a report changes or expires, so the
controller recomputes it on report changes and at the time
`serviceplan.NextProducerReportExpiry` returns.

## Attachment replacement continuity

When an attachment disappears, reappears or changes identity, the router repairs
only the affected service-route references. Unchanged attachments keep their
forwarding entries and shared references throughout the repair, so replacing one
instance does not interrupt another instance's private DNS requests.

A failed repair closes the policy gate and retries a complete generation.
Authorization expiry and inconsistent state also retain the complete rebuild
path. Attachment continuity therefore does not imply uninterrupted forwarding
during an incompatible map replacement. A router restart is covered in
[Router restarts](#router-restarts).

## CNI program reloads

A CNI restart preserves the service-policy gate and attachment incarnation
tokens when the live two-program chain uses exactly the same kernel map IDs
as the replacement programs. Both resolver frontends can continue forwarding
while those programs are replaced. Missing identities, incomplete chains and
changed map generations require new tokens; old authorization cannot transfer
to them. An incompatible map layout still drains authorization before replacing
maps, and the router must rebuild the policy before forwarding resumes.

This continuity applies to an unchanged set of referenced maps. A program that
starts referencing another map conservatively requires reauthorization even
if existing map layouts did not change. Router startup still performs its
cache-synchronized policy rebuild and stale-entry sweep.

## Router restarts

A restarted router reads the pinned policy gate before it touches anything.
If the previous process left it open, the node keeps forwarding that process's
last finalized generation until the new process's startup sync rebuilds and
sweeps the policy. This keeps persistent access working when the router
restarts while the API is unreachable. Kernel checks still enforce
time-bounded deadlines, and attachment identity tokens keep a recycled
interface from inheriting another attachment's access. A policy withdrawn
while the router was down stops forwarding at the next successful startup
sync.

The inherited gate closes, as it did before this behavior, when the startup
sync fails a dataplane mutation or cannot finalize. Only a finalizing router
opens the gate, and the CNI datapath only ever closes it, which it does when
it drains authorization to replace an incompatible map set. A compatible
reload keeps the pinned gate, so the router keeps the inherited generation
across it. A gate the previous process left closed, for example after a crash
during a rebuild, stays closed until the startup sync finalizes.

### Next-hop map roll order

Per-attachment next hops live in the `service_peer_table` map, which the CNI
datapath pins when its program loads. A router that rolls before the CNI finds
no such map. It programs every other map and records no next hops, and the
older program forwards to the destination address as it did before. When the
new program loads, the map set changes, and the router reopens the maps and
replays its desired state, including next hops. Roll the CNI first to get
next hops as soon as the router upgrades. Either order keeps routes
programmed.

### Remote target map roll order

A producer's node finds the producer a remote request is for in the
`service_remote_target_table` map, which the router writes with each remote
grant. Without a row, as while the router is older than the map or the CNI
datapath is older than the router, the node delivers the request by looking
up its destination in the producer VPC's routes, and the request reaches the
producer only if that VPC routes the service address to it. Roll the CNI
first, then the router, to deliver remote requests to producers whose VPC
does not route the service address. As with next hops, either order keeps
routes programmed.
