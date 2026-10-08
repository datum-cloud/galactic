# Private service routes

`ServiceEndpoint` declares the producer destination. Its declared
`spec.address`, `spec.protocol`, and `spec.port` are the exact destination tuple
that the selected producer attachment must accept. Galactic does not interpret
the address as a Kubernetes Service frontend: it does not discover
EndpointSlices or select a Kubernetes backend. A translated policy uses
`spec.frontend.address` inside the consumer VPC and translates it to the
endpoint address before delivery.

The controller that publishes the `ServiceEndpoint` owns the service
implementation and health. It must ensure every attachment selected by
`attachmentRef` or `attachmentSelector` is ready to receive the declared tuple.
`VPCAttachment`'s `Ready` and `Programmed` conditions are necessary networking
prerequisites; they do not attest that a service listener is healthy. A
listener may bind or configure the address in the producer, use a transparent
socket, or use another service-owned mechanism. Galactic does not configure the
producer VIP; that mechanism and its lifecycle are owned by the service.
Whatever mechanism is used must make the exact VIP routable through the
selected producer attachment and neighbor-resolvable on that attachment. A
transparent socket bind by itself is insufficient when the producer VPC's FIB
or neighbor discovery cannot deliver the VIP to that interface.

Galactic selects one ready producer for each consumer. A node-local producer is
preferred and ties are resolved deterministically by attachment namespace and
name. More than one ready producer in the same node and VPC is rejected because
the direct-VIP dataplane cannot distinguish those replicas. Replicas on
different nodes or in distinct VPCs remain valid. `NodeLocal` stops there when
no local producer is ready; `PreferNodeLocal` may select a remote producer and
carries the original packet through the SRv6 service tunnel. In both cases the
producer receives the declared destination and the original consumer source
unchanged.

## No consumer-visible route

Galactic does not add the service address or a service-specific route to a
consumer, and does not inject a route into a consumer guest. Consumers send the
packet through their ordinary default gateway. The attachment's TC-eBPF
classifier matches the exact service or frontend tuple and redirects it to the selected
producer; unauthorized ports are dropped. Galactic also does not install a
host route for the service address. The producer service may still need to
configure or bind the address locally so its own network stack or listener
accepts the packet; that producer-side configuration is not consumer-visible.

Operators should therefore expect all of the following:

- `ip route` inside a consumer contains no route for the service address;
- the node has no service-address route created by the service-route
  controller;
- the producer receives the original service destination rather than a hidden
  backend address; and
- publishing an address that the producer does not accept produces an
  unavailable service, not automatic backend discovery or translation.

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

A translated policy must pin the consumer VPC by name and UID and include an
`authorization.validUntil` deadline within the next two minutes. Selected
attachments must match that VPC's allocated network identity. Kernel checks
stop new requests and established replies when the authorization expires, even
if the controller or its API is unavailable. Renew authorization explicitly to
restore access.

Policies claiming the same frontend address, protocol, and port on one consumer
attachment are rejected together. Separate VPC attachments can reuse that tuple.
The publisher owns authorization renewal and service health; Galactic enforces
network access and forwards packets. It does not interpret DNS records or zones.

## Node programming reports

`ServiceRoutePolicy.status.nodes` reports whether each participating node
programmed the current path. A report identifies the policy UID, generation,
and input digest. It expires within 60 seconds or when authorization expires,
whichever comes first. Consumer and producer nodes report independently for
remote delivery.

Controllers using these reports must require the current topology digest and
all required nodes. `Accepted=True` means the policy is valid; it does not prove
that forwarding is installed. Reports cover network programming, not the
health of the producer application. Startup withdraws previous local readiness
before rebuilding the node's state.
