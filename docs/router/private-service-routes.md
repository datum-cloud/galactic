# Private service routes

`ServiceEndpoint` uses a direct-endpoint contract. Its declared
`spec.address`, `spec.protocol`, and `spec.port` are the exact destination tuple
that the selected producer attachment must accept. Galactic does not interpret
the address as a Kubernetes Service frontend: it does not discover
EndpointSlices, select a backend address, or translate the destination before
delivery.

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
classifier matches the exact service tuple and redirects it to the selected
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

If a service needs a distinct frontend and backend address or port, its API
must identify that backend explicitly and define its selection and health
semantics. `ServiceEndpoint` intentionally carries no such fields.
