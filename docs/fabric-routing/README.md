# Fabric routing

The fabric routing controller compiles typed BGP resources into immutable FRR revisions. The node's config agent validates and activates released revisions. These components manage the underlay; galactic-router distributes tenant EVPN routes separately.

- [Operating through the API](operations.md): installation, source transitions, releases, recovery, topology rollout and ConfigMap retirement.
- [Topology design](topology.md): endpoint records, generated sessions, ownership, cross-cell consistency, drain and remaining gaps.
- [Routing metrics](../observability/routing.md): fleet, node activation, FRR and tenant router series.
- [Node placement](../operations/node-labels.md): independent fabric and Galactic routing modes.

Begin with the operating guide's prerequisites and install sequence. Enabling node activation or changing a sidecar recreates fabric-router pods and must be treated as a routing rollout. Endpoint records still need an authoritative author; topology generation does not allocate their addresses.
