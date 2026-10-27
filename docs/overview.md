# Galactic overview

Galactic supplies the SRv6 data plane and routing control plane for VPC
networking. Kubernetes resources describe intent, node processes reconcile
that intent, and Linux VRFs and eBPF programs forward packets. Tenant traffic
can cross nodes and sites without exposing one VPC's routes to another.

This page describes the repository's implemented components. Feature presence
does not establish that a deployment has enabled or qualified it. Each feature's
deployment guide records its prerequisites and rollout gates.

## Components and ownership

| Component                  | Responsibility                                                                                                                                                                                                    | Start here                                          |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| CNI chain                  | `galactic-cni` installs the plugins and maintains node credentials and shared datapath state. `galactic-veth` or `galactic-tap`, delegated IPAM, optional `galactic-route`, and `galactic-bgp` attach a workload. | [CNI](cni/README.md)                                |
| Tenant routing             | `galactic-router` reconciles BGP resources through embedded GoBGP, installs learned routes, programs node policy and service bindings, and collects orphaned state. The reflector role distributes EVPN routes.   | [Router architecture](router/architecture.md)       |
| Ingress gateway            | `galactic-gateway` selects an ingress backend using XDP and advertises VIPs through BGP resources. The backend's reply uses direct server return.                                                                 | [Gateway deployment](gateway/deployment.md)         |
| Egress translation         | `galactic-nat` implements stateful NAT66/NAT64 for an `EgressShard`. Compute nodes reach eligible shards over SRv6.                                                                                               | [NAT deployment](nat/deployment.md)                 |
| VPC ingress sidecar        | `galactic-vrf` reconciles workload ingress and host return paths for its VPC. Its placement is defined by the workload deployment, not a generic DaemonSet in this repository.                                    | [VPC ingress metrics](observability/vpc-ingress.md) |
| Cell controller            | `galactic-controller --role=cell` serves admission, resolves traffic policy and projects BGP programming status. `--edge` adds Edge attachment and route reconciliation.                                          | [Controller](controller/README.md)                  |
| Central identity allocator | `galactic-controller --role=fabric` allocates shared fabric identities using hub and IPAM credentials in a separate deployment.                                                                                   | [Controller](controller/README.md)                  |
| Underlay routing           | `fabric-router` runs FRR. `fabric-config-agent` validates and activates per-node configuration. `fabric-router-controller` compiles typed routing intent and optionally manages releases and topology.            | [Fabric routing](fabric-routing/README.md)          |
| Fabric diagnostics         | `fabric-api` runs node sidecars, a cell gateway, certificate synchronization and query cleanup.                                                                                                                   | [Fabric API](fabric-api/README.md)                  |
| Provider attachments       | `galactic-edge` programs authorized provider attachments and forwarding gates on edge nodes.                                                                                                                      | [Galactic Edge](edge/README.md)                     |

The served cloud, network and policy resources use
`galactic.datumapis.com/v1alpha1`; their Go packages are separate. Consult the
[API index](api/README.md) to find the owning package and reference.

## Boundaries outside this repository

The Network Services Operator (NSO) cell manager owns VPC, attachment and subnet
reconciliation and writes NetworkAttachmentDefinitions when Galactic integration
is enabled. Galactic's cell controller retains BGP status projection and
admission/policy work. A CNI invocation consumes the resulting attachment
identifiers; it does not allocate the platform's network identity.

The distinction matters during upgrades: run one writer for each attachment and
NAD. The [API consolidation migration](operations/migrations/galactic-api-consolidation.md)
describes the handoff and legacy-resource audit. Code packaged in this repository
is not by itself evidence that this binary runs a particular controller; the
registration in each command is the execution boundary.

Infra owns deployment-specific overlays, node addresses, underlay reachability,
certificates and release rollout. This repository supplies reusable manifests,
controllers and a local lab. Provider implementations own their protocols and
client sessions; the [Edge contract](edge/provider-contract.md) defines their
authority at the VPC boundary.

## Packet paths

1. **Workload attachment.** Multus invokes the CNI chain with VPC and attachment
   identifiers. The chain creates the host link and VRF state, registers the
   datapath and writes BGP resources. The router publishes the EVPN path.
2. **VPC traffic.** A node resolves a tenant destination within that VPC's
   routing context. Remote delivery crosses the underlay in SRv6; the receiving
   node decapsulates into the destination VPC. Interface traffic policy applies
   according to the configured mode and bindings.
3. **Public ingress.** A gateway accepts a configured VIP and selects a backend.
   It encapsulates toward the backend node. Backend translation and return-path
   handling implement the VIP contract; the reply does not require gateway
   connection tracking.
4. **Public egress.** The tenant node forwards to an eligible egress shard. The
   shard translates the flow and retains session state for the reverse path.
   Shards do not replicate sessions; losing the selected shard can break flows.
5. **Private services and providers.** [Private-service routing](private-services/README.md)
   authorizes particular service tuples. [Edge providers](edge/provider-contract.md)
   use explicit attachments and forwarding ownership. These are separate from
   public gateway VIPs.

See the [system diagrams](architecture/README.md) for the component relationships,
and component architecture pages for algorithms and failure behavior.

## Deployment shape

`config/kustomization.yaml` includes the namespace, CNI and tenant-router
resources. It is not a complete production installation: CRDs, underlay,
controllers, optional gateways, translation, diagnostics and monitoring have
their own prerequisites and composition.

Use the [operations index](operations/README.md) for placement and shared host
settings. Node labels are opt-ins, and an edge node does not automatically run
every edge feature. Begin with the [local lab](getting-started.md) to exercise
the complete topology without assembling production overlays.
