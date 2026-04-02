---
status: provisional
stage: alpha
latest-milestone: "v0.1"
---

<!-- omit from toc -->
# Fleet Networking

- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Proposal](#proposal)
  - [Network Resource Management (IPAM)](#network-resource-management-ipam)
  - [BGP Control Plane](#bgp-control-plane)
  - [Topology Policy](#topology-policy)
  - [How It Comes Together](#how-it-comes-together)
  - [Cluster Self-Sufficiency](#cluster-self-sufficiency)
- [Dependencies](#dependencies)

## Summary

Fleet Networking automates how Datum Cloud configures routing across its fleet
of Kubernetes clusters. It builds on the
[Asset Inventory](../asset-inventory/) (which records what infrastructure
exists and where) and [Fleet Operations](../fleet-operations/) (which
provisions infrastructure and delivers configuration) to add two capabilities:

- **Network Resource Management (IPAM)** allocates network identities —
  [AS numbers][asn-overview] and IPv6 prefixes — from managed pools,
  eliminating manual address planning and preventing conflicts.
- **[BGP Control Plane][datum-bgp]** translates topology and addressing into
  routing configuration on each cluster, distributing
  [SRv6][srv6] reachability so VPC traffic can flow between any two nodes in
  the fleet.

Operators express *what connectivity they want* through topology policies. The
platform allocates addresses, configures routing, and maintains peering
sessions automatically.

See the [Infrastructure Platform overview](../README.md) for how Fleet
Networking layers with Asset Inventory and Fleet Operations.

## Motivation

Datum Cloud's [VPC networking](../../networking/vpc/) uses
[SRv6][srv6] (Segment Routing over IPv6) to provide isolated, multi-tenant
networks across clusters. For SRv6 to work, every node needs a unique SRv6
prefix, every cluster needs a [BGP autonomous system number][asn-overview],
and clusters need routing sessions between them so they can exchange
reachability information.

Today this requires manual address planning, per-cluster BGP configuration,
and careful coordination when clusters are added or removed. A misassigned
prefix or missing peering session can silently break cross-cluster VPC
connectivity.

### Goals

- Automate network identity allocation ([AS numbers][asn-overview],
  [SRv6][srv6] prefixes) through pool-based IPAM so operators never manually
  pick addresses.
- Express inter-cluster connectivity intent (mesh,
  [route-reflector][rr-overview], [eBGP][ebgp-overview]) as declarative policy
  rather than individual peering sessions.
- Deliver [BGP][bgp-overview] configuration to clusters automatically when
  they are registered in the [Asset Inventory](../asset-inventory/), using the
  [Fleet Operations fleet agent](../fleet-operations/) for delivery.
- Ensure each cluster is self-sufficient for its internal networking: node
  registration, intra-cluster peering, and per-node prefix allocation happen
  locally without management cluster involvement.

### Non-Goals

- Cluster inventory. See the
  [Asset Inventory enhancement](../asset-inventory/) for the topology and
  asset registry.
- Cluster provisioning or configuration delivery. See the
  [Fleet Operations enhancement](../fleet-operations/) for declarative
  deployments and pull-based delivery.
- VPC or tenant-level networking. See the
  [VPC networking enhancement](../../networking/vpc/) for multi-tenant SRv6
  isolation. VPC *consumes* the routing fabric that Fleet Networking provides.
- Data-plane configuration ([SRv6][srv6] encapsulation, VRF setup). The BGP
  control plane distributes routes; the existing galactic-agent handles
  kernel-level programming.

## Proposal

Fleet Networking adds two services to the management cluster, plus a topology
policy resource that bridges them with the
[Asset Inventory](../asset-inventory/).

### Network Resource Management (IPAM)

The IPAM system manages allocation of network resources through a
claim/allocation lifecycle — similar in concept to how Kubernetes manages
persistent storage through PersistentVolumeClaims and PersistentVolumes.

Three resource types are managed:

| Type | What it allocates | Example |
|------|-------------------|---------|
| [AS number][asn-overview] | [BGP][bgp-overview] autonomous system identifier | `65001` from a [private ASN range][private-asn] |
| IPv6 prefix | [SRv6][srv6] address space | A `/40` carved from a regional pool |
| Address | Single IPv6 address | A node's BGP speaker address |

**How it works:**

- A network admin creates **pools** defining available resources (a
  [range of private AS numbers][private-asn], a block of IPv6 prefixes).
- When a cluster is deployed via
  [Fleet Operations](../fleet-operations/), the platform creates **claims**
  against those pools for the cluster's AS number and SRv6 prefix.
- The IPAM controller **fulfills** claims automatically, selecting
  conflict-free values from the pool.
- For prefix allocations, the IPAM controller creates a **child pool** (e.g.,
  a `/40` allocation spawns a pool of `/48` sub-prefixes) that is delivered to
  the cluster for per-node self-service allocation.

This eliminates manual address planning. Operators define pools once; the
platform handles individual allocations. Pool resources surface total,
allocated, and available counts for capacity planning.

### BGP Control Plane

The [BGP control plane][datum-bgp] is a topology-agnostic routing service
that runs on every cluster in the fleet. It has no knowledge of regions, sites,
or fleet topology — it operates purely on abstract [BGP][bgp-overview]
primitives: configurations, endpoints, peering policies, sessions, and route
advertisements.

Each node runs a BGP controller alongside a [GoBGP][gobgp] speaker. The
controller reconciles BGP resources into GoBGP configuration and programs
learned routes into the kernel. This is the layer that makes [SRv6][srv6]
prefixes reachable across the fleet.

The BGP control plane is a **consumer** of configuration, not a producer. It
does not decide which clusters should peer or what routes to advertise — that
is determined by the topology policy and the IPAM allocations. Configuration
is created on the management cluster by the topology controller and delivered
to each cluster by the [fleet agent](../fleet-operations/).

See the [datum-cloud/bgp][datum-bgp] project for the full design and
implementation of the topology-agnostic BGP control plane.

### Topology Policy

Topology policies are the bridge between the
[Asset Inventory's](../asset-inventory/) topology model and the
[BGP][bgp-overview] control plane. Operators declare *how clusters should
interconnect*, and the topology controller translates that intent into BGP
configuration targeting the appropriate clusters.

Three modes:

| Mode | Use case | What happens |
|------|----------|-------------|
| **Mesh** | All selected clusters peer with each other | Full-mesh [iBGP][ibgp-overview] sessions between cluster gateways |
| **[Route-reflector][rr-overview]** | Hub-spoke within a region | Gateway clusters reflect routes for compute clusters, reducing session count |
| **[eBGP][ebgp-overview]** | Cross-region peering | Clusters in different AS numbers establish eBGP sessions |

Topology policies select clusters using labels from the
[Asset Inventory](../asset-inventory/). When a new cluster is registered with
matching labels, the topology controller automatically includes it in the
peering topology — no manual session creation required.

### How It Comes Together

When a new cluster joins the fleet:

1. **[Fleet Operations](../fleet-operations/)** provisions the cluster and
   creates IPAM claims for its [AS number][asn-overview] and [SRv6][srv6]
   prefix.
2. **IPAM** fulfills the claims and creates a child pool of per-node prefixes.
3. The **topology controller** reads the cluster's
   [inventory record](../asset-inventory/), its allocations, and the relevant
   topology policies. It creates [BGP][bgp-overview] configuration (AS number,
   peering policy, inter-cluster sessions) targeting the cluster.
4. The **[fleet agent](../fleet-operations/)** delivers the configuration to
   the cluster.
5. Within the cluster, nodes **self-register**: the nodepeer operator detects
   new Kubernetes nodes, claims per-node [SRv6][srv6] prefixes from the local
   pool, creates BGP endpoints, and establishes intra-cluster peering.
6. **[GoBGP][gobgp]** advertises the node's SRv6 prefix. Other nodes and
   clusters learn the route. SRv6 traffic can now reach the new node.

The operator's involvement was limited to creating the `ClusterDeployment` in
[Fleet Operations](../fleet-operations/). Everything else — from address
allocation to route advertisement — was automatic.

### Cluster Self-Sufficiency

Once the [fleet agent](../fleet-operations/) delivers initial
[BGP][bgp-overview] configuration and the node prefix pool, the cluster
manages its own internal networking independently:

- Nodes self-register and claim prefixes from the local pool
- Intra-cluster BGP peering operates without management cluster involvement
- Route advertisements and kernel route programming happen locally

The management cluster is only needed for fleet-level changes: new IPAM pools,
topology policy updates, or onboarding new clusters.

## Dependencies

- **[Asset Inventory](../asset-inventory/)**: Provides the cluster topology —
  regions, sites, clusters, network devices, and their connectivity
  relationships.

- **[Fleet Operations](../fleet-operations/)**: Provides configuration
  delivery via the fleet agent, creates IPAM claims during cluster
  provisioning, and registers clusters in the inventory.

- **[VPC Networking](../../networking/vpc/)**: The VPC system that uses
  [SRv6][srv6] for multi-tenant isolation. Fleet Networking provides the
  routing fabric that VPC relies on.

- **[BGP Control Plane][datum-bgp]**: The topology-agnostic
  [BGP][bgp-overview] control plane that runs on every cluster, using
  [GoBGP][gobgp] as the BGP speaker on each node.

<!-- References -->
[bgp-overview]: https://datatracker.ietf.org/doc/html/rfc4271
[asn-overview]: https://www.iana.org/assignments/as-numbers/as-numbers.xhtml
[private-asn]: https://datatracker.ietf.org/doc/html/rfc6996
[srv6]: https://datatracker.ietf.org/doc/html/rfc8986
[ibgp-overview]: https://datatracker.ietf.org/doc/html/rfc4456
[ebgp-overview]: https://datatracker.ietf.org/doc/html/rfc4271#section-5
[rr-overview]: https://datatracker.ietf.org/doc/html/rfc4456
[gobgp]: https://osrg.github.io/gobgp/
[datum-bgp]: https://github.com/datum-cloud/bgp
