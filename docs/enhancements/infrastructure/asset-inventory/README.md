---
status: provisional
stage: alpha
latest-milestone: "v0.1"
---

<!-- omit from toc -->
# Asset Inventory

- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Proposal](#proposal)
  - [Topology Model](#topology-model)
  - [Asset Types](#asset-types)
  - [Connectivity Graph](#connectivity-graph)
  - [Consumers](#consumers)
- [Dependencies](#dependencies)

## Summary

Asset Inventory provides Datum Cloud with a structured registry of all
infrastructure assets and their physical and logical placement, built on a
[Kubernetes control plane][kcp-style] as the API and storage layer. It answers
a simple question: **what do we have and where is it?**

The inventory models a geographic hierarchy (regions and sites) and the
infrastructure elements deployed at each location — individual machines,
Kubernetes clusters, and network devices. It also records connectivity
relationships between elements.

Asset Inventory is a **data model**, not an operational system. It does not
provision infrastructure, deliver configuration, or manage agents. It is a
shared foundation that multiple systems read from and write to:

- [Fleet Operations][fleet-operations] provisions infrastructure and
  automatically registers it in the inventory. See the
  [Fleet Operations enhancement](../fleet-operations/) for details on
  declarative deployments and pull-based configuration delivery.
- [Fleet Networking][fleet-networking] reads the inventory to determine how to
  configure routing and allocate network addresses. See the
  [Fleet Networking enhancement](../fleet-networking/) for details on IPAM and
  BGP automation.
- Compliance tools, capacity planning systems, and operators query the
  inventory directly for situational awareness.

See the [Infrastructure Platform overview](../README.md) for how these three
services layer together.

## Motivation

Datum Cloud's infrastructure spans multiple geographic regions with machines,
Kubernetes clusters, and network devices at each site. Today there is no
authoritative record of what exists where:

- **Machine information** lives in provider UIs
  ([Sidero Omni][sidero-omni] dashboard, cloud consoles) and is only visible
  within the context of the provider that manages it. There is no fleet-wide
  view of all machines, their hardware, or their assignment status.
- **Cluster information** lives in provider UIs, scattered kubeconfig files,
  and team knowledge.
- **Network device information** lives in router management interfaces,
  spreadsheets, and manually maintained configuration databases.
- **Topology relationships** — which machines belong to which clusters, which
  clusters are at which site, which routers connect to which clusters — live
  in operator heads and ad-hoc documentation.

This makes it impossible to answer basic questions without manual
investigation: "How many machines do we have in us-east?", "What clusters are
at this site?", "Which machines are unassigned?", "Is there a link between
these two sites?" Every system that needs topology awareness must build its own
inventory, leading to fragmented and inconsistent views of the infrastructure.

### Goals

- Provide a single source of truth for all infrastructure assets with
  structured topology metadata (region, site, role).
- Model distinct asset types — nodes, Kubernetes clusters, and network
  devices — each with focused fields relevant to that type.
- Record connectivity relationships between assets with capacity and latency
  metadata.
- Enable any system to discover assets by topology attributes using standard
  label selectors.
- Be a pure data model with no operational side effects — no agents, no
  configuration delivery, no provider integrations.

### Non-Goals

- Provisioning or managing infrastructure lifecycle. See
  [Fleet Operations](../fleet-operations/) for declarative deployment and
  provider integration.
- Delivering configuration to assets. See
  [Fleet Operations](../fleet-operations/) for the pull-based fleet agent.
- Networking, IPAM, or BGP configuration. See
  [Fleet Networking](../fleet-networking/) for network resource allocation and
  routing automation.
- Storing management credentials. Credential management belongs to the
  systems that use them.
- Enforcing topology correctness. The inventory records what is declared.
  Validation beyond schema correctness is the responsibility of consumers.

## Proposal

### Topology Model

The inventory has two layers:

**Geographic hierarchy** — where infrastructure is located:

- **Region**: A geographic area that groups sites (e.g., "US East", "EU West").
  Carries a human-readable name and optional coordinates for visualization.
- **Site**: A deployment location within a region — a datacenter, availability
  zone, or edge point-of-presence. Classified by type (datacenter,
  availability-zone, edge, virtual).

**Asset records** — what is deployed at each location. All asset types share
the same label conventions so they can be discovered together or independently
through the same selectors.

### Asset Types

Each asset type has a focused resource kind with fields relevant to that type:

**Node** — An individual machine. Records hardware characteristics (CPU,
memory, architecture), network addresses, and assignment status. A node may
belong to a cluster (as a control-plane or worker) or be unassigned —
available in the machine pool for future use. Nodes exist as assets
independent of clusters because machines have a lifecycle that spans cluster
membership: a machine exists before it joins a cluster, and continues existing
after it leaves one. This mirrors how [Sidero Omni][sidero-omni] treats
machines as first-class resources. The inventory gives fleet-wide visibility
into machine distribution, hardware capacity, and utilization across all
providers.

**Cluster** — A Kubernetes cluster. Records existence, placement, role
(compute, management, edge, gateway), and the provider that manages its
lifecycle. Clusters are composed of nodes, but the cluster record represents
the logical entity — the API endpoint, the control plane, the workload
boundary. Network devices and services at a site are managed through the
Kubernetes API of the cluster they belong to.

**NetworkDevice** — A distinct network element in the topology: a router,
switch, or firewall. References the cluster that manages it (the device runs
as a pod, dedicated node, or has its configuration represented as custom
resources on the parent cluster). Carries a device role (border-router, spine,
leaf, firewall). NetworkDevice exists as a separate asset type because routers
and switches are distinct elements in the network topology — they have their
own [BGP][bgp-overview] identity, their own peering sessions, and their own
role in the connectivity graph, even though they run on a cluster.

### Connectivity Graph

**Link** resources document physical or logical connectivity between any two
topology elements — cluster-to-router, router-to-router, site-to-site. Links
carry metadata: connection type (physical, logical, internet), capacity in
Mbps, and round-trip latency in milliseconds.

Links are informational. They provide context for operators and can inform
future routing or placement decisions, but they do not drive configuration
today.

### Consumers

The inventory is designed to be read by many systems, written by few:

| Consumer | How it uses the inventory |
|----------|--------------------------|
| [Fleet Operations](../fleet-operations/) | Writes asset records during provisioning. Reads topology labels for configuration targeting. |
| [Fleet Networking](../fleet-networking/) | Reads topology to determine inter-cluster peering and network address allocation. |
| Compliance / audit | Queries asset distribution by region, site, and role. |
| Capacity planning | Reads node counts, hardware specs, and assignment status for growth forecasting. |
| Platform operators | Queries the inventory for situational awareness. |
| Topology visualization (future) | Renders the fleet as an interactive map from inventory data. |

## Dependencies

- **[Kubernetes control plane][kcp-style]**: The inventory is implemented as
  custom resources on a Kubernetes-based control plane. Kubernetes is used here
  as a control plane framework — providing the API machinery, storage, watch
  semantics, and RBAC that the inventory resources are built on — not as a
  container runtime platform.

<!-- References -->
[fleet-operations]: ../fleet-operations/
[fleet-networking]: ../fleet-networking/
[sidero-omni]: https://www.siderolabs.com/platform/saas-for-kubernetes/
[bgp-overview]: https://datatracker.ietf.org/doc/html/rfc4271
[kcp-style]: https://www.kcp.io/
