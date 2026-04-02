---
status: provisional
stage: alpha
latest-milestone: "v0.1"
---

<!-- omit from toc -->
# Fleet Operations

- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Proposal](#proposal)
  - [Why Separate Inventory from Operations](#why-separate-inventory-from-operations)
  - [Declarative Deployments](#declarative-deployments)
  - [Pull-Based Configuration Delivery](#pull-based-configuration-delivery)
  - [Provider Abstraction](#provider-abstraction)
  - [Self-Sufficient Clusters](#self-sufficient-clusters)
- [Scope](#scope)
  - [v1: Cluster Lifecycle](#v1-cluster-lifecycle)
  - [Future: Other Infrastructure Elements](#future-other-infrastructure-elements)
- [Dependencies](#dependencies)

## Summary

Fleet Operations is the operational layer of the infrastructure platform. It
provisions, manages, and delivers configuration to the infrastructure that is
recorded in the [Asset Inventory](../asset-inventory/).

Where the Asset Inventory answers **"what do we have and where is it?"**, Fleet
Operations answers **"how do we bring it to life and keep it configured?"**

The initial release focuses on Kubernetes cluster lifecycle — the most critical
and complex asset type. Operators declare a single `ClusterDeployment` resource
and the platform handles everything: provisioning the cluster through a
provider, registering it in the inventory, allocating its network identity, and
delivering configuration through a fleet agent. Future releases will extend the
same pattern to network devices and other infrastructure elements.

See the [Infrastructure Platform overview](../README.md) for how Fleet
Operations layers with Asset Inventory and Fleet Networking.

## Motivation

Every infrastructure asset in the fleet goes through the same lifecycle:
provision it, register it in the inventory, allocate its network identity,
and deliver configuration to it. Today each step is manual and each asset type
has its own workflow.

For clusters, this means seven separate steps across multiple systems — create
the cluster in a provider, wait for it to come online, register it in the
inventory with the right labels, create IPAM claims, wait for fulfillment,
install an agent, and verify connectivity. A missed step or a wrong label
means the asset joins the fleet in a broken state.

This problem will repeat for every asset type as the fleet grows. Routers need
provisioning and configuration. Without a unified operational interface,
operational complexity scales linearly with fleet size and asset diversity.

### Goals

- Provide declarative, single-resource lifecycle management for infrastructure
  assets, starting with Kubernetes clusters.
- Abstract provider-specific provisioning behind a common interface so
  operators don't interact with providers
  ([Sidero Omni][sidero-omni], [Cluster API][cluster-api]) directly.
- Automatically register provisioned assets in the
  [Asset Inventory](../asset-inventory/) — operators declare what they want,
  not the inventory records to create.
- Deliver configuration to clusters through a pull-based mechanism that works
  through firewalls and NAT without centrally stored credentials.
- Ensure clusters are self-sufficient: ongoing operations must not depend on
  the management cluster being available.
- Establish a deployment pattern that can be extended to network devices
  and other asset types in future releases.

### Non-Goals

- Asset data modeling. See the
  [Asset Inventory enhancement](../asset-inventory/) for the topology and
  asset registry. Fleet Operations writes to the inventory as a side effect of
  provisioning — it does not own the data model.
- BGP routing or peering policy. See the
  [Fleet Networking enhancement](../fleet-networking/) for network resource
  allocation and routing automation.
- Network device provisioning in v1. Cluster lifecycle is the initial focus.

## Proposal

### Why Separate Inventory from Operations

The [Asset Inventory](../asset-inventory/) and Fleet Operations serve
different audiences, have different change rates, and should evolve
independently.

**The inventory is a shared data model.** Multiple systems read from it:
[Fleet Networking](../fleet-networking/) reads topology to configure routing.
Compliance tools audit asset distribution. Capacity planning queries counts by
region. These consumers need a stable, predictable data model that doesn't
change when operational workflows change.

**Operations is a provisioning workflow.** It is tightly coupled to specific
providers ([Sidero Omni][sidero-omni] today,
[Cluster API][cluster-api] tomorrow, others in the future) and to operational
patterns that evolve as the platform matures. Adding a new provider, changing
the deployment workflow, or introducing canary rollouts should not affect the
inventory schema that other systems depend on.

**Keeping them apart enables:**

- Different teams to own each — a platform team owns the inventory schema
  while an operations team owns provisioning workflows.
- Inventory records to exist without Fleet Operations — for assets registered
  manually, imported from external CMDBs, or managed by systems not yet
  integrated with Fleet Operations.
- Fleet Operations to evolve rapidly — new providers, new deployment patterns,
  new lifecycle features — without breaking inventory consumers.

### Declarative Deployments

Operators interact with Fleet Operations through **deployment resources** — a
single declaration that describes the desired end state of an infrastructure
asset. The platform orchestrates all the steps to make it real:

1. **Provision** the asset through the appropriate provider
2. **Register** it in the [Asset Inventory](../asset-inventory/) with correct
   topology metadata
3. **Allocate** network identity (AS numbers, [SRv6][srv6] prefixes) from
   [IPAM pools](../fleet-networking/)
4. **Bootstrap** the fleet agent for configuration delivery
5. **Report** progress through each phase

Day-two operations — scaling, role changes, decommissioning — go through the
same resource. Deleting the deployment resource triggers a clean teardown:
provider resources destroyed, inventory record removed, network allocations
released.

### Pull-Based Configuration Delivery

Fleet-level services ([Fleet Networking](../fleet-networking/), future policy
or observability services) need to deliver configuration to clusters. Fleet
Operations provides this through a **fleet agent** — a lightweight component
on every member cluster that connects outbound to the management cluster and
pulls configuration targeting that cluster.

**Why pull instead of push:**

- **Works through firewalls and NAT.** Clusters only need outbound
  connectivity. No inbound ports, no VPN tunnels, no firewall exceptions.
- **No centrally stored credentials.** The agent authenticates to the
  management cluster, not the other way around. No kubeconfigs for every
  cluster stored in one place.
- **Resilient to management cluster downtime.** If the management cluster is
  unreachable, the agent simply stops receiving updates — all previously
  delivered configuration remains in effect. Nothing breaks.
- **Ecosystem alignment.** This is how [ArgoCD][argocd], [Flux][flux],
  [Anthos Config Management][anthos-acm], and similar tools operate. It is a
  proven pattern at scale.

### Provider Abstraction

Fleet Operations supports multiple cluster providers through a **provider
adapter** pattern. Each adapter translates deployment resource specs into
the provider's native API:

- **[Sidero Omni][sidero-omni]** — bare-metal Kubernetes clusters via
  [Talos Linux][talos], accessed through Omni's COSI gRPC API.
- **[Cluster API][cluster-api]** — cloud-based Kubernetes clusters, accessed
  through standard Kubernetes resources.
- **Manual** — for environments without a supported provider, operators create
  inventory records and install the fleet agent directly.

The adapter abstraction means operators interact with a consistent deployment
resource regardless of the underlying provider. Fleet-level services never
know or care which provider manages a cluster.

### Self-Sufficient Clusters

A core design principle: **clusters must not depend on the management cluster
for their internal operations.**

The management cluster and fleet agent are a configuration delivery mechanism,
not a runtime dependency. After initial configuration is delivered, each
cluster operates independently:

- Nodes can join and leave through the cluster provider
- Internal controllers continue reconciling
- All previously delivered configuration remains applied
- Intra-cluster networking, scheduling, and storage are unaffected

The management cluster is only needed for delivering new or updated
configuration, registering new assets, and observing fleet-wide state.

## Scope

### v1: Cluster Lifecycle

The initial release delivers `ClusterDeployment` — declarative lifecycle
management for Kubernetes clusters. This covers:

- Provisioning clusters through [Sidero Omni][sidero-omni] and
  [Cluster API][cluster-api]
- Automatic [Asset Inventory](../asset-inventory/) registration
- Network identity allocation from [IPAM pools](../fleet-networking/)
- Fleet agent bootstrap and pull-based configuration delivery
- Day-two operations: scaling, role changes, decommissioning

Kubernetes clusters are the most complex and highest-value asset type. They are
the foundation that other infrastructure elements (routers, switches) run on
or are managed through.

### Future: Other Infrastructure Elements

The deployment resource pattern established by `ClusterDeployment` extends
naturally to other asset types:

- **NetworkDeviceDeployment** — lifecycle management for routers, switches,
  and firewalls. Declare the device, its site, and its managing cluster.
  [Fleet Networking](../fleet-networking/) configures
  [BGP][bgp-overview] peering through the managing cluster.

- **SiteDeployment** — an optional higher-level resource that bundles multiple
  element deployments into a single site-level declaration for standing up
  entire sites at once.

Other planned capabilities:

- **Deployment templates** for common patterns (gateway site, compute site,
  edge site) to reduce boilerplate
- **Canary rollouts** for fleet-wide updates with automatic rollback
- **Drift detection** when assets diverge from their declared state
- **GitOps integration** using [ArgoCD][argocd] or [Flux][flux] as the fleet
  agent backend

## Dependencies

- **[Asset Inventory](../asset-inventory/)**: Fleet Operations writes asset
  records as a side effect of provisioning. Configuration targeting uses
  inventory labels to determine which clusters receive which resources.

- **[Fleet Networking](../fleet-networking/)**: Provides the IPAM system that
  fulfills network allocation claims, and the topology controller that creates
  BGP configuration targeting clusters.

- **[Sidero Omni][sidero-omni]**: Primary cluster provider for bare-metal
  deployments.

- **[Cluster API][cluster-api]**: Cluster provider for cloud-based
  deployments.

<!-- References -->
[sidero-omni]: https://www.siderolabs.com/platform/saas-for-kubernetes/
[cluster-api]: https://cluster-api.sigs.k8s.io/
[talos]: https://www.talos.dev/
[argocd]: https://argo-cd.readthedocs.io/
[flux]: https://fluxcd.io/
[anthos-acm]: https://cloud.google.com/anthos/config-management
[srv6]: https://datatracker.ietf.org/doc/html/rfc8986
[bgp-overview]: https://datatracker.ietf.org/doc/html/rfc4271
