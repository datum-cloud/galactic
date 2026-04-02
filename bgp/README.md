# BGP Control Plane

A Kubernetes-native BGP control plane that manages BGP topology declaratively via Custom Resource Definitions. The controller runs as a DaemonSet alongside a GoBGP sidecar, reconciling CRDs into BGP sessions, prefix advertisements, and kernel routes.

**API group:** `bgp.miloapis.com` **Version:** `v1alpha1`

---

## Key Features

- **Topology-agnostic** — the BGP controller has no knowledge of nodes, clusters, or datacenter topology. All topology lives in the CRDs.
- **CNI-independent** — works with any CNI or no CNI. Does not depend on Cilium, Calico, or any other network plugin.
- **Declarative session management** — `BGPPeeringPolicy` automates session creation via label selectors. Full mesh and route-reflector topologies are supported.
- **Producer/consumer model** — any system (node operators, cluster discovery, humans) can create BGP CRDs. The controller reconciles them uniformly.
- **GoBGP sidecar** — each node runs a GoBGP daemon. The controller configures it over gRPC and programs kernel routes from BGP RIB events via netlink.

---

## Quick Start

Install CRDs and deploy the operator:

```bash
kubectl apply -k config/deploy
```

Create a BGPConfiguration (one per cluster):

```yaml
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPConfiguration
metadata:
  name: default
spec:
  asNumber: 65001
  listenPort: 1790
  routerIDSource: NodeIP
```

Create BGPEndpoints for your nodes and a peering policy:

```yaml
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPEndpoint
metadata:
  name: node-worker-01
  labels:
    bgp.miloapis.com/role: node
spec:
  address: "2001:db8:1::1"
  asNumber: 65001
---
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPPeeringPolicy
metadata:
  name: mesh
spec:
  selector:
    matchLabels:
      bgp.miloapis.com/role: node
  mode: mesh
```

Check session state:

```bash
kubectl get bgpsess
```

---

## CRDs

| Resource | Short Name | Scope | Description |
|----------|-----------|-------|-------------|
| `BGPConfiguration` | `bgpconfig` | Cluster | Speaker identity: AS number, listen port, router ID. One per cluster. |
| `BGPEndpoint` | `bgpep` | Cluster | BGP speaker address and AS. Created per node or manually. |
| `BGPSession` | `bgpsess` | Cluster | Peering relationship between two endpoints. |
| `BGPPeeringPolicy` | `bgppp` | Cluster | Automates session creation via label selectors. |
| `BGPAdvertisement` | `bgpadvert` | Cluster | Prefix advertisement with optional communities and local-pref. |
| `BGPRoutePolicy` | `bgprp` | Cluster | Import/export filtering with prefix matching. |

---

## Documentation

- [Overview](docs/overview.md) — design philosophy, architecture, and comparison with alternatives
- [Getting Started](docs/getting-started.md) — step-by-step deployment guide
- [API Reference](docs/api-reference.md) — complete field documentation for all six CRDs
- [Architecture](docs/architecture.md) — controller internals, GoBGP integration, route synchronization

### Examples

- [Single-cluster full mesh](docs/examples/single-cluster-mesh.yaml)
- [Route reflector topology](docs/examples/route-reflector.yaml)
- [eBGP peering](docs/examples/ebgp-peering.yaml)
- [Prefix advertisement with communities](docs/examples/prefix-advertisement.yaml)
- [Route filtering](docs/examples/route-filtering.yaml)

---

## Building

```bash
# Build the controller binary
CGO_ENABLED=0 go build -o bgp ./cmd/bgp

# Build the container image
docker build -f build/Dockerfile -t ghcr.io/datum-cloud/bgp:latest .
```

---

## License

Apache License 2.0. See [LICENSE](../LICENSE) for details.
