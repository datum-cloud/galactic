# Getting Started

> Last verified: 2026-03-16 against go.miloapis.com/bgp v1alpha1

This guide walks you through deploying the BGP control plane on a Kubernetes cluster and establishing your first BGP session. By the end, you will have:

- The BGP operator DaemonSet running on your nodes
- `BGPEndpoint` resources representing your nodes
- A `BGPPeeringPolicy` creating a full-mesh iBGP topology
- A `BGPAdvertisement` injecting a prefix into the RIB

---

## Prerequisites

- A Kubernetes cluster with IPv6 enabled on nodes (each node must have a global-scope IPv6 address)
- `kubectl` configured to reach your cluster
- A GoBGP container image accessible to your cluster (the DaemonSet expects `gobgpd:latest` by default)
- The BGP controller image (`ghcr.io/datum-cloud/bgp:latest`) accessible to your cluster

---

## Step 1 — Install the CRDs

Apply the CRD manifests from the `config/crd` directory:

```bash
kubectl apply -k config/crd
```

Verify the CRDs were installed:

```bash
kubectl get crds | grep bgp.miloapis.com
```

Expected output:

```
bgpadvertisements.bgp.miloapis.com    ...
bgpconfigurations.bgp.miloapis.com    ...
bgpendpoints.bgp.miloapis.com         ...
bgppeeringpolicies.bgp.miloapis.com   ...
bgproutepolicies.bgp.miloapis.com     ...
bgpsessions.bgp.miloapis.com          ...
```

---

## Step 2 — Deploy the BGP Operator

Apply the full deployment (namespace, RBAC, ConfigMap, DaemonSet, CRDs):

```bash
kubectl apply -k config/deploy
```

This creates the `bgp-system` namespace and deploys the DaemonSet. The DaemonSet runs on all non-control-plane nodes. Each pod contains two containers:

- `bgp` — the controller
- `gobgpd` — GoBGP daemon

An init container (`config-gen`) discovers the node's global IPv6 address and writes an initial `gobgp.conf` before GoBGP starts.

Verify the DaemonSet is running:

```bash
kubectl -n bgp-system get daemonset bgp
kubectl -n bgp-system get pods -l app.kubernetes.io/name=bgp
```

All pods should reach `Running` status with both containers ready (2/2). If pods are stuck, check:

```bash
kubectl -n bgp-system describe pod <pod-name>
kubectl -n bgp-system logs <pod-name> -c bgp
kubectl -n bgp-system logs <pod-name> -c gobgpd
```

---

## Step 3 — Create a BGPConfiguration

Create a single `BGPConfiguration` for your cluster. This resource declares the AS number and controls how GoBGP is configured:

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

Apply it:

```bash
kubectl apply -f bgpconfig.yaml
```

Verify the speaker is ready:

```bash
kubectl get bgpconfig default
```

Expected output:

```
NAME      AS      PORT   READY
default   65001   1790   True
```

---

## Step 4 — Create BGPEndpoints

Each BGP speaker needs a `BGPEndpoint` resource. In production, a node operator creates these automatically — one per node using the node's IPv6 address. For this guide, create them manually.

Find your nodes' IPv6 addresses:

```bash
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}'
```

Create an endpoint for each node. Replace the addresses and node names with your values:

```yaml
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPEndpoint
metadata:
  name: node-worker-01
  labels:
    bgp.miloapis.com/role: node
    bgp.miloapis.com/cluster: my-cluster
spec:
  address: "2001:db8:1::1"
  asNumber: 65001
---
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPEndpoint
metadata:
  name: node-worker-02
  labels:
    bgp.miloapis.com/role: node
    bgp.miloapis.com/cluster: my-cluster
spec:
  address: "2001:db8:1::2"
  asNumber: 65001
```

Apply:

```bash
kubectl apply -f endpoints.yaml
```

Verify:

```bash
kubectl get bgpep
```

Expected output:

```
NAME             ADDRESS      ASN
node-worker-01   2001:db8:1::1   65001
node-worker-02   2001:db8:1::2   65001
```

---

## Step 5 — Create a BGPPeeringPolicy

Create a full-mesh peering policy that selects your node endpoints:

```yaml
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPPeeringPolicy
metadata:
  name: node-mesh
spec:
  selector:
    matchLabels:
      bgp.miloapis.com/role: node
      bgp.miloapis.com/cluster: my-cluster
  mode: mesh
```

Apply:

```bash
kubectl apply -f policy.yaml
```

The `PeeringPolicyReconciler` will create `BGPSession` resources for every pair of matching endpoints. With two nodes, it creates one session.

---

## Step 6 — Verify Sessions Are Established

Check that `BGPSession` resources were created:

```bash
kubectl get bgpsess
```

Expected output (initially in `Active` or `Connect` state, becoming `Established` once both sides configure each other):

```
NAME                              LOCAL            REMOTE           SESSION       RX PREFIXES
worker-01-to-worker-02            node-worker-01   node-worker-02   Established   0
```

If sessions do not reach `Established` after a minute or two, check the GoBGP logs on both nodes:

```bash
kubectl -n bgp-system logs -l app.kubernetes.io/name=bgp -c gobgpd
```

Common causes of sessions staying in `Active`:

- The remote node's IPv6 address is not reachable on port 1790
- The `BGPEndpoint` address does not match the node's actual IPv6 address
- A firewall rule is blocking TCP on port 1790

---

## Step 7 — Advertise a Prefix

Create a `BGPAdvertisement` to inject a prefix into the local RIB:

```yaml
apiVersion: bgp.miloapis.com/v1alpha1
kind: BGPAdvertisement
metadata:
  name: cluster-prefix
spec:
  prefixes:
    - "2001:db8:ff00::/40"
```

Apply:

```bash
kubectl apply -f advertisement.yaml
```

Verify the advertisement status:

```bash
kubectl get bgpadvert cluster-prefix -o jsonpath='{.status}'
```

After a few seconds, check that the remote node's session shows received prefixes:

```bash
kubectl get bgpsess -o wide
```

The `RX PREFIXES` column should increment on the session from the advertising node's perspective, and on the remote node's session from the receiving perspective.

---

## Next Steps

- See the [API Reference](api-reference.md) for complete field documentation on all six CRDs.
- See the [Architecture](architecture.md) for a deeper look at the controller internals.
- See the [Examples](examples/) directory for common configuration patterns:
  - [Single-cluster full mesh](examples/single-cluster-mesh.yaml)
  - [Route reflector topology](examples/route-reflector.yaml)
  - [eBGP peering](examples/ebgp-peering.yaml)
  - [Prefix advertisement with communities](examples/prefix-advertisement.yaml)
  - [Route filtering](examples/route-filtering.yaml)
