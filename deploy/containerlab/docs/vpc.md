# ns50 — Deploy Workloads and Verify Connectivity

## Overview

The lab deploys a single test VPC (`ns50`) with an `nginx` webapp pod on every
site's worker node. That's 3 sites = 3 pods total. Multus attaches each pod to
its VPC's NetworkAttachmentDefinition (`private`), which invokes `galactic-cni`
to create a VRF, veth pair, SRv6 encapsulation route, and `BGPAdvertisement`
CRD. The `galactic-router` controller then advertises the pod's EVPN route to
the route reflector, distributing reachability across sites.

Each NAD also defines a `public` ptp interface with an IPv6 IPAM pool for
external connectivity testing.

Each site's tenant node advertises its own `/56` SRv6 locator block into the
fabric. The VRFID embedded in each USID is decoded from the NAD's
`vpcattachment` value (`vrfIDFromAttachment`, base62 → hex → uint16): `"50"`
→ `0xc8` (200). Each site gets its own IPv4 subnet:

| Site | VPC  | USID                          | IPv4 subnet        | Public IPv6 pool       |
|------|------|-------------------------------|--------------------|------------------------|
| dfw  | ns50 | `2001:db8:ff01:100:c800::/128` | `172.20.1.0/24`    | `2001:db8:1::/64`      |
| sjc  | ns50 | `2001:db8:ff02:100:c800::/128` | `172.20.20.0/24`   | `2001:db8:20::/64`     |
| iad  | ns50 | `2001:db8:ff03:100:c800::/128` | `172.20.10.0/24`   | `2001:db8:10::/64`     |

## Prerequisites

The lab must already be deployed and verified:

```bash
cd deploy/containerlab
task deploy        # build images, create clusters, deploy fabric + tenant
task verify          # verify BGP, SRv6, and EVPN routes
```

Confirm all `galactic-router` pods are running before proceeding:

```bash
docker exec dfw-control-plane kubectl get pods -n galactic-system
docker exec iad-control-plane kubectl get pods -n galactic-system
docker exec sjc-control-plane kubectl get pods -n galactic-system
```

## Deploy ns50 Workloads

`task deploy` already runs this as its final step. To (re-)apply just the test
workloads on their own — e.g. after the lab was restarted — run:

```bash
task deploy:ns50
```

This applies the `ns50` namespace, NADs, and webapp Deployments to each cluster.
It relies on `deploy:cni` (kubeconfig on each worker) and `deploy:galactic-router` (BGP
CRs) having already run — both are part of `task deploy`.

## Verify Pods Are Running

```bash
docker exec dfw-control-plane kubectl get pods -n ns50 -o wide
docker exec iad-control-plane kubectl get pods -n ns50 -o wide
docker exec sjc-control-plane kubectl get pods -n ns50 -o wide
```

Each should show one pod in `Running` state, named `webapp-...`.

### Inspect pod VPC interface

Each pod receives a second interface (`net1`) from its VPC's NAD. Verify it has
an IPv4 address from the site's subnet:

```bash
# Get the dfw pod name
DFW_POD=$(docker exec dfw-control-plane kubectl get pods -n ns50 -l app=private -o jsonpath='{.items[0].metadata.name}')

# Exec into the pod and check the VPC interface
docker exec dfw-control-plane kubectl exec -n ns50 "${DFW_POD}" -- ip -4 addr show net1
```

Expected: an IPv4 address in the site's pool — e.g. `172.20.1.x` (dfw),
`172.20.20.x` (sjc), `172.20.10.x` (iad).

## Run Cross-Site Pings

### Retrieve pod IPv4 addresses

```bash
pod_ip() {
  local site="$1"
  local pod
  pod=$(docker exec "${site}-control-plane" kubectl get pods -n ns50 -l "app=private" -o jsonpath='{.items[0].metadata.name}')
  docker exec "${site}-control-plane" kubectl exec -n ns50 "${pod}" \
    -- ip -4 addr show net1 | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1
}

DFW_IP=$(pod_ip dfw)
SJC_IP=$(pod_ip sjc)
IAD_IP=$(pod_ip iad)

echo "dfw: ${DFW_IP}"
echo "sjc: ${SJC_IP}"
echo "iad: ${IAD_IP}"
```

### Ping from dfw to sjc and iad

```bash
DFW_POD=$(docker exec dfw-control-plane kubectl get pods -n ns50 -l app=private -o jsonpath='{.items[0].metadata.name}')

docker exec dfw-control-plane kubectl exec -n ns50 "${DFW_POD}" -- ping -c 3 "${SJC_IP}"
docker exec dfw-control-plane kubectl exec -n ns50 "${DFW_POD}" -- ping -c 3 "${IAD_IP}"
```

## Troubleshooting

### Pods not getting VPC IPs

Check that `galactic-cni` can reach the API server:

```bash
docker exec dfw-worker cat /var/lib/galactic/kubeconfig
docker exec dfw-worker kubectl --kubeconfig /var/lib/galactic/kubeconfig get ns
```

### BGPAdvertisements not created

The CNI creates `BGPAdvertisement` CRDs on pod attach. Verify they exist —
each site should have one advertisement per pod (1 per site, 3 total):

```bash
docker exec dfw-control-plane kubectl get bgpadvertisements -n galactic-system
```

If missing, check CNI logs:

```bash
docker exec dfw-worker dmesg | grep galactic
```

### Pings fail but BGP looks healthy

1. Verify EVPN routes are distributed:

   ```bash
   docker exec dfw-control-plane kubectl get bgprouters -A -o yaml | grep -A 5 advertised
   ```

2. Check the SRv6 underlay — transit routers should have each site's per-node
   `/56` locator block:

   ```bash
   docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff01:100::/56"
   docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff02:100::/56"
   docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff03:100::/56"
   ```

3. Verify the pod's VRF and SRv6 route on the worker. The VRF interface name is
   `G<vpc, zero-padded to 9><vpcattachment, zero-padded to 3>V` — for ns50
   that's `G000000050050V`:

   ```bash
   docker exec dfw-worker ip -4 route show table G000000050050V
   docker exec dfw-worker ip -4 neigh show table G000000050050V
   ```

### Regenerate CNI kubeconfigs

If the lab was restarted, the control-plane IPv6 addresses may have changed.
Re-run:

```bash
task deploy:cni
task deploy:ns50
```

`deploy:cni` regenerates the kubeconfig on each worker; `deploy:ns50` re-applies
the Deployments, which triggers pod recreation against the refreshed kubeconfig.
