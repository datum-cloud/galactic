# Test VPC — Deploy Workloads and Verify Connectivity

## Overview

The test VPC deploys two `wbitt/network-multitool` pods (`testvpc` and `testvpc-2`) on each
site's worker node. Each pod is attached to its own NetworkAttachmentDefinition (`testvpc`
and `testvpc-2`), each with a distinct VPC ID and USID. `galactic-cni` creates a VRF, veth
pair, SRv6 encapsulation route, and `BGPAdvertisement` CRD per pod. The `galactic-router`
controller then advertises each pod's EVPN route to the route reflector, distributing
reachability across sites.

Each VPC on each site has its own USID and distinct IPAM pool:

| Pod       | VPC | Site | USID                         | IPAM pool            | Gateway          |
|-----------|-----|------|------------------------------|----------------------|------------------|
| testvpc   | 10  | dfw  | `2001:db8:ff00:1010::1/128`  | `fd00:10:ff01::/48`  | `fd00:10:ff01::1` |
| testvpc-2 | 11  | dfw  | `2001:db8:ff00:1010::b/128`  | `fd00:11:ff01::/48`  | `fd00:11:ff01::1` |
| testvpc   | 10  | sjc  | `2001:db8:ff00:1010::2/128`  | `fd00:10:ff02::/48`  | `fd00:10:ff02::1` |
| testvpc-2 | 11  | sjc  | `2001:db8:ff00:1010::c/128`  | `fd00:11:ff02::/48`  | `fd00:11:ff02::1` |
| testvpc   | 10  | iad  | `2001:db8:ff00:1010::3/128`  | `fd00:10:ff03::/48`  | `fd00:10:ff03::1` |
| testvpc-2 | 11  | iad  | `2001:db8:ff00:1010::d/128`  | `fd00:11:ff03::/48`  | `fd00:11:ff03::1` |

## Prerequisites

The lab must already be deployed and verified:

```bash
cd deploy/containerlab
task deploy        # build images, create clusters, deploy fabric + tenant
task test          # verify BGP, SRv6, and EVPN routes
```

Confirm all `galactic-router` pods are running before proceeding:

```bash
docker exec dfw-control-plane kubectl get pods -n galactic-system
docker exec iad-control-plane kubectl get pods -n galactic-system
docker exec sjc-control-plane kubectl get pods -n galactic-system
```

## Deploy Test VPC Workloads

```bash
task deploy:testvpc
```

This does the following:

1. **Writes a kubeconfig** to each worker so `galactic-cni` can reach the API server and
   create `BGPAdvertisement` CRDs on pod attach (requires `deploy:system` for RBAC).
2. **Patches the CNI wrapper** (`/opt/cni/bin/galactic-cni`) to export `KUBECONFIG` and
   `GALACTIC_CNI_NODE_NAME`.
3. **Applies the testvpc Deployment** to each cluster's `vpc` namespace.

## Verify Pods Are Running

```bash
docker exec dfw-control-plane kubectl get pods -n vpc -o wide
docker exec iad-control-plane kubectl get pods -n vpc -o wide
docker exec sjc-control-plane kubectl get pods -n vpc -o wide
```

Each should show two pods (`testvpc` and `testvpc-2`) in `Running` state.

### Inspect pod VPC interface

Each pod receives a second interface (`net1`) from its NAD. Verify both pods have IPv6
addresses from the site's IPAM pool:

```bash
# Get the pod name
DFW_POD=$(docker exec dfw-control-plane kubectl get pods -n vpc -o jsonpath='{.items[0].metadata.name}')

# Exec into the pod and check the VPC interface
docker exec dfw-control-plane kubectl exec -n vpc "${DFW_POD}" -- ip -6 addr show net1
```

Expected: a global address in `fd00:10:ff01::/80` (dfw), `fd00:10:ff02::/80` (sjc), or `fd00:10:ff03::/80` (iad).

## Run Cross-Site Pings

### Retrieve pod addresses

```bash
DFW_IP=$(docker exec dfw-control-plane kubectl exec -n vpc \
  "$(docker exec dfw-control-plane kubectl get pods -n vpc -o jsonpath='{.items[0].metadata.name}')" \
  -- ip -6 addr show net1 | grep 'inet6.*scope global' \
  | awk '{print $2}' | cut -d'/' -f1)

SJC_IP=$(docker exec sjc-control-plane kubectl exec -n vpc \
  "$(docker exec sjc-control-plane kubectl get pods -n vpc -o jsonpath='{.items[0].metadata.name}')" \
  -- ip -6 addr show net1 | grep 'inet6.*scope global' \
  | awk '{print $2}' | cut -d'/' -f1)

IAD_IP=$(docker exec iad-control-plane kubectl exec -n vpc \
  "$(docker exec iad-control-plane kubectl get pods -n vpc -o jsonpath='{.items[0].metadata.name}')" \
  -- ip -6 addr show net1 | grep 'inet6.*scope global' \
  | awk '{print $2}' | cut -d'/' -f1)

echo "dfw: ${DFW_IP}"
echo "sjc: ${SJC_IP}"
echo "iad: ${IAD_IP}"
```

### Ping from dfw to sjc and iad

```bash
DFW_POD=$(docker exec dfw-control-plane kubectl get pods -n vpc -o jsonpath='{.items[0].metadata.name}')

docker exec dfw-control-plane kubectl exec -n vpc "${DFW_POD}" -- ping -6 -c 3 "${SJC_IP}"
docker exec dfw-control-plane kubectl exec -n vpc "${DFW_POD}" -- ping -6 -c 3 "${IAD_IP}"
```

### Ping from sjc to dfw and iad

```bash
SJC_POD=$(docker exec sjc-control-plane kubectl get pods -n vpc -o jsonpath='{.items[0].metadata.name}')

docker exec sjc-control-plane kubectl exec -n vpc "${SJC_POD}" -- ping -6 -c 3 "${DFW_IP}"
docker exec sjc-control-plane kubectl exec -n vpc "${SJC_POD}" -- ping -6 -c 3 "${IAD_IP}"
```

### Ping from iad to dfw and sjc

```bash
IAD_POD=$(docker exec iad-control-plane kubectl get pods -n vpc -o jsonpath='{.items[0].metadata.name}')

docker exec iad-control-plane kubectl exec -n vpc "${IAD_POD}" -- ping -6 -c 3 "${DFW_IP}"
docker exec iad-control-plane kubectl exec -n vpc "${IAD_POD}" -- ping -6 -c 3 "${SJC_IP}"
```

## Troubleshooting

### Pods not getting VPC IPs

Check that `galactic-cni` can reach the API server:

```bash
docker exec dfw-worker cat /etc/galactic/kubeconfig
docker exec dfw-worker kubectl --kubeconfig /etc/galactic/kubeconfig get ns
```

### BGPAdvertisements not created

The CNI creates `BGPAdvertisement` CRDs on pod attach. Verify they exist:

```bash
docker exec dfw-control-plane kubectl get bgpadvertisements -n galactic-system
```

Each site should have two BGPAdvertisements (one per pod). If missing, check CNI logs:

```bash
docker exec dfw-worker dmesg | grep galactic
```

### Pings fail but BGP looks healthy

1. Verify EVPN routes are distributed:

   ```bash
   docker exec dfw-control-plane kubectl get bgprouters -A -o yaml | grep -A 5 advertised
   ```

2. Check the SRv6 underlay — transit routers should have all USIDs:

   ```bash
   docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff00:1010::1/128"
   docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff00:1010::2/128"
   docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff00:1010::3/128"
   docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff00:1010::b/128"
   docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff00:1010::c/128"
   docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff00:1010::d/128"
   ```

3. Verify the pod's VRF and SRv6 route on the worker:

   ```bash
   docker exec dfw-worker ip -6 route show table vrf-vpc-testvpc-*
   docker exec dfw-worker ip -6 neigh show table vrf-vpc-testvpc-*
   ```

### Regenerate CNI kubeconfigs

If the lab was restarted, the control-plane IPv6 addresses may have changed. Re-run:

```bash
task deploy:testvpc
```

This regenerates kubeconfigs and re-applies the deployments (which triggers pod recreation).
