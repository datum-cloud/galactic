# Test VPCs — Deploy Workloads and Verify Connectivity

## Overview

The lab deploys two isolated test VPCs — `vpc10` and `vpc20` — each with a
`nicolaka/netshoot` pod on every site's worker node. That's 2 VPCs × 3
sites = 6 pods total. Multus attaches each pod to its VPC's
NetworkAttachmentDefinition (`vpc10` or `vpc20`), which invokes `galactic-cni`
to create a VRF, veth pair, SRv6 encapsulation route, and `BGPAdvertisement`
CRD. The `galactic-router` controller then advertises the pod's EVPN route to
the route reflector, distributing reachability across sites — but only within
the same VPC. `vpc10` and `vpc20` use distinct VRFs, route targets, and SRv6
SIDs, so pods in different VPCs cannot reach each other.

Each site advertises one aggregate `/48` SRv6 locator block into the fabric —
individual VPC USIDs are just sequential host addresses within it, so adding
a VPC to a site that's already advertising the block requires zero fabric
config changes. Each VPC also gets its own IPv6 IPAM pool, unrelated to the
SID numbering:

| Site | VPC   | USID                  | IPAM pool           | Gateway           |
|------|-------|-----------------------|---------------------|-------------------|
| dfw  | vpc10 | `2001:db8:ff01::1/128` | `fd00:10:ff01::/48` | `fd00:10:ff01::1` |
| dfw  | vpc20 | `2001:db8:ff01::2/128` | `fd00:20:ff01::/48` | `fd00:20:ff01::1` |
| sjc  | vpc10 | `2001:db8:ff02::1/128` | `fd00:10:ff02::/48` | `fd00:10:ff02::1` |
| sjc  | vpc20 | `2001:db8:ff02::2/128` | `fd00:20:ff02::/48` | `fd00:20:ff02::1` |
| iad  | vpc10 | `2001:db8:ff03::1/128` | `fd00:10:ff03::/48` | `fd00:10:ff03::1` |
| iad  | vpc20 | `2001:db8:ff03::2/128` | `fd00:20:ff03::/48` | `fd00:20:ff03::1` |

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

`task deploy` already runs this as its final step. To (re-)apply just the test
workloads on their own — e.g. after the lab was restarted, per
[Regenerate CNI kubeconfigs](#regenerate-cni-kubeconfigs) below — run:

```bash
task deploy:vpc
```

This applies the `vpc10`/`vpc20` NADs and Deployments to each cluster's `vpc`
namespace. It relies on `deploy:cni` (kubeconfig on each worker) and
`deploy:tenant` (BGP CRs) having already run — both are part of `task deploy`.

## Verify Pods Are Running

```bash
docker exec dfw-control-plane kubectl get pods -n vpc -o wide
docker exec iad-control-plane kubectl get pods -n vpc -o wide
docker exec sjc-control-plane kubectl get pods -n vpc -o wide
```

Each should show two pods in `Running` state, named `vpc10-...` and `vpc20-...`.

### Inspect pod VPC interface

Each pod receives a second interface (`net1`) from its VPC's NAD. Verify it has an
IPv6 address from the site's IPAM pool for that VPC:

```bash
# Get the dfw vpc10 pod name
DFW_VPC10_POD=$(docker exec dfw-control-plane kubectl get pods -n vpc -l app=vpc10 -o jsonpath='{.items[0].metadata.name}')

# Exec into the pod and check the VPC interface
docker exec dfw-control-plane kubectl exec -n vpc "${DFW_VPC10_POD}" -- ip -6 addr show net1
```

Expected: a global address in the site's pool for that VPC — e.g. `fd00:10:ff01::/80`
(dfw/vpc10) or `fd00:20:ff01::/80` (dfw/vpc20); see the table above for sjc/iad.

## Run Cross-Site Pings (same VPC)

### Retrieve vpc10 pod addresses

```bash
vpc_pod_ip() {
  local site="$1" vpc="$2"
  local pod
  pod=$(docker exec "${site}-control-plane" kubectl get pods -n vpc -l "app=${vpc}" -o jsonpath='{.items[0].metadata.name}')
  docker exec "${site}-control-plane" kubectl exec -n vpc "${pod}" \
    -- ip -6 addr show net1 | grep 'inet6.*scope global' | awk '{print $2}' | cut -d'/' -f1
}

DFW_VPC10_IP=$(vpc_pod_ip dfw vpc10)
SJC_VPC10_IP=$(vpc_pod_ip sjc vpc10)
IAD_VPC10_IP=$(vpc_pod_ip iad vpc10)

echo "dfw/vpc10: ${DFW_VPC10_IP}"
echo "sjc/vpc10: ${SJC_VPC10_IP}"
echo "iad/vpc10: ${IAD_VPC10_IP}"
```

### Ping from dfw/vpc10 to sjc/vpc10 and iad/vpc10

```bash
DFW_VPC10_POD=$(docker exec dfw-control-plane kubectl get pods -n vpc -l app=vpc10 -o jsonpath='{.items[0].metadata.name}')

docker exec dfw-control-plane kubectl exec -n vpc "${DFW_VPC10_POD}" -- ping -6 -c 3 "${SJC_VPC10_IP}"
docker exec dfw-control-plane kubectl exec -n vpc "${DFW_VPC10_POD}" -- ping -6 -c 3 "${IAD_VPC10_IP}"
```

Repeat the same pattern for `vpc20` (pass `vpc20` to `vpc_pod_ip` and select pods with
`-l app=vpc20`) to confirm the second VPC is independently reachable across all three
sites.

## Verify VPC Isolation (cross-VPC)

`vpc10` and `vpc20` are separate VRFs with separate route targets — a pod in one
should **not** be able to reach a pod in the other, even on the same site:

```bash
DFW_VPC10_POD=$(docker exec dfw-control-plane kubectl get pods -n vpc -l app=vpc10 -o jsonpath='{.items[0].metadata.name}')
DFW_VPC20_IP=$(vpc_pod_ip dfw vpc20)

# Expected: 100% packet loss — vpc20's address is unreachable from vpc10.
docker exec dfw-control-plane kubectl exec -n vpc "${DFW_VPC10_POD}" -- ping -6 -c 3 -W 2 "${DFW_VPC20_IP}"
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
each site should have one advertisement per pod (2 per site, 6 total):

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

2. Check the SRv6 underlay — transit routers should have each site's aggregate
   `/48` locator block, which covers every VPC's USID on that site (vpc10 and
   vpc20 alike):

   ```bash
   docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff01::/48"
   docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff02::/48"
   docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff03::/48"
   ```

3. Verify the pod's VRF and SRv6 route on the worker. The VRF interface name is
   `G<vpc, zero-padded to 9><vpcattachment, zero-padded to 3>V` — for `vpc10`
   that's `G000000010010V`, for `vpc20` it's `G000000020020V`:

   ```bash
   docker exec dfw-worker ip -6 route show table G000000010010V
   docker exec dfw-worker ip -6 neigh show table G000000010010V
   ```

### Regenerate CNI kubeconfigs

If the lab was restarted, the control-plane IPv6 addresses may have changed. Re-run:

```bash
task deploy:cni
task deploy:vpc
```

`deploy:cni` regenerates the kubeconfig on each worker; `deploy:vpc` re-applies the
Deployments, which triggers pod recreation against the refreshed kubeconfig.
