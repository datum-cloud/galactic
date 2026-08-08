# Tenant Test VPCs (ns10–ns50)

## Overview

The lab deploys five test VPCs — `ns50`, `ns10`, `ns20`, `ns30`, `ns40` — to
exercise different corners of the CNI/BGP/SRv6 path: single- vs. dual-stack
addressing, 3-site cross-site EVPN reachability, and same-node/same-VRF
pod-to-pod connectivity. Every one of them follows the same mechanism: Multus
attaches each `netshoot` pod to its VPC's `private` NetworkAttachmentDefinition
(via the `v1.multus-cni.io/default-network` annotation, which makes the VPC
interface the pod's `eth0` rather than an additional `net1` — there is no
`k8s.v1.cni.cncf.io/networks` annotation in play here), which invokes the
galactic CNI plugin chain: `galactic-cni` creates a VRF and veth pair, then
`galactic-bgp` registers the attachment against the eBPF uSID datapath and
writes a `BGPAdvertisement` CRD (see [docs/cni-cmd-sequence.md](../../../docs/cni-cmd-sequence.md)
for the full per-binary ADD sequence). The `galactic-router` controller then
advertises each pod's EVPN route to the route reflector, distributing
reachability across sites.

They differ only in scope and addressing:

| VPC    | Sites                     | Address families | VRF interface    | Notes |
|--------|---------------------------|-------------------|-------------------|-------|
| `ns50` | dfw, sjc, iad (3-site)    | IPv4 + public IPv6 ptp | `G000000050050V` | Also defines a `public` NAD with an IPv6 IPAM pool for external-connectivity testing. |
| `ns10` | dfw, sjc, iad (3-site)    | IPv6-only (fd20 ULA) | `G000000010010V` | No `ipv4_subnet` at all. |
| `ns20` | dfw, sjc, iad (3-site)    | Dual-stack (fd20 ULA + IPv4) | `G000000020020V` | Both families active; exercises the dual-stack IPAM path. |
| `ns30` | dfw only, 2 replicas      | IPv6-only (fd20 ULA) | `G000000030030V` | Both pods land on `dfw-worker` and share one VRF — same-node connectivity, no cross-site hop. |
| `ns40` | iad only, 2 replicas      | IPv4-only | `G000000040040V` | Both pods land on `iad-worker` (not `iad-worker-control`, which is tainted for the route-reflector role) and share one VRF. |

The VRF interface name follows `G<vpc, zero-padded to 9><vpcattachment,
zero-padded to 3>V` on every worker — e.g. `ns20` (`vpc="20"`,
`vpcattachment="20"`) is `G000000020020V`.

### SRv6 USID Argument allocation

Each site's tenant node advertises its own `/56` SRv6 locator block into the
fabric. The low hextet of a pod's USID is `(Function << 12) | Argument`
(`uFMT 48+16`, `internal/plumbing/ebpf/uformat`): `Function` is the constant
`0xE` (`FunctionEndDT46`) for every plain L3 VRF attachment, and `Argument` is
a 12-bit value `galactic-router` allocates per-node as the lowest unused slot
in `[0x001, 0xFFF]` among that node's existing `BGPVRFInstance` CRDs
(`allocateArgument`, `internal/cnibgp/bgp.go`) — **not** a decode of the NAD's
`vpc`/`vpcattachment` values. Concretely, expect hextets in the
`0xe001`–`0xefff` range; the exact value depends on allocation order (`ns50`
is provisioned first in `task deploy`, then `ns10`, `ns20`, `ns30`, `ns40` in
that order, each consuming the next free slot on each node it lands on).
Always confirm the live value rather than trusting a table:

```bash
docker exec dfw-control-plane kubectl get bgpvrfinstances -A
```

## Addressing reference

| Site | VPC    | IPv6 pool (fd20 ULA)  | IPv4 subnet       | Public IPv6 pool   |
|------|--------|------------------------|--------------------|---------------------|
| dfw  | `ns50` | —                      | `172.20.1.0/24`   | `2001:db8:1::/64`  |
| sjc  | `ns50` | —                      | `172.20.20.0/24`  | `2001:db8:20::/64` |
| iad  | `ns50` | —                      | `172.20.10.0/24`  | `2001:db8:10::/64` |
| dfw  | `ns10` | `fd20:10:ff01::/48`   | none               | —                   |
| sjc  | `ns10` | `fd20:10:ff02::/48`   | none               | —                   |
| iad  | `ns10` | `fd20:10:ff03::/48`   | none               | —                   |
| dfw  | `ns20` | `fd20:20:ff01::/48`   | `172.21.1.0/24`   | —                   |
| sjc  | `ns20` | `fd20:20:ff02::/48`   | `172.21.20.0/24`  | —                   |
| iad  | `ns20` | `fd20:20:ff03::/48`   | `172.21.10.0/24`  | —                   |
| dfw  | `ns30` | `fd20:30:ff01::/48`   | none               | —                   |
| iad  | `ns40` | none                   | `172.40.10.0/24`  | —                   |

`ns50`'s IPv4 pools and `ns20`'s are deliberately from distinct `/16` blocks
(`172.20.0.0/16` vs. `172.21.0.0/16`) so the two VPCs' addressing never
overlaps; `ns40`'s `172.40.0.0/16` is separate again. The IPv6 pools for
`ns10`/`ns20`/`ns30` share the `fd20` ULA prefix, distinguished by the second
hextet (`10`/`20`/`30`).

## Prerequisites

The lab must already be deployed and verified:

```bash
cd deploy/containerlab
task deploy   # build images, create clusters, deploy fabric + tenant + all VPCs
task verify   # verify BGP, SRv6, and EVPN routes
```

Confirm all `galactic-router` pods are running before proceeding:

```bash
docker exec dfw-control-plane kubectl get pods -n galactic-system
docker exec iad-control-plane kubectl get pods -n galactic-system
docker exec sjc-control-plane kubectl get pods -n galactic-system
```

## Deploying a VPC's workloads

`task deploy` already runs all five as its final steps. To (re-)apply just
one VPC's workloads on its own — e.g. after the lab was restarted — use its
`task deploy:nsNN` target, which wraps `scripts/deploy-ns.sh <namespace>
<site...>`:

```bash
task deploy:ns50   # -> deploy-ns.sh ns50 dfw sjc iad
task deploy:ns10   # -> deploy-ns.sh ns10 dfw sjc iad
task deploy:ns20   # -> deploy-ns.sh ns20 dfw sjc iad
task deploy:ns30   # -> deploy-ns.sh ns30 dfw
task deploy:ns40   # -> deploy-ns.sh ns40 iad
```

Each applies that VPC's namespace, NAD(s), and `netshoot` Deployment to the
listed site(s). All of them rely on `deploy:cni` (kubeconfig on each worker)
and `deploy:galactic-router` (BGP CRs) having already run — both are part of
`task deploy`.

## Verifying pods are running

```bash
docker exec dfw-control-plane kubectl get pods -n <namespace> -o wide
docker exec sjc-control-plane kubectl get pods -n <namespace> -o wide
docker exec iad-control-plane kubectl get pods -n <namespace> -o wide
```

For the 3-site VPCs (`ns50`, `ns10`, `ns20`), expect one `Running` pod per
site. For the single-site VPCs, expect **two** `Running` pods, both on the
one site's worker (`dfw-worker` for `ns30`, `iad-worker` for `ns40` — not
`iad-worker-control`, which carries the route-reflector taint).

### Inspect a pod's VPC interface

Every pod's VPC address lands on `eth0` (the `default-network` annotation
replaces the pod's primary interface — see [Overview](#overview)):

```bash
POD=$(docker exec dfw-control-plane kubectl get pods -n <namespace> -l app=private -o jsonpath='{.items[0].metadata.name}')
docker exec dfw-control-plane kubectl exec -n <namespace> "${POD}" -- ip -6 addr show eth0   # IPv6-capable VPCs
docker exec dfw-control-plane kubectl exec -n <namespace> "${POD}" -- ip -4 addr show eth0   # IPv4-capable VPCs
```

Expect an address from that site's pool in the [addressing reference](#addressing-reference)
above, and nothing at all from the family(ies) the VPC doesn't use (e.g. `ip
-4 addr show eth0` prints nothing for an `ns10` pod).

## Running connectivity checks

Each VPC has a `task verify:nsNN` target (`scripts/verify-nsNN.sh`) that
resolves every pod's address and pings across every applicable pair, in both
directions:

```bash
task verify:ns50   # 3-site mesh, IPv4
task verify:ns10   # 3-site mesh, IPv6
task verify:ns20   # 3-site mesh, both families
task verify:ns30   # same-node pod-to-pod, IPv6 (dfw)
task verify:ns40   # same-node pod-to-pod, IPv4 (iad)
```

`task verify` (via `task verify:scenarios`) runs all five. Use the scripts as
the reference for how to resolve pod names/addresses by hand (`lib.sh`'s
`pod_name`/`pod_ip4`/`pod_ip6`/`ping_pod` helpers) if you need to reproduce a
step manually while debugging — e.g. to ping the `ns30` pods on dfw directly:

```bash
source scripts/lib.sh
NODE=$(control_plane dfw)
mapfile -t PODS < <(pod_names "${NODE}" ns30 | tr ' ' '\n')
IP=$(pod_ip6 "${NODE}" ns30 "${PODS[1]}")
ping_pod "${NODE}" ns30 "${PODS[0]}" -6 "${IP}"
```

## Troubleshooting

### Pods not getting VPC IPs

Check that `galactic-cni` can reach the API server:

```bash
docker exec dfw-worker cat /var/lib/galactic/kubeconfig
docker exec dfw-worker kubectl --kubeconfig /var/lib/galactic/kubeconfig get ns
```

If the lab was restarted, the control-plane IPv6 addresses may have changed
and every worker's kubeconfig is stale. Re-run `deploy:cni`, then the
affected VPC's `deploy:nsNN`:

```bash
task deploy:cni
task deploy:ns50   # or whichever VPC's pods aren't getting IPs
```

### BGPAdvertisements not created

The CNI creates a `BGPAdvertisement` CRD per pod on attach. The 3-site VPCs
get one advertisement per site; the single-site VPCs get **two** (one per
pod, both on the same site):

```bash
docker exec dfw-control-plane kubectl get bgpadvertisements -n galactic-system
```

If missing, check CNI logs:

```bash
docker exec dfw-worker dmesg | grep galactic
```

### Pings fail but BGP looks healthy

1. Verify EVPN routes are distributed (3-site VPCs only — same-node VPCs
   don't depend on this):

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

3. Verify the pod's VRF and SRv6 route on the worker, using that VPC's VRF
   interface name from the [Overview](#overview) table:

   ```bash
   docker exec dfw-worker ip -4 route show table G000000050050V   # ns50
   docker exec dfw-worker ip -6 route show table G000000010010V   # ns10
   docker exec dfw-worker ip -6 route show table G000000020020V   # ns20 (IPv6 leg)
   docker exec dfw-worker ip -4 route show table G000000020020V   # ns20 (IPv4 leg)
   docker exec dfw-worker ip -6 route show table G000000030030V   # ns30
   docker exec iad-worker ip -4 route show table G000000040040V   # ns40
   ```

   An empty table for a family the VPC doesn't use (e.g. IPv4 on `ns10`/`ns30`,
   IPv6 on `ns40`) is expected, not a failure signature. For the single-site
   VPCs (`ns30`/`ns40`), a healthy ping also depends only on this VRF's local
   routes/neighbor table — there's no cross-site EVPN dependency to check.

### Pod scheduled on iad-worker-control instead of iad-worker (ns40)

Every test VPC's Deployment uses a `node-role.kubernetes.io/control-plane
DoesNotExist` affinity, but that doesn't exclude `iad-worker-control` — it's
a tainted *worker*, not a Kubernetes control-plane node. If an `ns40` pod ends
up `Pending`, confirm the route-reflector taint is still in place rather than
assuming the affinity alone keeps pods off it:

```bash
docker exec iad-control-plane kubectl describe node iad-worker-control | grep -A2 Taints
```

## See also

- [docs/verification.md](verification.md) — transit fabric, FRR, and `galactic-router` health checks
- [docs/cni/configuration.md](../../../docs/cni/configuration.md#pool-ipam-via-ipv6_subnetipv4_subnet) — how `ipv6_subnet`/`ipv4_subnet` drive pool IPAM, including the dual-stack and IPv6-only/IPv4-only cases these VPCs exercise
