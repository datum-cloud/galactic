# Verification

Run these checks after `task deploy` to confirm the lab is healthy end-to-end. For
deploying and verifying the `ns10`/`ns20`/`ns30`/`ns40` test workloads,
see [docs/tenants.md](tenants.md).

## Transit fabric

The transit underlay is dual-stack and runs one BGP session per address family on every
link, so each summary below has an IPv4 counterpart — both should be Established.

```bash
# iBGP full mesh — expect all sessions Established
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast summary"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv4 unicast summary"

# Each site's per-node /56 SRv6 locator block should be present on all TR nodes
# (covers ns10's USID on that node — see docs/tenants.md)
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff01:100::/56"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff02:100::/56"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff03:100::/56"
```

## Dual-stack underlay reachability

The IPv4 address family carries per-node `/32` loopbacks only — link subnets are never
redistributed — so every check must be sourced from the local loopback, not the link
address, or the reply has no route home.

```bash
# tr1 -> dfw-worker, both families
docker exec clab-gvpc-tr1 ping -c2 -I 10.255.255.100 10.255.255.2
docker exec clab-gvpc-tr1 ping -6 -c2 -I fc00:0:1::1 fc00:0:2::1

# Every loopback in one shot (IPv4 and IPv6), non-zero exit on any failure
task verify:underlay

# What a transit router actually learned over IPv4 — expect one /32 per node
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv4 unicast"

# The worker side of the same session, from inside the fabric-router pod
docker exec dfw-control-plane kubectl exec -n galactic-system ds/fabric-router \
  -- vtysh -c "show bgp ipv4 unicast summary"
```

## FRR DaemonSets (eBGP fabric)

```bash
# Check pods are running
docker exec dfw-control-plane kubectl get pods -n galactic-system
docker exec iad-control-plane kubectl get pods -n galactic-system
docker exec sjc-control-plane kubectl get pods -n galactic-system

# Run vtysh inside a pod (swap ipv6 for ipv4 to check the other family's session)
docker exec dfw-control-plane kubectl exec -n galactic-system ds/fabric-router \
  -- vtysh -c "show bgp ipv6 unicast summary"
docker exec sjc-control-plane kubectl exec -n galactic-system ds/fabric-router \
  -- vtysh -c "show bgp ipv6 unicast summary"
docker exec iad-control-plane kubectl exec -n galactic-system ds/fabric-router \
  -- vtysh -c "show bgp ipv6 unicast summary"
```

## galactic-router DaemonSets (EVPN tenant)

```bash
# Check pods are running
docker exec dfw-control-plane kubectl get pods -n galactic-system
docker exec iad-control-plane kubectl get pods -n galactic-system
docker exec sjc-control-plane kubectl get pods -n galactic-system

# Tenant iBGP peer sessions to the iad-control-plane route reflector —
# STATE column should read Established for every peer
docker exec dfw-control-plane kubectl get bgppeers -n galactic-system
docker exec sjc-control-plane kubectl get bgppeers -n galactic-system
docker exec iad-control-plane kubectl get bgppeers -n galactic-system

# Check EVPN routes via BGPRouter status
docker exec dfw-control-plane kubectl get bgprouters -A
docker exec iad-control-plane kubectl get bgprouters -A
docker exec sjc-control-plane kubectl get bgprouters -A
```

## Automated checks

```bash
task verify           # run all verification (bgp-transit, bgp-fabric, bgp-peers, underlay, srv6, evpn)
task verify:bgp-transit
task verify:bgp-fabric
task verify:bgp-peers
task verify:underlay
task verify:srv6
task verify:evpn
```
