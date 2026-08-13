# Verification

Run these checks after `task deploy` to confirm the lab is healthy end-to-end. For
deploying and verifying the `ns10`/`ns20`/`ns30`/`ns40` test workloads,
see [docs/tenants.md](tenants.md).

## Transit fabric

```bash
# iBGP full mesh — expect all sessions Established
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast summary"

# Each site's per-node /56 SRv6 locator block should be present on all TR nodes
# (covers ns10's USID on that node — see docs/tenants.md)
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff01:100::/56"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff02:100::/56"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff03:100::/56"
```

## FRR DaemonSets (eBGP fabric)

```bash
# Check pods are running
docker exec dfw-control-plane kubectl get pods -n galactic-system
docker exec iad-control-plane kubectl get pods -n galactic-system
docker exec sjc-control-plane kubectl get pods -n galactic-system

# Run vtysh inside a pod
docker exec dfw-control-plane kubectl exec -n galactic-system ds/fabric-router \
  -- vtysh -c "show bgp ipv6 unicast summary"
docker exec sjc-control-plane kubectl exec -n galactic-system ds/fabric-router \
  -- vtysh -c "show bgp ipv6 unicast summary"
docker exec iad-control-plane kubectl exec -n galactic-system ds/fabric-router \
  -- vtysh -c "show bgp ipv6 unicast summary"
docker exec iad-control-plane kubectl exec -n galactic-system ds/fabric-control \
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
task verify           # run all verification (bgp-transit, bgp-fabric, bgp-peers, srv6, evpn)
task verify:bgp-transit
task verify:bgp-fabric
task verify:bgp-peers
task verify:srv6
task verify:evpn
```
