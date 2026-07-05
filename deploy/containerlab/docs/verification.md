# Verification

Run these checks after `task deploy` to confirm the lab is healthy end-to-end. For
deploying and verifying the `vpc10`/`vpc20` test workloads specifically (cross-site and
cross-VPC connectivity), see [docs/vpc.md](vpc.md).

## Transit fabric

```bash
# iBGP full mesh — expect all sessions Established
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast summary"

# Worker USIDs should be present on all TR nodes (vpc10, then vpc20)
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff00:1010::1/128"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff00:1010::2/128"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff00:1010::3/128"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff00:1020::1/128"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff00:1020::2/128"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff00:1020::3/128"
```

## FRR DaemonSets (eBGP fabric)

```bash
# Check pods are running
docker exec dfw-control-plane kubectl get pods -n galactic-system
docker exec iad-control-plane kubectl get pods -n galactic-system
docker exec sjc-control-plane kubectl get pods -n galactic-system

# Run vtysh inside a pod
docker exec iad-control-plane kubectl exec -n galactic-system ds/iad-worker-fabric \
  -- vtysh -c "show bgp ipv6 unicast summary"
docker exec iad-control-plane kubectl exec -n galactic-system ds/iad-control-fabric \
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
task test           # run all verification (bgp-transit, bgp-fabric, bgp-peers, srv6, evpn)
task test:bgp-transit
task test:bgp-fabric
task test:bgp-peers
task test:srv6
task test:evpn
```
