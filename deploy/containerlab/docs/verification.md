# Verification

Run these checks after `task deploy` to confirm the lab is healthy end-to-end.

## Transit fabric

```bash
# iBGP full mesh — expect all sessions Established
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast summary"

# Worker SRv6 prefixes should be present on all TR nodes
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff01::/48"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff02::/48"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff03::/48"
```

## FRR DaemonSets (eBGP fabric)

```bash
# Check pods are running
docker exec dfw-control-plane kubectl get pods -n galactic-system
docker exec iad-control-plane kubectl get pods -n galactic-system
docker exec sjc-control-plane kubectl get pods -n galactic-system

# Run vtysh inside a pod
docker exec iad-control-plane kubectl exec -n galactic-system ds/iad-fabric \
  -- vtysh -c "show bgp ipv6 unicast summary"
docker exec iad-control-plane kubectl exec -n galactic-system ds/iad-fabric-control \
  -- vtysh -c "show bgp ipv6 unicast summary"
```

## galactic-router DaemonSets (EVPN tenant)

```bash
# Check pods are running
docker exec dfw-control-plane kubectl get pods -n galactic-system
docker exec iad-control-plane kubectl get pods -n galactic-system
docker exec sjc-control-plane kubectl get pods -n galactic-system

# Check EVPN routes via BGPRouter status
docker exec dfw-control-plane kubectl get bgprouters -A
docker exec iad-control-plane kubectl get bgprouters -A
docker exec sjc-control-plane kubectl get bgprouters -A
```

## Automated checks

```bash
task test           # run all verification (bgp-transit, bgp-fabric, srv6, evpn)
task test:bgp-transit
task test:bgp-fabric
task test:srv6
task test:evpn
```
