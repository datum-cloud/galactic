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

# tr1 -> an edge node, and -> the route reflector every overlay session
# depends on being able to reach
docker exec clab-gvpc-tr1 ping -6 -c2 -I fc00:0:1::1 fc00:0:a::1
docker exec clab-gvpc-tr1 ping -6 -c2 -I fc00:0:1::1 fc00:0:8::1

# Every loopback in one shot (IPv4 and IPv6), non-zero exit on any failure
task verify:underlay

# What a transit router actually learned over IPv4 — expect one /32 per node
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv4 unicast"

# The worker side of the same session, from inside the fabric-router pod
docker exec dfw-control-plane kubectl exec -n galactic-system ds/fabric-router \
  -- vtysh -c "show bgp ipv4 unicast summary"
```

## FRR DaemonSets (site fabric)

Only edge nodes peer with the transit. A compute node or the route reflector shows exactly
one neighbour — its site's edge node — and an edge node shows its transit router plus
whatever sits behind it.

```bash
# Per-node, rather than per-site: `ds/fabric-router` picks an arbitrary pod,
# and the roles differ. -o wide names the node each pod is on.
docker exec dfw-control-plane kubectl get pods -n galactic-system -o wide \
  -l app.kubernetes.io/name=fabric-router

# An edge node: expect the transit router as an eBGP (AS 65100) neighbour,
# plus its site-internal iBGP clients
docker exec dfw-control-plane kubectl exec -n galactic-system <edge-pod> \
  -- vtysh -c "show bgp ipv6 unicast summary"

# A compute node: expect exactly one neighbour, its edge node, AS 65000
docker exec dfw-control-plane kubectl exec -n galactic-system <compute-pod> \
  -- vtysh -c "show bgp ipv6 unicast summary"

# The edge node should be passing the whole fabric down to it with
# next-hop-self, so every remote site's locator resolves via the edge node
docker exec dfw-control-plane kubectl exec -n galactic-system <compute-pod> \
  -- vtysh -c "show bgp ipv6 unicast 2001:db8:ff03::/48"
```

## FRR DaemonSets (all sites at a glance)

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

## Off-fabric host (remote-host)

`remote-host` hangs off `tr4` and is in no cluster: nginx on `2001:db8:1:40::2`
and `10.1.40.2`, reachable from anywhere the transit reaches. It speaks no BGP
— `tr4` originates its subnets on its behalf, so a missing route here means
`tr4`'s `network` statements, not the host.

```bash
# The host itself, and what it serves
docker exec clab-gvpc-remote-host ip -brief addr show eth1
docker exec clab-gvpc-remote-host curl -sS http://[2001:db8:1:40::2]/

# Its subnets should be in every transit router's RIB, both families
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:1:40::/64"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv4 unicast 10.1.40.0/24"

# ...and in each site's fabric, which is what a tenant's egress path needs
docker exec dfw-control-plane kubectl exec -n galactic-system ds/fabric-router \
  -- vtysh -c "show bgp ipv6 unicast 2001:db8:1:40::/64"

# Reachable from a compute node (the NAT66 shard's own vantage point)
docker exec dfw-worker curl -sS --max-time 5 http://[2001:db8:1:40::2]/

# And the reverse direction: the off-fabric client curling an anycast
# ingress VIP, which is what the edge gateways exist to answer
docker exec clab-gvpc-remote-host curl -sS --max-time 5 http://[2001:db8:6060::1]/
```

## Edge gateways

Four edge nodes across three sites (`dfw-worker2`, `dfw-worker3`, `sjc-worker2`,
`iad-worker2`), all originating the same anycast VIP.

```bash
task verify:gateway

# Every edge node's own gateway DaemonSet should be Ready on its pinned node
docker exec dfw-control-plane kubectl get pods -n galactic-system -o wide \
  -l app.kubernetes.io/name=galactic-gateway

# The VIP aggregate each edge node's FRR originates -- dfw should show two
# equal-cost paths (one per edge node), sjc and iad one each
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:6060::/48"
```

## EVPN route reflector

`iad-worker3` is the single reflector for all three clusters; every
galactic-router is a client of it. A client stuck in `Active` is almost always
an underlay problem (its loopback or the reflector's `fc00:0:8::1` not
reachable), not an EVPN one.

```bash
# Every client session, from the reflector's own side
docker exec iad-control-plane kubectl get bgppeers -n galactic-system

# Seven clients are expected: three compute nodes and four edge nodes
docker exec iad-control-plane kubectl get bgppeers -n galactic-system \
  --no-headers | wc -l
```

## Egress datapath, end to end

`verify:nat-egress` proves a translated packet reached the wire. It does not
prove the packet arrived anywhere or that a reply came back, so it passes on a
datapath where no session completes. `verify:nat-datapath` drives real traffic
to `remote-host` instead — the one node outside every cluster — and asserts
both directions on both families.

```bash
task verify:nat-datapath
```

IPv6 leaves as NAT66, masqueraded to the shard's IPv6 public address. IPv4
leaves as NAT64: an IPv6-only tenant addresses the destination's synthesized
form (the fabric NAT64 prefix with the IPv4 address in the low 32 bits) and the
shard translates it down to IPv4.

```bash
# What the far end actually sees, by hand
docker exec clab-gvpc-remote-host tcpdump -i eth1 -nn 'tcp port 80'

# The tenant side of the same request
pod=$(docker exec dfw-control-plane kubectl -n ns10 get pods -o jsonpath='{.items[0].metadata.name}')
docker exec dfw-control-plane kubectl -n ns10 exec "$pod" -- curl -sS --max-time 8 http://[2001:db8:1:40::2]/
docker exec dfw-control-plane kubectl -n ns10 exec "$pod" -- curl -sS --max-time 8 http://[2001:db8:64::a01:2802]/
```

The forward half passes on both families today; the return half fails on both.
See the README's Known limitations.

## Automated checks

```bash
task verify           # run all verification (bgp-transit, bgp-fabric, bgp-peers, underlay, srv6, evpn, gateway, nat66, scenarios)
task verify:bgp-transit
task verify:bgp-fabric
task verify:bgp-peers
task verify:underlay
task verify:srv6
task verify:evpn
```
