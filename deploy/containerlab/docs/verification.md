# Verification

Run these checks after `task deploy` to confirm the lab is healthy end-to-end. For
deploying and verifying the `ns10`/`ns20`/`ns30`/`ns40` test workloads,
see [docs/tenants.md](tenants.md).

## Bonds

Every datapath-carrying link is a two-member LACP bond (see the README's "Bonded
links"). Check these first: a member that never joined its aggregate leaves
everything below passing over the other member, with the datapath attachments
on the missing one never exercised.

```bash
# Every bond on both ends: two members, both collecting+distributing in the
# bond's active aggregator, with a real LACP partner
task verify:bonds

# One bond by hand -- expect both members "MII Status: up" with the same
# Aggregator ID, and a non-zero partner system MAC
docker exec dfw-worker2 cat /proc/net/bonding/bond0
docker exec clab-gvpc-tr1 cat /proc/net/bonding/bond1

# A member's LACP actor state: 63 (0x3f) is fully up; bits 0x30 are
# collecting+distributing
docker exec dfw-worker2 ip -d link show dev eth1 | grep -o 'ad_actor_oper_port_state [0-9]*'

# The datapaths attach to the members, never the master: expect an xdp
# program on eth1 and eth3 and none on bond0
docker exec dfw-worker2 ip -d link show dev eth1 | grep -o 'prog/xdp id [0-9]*'
docker exec dfw-worker2 ip -d link show dev eth3 | grep -o 'prog/xdp id [0-9]*'
docker exec dfw-worker2 ip -d link show dev bond0 | grep -o 'prog/xdp id [0-9]*' || echo "none on bond0"

# Take each member down in turn; BGP over the bond and reachability through
# it must hold. Disruptive, briefly -- not part of `task verify`
task verify:bond-failover
```

## Transit fabric

The transit underlay is dual-stack and runs one BGP session per address family on every
link, so each summary below has an IPv4 counterpart — both should be Established.

```bash
# iBGP full mesh — expect all sessions Established
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast summary"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv4 unicast summary"

# Each site's SRv6 locator /48 should be present on all TR nodes. This is the
# aggregate the site's compute node originates; it covers every node's /64 in
# that site, including ns10's USID (see docs/tenants.md).
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff01::/48"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff02::/48"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff03::/48"
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
and `11.1.40.2`, reachable from anywhere the transit reaches. It speaks no BGP
— `tr4` originates its subnets on its behalf, so a missing route here means
`tr4`'s `network` statements, not the host.

Its IPv4 address has to be globally reachable, because a shard refuses NAT64
to anything else, and every IPv4 documentation block is on that list. So the
lab uses `11.1.40.0/24`, one octet past the private `10.1.x.0/24` links, and
never announces it.

```bash
# The host itself, and what it serves
docker exec clab-gvpc-remote-host ip -brief addr show eth1
docker exec clab-gvpc-remote-host curl -sS http://[2001:db8:1:40::2]/

# Its subnets should be in every transit router's RIB, both families
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:1:40::/64"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv4 unicast 11.1.40.0/24"

# ...and in each site's fabric, which is what a tenant's egress path needs
docker exec dfw-control-plane kubectl exec -n galactic-system ds/fabric-router \
  -- vtysh -c "show bgp ipv6 unicast 2001:db8:1:40::/64"

# Reachable from an edge node (an egress shard's own vantage point)
docker exec dfw-worker2 curl -sS --max-time 5 http://[2001:db8:1:40::2]/
```

## Egress shards

Four edge nodes across three sites (`dfw-worker2`, `dfw-worker3`, `sjc-worker2`,
`iad-worker2`), each running its own shard. Every one of them also runs
`galactic-gateway`, so the shard runs from its own slot of the node's XDP
dispatcher (`GALACTIC_NAT_XDP_ATTACH=dispatch`) rather than attaching its own
program.

```bash
task verify:nat-sharding

# One galactic-nat pod per edge node
docker exec dfw-control-plane kubectl get pods -n galactic-system -o wide \
  -l app.kubernetes.io/name=galactic-nat

# The dispatcher's root program, on every member of both bonds (eth1-eth4);
# the shard and the gateway run from its slots
docker exec dfw-worker2 ip -d link show dev eth1 | grep -o 'prog/xdp id [0-9]*'
```

## Ingress gateway

The same four edge nodes each run `galactic-gateway` (`galactic-gateway-<node>`)
and a `NetworkGateway` named after the node. Each site has its own VIP
(`2001:db8:6060:1::1` in dfw, `:2::1` in sjc, `:3::1` in iad), in a `/64` only
that site's edge nodes originate, and two `ns60` backends on its compute node
that answer TCP and UDP on port 80 with their pod name and the client address
they saw. The site's `NetworkRule`s select both through their
`VPCAttachment`s, and the compute node writes one `ServiceVIPBinding` per rule
per backend. `verify:gateway-ingress` fails unless both backends answer.

```bash
# NetworkGateways Ready, NetworkRules Accepted, ServiceVIPBindings Bound
task verify:gateway

# TCP and UDP from remote-host to every site's VIP, pinned through each
# gateway node in turn; checks the replies and the datapath's counters
task verify:gateway-ingress

# Restart dfw-worker2's gateway, then its shard, while the other carries
# traffic (#710)
task verify:gateway-restart

# Turn dfw-worker2's datapath off; the ingress check must fail, then pass
# again. Disruptive -- not part of `task verify`
task verify:gateway-detach

# By hand: one TCP request to dfw's VIP, from the off-fabric host
echo probe | docker exec -i clab-gvpc-remote-host \
  socat -t2 -T3 - 'TCP6:[2001:db8:6060:1::1]:80'

# The datapath's own account of it, on a gateway node
docker exec dfw-worker2 curl -s http://localhost:8081/metrics \
  | grep -E '^galactic_edge_(rule|return)_packets_total'
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

The shard is the sender's own site's: every site's compute node egresses only
through that site's edge shards, so dfw's tenant leaves through
`dfw-worker2`'s. `verify:nat-local` asserts that for every site, by the
masquerade source `remote-host` sees.

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
docker exec dfw-control-plane kubectl -n ns10 exec "$pod" -- curl -sS --max-time 8 http://[2001:db8:64::b01:2802]/
```

The forward half passes on both families, and so does the SRv6 return path:
#549 gave a reply a path to the shard, and #550 gave the shard a usable
address to forward the un-translated reply on to -- the tenant node's own
End.DT46 SID rather than its uplink interface address, which nothing in the
underlay carries and no node decapsulates. A UDP round trip completes.

A TCP session still does not. The shard's forward leg XDP_PASSes into the
kernel and its return leg XDP_TXes around it, so conntrack sees the SYN and
never the SYN-ACK; the entry stays `SYN_SENT [UNREPLIED]`, the tenant's ACK is
marked INVALID, and kube-proxy's `KUBE-FORWARD` INVALID rule drops it. See
the README's Known limitations.

### Full-size segments

Every lab link is 1500 bytes and the fabric adds a 40-byte outer IPv6
header, so a pod with a 1500-byte interface advertises an MSS the path
cannot carry. Small requests work and every full-size segment is dropped,
at the shard as `fib_frag_needed`. The uSID datapath clamps the MSS in each
SYN to 1400 for IPv6 tenants and 1420 for IPv4.

`task verify:mss-clamp` checks every galactic-cni node reports those
limits, then moves 1 MiB from the off-fabric host to each site's ns10 pod
over NAT64 and NAT66, and 3 MB between sites for ns10 and ns20. It refuses
a pod whose default route has a cached `mtu`: such a pod advertises a
smaller MSS on its own and would pass with no clamp at all. Delete the pod
and re-run.

To see the clamp on the wire, capture SYNs at the off-fabric host while a
tenant opens a connection:

```bash
docker exec clab-gvpc-remote-host tcpdump -i eth1 -nn -v -c 1 \
  'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'
```

It shows `mss 1400`. Each node's counters are in
`galactic_usid_tcp_mss_clamp_syns_total{result}` on port 9180.

### Packets too big for the fabric

The largest tenant packet that crosses the fabric is 1460 bytes. A bigger
one gets an ICMPv6 Packet Too Big, or an ICMPv4 Fragmentation Needed for
an IPv4 tenant, from the tenant's own gateway on its own node, so its path
MTU discovery adapts.

`task verify:pmtu` checks every galactic-cni node reports
`galactic_usid_pmtu_limit_bytes` 1460, then:

- **Between sites.** A 1500-byte ping from dfw to sjc, for ns10 and ns20,
  must leave the sender's route with MTU 1460, and a 1460-byte ping must
  then get through.
- **Over NAT66.** A 1500-byte UDP datagram from each site's ns10 pod to the
  off-fabric host must leave the route with MTU 1460.
- **Counters.** Each sending node's
  `galactic_usid_pmtu_packets_total{result}` must show the errors sent and
  no packet refused without one.

The task flushes each pod's learned MTUs before and after, from the pod's
node, for the same reason as `verify:nat-icmp`.

### ICMP through a shard

`task verify:nat-icmp` runs from each site's ns10 pod toward the off-fabric
host:

- **Ping.** The shard translates the tenant's Echo Request with its Echo
  Identifier masqueraded in the port's place, and the reply comes back to
  the tenant's own Identifier.
- **Time Exceeded.** `mtr` has to name at least one transit router. Each
  router's Time Exceeded quotes an Echo Request the shard sent, so each hop
  that appears was matched and translated back. The first hop always shows
  `???`: the probe expires at the shard, which counts `hop_limit_exceeded`
  and sends no error of its own. netshoot's BusyBox `traceroute -I` shows
  no hops at all even when translation works, because BusyBox matches only
  errors that quote a UDP probe. Use `mtr` or UDP `traceroute`.
- **Packet Too Big.** The task narrows `tr4`'s link to the off-fabric host
  to 1300 bytes, sends a 1398-byte packet with DF set, and expects the
  tenant's route to learn MTU 1300 from the translated Packet Too Big. It
  restores the link and flushes the pod's learned MTU afterwards, from the
  pod's node, because the pod has no `NET_ADMIN` to do it itself. A
  leftover MTU of 1300 lowers the MSS the pod advertises and fails
  `verify:mss-clamp` for ten minutes.
- **NAT64.** The same three checks against the host's synthesized address,
  `2001:db8:64::b01:2802`. Each transit hop appears as its IPv4 address
  synthesized into the NAT64 prefix (`2001:db8:64::a01:b01` is
  `10.1.11.1`), and the Packet Too Big carries MTU 1320: the narrowed
  link's 1300 plus the 20 bytes the translation strips. NAT64 traceroute
  uses BusyBox's UDP mode on purpose. BusyBox matches an error on the
  probe's payload, so a hop only appears if the shard carried the whole
  quoted packet, not just its first 8 transport bytes.
- **Echo responder.** The off-fabric host pings each site's first shard's
  masquerade addresses. iad's shard has `GALACTIC_NAT_ECHO_RESPONDER` on
  and must answer both. The others must refuse both and count them as
  `icmp_unsolicited`.

- **Shard-sent Packet Too Big.** The tenant opens a UDP flow to the
  off-fabric host, and the host answers the flow's masquerade port with a
  1450-byte datagram. That fits every lab link but not the fabric once the
  shard re-encapsulates it, so the shard must tell the host itself. The
  host's route to the masquerade address has to learn MTU 1460 over NAT66,
  or 1440 over NAT64, which has 20 more bytes of translation. The task
  flushes the host's learned MTUs before and after.

The site's shard must count no ICMP drop reason, and no
`nat64_non_global_dest`, while the first six checks run.

### Non-global NAT64 destinations

`task verify:nat64-non-global` sends Echo Requests and a UDP datagram from
each site's ns10 pod to the synthesized form of `10.255.255.103` (`tr4`'s
loopback, which the lab can route to), `192.168.0.1` and `100.64.0.1`. The
site's first shard must answer none of them and count each packet as
`nat64_non_global_dest`.

### The reply's underlay path

A reply is addressed to the shard's masquerade address, and only the IPv6 one
is advertised anywhere — as an EVPN Type 5 path, inside `galactic-router`'s
iBGP mesh, which the plain-unicast transit never sees. Each shard node — an
edge node — therefore has its `fabric-router` originate both of its own
masquerade addresses into the underlay (a `/64` and a `/32`), along with its
shard SID's covering `/64`; see
`resources/fabric-router/dfw/frr.conf.dfw-worker2`. `verify:nat-return-route`
isolates that half of the return path from what the shard then does with the
packet: it asserts every transit router resolves both addresses to a BGP path
rather than to its own default, and that a probe from `remote-host` reaches
the shard's datapath.

```bash
task verify:nat-return-route

# By hand: the transit's view, which was the ::/0 default before #549
docker exec clab-gvpc-tr4 vtysh -c "show ipv6 route 2001:db8:9966:3::1"
docker exec clab-gvpc-tr4 vtysh -c "show ip route 192.0.2.3"
```

A probe with no connection row behind it is dropped by the shard by design, so
arrival is read from `galactic_nat_drops_total{reason="nat66_no_return_conn"}`
(and its `nat64_` counterpart) moving, which a packet that never reached the
XDP program could not do.

## Automated checks

```bash
task verify           # run all verification (bgp-transit, bgp-fabric, bgp-peers, underlay, srv6, evpn, gateway, nat, scenarios)
task verify:bgp-transit
task verify:bgp-fabric
task verify:bgp-peers
task verify:underlay
task verify:srv6
task verify:evpn
task verify:gateway
task verify:gateway-ingress
task verify:gateway-restart
```
