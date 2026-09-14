# Galactic VPC Lab Deployment

Three Kind clusters (dfw, iad, sjc) connected over an SRv6 transit mesh. The transit
(underlay) network is dual-stack: every transit link and loopback carries both an IPv4 and
an IPv6 address, and each link runs one BGP session per address family. Each cluster runs
FRR as a node routing daemon (hostNetwork DaemonSet) to peer with the transit layer via
eBGP over those numbered links. galactic-router runs alongside FRR on the workers to distribute EVPN routes
over iBGP to the single route reflector, `iad-worker3`.

The SRv6 data plane itself is IPv6-only and unchanged — tenant IPv4 (`ns20`, `ns40`) rides
inside SRv6 encapsulation and never reaches the IPv4 underlay FIB. IPv4 on the transit
exists so the underlay is reachable over both families (loopback-to-loopback), not to carry
tenant traffic.

## Topology

```
   dfw-worker ─┬─┐                              ┌─ sjc-worker
     (compute) │ │                              │   (compute)
                ▼ ▼                            ▼
        dfw-worker2 ─eth1─ tr1 ────────── tr2 ─eth1─ sjc-worker2
        dfw-worker3 ─eth5─  │ ╲          ╱ │             (edge)
             (edge)         │  tr3 ─ tr4   │
                            │ ╱         ╲  │ ─eth4─ remote-host
                           (mesh)      (mesh)           (nginx)
                       tr3 ─eth4─ iad-worker2 ◀─ iad-worker  (compute)
                                     (edge)   ◀─ iad-worker3 (EVPN RR)
```

Only edge nodes touch the transit. Each holds the eBGP session to its site's
transit router, and every other worker in the site sits behind it, reaching
the fabric over an iBGP session to that edge node — compute nodes and the
route reflector have no transit uplink and no eBGP session anywhere.

`dfw-worker` is **dual-homed**, one link to each of dfw's two edge nodes, so
losing an edge node does not take the site's compute node off the fabric with
it. sjc and iad have a single edge node each and nothing to dual-home to. The
second link is a backup rather than an equal path — see the BGP design below
for why.

Every worker's role comes from its labels alone — Kind's sequential names
(`<cluster>-worker`, `-worker2`, `-worker3`) are used as-is, with no renaming
step. `remote-host` is the one node outside every cluster: a plain nginx host
hanging off `tr4`, the transit router with no site attached.

### Node roles

| Node                | Kind          | Role                                                             |
|---------------------|---------------|------------------------------------------------------------------|
| `dfw-control-plane` | ext-container | Kind control-plane; runs Cilium, Multus                          |
| `dfw-worker`        | ext-container | compute: FRR PE, galactic-router PE, galactic-cni, egress shard  |
| `dfw-worker2`       | ext-container | edge: FRR PE, galactic-router PE, galactic-cni, galactic-gateway |
| `dfw-worker3`       | ext-container | edge: second gateway of dfw's active-active pair                 |
| `sjc-control-plane` | ext-container | Kind control-plane; runs Cilium, Multus                          |
| `sjc-worker`        | ext-container | compute: FRR PE, galactic-router PE, galactic-cni, egress shard  |
| `sjc-worker2`       | ext-container | edge: FRR PE, galactic-router PE, galactic-cni, galactic-gateway |
| `iad-control-plane` | ext-container | Kind control-plane; runs Cilium, Multus                          |
| `iad-worker`        | ext-container | compute: FRR PE, galactic-router PE, galactic-cni, egress shard  |
| `iad-worker2`       | ext-container | edge: FRR PE, galactic-router PE, galactic-cni, galactic-gateway |
| `iad-worker3`       | ext-container | EVPN route reflector for all three clusters; FRR PE only         |
| `tr1`–`tr4`         | linux (FRR)   | iBGP full mesh, AS 65100                                         |
| `remote-host`       | linux (nginx) | off-fabric host on `tr4`; runs no Galactic component, no BGP     |

Every edge node is tainted (`galactic.datumapis.com/node=edge:NoSchedule`) and so is the
route reflector (`galactic.datumapis.com/galactic=control:NoSchedule`): no tenant pods land
on either, only DaemonSets with a blanket toleration. Edge nodes run `galactic-cni` and
plain-mode `galactic-router` as their own independent DaemonSets, exactly like compute
nodes, plus their own single-container `galactic-gateway`. They never run `galactic-nat`
(compute-only). The reflector runs neither `galactic-cni` nor the gateway — its
`galactic=control` label is mutually exclusive with the `galactic=router` value that pulls
those in, which is why the reflector needs a worker of its own (see
[docs/node-labels.md](../../docs/node-labels.md)).

Real end-to-end ingress traffic through the edge datapath is **live-validated** — three
stacked issues were found and fixed along the way, not one: (1) IPv6 forwarding sysctls
weren't enabled (fixed, `sysctl.ConfigureFIBLookupUplinkSysctls`); (2) veth's native
`XDP_TX` fast path does not deliver a frame to the peer interface's normal receive stack at
all unless the peer *also* runs an XDP program — confirmed live via a real destination-side
packet counter, not just `tcpdump` invisibility. Worked around for this lab specifically,
not by converting `edgedsr.c`'s production datapath from XDP to TC (a real gateway's public
uplink is a physical NIC, where this veth-specific behavior doesn't apply, and XDP's
throughput advantage is exactly why that datapath uses it): `task deploy:lab-xdp-passthrough`
loads a trivial pass-through XDP program on every edge-facing transit port
(`node_files/common/xdp-passthrough.c`), already wired into `task deploy`. (3)
`vip_xlat_table`'s veth-kind delivery gap and its identical-VIP/backend-port key collision,
both fixed in galactic. See the redesign plan's
[§8](../../docs/plans/dsr-maglev-nptv6-nat66-gateway-redesign.md#8-containerlab-validation) for
the full account, and `resources/galactic-gateway/`.

The NAT/default-egress gap that validation surfaced (no tenant VRF had any route out at
all) is now closed: `task deploy:galactic-nat` stands up the sharded NAT egress tier on the
three site compute workers as shards (`resources/galactic-nat/`), and every CNI ADD now
installs a default route toward those shards' advertised SIDs
(`internal/plumbing/srv6.EgressDefaultRouteAdd`, `internal/cnibgp`) — see
`resources/galactic-nat/README.md` for the full mechanism. `remote-host` is what that
egress path now has to reach: nginx on `2001:db8:1:40::2` and `10.1.40.2`, outside every
cluster, advertised into the fabric by `tr4` on the host's behalf.

`dfw`, `iad`, and `sjc` are the three Kind cluster names — not separate ContainerLab
topology nodes. Each cluster's `control-plane`/`worker` nodes above are its members.

### BGP design

```
underlay (FRR fabric, IPv6 + IPv4 unicast)
  edge nodes only     ──eBGP──▶  their own site's TR (AS 65100)
    dfw-worker2 ── tr1:eth1     dfw-worker3 ── tr1:eth5
    sjc-worker2 ── tr2:eth1     iad-worker2 ── tr3:eth4

  everything else     ──iBGP──▶  its own site's edge node (AS 65000)
    dfw-worker  ──▶ dfw-worker2     sjc-worker  ──▶ sjc-worker2
    iad-worker  ──▶ iad-worker2     iad-worker3 ──▶ iad-worker2

overlay (galactic-router, l2vpn/evpn)
  dfw-worker, dfw-worker2, dfw-worker3  ─┐
  sjc-worker, sjc-worker2               ─┼─iBGP─▶  iad-worker3 (AS 65000 RR)
  iad-worker, iad-worker2               ─┘
```

- All clusters use a single AS (65000) for both the FRR fabric and the galactic-router tenant.
- The transit mesh carries IPv6 unicast (SRv6 locator prefixes and loopbacks) via iBGP within AS 65100.
- Every transit link runs **two** BGP sessions, one per address family: the existing IPv6 session
  (unnumbered `interface` peers inside the TR mesh, numbered global addresses toward the workers)
  plus a numbered IPv4 session. One session per family rather than one multiprotocol session with
  extended next-hop (RFC 8950) keeps `show bgp ipv4 unicast summary` readable and avoids relying on
  IPv4-over-IPv6-next-hop resolution in the kernel FIB.
- The IPv4 address family carries per-node `/32` loopbacks only. There is no IPv4 counterpart to the
  SRv6 locator block, and the numbered link subnets are never redistributed — so a ping between
  underlay nodes must be sourced from a loopback (`task verify:underlay` does this).
- FRR PE nodes originate their per-node SRv6 locator block (`2001:db8:ffXX:100::/56`) and BGP peering loopback (`fc00:0:X::1/128`) toward the transit layer via eBGP over numbered links — never the site's full `/48` uSID Block or loopback pool, which would create an anycast ambiguity once a second worker joins a site.
- `allowas-in 1` is configured on all cluster FRR instances so each site accepts prefixes that carry AS 65000 in the path — necessary because the transit reflects routes from one AS 65000 site to another.
- **Only edge nodes are transit-facing.** They alone hold eBGP sessions to AS 65100; a compute node or the route reflector has no link to a transit router and no eBGP session anywhere. Each site's edge node is its border router.
- Everything behind an edge node reaches the fabric over an iBGP session to it. The edge node sets `next-hop-self force` on those sessions (a path learned from the transit carries the transit router's own address as next hop, which the node behind it has no route to; `force` is required because plain `next-hop-self` is not applied to *reflected* paths — a route reflector preserves the originator's NEXT_HOP by design, RFC 4456 §10) and `route-reflector-client` (iBGP split horizon would otherwise stop it passing one client's prefixes to another — iad has two behind it).
- **`dfw-worker`'s second uplink is a backup, not an equal path.** `galactic-nat`'s shard XDP program attaches to a single interface (`GALACTIC_NAT_UPLINK_INTERFACE`, `eth1`), so egress-shard traffic from another site arriving on `eth2` would reach no translation program at all and be forwarded untranslated. `dfw-worker` tags what it advertises over `eth2` with community `65000:900`; `dfw-worker3` matches that tag and re-advertises to `tr1` with `MED 100`, so the fabric keeps using `dfw-worker2` while that path is up, and `dfw-worker` sets `local-preference 90` on what it learns over `eth2` so its own egress prefers `eth1` too. `dfw-worker3`'s *own* originations are deliberately not de-preferred — the anycast ingress VIP has to stay equal-cost from both edge nodes.
- The uSID decap hook does attach to both of `dfw-worker`'s uplinks (`GALACTIC_CNI_EBPF_INTERFACES` is `eth1,eth2` in dfw, `eth1` elsewhere), so ordinary tenant traffic survives a failover. The egress-shard role does not — see Known limitations.
- Edge and compute nodes exchange EVPN paths over iBGP **through the reflector**, never as direct sessions between them: `iad-worker3` is the lab's single route reflector and every galactic-router in all three clusters is a client of it. A node cannot be both a reflector and a compute/edge node, since `galactic=control` and `galactic=router` are two values of one label key.
- galactic-router runs with outbound-only mode (`listenPort=-1`) on every client; only the reflector listens, on port `1790`. All sessions are initiated outbound toward it.

## Addressing

Every underlay address below is dual-stack. The IPv4 loopbacks were chosen to match each
node's pre-existing `bgp router-id`, so router-id and loopback are the same value everywhere.

### Transit loopbacks

| Node | IPv6 loopback   | IPv4 loopback     |
|------|-----------------|-------------------|
| tr1  | fc00:0:1::1/128 | 10.255.255.100/32 |
| tr2  | fc00:0:5::1/128 | 10.255.255.101/32 |
| tr3  | fc00:0:6::1/128 | 10.255.255.102/32 |
| tr4  | fc00:0:7::1/128 | 10.255.255.103/32 |

### Fabric (worker) loopbacks

| Node        | Role    | IPv6 loopback   | IPv4 loopback   |
|-------------|---------|-----------------|-----------------|
| iad-worker  | compute | fc00:0:4::1/128 | 10.255.255.1/32 |
| dfw-worker  | compute | fc00:0:2::1/128 | 10.255.255.2/32 |
| sjc-worker  | compute | fc00:0:3::1/128 | 10.255.255.3/32 |
| iad-worker3 | EVPN RR | fc00:0:8::1/128 | 10.255.255.4/32 |
| iad-worker2 | edge    | fc00:0:9::1/128 | 10.255.255.5/32 |
| dfw-worker2 | edge    | fc00:0:a::1/128 | 10.255.255.6/32 |
| dfw-worker3 | edge    | fc00:0:b::1/128 | 10.255.255.7/32 |
| sjc-worker2 | edge    | fc00:0:c::1/128 | 10.255.255.8/32 |

### TR–TR point-to-point links (numbered)

The host octet/hextet is the transit router's own index on both families, so `10.0.13.3`
and `2001:db8:0:13::3` are both tr3 on the tr1–tr3 link.

| Link    | IPv6 subnet        | IPv4 subnet  |
|---------|--------------------|--------------|
| tr1–tr2 | 2001:db8:0:12::/64 | 10.0.12.0/24 |
| tr1–tr3 | 2001:db8:0:13::/64 | 10.0.13.0/24 |
| tr1–tr4 | 2001:db8:0:14::/64 | 10.0.14.0/24 |
| tr2–tr3 | 2001:db8:0:23::/64 | 10.0.23.0/24 |
| tr2–tr4 | 2001:db8:0:24::/64 | 10.0.24.0/24 |
| tr3–tr4 | 2001:db8:0:34::/64 | 10.0.34.0/24 |

### Edge uplinks (numbered, eBGP to the transit)

The TR takes `::1`/`.1` and the edge node `::2`/`.2`. The third hextet group encodes the
site (`1x` dfw, `2x` sjc, `3x` iad) and the node within it; the IPv4 third octet mirrors it
exactly. `remote-host` is not a worker and runs no BGP — `tr4` originates its subnets on
its behalf.

| Link                   | IPv6 subnet        | TR address       | Edge address     | IPv4 subnet  | TR address | Edge address |
|------------------------|--------------------|------------------|------------------|--------------|------------|--------------|
| dfw-worker2 – tr1:eth1 | 2001:db8:1:11::/64 | 2001:db8:1:11::1 | 2001:db8:1:11::2 | 10.1.11.0/24 | 10.1.11.1  | 10.1.11.2    |
| dfw-worker3 – tr1:eth5 | 2001:db8:1:12::/64 | 2001:db8:1:12::1 | 2001:db8:1:12::2 | 10.1.12.0/24 | 10.1.12.1  | 10.1.12.2    |
| sjc-worker2 – tr2:eth1 | 2001:db8:1:21::/64 | 2001:db8:1:21::1 | 2001:db8:1:21::2 | 10.1.21.0/24 | 10.1.21.1  | 10.1.21.2    |
| iad-worker2 – tr3:eth4 | 2001:db8:1:32::/64 | 2001:db8:1:32::1 | 2001:db8:1:32::2 | 10.1.32.0/24 | 10.1.32.1  | 10.1.32.2    |
| remote-host – tr4:eth4 | 2001:db8:1:40::/64 | 2001:db8:1:40::1 | 2001:db8:1:40::2 | 10.1.40.0/24 | 10.1.40.1  | 10.1.40.2    |

### Site-internal links (numbered, iBGP to the site's edge node)

Same convention with the edge node in the router's seat: it takes `::1`/`.1`, the worker
behind it `::2`/`.2`.

| Link                           | IPv6 subnet        | Edge address     | Node address     | IPv4 subnet  | Edge address | Node address |
|--------------------------------|--------------------|------------------|------------------|--------------|--------------|--------------|
| dfw-worker – dfw-worker2:eth2  | 2001:db8:1:10::/64 | 2001:db8:1:10::1 | 2001:db8:1:10::2 | 10.1.10.0/24 | 10.1.10.1    | 10.1.10.2    |
| dfw-worker – dfw-worker3:eth2  | 2001:db8:1:13::/64 | 2001:db8:1:13::1 | 2001:db8:1:13::2 | 10.1.13.0/24 | 10.1.13.1    | 10.1.13.2    |
| sjc-worker – sjc-worker2:eth2  | 2001:db8:1:20::/64 | 2001:db8:1:20::1 | 2001:db8:1:20::2 | 10.1.20.0/24 | 10.1.20.1    | 10.1.20.2    |
| iad-worker – iad-worker2:eth2  | 2001:db8:1:30::/64 | 2001:db8:1:30::1 | 2001:db8:1:30::2 | 10.1.30.0/24 | 10.1.30.1    | 10.1.30.2    |
| iad-worker3 – iad-worker2:eth3 | 2001:db8:1:31::/64 | 2001:db8:1:31::1 | 2001:db8:1:31::2 | 10.1.31.0/24 | 10.1.31.1    | 10.1.31.2    |

### Cluster SRv6 addressing

Each worker has a standalone blackhole route (no interface needed) covering its
whole `/56` locator block (metric 2048, lower priority than any pod's seg6local
route at metric 1024 — IPv6 FIB lookup is longest-prefix-match first, so a real
`/128` decap route always wins regardless of metric). The blackhole prevents the
default route from matching any USID this node could compute before or without
a matching seg6local route installed, for any current or future VPC — not just
the ones with a pod running today. The FRR fabric DaemonSet advertises the same
`/56` into the transit mesh via a static Null0 route + BGP `network` statement.

Each site's compute node advertises its own `/56` SRv6 locator block into the
fabric — never the site's full `/48` uSID Block, which would create an
anycast ambiguity the instant a second compute node joins a site. The test VPC
`ns10` (see [docs/tenants.md](docs/tenants.md)) gets a host address within its node's
block (illustrative only — the exact hextet depends on allocation order; see
docs/tenants.md's [SRv6 USID Argument allocation](docs/tenants.md#srv6-usid-argument-allocation)):

| Cluster | Compute node | FRR loopback    | Node locator block     | USID ns10                    |
|---------|--------------|-----------------|------------------------|------------------------------|
| dfw     | dfw-worker   | fc00:0:2::1/128 | 2001:db8:ff01:100::/56 | 2001:db8:ff01:100:c800::/128 |
| sjc     | sjc-worker   | fc00:0:3::1/128 | 2001:db8:ff02:100::/56 | 2001:db8:ff02:100:c800::/128 |
| iad     | iad-worker   | fc00:0:4::1/128 | 2001:db8:ff03:100::/56 | 2001:db8:ff03:100:c800::/128 |

The `galactic-router address` column is no longer set explicitly in the
per-cluster Kustomize patches — `galactic-router` auto-detects it from `lo`
at startup (see `docs/router/configuration.md`), since it always matches the
FRR loopback address on the same host.

### Edge node self-addressing

Each edge node gets a uFMT 48+16 uSID over its own site's locator, at the reserved
Argument 0 (never registered into any tenant VRF — see
`internal/plumbing/ebpf/uformat.go`'s `ArgumentMin`). Unlike a tenant's per-VPC uSID,
`srv6.ComputeSID` can't derive this value (it rejects `argument==0` by design), so these
were computed directly via `internal/plumbing/ebpf/uformat.Encode` and are supplied
statically through `GALACTIC_GATEWAY_SRV6_ADDRESS` — see
`resources/galactic-gateway/<node>/node-patch.yaml`.

Node-IDs are per site, and a site's compute worker always takes 1: within `2001:db8:ff01::/48`,
`dfw-worker` is nodeID 1, its two edge nodes are 2 and 3, and the egress shard is 9.

| Node        | Site locator       | nodeID | SRv6 self-address (Argument 0) |
|-------------|--------------------|--------|--------------------------------|
| dfw-worker2 | 2001:db8:ff01::/48 | 2      | 2001:db8:ff01:2:e000::         |
| dfw-worker3 | 2001:db8:ff01::/48 | 3      | 2001:db8:ff01:3:e000::         |
| sjc-worker2 | 2001:db8:ff02::/48 | 2      | 2001:db8:ff02:2:e000::         |
| iad-worker2 | 2001:db8:ff03::/48 | 2      | 2001:db8:ff03:2:e000::         |

All four originate the same anycast ingress VIP aggregate (`2001:db8:6060::/48`) into the
underlay, and each site's `NetworkRule` binds the same VIP `2001:db8:6060::1` to its own
site-local `ns60` backend — one anycast service, three sites, four gateways.

### Management network (fc00:10::/64)

| Node              | Address      |
|-------------------|--------------|
| dfw-control-plane | fc00:10::102 |
| dfw-worker        | fc00:10::103 |
| dfw-worker2       | fc00:10::104 |
| dfw-worker3       | fc00:10::105 |
| iad-control-plane | fc00:10::112 |
| iad-worker        | fc00:10::113 |
| iad-worker2       | fc00:10::114 |
| iad-worker3       | fc00:10::115 |
| sjc-control-plane | fc00:10::122 |
| sjc-worker        | fc00:10::123 |
| sjc-worker2       | fc00:10::124 |

## Known limitations

- **Tenant egress is one-way.** The forward half works on both families and is
  proven end to end by `task verify:nat-datapath`: a tenant's traffic reaches
  `remote-host`, outside every cluster, masqueraded to the shard's own public
  address. Nothing that answers gets back, for two independent reasons — the
  masquerade address is advertised only into the EVPN overlay and never into
  the unicast underlay the outside world routes on
  ([#549](https://github.com/datum-cloud/galactic/issues/549)), and a shard
  cannot forward a reply back to a tenant it does not itself host
  ([#550](https://github.com/datum-cloud/galactic/issues/550)) — which is every
  tenant, since a node never uses its own shard. `verify:nat-datapath` is
  therefore expected to fail today and is deliberately kept out of the `verify`
  chain; move it in once those land.
- **A dual-homed node's egress-shard role does not survive failover.**
  `galactic-nat` takes a single `GALACTIC_NAT_UPLINK_INTERFACE` and attaches
  its shard XDP program to that one interface, so if `dfw-worker`'s traffic
  ever shifts to `eth2`, egress traffic from other sites reaches no
  translation program. BGP policy keeps that from happening while `eth1` is
  up, but an `eth1` failure degrades the shard role rather than failing over
  it. The uSID decap hook has no such limit — it takes a list.
- **The tenant egress route resolves its outgoing link once, at CNI ADD.**
  `srv6.EgressPrefixRouteAdd` stores the resolved `ifindex` in
  `egress_route_table`, and nothing re-resolves it when routing changes. A pod
  attached before its site's underlay has converged keeps sending egress
  traffic out whichever interface was correct at that moment — in practice
  `eth0`, the Kind management bridge — with no drop counter and no error.
  Re-attaching the workload (scale to 0, wait, scale back) rewrites it.
- **`galactic_nat_drops_total` is cumulative and survives a pod restart**, so
  `task verify:nat-egress` fails on drops recorded during any earlier
  transient, not just current ones. The counters live in a pinned map;
  clearing one needs `bpftool map update` against it directly.
- Replacing a pod on an existing VPCAttachment races with its own teardown:
  the host veth is named per VPC/attachment rather than per container, so the
  replacement's ADD removes the veth the terminating pod still holds. Scale to
  0 and wait before scaling back rather than deleting a pod in place.

## Lab layout

```
deploy/containerlab/
├── gvpc.clab.yaml
├── Taskfile.yaml
├── containers/
│   └── kindest-node-galactic/   # Custom Kind node image (git/tcpdump, kubectl DooD wrapper)
├── resources/
│   ├── galactic-cni/            # galactic-cni installer DaemonSet + ConfigMap
│   ├── fabric-router/           # FRR DaemonSet per-site overlays (dfw, iad, sjc),
│   │                            #   one frr.conf.<nodename> per worker
│   ├── galactic-router/         # galactic-router DaemonSet + BGP CRs, compute nodes
│   ├── galactic-control/iad/    # the EVPN route reflector + one BGPPeer per client
│   ├── galactic-gateway/        # per-edge-node overlays (dfw-worker2, dfw-worker3,
│   │                            #   sjc-worker2, iad-worker2) + per-site VIP rules
│   ├── galactic-nat/          # egress shard per site, on that site's compute node
│   └── tenants/                 # test VPCs — one shared base/ (Namespace + netshoot
│       ├── base/                 # Deployment), each tenant patching its namespace and
│       ├── ns10/                 # default-network annotation; per-site dirs hold each
│       ├── ns20/                 # site's NAD(s): ns10 (IPv6-only, 3-site), ns20
│       ├── ns30/                 # (dual-stack, 3-site), ns30 (IPv6-only, dfw only, 2
│       └── ns40/                 # attachments), ns40 (IPv4-only, iad only, 2
│                                  # attachments) — ns30/ns40's two attachments are each
│                                  # their own NAD+Deployment (distinct vpcattachment,
│                                  # same vpc), not one NAD scaled to replicas: 2 — see
│                                  # docs/tenants.md for why.
├── node_files/
│   ├── dfw/          config.yaml
│   ├── iad/          config.yaml
│   ├── sjc/          config.yaml
│   ├── tr1/          frr.conf  startup.sh
│   ├── tr2/          frr.conf  startup.sh
│   ├── tr3/          frr.conf  startup.sh
│   ├── tr4/          frr.conf  startup.sh
│   └── remote-host/  startup.sh
├── group_files/
│   ├── common/  hosts  vtysh.conf  startup-lib.sh
│   └── transit/ daemons
└── scripts/
    ├── host-setup.sh
    ├── lib.sh
    ├── deploy-system.sh
    ├── deploy-cni.sh
    ├── deploy-fabric.sh
    ├── deploy-galactic-router.sh
    └── deploy-ns.sh
```

## Prerequisites

- ContainerLab >= 0.54
- Docker
- `kind` CLI
- Host kernel with SRv6 support

## Quick start

```bash
cd deploy/containerlab
task deploy   # build all images, apply host sysctls, deploy lab end-to-end
```

To tear down and start fresh:

```bash
task destroy  # remove all lab containers and Kind clusters
task clean    # destroy + delete built images and lab artifacts
task deploy
```

## Tasks

| Task                     | Description                                                                   |
|--------------------------|-------------------------------------------------------------------------------|
| `build`                  | Build all container images (node, galactic-router, galactic-cni, frr, host)   |
| `build:node`             | Build the custom `kindest/node:galactic` image                                |
| `build:galactic-router`  | Build the galactic-router container from Go source                            |
| `build:galactic-cni`     | Build the galactic-cni installer image                                        |
| `build:frr`              | Build the FRR container from Alpine edge                                      |
| `build:remote-host`      | Build the off-fabric nginx host image                                         |
| `deploy`                 | Build images, apply host sysctls, and deploy the lab                          |
| `deploy:topology`        | Deploy the ContainerLab topology (transit routers)                            |
| `deploy:clusters`        | Create the three Kind clusters and export their kubeconfigs                   |
| `deploy:images`          | Load container images into Kind clusters                                      |
| `deploy:system`          | Install BGP and VPC CRDs; apply the galactic-system namespace and shared RBAC |
| `deploy:cni`             | Install Cilium and Multus, then the galactic-cni DaemonSet                    |
| `deploy:fabric`          | Apply FRR DaemonSets to all clusters                                          |
| `deploy:galactic-router` | Apply galactic-router DaemonSets and BGP CRs                                  |
| `deploy:scenarios`       | Deploy all VPC test scenarios                                                 |
| `deploy:ns10`            | Deploy ns10 test VPC (IPv6-only, fd20 ULA)                                    |
| `deploy:ns20`            | Deploy ns20 test VPC (dual-stack, fd20 ULA + IPv4)                            |
| `deploy:ns30`            | Deploy ns30 test VPC (dfw only, 2 pods)                                       |
| `deploy:ns40`            | Deploy ns40 test VPC (iad only, 2 pods)                                       |
| `verify:underlay`        | Ping every underlay loopback from tr1 over both IPv4 and IPv6                 |
| `verify:nat-datapath`    | Full egress round trip to the off-fabric host, IPv6 (NAT66) and IPv4 (NAT64)  |
| `verify:scenarios`       | Verify ping across all VPC test scenarios                                     |
| `verify:ns10`            | Verify ns10 ping (IPv6-only, 3-site mesh)                                     |
| `verify:ns20`            | Verify ns20 ping (dual-stack, 3-site mesh)                                    |
| `verify:ns30`            | Verify ns30 ping (dfw only, 2 pods)                                           |
| `verify:ns40`            | Verify ns40 ping (iad only, 2 pods)                                           |
| `verify:gateway`         | Verify every site's edge gateway CRDs and DaemonSets                          |
| `destroy`                | Destroy the lab and remove all Kind clusters                                  |
| `restart`                | Full rebuild — destroy then redeploy                                          |
| `rebuild`                | Full rebuild — clean (destroy + delete images/artifacts) then redeploy        |
| `inspect`                | Show running nodes and management addresses                                   |
| `graph`                  | Generate a draw.io diagram for the topology                                   |
| `host-setup`             | Apply required host sysctls (IPv6 forwarding, inotify limits)                 |
| `clean`                  | Destroy lab, delete built images, and remove lab artifacts                    |
| `test`                   | Run all verification checks                                                   |

## Verification

See [docs/verification.md](docs/verification.md) for transit fabric, FRR, and galactic-router
health checks, and [docs/tenants.md](docs/tenants.md) for deploying and verifying
the `ns10`/`ns20`/`ns30`/`ns40` test VPCs.

`task verify` (and its constituent `task verify:scenarios`) also pings every
VPC's pods end-to-end via `task verify:ns10`/`ns20`/`ns30`/`ns40` —
full site-pair mesh for the 3-site VPCs, both-direction pod-to-pod for the
single-site `ns30`/`ns40`. Run one on its own after redeploying a single
scenario, e.g. `task verify:ns30` after `task deploy:ns30`.

Quick smoke test:

```bash
task verify  # automated: bgp-transit, bgp-fabric, bgp-peers, srv6, evpn
```

## Notes

- All three Kind clusters use `disableDefaultCNI: true`. Cilium and Multus are installed
  by `scripts/deploy-cni.sh` (task `deploy:cni`); the BGP (datum-cloud/network) and VPC
  (datum-cloud/cloud) CRDs are installed by `scripts/deploy-system.sh` (task `deploy:system`).
  Neither is baked into the `kindest/node:galactic` image.
- Every link is dual-stack: numbered IPv6 (/64) and IPv4 (/24) subnets, each carrying its own
  BGP session — eBGP on the edge uplinks, iBGP on the site-internal links.
- Kind worker names are used exactly as Kind assigns them. Nothing renames a container or a
  node after creation, so `frr.conf.<nodename>` keys, `targetRef` names, `kubernetes.io/hostname`
  pins and container names never drift apart.
- Cilium's iptables rules block BGP by default; the worker bootstrap script
  (`install.sh`) inserts `ip6tables -I INPUT` *and* `iptables -I INPUT` rules for TCP/179 before
  Cilium starts — one per address family, since the underlay runs a session on each. Changing
  `install.sh` requires rebuilding the node image (`task build:node`).
- Cilium itself is installed with `ipv4.enabled=false` (the clusters are `ipFamily: ipv6`), so the
  IPv4 addresses FRR puts on `lo`/`eth1` are underlay-only and invisible to the cluster network.
- iad-worker3, the EVPN route reflector, peers with tr3 as AS 65000 like every other worker — its reflector role is an overlay concern only, invisible to the underlay.
