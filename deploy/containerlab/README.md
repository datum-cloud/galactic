# Galactic VPC Lab Deployment

Three Kind clusters (dfw, iad, sjc) connected over an IPv6 SRv6 transit mesh. Each cluster
runs FRR as a node routing daemon (hostNetwork DaemonSet) to peer with the transit layer via
eBGP over numbered IPv6 links. galactic-router runs alongside FRR on the workers to distribute EVPN routes
over iBGP to the route reflector on iad-control.

## Topology

```
  dfw-worker ──eth1── tr1 ──────────── tr2 ──eth1── sjc-worker
                       │  ╲          ╱  │
                       │   tr3 ── tr4   │
                       │  ╱          ╲  │
                      (mesh)        (mesh)
                                    tr3 ──eth5── iad-worker
                                    tr3 ──eth4── iad-worker-control
                                    tr3 ──eth6── iad-gateway1
                                    tr3 ──eth7── iad-gateway2
```

### Node roles

| Node                                                     | Kind          | Role                                                  |
|----------------------------------------------------------|---------------|-------------------------------------------------------|
| `dfw-control-plane`                                      | ext-container | Kind control-plane; runs Cilium, Multus               |
| `dfw-worker`                                             | ext-container | Kind worker; runs FRR PE + galactic-router PE         |
| `iad-control-plane`                                      | ext-container | Kind control-plane; runs Cilium, Multus               |
| `iad-worker`                                             | ext-container | Kind worker; runs FRR PE + galactic-router PE         |
| `iad-worker2` (renamed `iad-worker-control` post-deploy) | ext-container | Kind worker; runs FRR PE + galactic-router RR         |
| `iad-worker3` (renamed `iad-gateway1` post-deploy)       | ext-container | Kind worker; edge XDP NAT+LB gateway canary (Phase D) |
| `iad-worker4` (renamed `iad-gateway2` post-deploy)       | ext-container | Kind worker; edge XDP NAT+LB gateway canary (Phase D) |
| `sjc-control-plane`                                      | ext-container | Kind control-plane; runs Cilium, Multus               |
| `sjc-worker`                                             | ext-container | Kind worker; runs FRR PE + galactic-router PE         |
| `tr1`–`tr4`                                              | linux (FRR)   | iBGP full mesh, AS 65100                              |

`iad-gateway1`/`iad-gateway2` are tainted (`galactic.datumapis.com/node=gateway:NoSchedule`)
dedicated nodes, same idea as `iad-worker-control`'s taint: no tenant pods land there, only
DaemonSets with a blanket toleration (`fabric-router`, `galactic-gateway1`/`-gateway2` — each a
two-container pod, `galactic-router` + `galactic-gateway`).
They never run `galactic-cni` (config/cni's affinity is edge-only) or a route-reflector.
**Underlay BGP peering on their `tr3` uplinks is now wired** (`node_files/tr3/frr.conf`,
plus two `BGPPeer` objects in `resources/galactic-control/iad/` for the route reflector side)
and the full fabric converges, but real end-to-end ingress traffic through the datapath still
doesn't reach a backend in this topology — it currently stops on a veth-specific `XDP_TX`
behavior in this lab environment, not a code bug; see `resources/galactic-gateway/`.

`dfw`, `iad`, and `sjc` are the three Kind cluster names — not separate ContainerLab
topology nodes. Each cluster's `control-plane`/`worker` nodes above are its members.

### BGP design

```
AS 65000 (dfw fabric-router / FRR)   ──eBGP──  tr1 (AS 65100)
AS 65000 (iad fabric-router / FRR)   ──eBGP──  tr3:eth5,eth6,eth7 (AS 65100)
AS 65000 (iad fabric-control / FRR)  ──eBGP──  tr3:eth4 (AS 65100)
AS 65000 (sjc fabric-router / FRR)   ──eBGP──  tr2 (AS 65100)

AS 65000 (dfw-tenant / galactic-router)    ──iBGP──  iad-control-tenant (AS 65000 RR)
AS 65000 (iad-tenant / galactic-router)    ──iBGP──  iad-control-tenant (AS 65000 RR)
AS 65000 (sjc-tenant / galactic-router)    ──iBGP──  iad-control-tenant (AS 65000 RR)
```

- All clusters use a single AS (65000) for both the FRR fabric and the galactic-router tenant.
- The transit mesh carries IPv6 unicast (SRv6 locator prefixes and loopbacks) via iBGP within AS 65100.
- FRR PE nodes originate their per-node SRv6 locator block (`2001:db8:ffXX:100::/56`) and BGP peering loopback (`fc00:0:X::1/128`) toward the transit layer via eBGP over numbered IPv6 links — never the site's full `/48` uSID Block or loopback pool, which would create an anycast ambiguity once a second worker joins a site.
- `allowas-in 1` is configured on all cluster FRR instances so each site accepts prefixes that carry AS 65000 in the path — necessary because the transit reflects routes from one AS 65000 site to another.
- galactic-router instances on dfw/iad/sjc workers peer with iad-worker-control over iBGP (AS 65000) for `l2vpn-evpn` routes. GoBGP runs with outbound-only mode (`listenPort=-1`); all BGP sessions are initiated outbound.

## Addressing

### Transit loopbacks

| Node | Loopback        |
|------|-----------------|
| tr1  | fc00:0:1::1/128 |
| tr2  | fc00:0:5::1/128 |
| tr3  | fc00:0:6::1/128 |
| tr4  | fc00:0:7::1/128 |

### TR–TR point-to-point links (numbered)

| Link    | Subnet              |
|---------|---------------------|
| tr1–tr2 | 2001:db8:0:12::/64  |
| tr1–tr3 | 2001:db8:0:13::/64  |
| tr1–tr4 | 2001:db8:0:14::/64  |
| tr2–tr3 | 2001:db8:0:23::/64  |
| tr2–tr4 | 2001:db8:0:24::/64  |
| tr3–tr4 | 2001:db8:0:34::/64  |

### Worker–TR links (numbered, eBGP)

| Link                     | Subnet             | TR address       | Worker address   |
|--------------------------|--------------------|------------------|------------------|
| dfw-worker – tr1         | 2001:db8:1:10::/64 | 2001:db8:1:10::1 | 2001:db8:1:10::2 |
| sjc-worker – tr2         | 2001:db8:1:20::/64 | 2001:db8:1:20::1 | 2001:db8:1:20::2 |
| iad-worker – tr3         | 2001:db8:1:30::/64 | 2001:db8:1:30::1 | 2001:db8:1:30::2 |
| iad-worker-control – tr3 | 2001:db8:1:31::/64 | 2001:db8:1:31::1 | 2001:db8:1:31::2 |
| iad-gateway1 – tr3       | 2001:db8:1:32::/64 | 2001:db8:1:32::1 | 2001:db8:1:32::2 |
| iad-gateway2 – tr3       | 2001:db8:1:33::/64 | 2001:db8:1:33::1 | 2001:db8:1:33::2 |

### Cluster SRv6 addressing

Each worker has a standalone blackhole route (no interface needed) covering its
whole `/56` locator block (metric 2048, lower priority than any pod's seg6local
route at metric 1024 — IPv6 FIB lookup is longest-prefix-match first, so a real
`/128` decap route always wins regardless of metric). The blackhole prevents the
default route from matching any USID this node could compute before or without
a matching seg6local route installed, for any current or future VPC — not just
the ones with a pod running today. The FRR fabric DaemonSet advertises the same
`/56` into the transit mesh via a static Null0 route + BGP `network` statement.

Each site's tenant node advertises its own `/56` SRv6 locator block into the
fabric — never the site's full `/48` uSID Block, which would create an
anycast ambiguity the instant a second tenant node joins a site. The test VPC
`ns10` (see [docs/tenants.md](docs/tenants.md)) gets a host address within its node's
block (illustrative only — the exact hextet depends on allocation order; see
docs/tenants.md's [SRv6 USID Argument allocation](docs/tenants.md#srv6-usid-argument-allocation)):

| Cluster | FRR loopback    | Node locator block     | USID ns10                    | galactic-router address |
|---------|-----------------|------------------------|------------------------------|-------------------------|
| dfw     | fc00:0:2::1/128 | 2001:db8:ff01:100::/56 | 2001:db8:ff01:100:c800::/128 | fc00:0:2::1             |
| sjc     | fc00:0:3::1/128 | 2001:db8:ff02:100::/56 | 2001:db8:ff02:100:c800::/128 | fc00:0:3::1             |
| iad     | fc00:0:4::1/128 | 2001:db8:ff03:100::/56 | 2001:db8:ff03:100:c800::/128 | fc00:0:4::1             |

The `galactic-router address` column is no longer set explicitly in the
per-cluster Kustomize patches — `galactic-router` auto-detects it from `lo`
at startup (see `docs/router/configuration.md`), since it always matches the
FRR loopback address on the same host.

### Gateway node self-addressing (Phase D canary)

`iad-gateway1`/`iad-gateway2` each get a uFMT 48+16 uSID over iad's shared
`2001:db8:ff03::/48` locator, at the reserved Argument 0 (never registered
into any tenant VRF — see `internal/plumbing/ebpf/uformat.go`'s
`ArgumentMin`). Unlike a tenant's per-VPC uSID, `srv6.ComputeSID` can't
derive this value (it rejects `argument==0` by design), so these were
computed directly via `internal/plumbing/ebpf/uformat.Encode` and are
supplied statically through `GALACTIC_GATEWAY_SRV6_ADDRESS` (originally
`GALACTIC_ROUTER_GATEWAY_SRV6_ADDRESS` before the binary split) — see
`resources/galactic-gateway/iad-gateway{1,2}/node-patch.yaml`.

| Node         | FRR loopback    | nodeID | SRv6 self-address (Argument 0) |
|--------------|-----------------|--------|--------------------------------|
| iad-gateway1 | fc00:0:9::1/128 | 2      | 2001:db8:ff03:2:e000::         |
| iad-gateway2 | fc00:0:a::1/128 | 3      | 2001:db8:ff03:3:e000::         |

### Egress (masquerade) canary (Phase E, datum-cloud/enhancements#865)

Each gateway node also gets a second, dedicated fabric loopback address
(`GALACTIC_GATEWAY_EGRESS_ADDRESS`) and shares its ingress locator for
`GALACTIC_GATEWAY_EGRESS_SID` (only the top 64 bits — Block+Node-ID — are
ever compared for egress dispatch, so the low bits shown below are just an
obviously-distinct placeholder, not a value with its own meaning). The
egress address must be its own, separate address from the node's BGP
session address (`fc00:0:9::1`/`fc00:0:a::1` above) — reusing it would mean
`edgenat.c`'s fail-closed egress-return dispatch also claims, and drops,
this node's own inbound BGP TCP traffic.

| Node         | Egress address (masq_addr) | Egress SID (locator, low bits arbitrary) |
|--------------|-----------------------------|-------------------------------------------|
| iad-gateway1 | fc00:0:9::2/128             | 2001:db8:ff03:2:e0ff::                    |
| iad-gateway2 | fc00:0:a::2/128             | 2001:db8:ff03:3:e0ff::                    |

`ns10`'s iad attachment (`resources/galactic-gateway/iad/
networkegresspolicy-ns10.yaml`) is the egress canary tenant — chosen over
`ns60` (the ingress canary) because its `netshoot` image has `ping`; `ns60`'s
`nginx` image doesn't. Only `ns10`'s **iad** attachment can egress in this
lab: `NetworkGateway`/`NetworkEgressPolicy` only exist in iad's own Kind
cluster, since each site here is a fully separate cluster connected only by
the data-plane SRv6/BGP mesh, not a shared control plane — see
`scripts/verify-egress.sh`. `task verify:egress` pings `tr1`'s own loopback
(`fc00:0:1::1`, already announced into the transit mesh, standing in for "an
arbitrary internet destination" since this lab has no real internet uplink)
from that pod.

**This canary could not be run live in this session** — bringing up three
Kind clusters plus the full FRR/BGP mesh is a multi-minute operation not
attempted here. Every value and code path above was worked through by
reading the existing lab's real configuration and this design's own
datapath code, not confirmed against a live cluster; treat it as a
reasoned-through starting point; the first real run of `task verify:egress`
is this canary's actual proof.

### Management network (fc00:10::/64)

| Node                                       | Address      |
|--------------------------------------------|--------------|
| dfw-control-plane                          | fc00:10::102 |
| dfw-worker                                 | fc00:10::103 |
| sjc-control-plane                          | fc00:10::122 |
| sjc-worker                                 | fc00:10::123 |
| iad-control-plane                          | fc00:10::112 |
| iad-worker                                 | fc00:10::113 |
| iad-worker2 (renamed `iad-worker-control`) | fc00:10::114 |
| iad-worker3 (renamed `iad-gateway1`)       | fc00:10::115 |
| iad-worker4 (renamed `iad-gateway2`)       | fc00:10::116 |

## Lab layout

```
deploy/containerlab/
├── gvpc.clab.yaml
├── Taskfile.yaml
├── containers/
│   └── kindest-node-galactic/   # Custom Kind node image (git/tcpdump, kubectl DooD wrapper)
├── resources/
│   ├── galactic-cni/            # galactic-cni installer DaemonSet + ConfigMap
│   ├── fabric-router/           # FRR DaemonSet per-site overlays (dfw, iad, sjc)
│   ├── fabric-control/iad/        # FRR DaemonSet iad-control overlay
│   ├── galactic-router/         # galactic-router DaemonSet + BGP CRs (dfw, iad, sjc)
│   ├── galactic-control/iad/    # galactic-router RR + BGP CRs (iad-control)
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
│   ├── dfw/     config.yaml
│   ├── iad/     config.yaml
│   ├── sjc/     config.yaml
│   ├── tr1/     frr.conf  startup.sh
│   ├── tr2/     frr.conf  startup.sh
│   ├── tr3/     frr.conf  startup.sh
│   └── tr4/     frr.conf  startup.sh
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
| `build`                  | Build all container images (node, galactic-router, galactic-cni, frr)         |
| `build:node`             | Build the custom `kindest/node:galactic` image                                |
| `build:galactic-router`  | Build the galactic-router container from Go source                            |
| `build:galactic-cni`     | Build the galactic-cni installer image                                        |
| `build:frr`              | Build the FRR container from Alpine edge                                      |
| `deploy`                 | Build images, apply host sysctls, and deploy the lab                          |
| `deploy:topology`        | Deploy the ContainerLab topology (transit routers)                            |
| `deploy:clusters`        | Create the three Kind clusters and export their kubeconfigs                   |
| `deploy:rename-control`  | Rename `iad-worker2`→`iad-worker-control`, `iad-worker3/4`→`iad-gateway1/2`   |
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
| `verify:scenarios`       | Verify ping across all VPC test scenarios                                     |
| `verify:ns10`            | Verify ns10 ping (IPv6-only, 3-site mesh)                                     |
| `verify:ns20`            | Verify ns20 ping (dual-stack, 3-site mesh)                                    |
| `verify:ns30`            | Verify ns30 ping (dfw only, 2 pods)                                           |
| `verify:ns40`            | Verify ns40 ping (iad only, 2 pods)                                           |
| `verify:gateway`         | Verify iad's gateway canary CRDs exist (manifests only, no live traffic)      |
| `verify:egress`          | Verify egress (masquerade) datapath end-to-end (ns10/iad → tr1's loopback)    |
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
- Worker–TR links use numbered IPv6 subnets (/64) with eBGP peering.
- Cilium's iptables rules block BGP by default; the worker bootstrap script
  (`install.sh`) inserts `ip6tables -I INPUT` rules for TCP/179 before Cilium starts.
- iad-worker-control peers with tr3 as AS 65000, the same AS used by all three clusters.
