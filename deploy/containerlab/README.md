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
```

### Node roles

| Node                  | Kind          | Role                                          |
|-----------------------|---------------|-----------------------------------------------|
| `dfw-control-plane`   | ext-container | Kind control-plane; runs Cilium, Multus       |
| `dfw-worker`          | ext-container | Kind worker; runs FRR PE + galactic-router PE |
| `iad-control-plane`   | ext-container | Kind control-plane; runs Cilium, Multus       |
| `iad-worker`          | ext-container | Kind worker; runs FRR PE + galactic-router PE |
| `iad-worker2` (renamed `iad-worker-control` post-deploy) | ext-container | Kind worker; runs FRR PE + galactic-router RR |
| `sjc-control-plane`   | ext-container | Kind control-plane; runs Cilium, Multus       |
| `sjc-worker`          | ext-container | Kind worker; runs FRR PE + galactic-router PE |
| `tr1`–`tr4`           | linux (FRR)   | iBGP full mesh, AS 65100                      |

`dfw`, `iad`, and `sjc` are the three Kind cluster names — not separate ContainerLab
topology nodes. Each cluster's `control-plane`/`worker` nodes above are its members.

### BGP design

```
AS 65000 (dfw-fabric / FRR)          ──eBGP──  tr1 (AS 65100)
AS 65000 (iad-fabric / FRR)          ──eBGP──  tr3:eth5 (AS 65100)
AS 65000 (iad-control-fabric / FRR)  ──eBGP──  tr3:eth4 (AS 65100)
AS 65000 (sjc-fabric / FRR)          ──eBGP──  tr2 (AS 65100)

AS 65000 (dfw-tenant / galactic-router)    ──iBGP──  iad-control-tenant (AS 65000 RR)
AS 65000 (iad-tenant / galactic-router)    ──iBGP──  iad-control-tenant (AS 65000 RR)
AS 65000 (sjc-tenant / galactic-router)    ──iBGP──  iad-control-tenant (AS 65000 RR)
```

- All clusters use a single AS (65000) for both the FRR fabric and the galactic-router tenant.
- The transit mesh carries IPv6 unicast (SRv6 locator prefixes and loopbacks) via iBGP within AS 65100.
- FRR PE nodes originate their SRv6 forwarding prefix (`2001:db8:ffXX::/48`) and SRv6 SID block (`fc00:0:X::/48`) toward the transit layer via eBGP over numbered IPv6 links.
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

### Cluster SRv6 addressing

Each worker has a `lo-galactic` dummy interface with a blackhole route for its
/128 USID (metric 2048, lower priority than the seg6local route at metric 1024).
The blackhole prevents the default route from matching the USID while the
seg6local route handles SRv6 decapsulation. The FRR fabric DaemonSet advertises
the USID into the transit mesh via a static Null0 route + BGP `network` statement.

Each site advertises one aggregate `/48` SRv6 locator block into the fabric; test VPCs
`vpc10` and `vpc20` (see [docs/vpc.md](docs/vpc.md)) get sequential host addresses
within their site's block rather than a separate per-VPC prefix:

| Cluster     | FRR loopback   | Site aggregate block | USID vpc10             | USID vpc20             | galactic-router address |
|-------------|----------------|-----------------------|-------------------------|-------------------------|-------------------------|
| dfw         | fc00:0:2::1/48 | 2001:db8:ff01::/48    | 2001:db8:ff01::1/128    | 2001:db8:ff01::2/128    | fc00:0:2::1             |
| sjc         | fc00:0:3::1/48 | 2001:db8:ff02::/48    | 2001:db8:ff02::1/128    | 2001:db8:ff02::2/128    | fc00:0:3::1             |
| iad         | fc00:0:4::1/48 | 2001:db8:ff03::/48    | 2001:db8:ff03::1/128    | 2001:db8:ff03::2/128    | fc00:0:4::1             |

The `galactic-router address` column is no longer set explicitly in the
per-cluster Kustomize patches — `galactic-router` auto-detects it from `lo`
at startup (see `docs/router/configuration.md`), since it always matches the
FRR loopback address on the same host.

### Management network (fc00:10::/64)

| Node                                          | Address       |
|------------------------------------------------|---------------|
| dfw-control-plane                             | fc00:10::102  |
| dfw-worker                                    | fc00:10::103  |
| sjc-control-plane                             | fc00:10::122  |
| sjc-worker                                    | fc00:10::123  |
| iad-control-plane                             | fc00:10::112  |
| iad-worker                                    | fc00:10::113  |
| iad-worker2 (renamed `iad-worker-control`)    | fc00:10::114  |

## Lab layout

```
deploy/containerlab/
├── gvpc.clab.yaml
├── Taskfile.yaml
├── containers/
│   ├── kindest-node-galactic/   # Custom Kind node image (git/tcpdump, kubectl DooD wrapper)
│   └── frr/                     # FRR container built from Alpine edge
├── resources/
│   ├── cni/                     # galactic-cni installer DaemonSet + ConfigMap
│   ├── fabric/                  # FRR DaemonSet manifests (dfw, iad, sjc)
│   ├── tenant/                  # galactic-router DaemonSet overlays (dfw, iad, sjc)
│   ├── vpc/                     # vpc10/vpc20 NAD manifests + test workload Deployments (dfw, iad, sjc)
│   ├── control/                 # iad-control node resources (fabric/iad, tenant/iad)
│   └── bgp/                     # BGP CRs (tenant/$SITE, control/tenant/$SITE)
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
    ├── deploy-tenant.sh
    └── deploy-vpc.sh
```

## Prerequisites

- ContainerLab >= 0.54
- Docker
- `kind` CLI
- Host kernel with SRv6 support

## Quick start

```bash
cd deploy/containerlab
task deploy   # build local images, pull galactic-cni/galactic-router, apply host sysctls, deploy lab end-to-end
```

`galactic-cni` and `galactic-router` are pulled from `ghcr.io/datum-cloud/galactic-{cni,router}`
(published by `.github/workflows/publish.yaml`), not built locally. The tag defaults to
`v0.0.0-main` (floating, tracks the latest push to `main`); override it to pin a commit:

```bash
task deploy GALACTIC_TAG=v0.0.0-<short-sha>
```

To tear down and start fresh:

```bash
task destroy  # remove all lab containers and Kind clusters
task clean    # destroy + delete locally-built images and lab artifacts
task deploy
```

## Tasks

| Task                    | Description                                                              |
|-------------------------|--------------------------------------------------------------------------|
| `build`                 | Build locally-built container images (node, frr)                        |
| `build:node`            | Build the custom `kindest/node:galactic` image                           |
| `build:frr`             | Build the FRR container from Alpine edge                                 |
| `deploy`                | Build local images, apply host sysctls, and deploy the lab               |
| `deploy:topology`       | Deploy the ContainerLab topology (transit routers)                       |
| `deploy:clusters`       | Create the three Kind clusters and export their kubeconfigs              |
| `deploy:rename-control` | Rename the `iad-worker2` Docker container to `iad-worker-control`        |
| `deploy:images`         | Load locally-built container images (node, frr) into Kind clusters       |
| `deploy:system`         | Install BGP and VPC CRDs; apply the galactic-system namespace and shared RBAC |
| `deploy:cni`            | Install Cilium and Multus, then the galactic-cni DaemonSet (pulled from GHCR) |
| `deploy:fabric`         | Apply FRR DaemonSets to all clusters                                     |
| `deploy:tenant`         | Apply galactic-router DaemonSets (pulled from GHCR) and BGP CRs          |
| `deploy:vpc`            | Deploy vpc10 and vpc20 test workloads across all clusters (6 pods)       |
| `destroy`               | Destroy the lab and remove all Kind clusters                             |
| `reload`                | Full rebuild — destroy then redeploy                                     |
| `rebuild`               | Full rebuild — clean (destroy + delete images/artifacts) then redeploy   |
| `inspect`               | Show running nodes and management addresses                              |
| `graph`                 | Generate a draw.io diagram for the topology                              |
| `host-setup`            | Apply required host sysctls (IPv6 forwarding, inotify limits)            |
| `clean`                 | Destroy lab, delete locally-built images, and remove lab artifacts       |
| `test`                  | Run all verification checks                                              |

## Verification

See [docs/verification.md](docs/verification.md) for transit fabric, FRR, and galactic-router
health checks, and [docs/vpc.md](docs/vpc.md) for deploying the `vpc10`/`vpc20` test
workloads and verifying cross-site and cross-VPC connectivity. Quick smoke test:

```bash
task test  # automated: bgp-transit, bgp-fabric, bgp-peers, srv6, evpn
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
