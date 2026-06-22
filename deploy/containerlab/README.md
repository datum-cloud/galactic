# Galactic VPC Lab Deployment

Three Kind clusters (dfw, iad, sjc) connected over an IPv6 SRv6 transit mesh. Each cluster
runs FRR as a node routing daemon (hostNetwork DaemonSet) to peer with the transit layer via
BGP unnumbered. galactic-router runs alongside FRR on the workers to distribute EVPN routes
over iBGP to the route reflector on iad-rr.

## Topology

```
  dfw-worker ──eth1── tr1 ──────────── tr2 ──eth1── sjc-worker
                       │  ╲          ╱  │
                       │   tr3 ── tr4   │
                       │  ╱          ╲  │
                      (mesh)        (mesh)
                                    tr3 ──eth5── iad-worker
                                    tr3 ──eth4── iad-worker-rr
```

### Node roles

| Node                  | Kind          | Role                                              |
|-----------------------|---------------|---------------------------------------------------|
| `dfw`                 | k8s-kind      | Kind cluster definition (dfw region)              |
| `dfw-control-plane`   | ext-container | Kind control-plane; runs Cilium, Multus, cert-mgr |
| `dfw-worker`          | ext-container | Kind worker; runs FRR PE + galactic-router PE     |
| `iad`                 | k8s-kind      | Kind cluster definition (iad region)              |
| `iad-control-plane`   | ext-container | Kind control-plane; runs Cilium, Multus, cert-mgr |
| `iad-worker`          | ext-container | Kind worker; runs FRR PE + galactic-router PE     |
| `iad-worker-rr`       | ext-container | Kind worker; runs FRR PE + galactic-router RR     |
| `sjc`                 | k8s-kind      | Kind cluster definition (sjc region)              |
| `sjc-control-plane`   | ext-container | Kind control-plane; runs Cilium, Multus, cert-mgr |
| `sjc-worker`          | ext-container | Kind worker; runs FRR PE + galactic-router PE     |
| `tr1`–`tr4`           | linux (FRR)   | iBGP full mesh, AS 65100                          |

### BGP design

```
AS 65000 (dfw-underlay / FRR)          ──eBGP unnumbered──  tr1 (AS 65100)
AS 65000 (iad-underlay / FRR)          ──eBGP unnumbered──  tr3:eth5 (AS 65100)
AS 65000 (iad-rr-underlay / FRR)       ──eBGP unnumbered──  tr3:eth4 (AS 65100)
AS 65000 (sjc-underlay / FRR)          ──eBGP unnumbered──  tr2 (AS 65100)

AS 65000 (dfw-overlay / galactic-router)  ──iBGP──  iad-rr (AS 65000 RR)
AS 65000 (iad-overlay / galactic-router)  ──iBGP──  iad-rr (AS 65000 RR)
AS 65000 (sjc-overlay / galactic-router)  ──iBGP──  iad-rr (AS 65000 RR)
```

- All clusters use a single AS (65000) for both the FRR underlay and the galactic-router overlay.
- The transit mesh carries IPv6 unicast (SRv6 locator prefixes and loopbacks) via iBGP within AS 65100.
- FRR PE nodes originate their SRv6 forwarding prefix (`2001:db8:ffXX::/48`) and SRv6 SID block (`fc00:0:X::/48`) toward the transit layer via eBGP unnumbered.
- `allowas-in 1` is configured on all cluster FRR instances so each site accepts prefixes that carry AS 65000 in the path — necessary because the transit reflects routes from one AS 65000 site to another.
- galactic-router instances on dfw/iad/sjc workers peer with iad-worker-rr over iBGP (AS 65000) for `l2vpn-evpn` routes. GoBGP runs with outbound-only mode (`listenPort=-1`); all BGP sessions are initiated outbound.

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

### Worker–TR links (BGP unnumbered, link-local only)

| Link                   | TR interface |
|------------------------|--------------|
| dfw-worker – tr1       | eth1         |
| sjc-worker – tr2       | eth1         |
| iad-worker – tr3       | eth5         |
| iad-worker-rr – tr3    | eth4         |

### Cluster SRv6 addressing

| Cluster   | FRR loopback / SID block | SRv6 forwarding prefix | galactic-router address |
|-----------|--------------------------|------------------------|-------------------------|
| dfw       | fc00:0:2::1/48           | 2001:db8:ff01::/48     | fc00:0:2::1             |
| iad       | fc00:0:4::1/48           | 2001:db8:ff03::/48     | fc00:0:4::1             |
| iad-rr    | fc00:0:8::1/48           | —                      | fc00:0:8::1             |
| sjc       | fc00:0:3::1/48           | 2001:db8:ff02::/48     | fc00:0:3::1             |

Worker SRv6 node SIDs (on `lo-galactic`):

| Node          | Address                                    |
|---------------|--------------------------------------------|
| dfw-worker    | 2001:db8:ff01:100:ffff:ffff:ffff:ffff/128  |
| iad-worker    | 2001:db8:ff03:100:ffff:ffff:ffff:ffff/128  |
| sjc-worker    | 2001:db8:ff02:100:ffff:ffff:ffff:ffff/128  |

### Management network (fc00:10::/64)

| Node                  | Address          |
|-----------------------|------------------|
| dfw                   | fc00:10::101     |
| dfw-control-plane     | fc00:10::102     |
| dfw-worker            | fc00:10::103     |
| iad                   | fc00:10::111     |
| iad-control-plane     | fc00:10::112     |
| iad-worker            | fc00:10::113     |
| iad-worker-rr         | fc00:10::114     |
| sjc                   | fc00:10::121     |
| sjc-control-plane     | fc00:10::122     |
| sjc-worker            | fc00:10::123     |

## Lab layout

```
deploy/containerlab/
├── gvpc.clab.yaml
├── Taskfile.yaml
├── containers/
│   ├── kindest-node-galactic/   # Custom Kind node image (Cilium, Multus, cert-manager, galactic)
│   ├── galactic-router/         # galactic-router container built from Go source
│   └── frr/                     # FRR container built from Alpine edge
├── resources/
│   ├── underlay/                # FRR DaemonSet kustomize overlays (dfw, iad, iad-rr, sjc)
│   ├── overlay/                 # galactic-router DaemonSet kustomize overlays (dfw, iad, sjc)
│   └── bgp/                     # BGP CRs (BGPRouter, BGPPeer, BGPAdvertisement)
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
    ├── install-underlay.sh
    └── install-overlay.sh
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

| Task               | Description                                                    |
|--------------------|----------------------------------------------------------------|
| `build`            | Build all container images (node, galactic-router, frr) |
| `build:node`       | Build the custom `kindest/node:galactic` image                 |
| `build:galactic-router` | Build the galactic-router container from Go source        |
| `build:frr`        | Build the FRR container from Alpine edge                       |
| `deploy`           | Build images, apply host sysctls, and deploy the lab           |
| `deploy:topology`  | Deploy the ContainerLab topology (transit routers + clusters)  |
| `deploy:images`    | Load container images into Kind clusters                       |
| `deploy:underlay`  | Apply FRR DaemonSets to all clusters                           |
| `deploy:overlay`   | Apply galactic-router DaemonSets and BGP CRs                   |
| `destroy`          | Destroy the lab and remove all Kind clusters                   |
| `reload`           | Full rebuild — destroy then redeploy                           |
| `inspect`          | Show running nodes and management addresses                    |
| `graph`            | Generate a draw.io diagram for the topology                    |
| `host-setup`       | Apply required host sysctls (IPv6 forwarding, inotify limits)  |
| `clean`            | Destroy lab, delete built images, and remove lab artifacts     |
| `test`             | Run all verification checks                                    |

## Verification

### Transit underlay

```bash
# iBGP full mesh — expect all sessions Established
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast summary"

# Worker SRv6 prefixes should be present on all TR nodes
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff01::/48"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff02::/48"
docker exec clab-gvpc-tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff03::/48"
```

### FRR DaemonSets (eBGP underlay)

```bash
# Check pods are running
docker exec dfw-control-plane kubectl get pods -n galactic-system
docker exec iad-control-plane kubectl get pods -n galactic-system
docker exec sjc-control-plane kubectl get pods -n galactic-system

# Run vtysh inside a pod
docker exec iad-control-plane kubectl exec -n galactic-system ds/iad-underlay \
  -- vtysh -c "show bgp ipv6 unicast summary"
docker exec iad-control-plane kubectl exec -n galactic-system ds/iad-rr-underlay \
  -- vtysh -c "show bgp ipv6 unicast summary"
```

### galactic-router DaemonSets (EVPN overlay)

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

## Notes

- All three Kind clusters use `disableDefaultCNI: true`. Cilium is installed by the
  `kindest/node:galactic` bootstrap script. cert-manager and Multus are only installed
  on iad and sjc.
- Worker–TR links use BGP unnumbered (IPv6 link-local only). No numbered addresses are
  configured on worker data-plane interfaces.
- Cilium's iptables rules block BGP by default; the bootstrap script inserts
  `ip6tables -I INPUT` rules for TCP/179 before Cilium starts on each worker.
- iad-worker-rr peers with tr3 as AS 65000, the same AS used by all three clusters.
