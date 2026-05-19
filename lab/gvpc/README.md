# GVPC Lab

Three Kind clusters connected over an IPv6 SRv6 transit mesh. Each cluster runs FRR
as a node routing daemon (hostNetwork DaemonSet) to peer with the transit layer via
BGP unnumbered. GoBGP runs alongside FRR on the iad and sjc workers to exchange
L3VPN type-5 routes with the infra route reflector over iBGP.

## Topology

```
  iad-worker ──eth1── tr1 ──────────── tr2 ──eth1── sjc-worker
                       │  ╲          ╱  │
                       │   tr3 ── tr4   │
                       │  ╱          ╲  │
                      (mesh)        (mesh)
                                    tr3 ──eth5── infra-worker
```

### Node roles

| Node                  | Kind          | Role                                              |
|-----------------------|---------------|---------------------------------------------------|
| `iad`                 | k8s-kind      | Kind cluster definition (iad region)              |
| `iad-control-plane`   | ext-container | Kind control-plane; runs Cilium, Multus, cert-mgr |
| `iad-worker`          | ext-container | Kind worker; runs FRR PE + GoBGP PE               |
| `sjc`                 | k8s-kind      | Kind cluster definition (sjc region)              |
| `sjc-control-plane`   | ext-container | Kind control-plane; runs Cilium, Multus, cert-mgr |
| `sjc-worker`          | ext-container | Kind worker; runs FRR PE + GoBGP PE               |
| `infra`               | k8s-kind      | Kind cluster definition (infra)                   |
| `infra-control-plane` | ext-container | Kind control-plane; runs Cilium                   |
| `infra-worker`        | ext-container | Kind worker; runs FRR route reflector             |
| `tr1`–`tr4`           | linux (FRR)   | iBGP full mesh, AS 65100                          |

### BGP design

```
AS 65000 (iad-underlay / FRR)         ──eBGP unnumbered──  tr1 (AS 65100)
AS 65000 (sjc-underlay / FRR)         ──eBGP unnumbered──  tr2 (AS 65100)
AS 65000 (infra-control-plane / FRR)  ──eBGP unnumbered──  tr3 (AS 65100)

AS 65000 (iad-overlay / GoBGP)  ──iBGP──  infra-control-plane (AS 65000 RR)
AS 65000 (sjc-overlay / GoBGP)  ──iBGP──  infra-control-plane (AS 65000 RR)
```

- All clusters use a single AS (65000) for both the FRR underlay and the GoBGP overlay.
- The transit mesh carries IPv6 unicast (SRv6 locator prefixes and loopbacks) via iBGP within AS 65100.
- FRR PE nodes originate their SRv6 forwarding prefix (`2001:db8:ffXX::/48`) and SRv6 SID block (`fc00:0:X::/48`) toward the transit layer via eBGP unnumbered.
- `allowas-in 1` is configured on all cluster FRR instances so each site accepts prefixes that carry AS 65000 in the path — necessary because the transit reflects routes from one AS 65000 site to another.
- GoBGP instances on iad/sjc workers peer with infra-control-plane over iBGP (AS 65000) for `l3vpn-ipv4-unicast` (type-5 VPN routes). GoBGP runs with `port = -1`; FRR owns TCP/179.

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

| Link               | TR interface |
|--------------------|--------------|
| iad-worker – tr1   | eth1         |
| sjc-worker – tr2   | eth1         |
| infra-worker – tr3 | eth5         |

### Cluster SRv6 addressing

| Cluster | FRR loopback / SID block | SRv6 forwarding prefix | GoBGP local-address |
|---------|--------------------------|------------------------|---------------------|
| iad     | fc00:0:2::1/48           | 2001:db8:ff01::/48     | fc00:0:2::1         |
| sjc     | fc00:0:3::1/48           | 2001:db8:ff02::/48     | fc00:0:3::1         |
| infra   | fc00:0:4::1/128          | —                      | —                   |

Worker SRv6 node SIDs (on `lo-galactic`):

| Node         | Address                                    |
|--------------|--------------------------------------------|
| iad-worker   | 2001:db8:ff01:100:ffff:ffff:ffff:ffff/128  |
| sjc-worker   | 2001:db8:ff02:100:ffff:ffff:ffff:ffff/128  |
| infra-worker | 2001:db8:ff03:100:ffff:ffff:ffff:ffff/128  |

### Management network (172.20.20.0/24)

| Node                  | Address       |
|-----------------------|---------------|
| iad                   | 172.20.20.101 |
| iad-control-plane     | 172.20.20.102 |
| iad-worker            | 172.20.20.103 |
| infra                 | 172.20.20.111 |
| infra-control-plane   | 172.20.20.112 |
| infra-worker          | 172.20.20.113 |
| sjc                   | 172.20.20.121 |
| sjc-control-plane     | 172.20.20.122 |
| sjc-worker            | 172.20.20.123 |

## Lab layout

```
gvpc/
├── gvpc.clab.yaml
├── Makefile
├── containers/
│   └── kindest-node-galactic/   # Custom Kind node image (Cilium, Multus, cert-manager)
├── resources/
│   ├── iad-underlay.k8s.yaml     # FRR DaemonSet — iad cluster PE
│   ├── sjc-underlay.k8s.yaml     # FRR DaemonSet — sjc cluster PE
│   ├── infra-control-plane.k8s.yaml       # FRR DaemonSet — infra cluster route reflector
│   ├── iad-overlay.k8s.yaml      # GoBGP DaemonSet — iad cluster L3VPN PE
│   └── sjc-overlay.k8s.yaml      # GoBGP DaemonSet — sjc cluster L3VPN PE
├── node_files/
│   ├── iad/     config.yaml
│   ├── sjc/     config.yaml
│   ├── infra/   config.yaml
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

- ContainerLab ≥ 0.54
- Docker
- `kind` CLI
- Host kernel with SRv6 support

## Quick start

```bash
make up       # build Kind node image, apply host sysctls, deploy lab
make underlay # apply FRR DaemonSets to all three clusters
make overlay  # apply GoBGP DaemonSets to iad and sjc clusters
```

## Make targets

| Target           | Description                                               |
|------------------|-----------------------------------------------------------|
| `build`          | Build the custom `kindest/node:galactic` image            |
| `up`             | Build, apply host sysctls, and deploy the lab             |
| `down`           | Destroy the lab and remove state                          |
| `reload`         | Full rebuild — destroy then redeploy                      |
| `inspect`        | Show running nodes and management addresses               |
| `graph`          | Generate a draw.io diagram for the topology               |
| `host-setup`     | Apply required host sysctls (IPv6 forwarding etc.)        |
| `underlay`       | Apply FRR DaemonSets to all three clusters                |
| `overlay`        | Apply GoBGP DaemonSets to iad and sjc clusters            |
| `clean`          | Destroy lab, remove state, and delete the Kind node image |

## Verification

### Transit underlay

```bash
# iBGP full mesh — expect all sessions Established
docker exec tr1 vtysh -c "show bgp ipv6 unicast summary"

# Worker SRv6 prefixes should be present on all TR nodes
docker exec tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff01::/48"
docker exec tr1 vtysh -c "show bgp ipv6 unicast 2001:db8:ff02::/48"
```

### FRR DaemonSets (eBGP underlay)

```bash
# Check pods are running
docker exec iad-control-plane kubectl get pods -n iad-underlay
docker exec sjc-control-plane kubectl get pods -n sjc-underlay
docker exec infra-control-plane kubectl get pods -n infra-control-plane

# Run vtysh inside a pod
docker exec iad-control-plane kubectl exec -n iad-underlay deploy/iad-underlay \
  -- vtysh -c "show bgp ipv6 unicast summary"
```

### GoBGP DaemonSets (L3VPN overlay)

```bash
# Check pods are running
docker exec iad-control-plane kubectl get pods -n iad-overlay
docker exec sjc-control-plane kubectl get pods -n sjc-overlay

# Check iBGP session to infra-control-plane
docker exec iad-control-plane kubectl exec -n iad-overlay deploy/iad-overlay \
  -- gobgp neighbor
docker exec sjc-control-plane kubectl exec -n sjc-overlay deploy/sjc-overlay \
  -- gobgp neighbor

# Inspect VRF RIB
docker exec iad-control-plane kubectl exec -n iad-overlay deploy/iad-overlay \
  -- gobgp vrf
```

## Notes

- All three Kind clusters use `disableDefaultCNI: true`. Cilium is installed by the
  `kindest/node:galactic` bootstrap script. cert-manager and Multus are only installed
  on iad and sjc.
- Worker–TR links use BGP unnumbered (IPv6 link-local only). No numbered addresses are
  configured on worker data-plane interfaces.
- Cilium's iptables rules block BGP by default; the bootstrap script inserts
  `ip6tables -I INPUT` rules for TCP/179 before Cilium starts on each worker.
- infra-control-plane peers with tr3 as AS 65000, the same AS used by all three clusters.
