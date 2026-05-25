# Galactic Lab

Local development and integration-testing environments for [Galactic VPC](https://www.datum.net/docs/galactic-vpc/).

```
lab/
├── network/   # ContainerLab SRv6 underlay — standalone BGP/SRv6 network with FRR + GoBGP
└── gvpc/      # ContainerLab multi-cluster lab — three Kind clusters over an SRv6 transit mesh
```

---

## `network/` — SRv6 Underlay Lab

A ContainerLab topology that validates the BGP/SRv6 underlay that Galactic depends on.
Eight nodes across PE, transit, and route-reflector roles run FRR + GoBGP with SRv6
uSID L3VPN. Use this to develop and test routing behaviour independently of Kubernetes.

See [`network/README.md`](network/README.md) for topology details, addressing, and
verification commands.

### Prerequisites

- ContainerLab ≥ 0.54
- Docker
- Linux kernel ≥ 5.18 (SRv6 `encap.red` support)

### Quick start

```bash
cd network
task build     # build the gobgp-pe container image
task up        # apply host sysctls and deploy the lab
task inspect   # show node addresses
task down      # tear down
```

---

## `gvpc/` — Multi-Cluster GVPC Lab

A ContainerLab topology that connects three Kind clusters (`iad`, `sjc`, `infra`) over
an IPv6 SRv6 transit mesh. FRR runs as a node routing daemon on each cluster worker for
the eBGP underlay; GoBGP runs on `iad` and `sjc` workers to exchange L3VPN type-5 routes
with the `infra` route reflector over iBGP. Cilium, cert-manager, and Multus are
pre-installed on each cluster.

See [`gvpc/README.md`](gvpc/README.md) for topology details, addressing, and
verification commands.

### Prerequisites

- ContainerLab ≥ 0.54
- Docker
- `kind` CLI
- Host kernel with SRv6 support

### Quick start

```bash
cd gvpc
task up        # build Kind node image, apply host sysctls, deploy lab
task underlay  # apply FRR DaemonSets to all three clusters
task overlay   # pull GoBGP image, load into clusters, apply DaemonSets
task down      # tear down
```
