# Galactic Lab

Local development and integration-testing environments for [Galactic VPC](https://www.datum.net/docs/galactic-vpc/).

```
lab/
├── network/    # ContainerLab SRv6 underlay network (standalone)
└── gvpc/       # ContainerLab GVPC multi-cluster lab (3 Kind clusters over SRv6 mesh)
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
make build     # build the gobgp-pe container image
make up        # apply host sysctls and deploy the lab
make inspect   # show node addresses
make down      # tear down
```

---

## `gvpc/` — GVPC Multi-Cluster Lab

Three Kind clusters (iad, sjc, infra) connected over an IPv6 SRv6 transit mesh. Each
cluster runs FRR as a node routing daemon (hostNetwork DaemonSet) to peer with the
transit layer via BGP unnumbered. GoBGP runs alongside FRR on the iad and sjc workers
to exchange L3VPN type-5 routes with the infra route reflector over iBGP.

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
make up        # build Kind node image, apply host sysctls, deploy lab
make underlay  # apply FRR DaemonSets to all three clusters
make overlay   # apply GoBGP DaemonSets to iad and sjc clusters
make down      # tear down
```
