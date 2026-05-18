# Galactic Lab

Local development and integration-testing environments for [Galactic VPC](https://www.datum.net/docs/galactic-vpc/).

```
lab/
├── network/                        # ContainerLab SRv6 underlay network
└── containers/
    └── kindest-node-galactic/      # Custom Kind node image with Galactic pre-installed
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

## `containers/kindest-node-galactic/` — Custom Kind Node Image

A `kindest/node` image extended with the tooling and Kubernetes manifests needed to
run a full Galactic stack inside a [Kind](https://kind.sigs.k8s.io/) cluster.

```
kindest-node-galactic/
├── Dockerfile
├── resources/          # Kubernetes manifests applied at cluster boot
│   ├── agent.k8s.yaml
│   ├── mqtt.k8s.yaml
│   ├── operator.k8s.yaml
│   └── router.k8s.yaml
└── scripts/
    └── install.sh      # Installs Cilium, cert-manager, Multus, and Galactic
```

`install.sh` is invoked once per node after the cluster comes up. On the control-plane
node it applies each Kubernetes manifest in order (Cilium → cert-manager → Multus →
MQTT → Galactic operator → router → agent). On worker nodes it loads kernel modules,
sets SRv6 sysctls, and drops in the CNI binaries.

### Prerequisites

- Docker
- [`kind`](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
- Linux kernel with `vrf` module and SRv6 support (or a VM with those features)

### Build

```bash
cd containers/kindest-node-galactic
docker build -t kindest/node:galactic .
```

### Use with Kind

Reference the custom image in your Kind cluster config:

```yaml
# kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:galactic
  - role: worker
    image: kindest/node:galactic
  - role: worker
    image: kindest/node:galactic
```

```bash
kind create cluster --config kind-config.yaml
```

After the cluster is up, run `install.sh` on each node:

```bash
for node in $(kind get nodes); do
  docker exec "$node" /galactic/scripts/install.sh
done
```

### Component versions (pinned in `scripts/install.sh`)

| Component    | Version  |
|--------------|----------|
| Cilium CLI   | v0.18.8  |
| cert-manager | v1.19.1  |
| Multus CNI   | v4.2.3   |
| CNI plugins  | v1.8.0   |
| Galactic     | v0.0.5   |
