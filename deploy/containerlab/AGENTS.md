# ContainerLab Deployment — Galactic VPC Lab

## Important Conventions

- **YAML extensions**: Always use `.yaml`, never `.yml`.
- **FRR image pinning**: Taskfile and DaemonSets pin FRR to `10.6.1`. Transit routers in `gvpc.clab.yaml` default to `frrouting/frr:latest` — this is a known mismatch (see review findings).
- **Image loading**: Uses `ctr --namespace k8s.io images import` (not `kind load docker-image`) due to containerd v2 incompatibility.
- **iad-worker-control**: Created as `iad-worker2` in the topology, renamed post-deploy via `deploy:rename-control`. The Kind config sets the hostname via `kubeadmConfigPatches`. Runs the galactic-router route reflector (RR) for the iad region.
- **galactic-router image**: Uses `galactic-router:latest` with `imagePullPolicy: Never` — stale images persist across rebuilds.
- **Kind serviceSubnet**: All clusters use `/108` service subnet (non-standard; may cause issues with some services).
- **BGP listen port**: Tenant worker DaemonSets run with `GALACTIC_ROUTER_BGP_LISTEN_PORT=-1` (outbound-only). The RR role listens on `1790` (set in `config/router/tenant-control/daemonset-patch.yaml`).
- **BGP remote port**: Tenant BGPPeer CRDs in `resources/bgp/tenant/` explicitly set `remotePort: 1790` to connect to the RR. The control/RR-side peers rely on galactic-router's default of `1790`.
- **Worker SRv6 blackhole route**: A single standalone blackhole route covering the node's whole `/56` locator block (`metric 2048`, no interface — `ip -6 route add blackhole` takes no `dev`) prevents the default route from matching any USID this node could compute, set via `exec` commands in the ContainerLab topology. One aggregate route rather than one per VPC: IPv6 FIB lookup is longest-prefix-match first, so a real seg6local `/128` decap route always wins over the covering blackhole regardless of metric — the aggregate protects every current and future VPC's SID with no per-VPC config needed. The USID is **not** configured as an address on any interface. The seg6local route (`metric 1024`) in the main table handles SRv6 decapsulation. If the USID were an interface address, the kernel's local table route (metric 0) would shadow the seg6local route and break decapsulation. (A dedicated `lo-galactic` dummy interface previously hosted this — removed since it wasn't referenced by any Go code or by the blackhole route itself; `install.sh`'s `all`/`default` sysctl entries already cover the SRv6 kernel knobs it existed for.)
- **Node labels**: Workers use `galactic.datumapis.com/node: edge` (not `galactic.io/role: pop`). The control node uses `galactic.datumapis.com/node: control` with a matching `NoSchedule` taint.
- **GC namespace**: The tenant DaemonSet sets `GALACTIC_ROUTER_GC_NAMESPACE=galactic-system` for namespace-scoped garbage collection.
- **FRR config**: Transit router configs omit the `frr version` directive (managed by the FRR image, not the config).
- **Shared manifests**: `resources/cni/kustomization.yaml` builds on `config/cni/`, `resources/tenant/base/kustomization.yaml` builds on `config/router/tenant/`, and `resources/control/tenant/iad/kustomization.yaml` builds on `config/router/tenant-control/` (each of the router ones in turn pulls in `config/router/base/`) rather than forking them, patching in only what the lab needs to differ (image, env). Each role's node affinity and the base's blanket tolerations apply as-is — the lab doesn't need its own. `kubectl apply -k` refuses to load resource files from outside a kustomization's own root, so `deploy-cni.sh`/`deploy-tenant.sh` `docker cp` those directories into a local `base/` subdirectory on the node at deploy time (`resources/cni/base/`, `resources/tenant/base/{base,tenant}/`, `resources/control/tenant/iad/{base,tenant-control}/`) instead of referencing `config/` across that boundary. The `galactic-system` namespace and RBAC/ServiceAccount are applied straight from `config/system/namespace.yaml` and `config/*/{rbac,serviceaccount}.yaml` by `deploy-system.sh` via `lib.sh`'s `copy_config` (which copies all of `config/` to `/galactic/config/`) — not part of any kustomize build, so per-site `namePrefix` never touches the shared cluster-scoped RBAC. `config/system/namespace.yaml` is also the only place `galactic-system` gets created for production — there is no other bootstrap step in this repo, so if it's ever missing on a real cluster, deploying `config/router/` or `config/cni/` fails outright.

## Naming Layers

- **Fabric** — FRR DaemonSets running on each cluster's workers; handle eBGP to the transit mesh. Resources live in `resources/fabric/`.
- **Tenant** — galactic-router DaemonSets running on each cluster's workers; handle iBGP EVPN route distribution. Resources live in `resources/tenant/`.
- **Control** — iad-control node resources (FRR fabric + galactic-router route reflector). Resources live in `resources/control/` under `fabric/iad` and `tenant/iad`.
- **iad-control** — The iad region's second worker node; runs the route reflector for all tenant BGP sessions. Fabric resources in `resources/control/fabric/iad/`, tenant resources in `resources/control/tenant/iad/`, BGP CRDs in `resources/bgp/control/tenant/iad/`.

## References

Full documentation — topology, addressing, tasks — is in [README.md](README.md).
Verification commands are in [docs/verification.md](docs/verification.md).
Deploying the two test VPCs and verifying cross-site/cross-VPC connectivity is documented in [docs/vpc.md](docs/vpc.md).
