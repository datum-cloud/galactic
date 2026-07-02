# ContainerLab Deployment — Galactic VPC Lab

## Important Conventions

- **YAML extensions**: Always use `.yaml`, never `.yml`.
- **FRR image pinning**: Taskfile and DaemonSets pin FRR to `10.6.1`. Transit routers in `gvpc.clab.yaml` default to `frrouting/frr:latest` — this is a known mismatch (see review findings).
- **Image loading**: Uses `ctr --namespace k8s.io images import` (not `kind load docker-image`) due to containerd v2 incompatibility.
- **iad-worker-control**: Created as `iad-worker2` in the topology, renamed post-deploy via `deploy:rename-control`. The Kind config sets the hostname via `kubeadmConfigPatches`. Runs the galactic-router route reflector (RR) for the iad region.
- **galactic-router image**: Uses `galactic-router:latest` with `imagePullPolicy: Never` — stale images persist across rebuilds.
- **Kind serviceSubnet**: All clusters use `/108` service subnet (non-standard; may cause issues with some services).
- **BGP listen port**: galactic-router tenant DaemonSets run with `GALACTIC_ROUTER_BGP_LISTEN_PORT=-1` (outbound-only, all sessions initiated outbound).
- **Worker SRv6 loopback**: The `lo-galactic` dummy interface with the SRv6 node SID is created via `exec` commands in the ContainerLab topology (not in the Kind bootstrap script).
- **Node labels**: Workers use `galactic.datum.net/node: edge` (not `galactic.io/role: pop`). The control node uses `galactic.datum.net/node: control` with a matching `NoSchedule` taint.
- **GC namespace**: The tenant DaemonSet sets `GALACTIC_ROUTER_GC_NAMESPACE=galactic-system` for namespace-scoped garbage collection.
- **FRR config**: Transit router configs omit the `frr version` directive (managed by the FRR image, not the config).

## Naming Layers

- **Fabric** — FRR DaemonSets running on each cluster's workers; handle eBGP to the transit mesh. Resources live in `resources/fabric/`.
- **Tenant** — galactic-router DaemonSets running on each cluster's workers; handle iBGP EVPN route distribution. Resources live in `resources/tenant/`.
- **iad-control** — The iad region's second worker node; runs the route reflector for all tenant BGP sessions. BGP resources in `resources/bgp/iad-control/`.

## References

Full documentation — topology, addressing, tasks — is in [README.md](README.md).
Verification commands are in [docs/verification.md](docs/verification.md).
Deploying test pods and verifying cross-site connectivity is documented in [docs/testvpc.md](docs/testvpc.md).
