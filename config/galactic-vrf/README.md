# galactic-vrf Component

A kustomize Component that adds the `galactic-vrf` ingress sidecar to an
Envoy proxy Deployment. It carries the ServiceAccount, read-only RBAC, the
container, and its volumes.

```yaml
resources:
  - envoy-deployment.yaml
components:
  - ../../config/galactic-vrf
```

## What the consumer supplies

- The Deployment, labelled `galactic.datumapis.com/galactic-vrf: enabled`.
  Only Deployments with that label are patched.
- `GALACTIC_VRF_ATTACHMENT_SELECTOR` on the `galactic-vrf` container: a label
  selector for the proxy's own VPCAttachments, for example
  `galactic.datumapis.com/proxy=envoy`. The Component ships the placeholder
  `galactic.datumapis.com/proxy=REPLACE_ME`; patch it.
- `namespace:` in its kustomization, if the Deployment is not in
  `envoy-gateway-system`. It moves the `galactic-vrf` ServiceAccount and the
  ClusterRoleBinding subject with it. The ClusterRole is cluster-scoped.

Other settings use the sidecar's defaults: `GALACTIC_VRF_NAMESPACE`
(`galactic-system`, the namespace of the node's BGPRouter), the Worker socket
and token paths, and ports 9182 (`/metrics`) and 9183 (`/healthz`, `/readyz`).
The image tag is set through the `images:` entry. See
[configuration](../../docs/vrf/configuration.md).

## Rollout

The patch sets the Deployment's rollout to `maxSurge: 0` and
`maxUnavailable: 1`. Galactic Worker serves each VPC's claim to one pod at a
time, and the sidecar is ready only once it holds every claim, so a rollout
that keeps the old pod until the new one is ready never finishes. With this
strategy the old pod stops first, its sidecar releases the claims on
`SIGTERM`, and the new pod takes them over. Upstream connections pause for
that handover. For the same reason two replicas on one node never both become
ready, so spread replicas across nodes, for example with pod anti-affinity.

## Worker allowlist

The sidecar reaches the Worker over the hostPath socket at
`/run/galactic-worker/worker.sock`, authenticating with a projected token for
audience `galactic-worker`. The operator must allow its ServiceAccount in the
Worker's allowlist, using the Deployment's namespace:

```yaml
# serviceAccounts:
#   - serviceAccount: envoy-gateway-system/galactic-vrf
#     capabilities: [local.socket, fabric.srv6]
```

## Prerequisites outside this Component

- Galactic Worker on every node that runs the proxy must be deployed with the
  `config/galactic-worker/profiles/routed-link` Component. The sidecar's
  `local.socket` claims need a routed link, and Worker can set up the link's
  pod end only with `SYS_PTRACE` and `SYS_ADMIN`, which that Component adds
  to Worker's base `NET_ADMIN` and `BPF`. Without it, Worker reports
  `local.socket` unavailable with `RoutedLinkUnavailable`, the sidecar's
  claims are never programmed, and the proxy never becomes ready
  ([Worker operations](../../docs/worker/operations.md#install)).
- NSO (network-services-operator) creates the proxy pod's per-VPC
  VPCAttachment in production. This Component does not.
- bpffs mounted at `/sys/fs/bpf` and `/run/galactic-worker` present on each
  node (both are `type: Directory` hostPaths).

## RBAC

Read-only: `get`, `list` and `watch` on `endpointslices`, `vpcattachments`
and `bgprouters`. There is no write access to `bgpvrfinstances` or
`bgpadvertisements`; the Worker writes those.
