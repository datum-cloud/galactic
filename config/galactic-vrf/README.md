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

## How the proxy reaches backends

The sidecar sends all of the proxy's upstream traffic over the routed link
Worker gives each VPC's claim, into the node's VPC routing table. Worker
attaches the node's egress datapath to the link's host end, so a backend on
another node is reached over the fabric the way a tenant reaches it, and the
traffic never leaves through the pod's own interface. The sidecar's earlier
in-pod encapsulation is off by default (`--in-pod-encapsulation`); a primary
CNI that checks a pod's source address, such as Cilium, drops its packets.
See the [Worker contract](../../docs/worker/contract.md#envoy-and-the-galactic-vrf-sidecar).

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
- NSO (network-services-operator) creates the proxy's per-VPC
  VPCAttachment in production, one per proxy, node and VPC, with
  `status.podName` naming the proxy pod; it names a replacement pod on the
  same attachment. galactic-controller then certifies the attachment's node
  from that pod. This Component creates no attachment
  ([Worker contract](../../docs/worker/contract.md#envoy-and-the-galactic-vrf-sidecar)).
- bpffs mounted at `/sys/fs/bpf` and `/run/galactic-worker` present on each
  node (both are `type: Directory` hostPaths).

## Privileges

The sidecar runs as root with every capability dropped except three:
`NET_ADMIN` for the VRF devices, routes and tc attachments in the pod's
network namespace, `BPF` to open and update the node's pinned uSID maps, and
`SYS_ADMIN`, because attaching its egress program first opens the pinned
programs already on the hook by ID, which the kernel allows only with
`SYS_ADMIN`. Kubernetes refuses `allowPrivilegeEscalation: false` beside
`SYS_ADMIN`, so the Component does not set it. The root filesystem is
read-only; the VRF lock directory and the tc attach lock directory
(`/run/galactic`) are `emptyDir`s, since everything they lock is in the pod. Its host mounts are
bpffs and the Worker socket directory. `tests/manifests/galactic-vrf/privileges.yaml`
records every grant, and `task test:manifests` fails when the rendered
Component grants anything else.

## RBAC

Read-only: `get`, `list` and `watch` on `endpointslices`, `vpcattachments`
and `bgprouters`. There is no write access to `bgpvrfinstances` or
`bgpadvertisements`; the Worker writes those.
