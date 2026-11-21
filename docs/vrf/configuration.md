# VPC ingress sidecar configuration

`galactic-vrf` reconciles VPC ingress in the proxy pod's network namespace and
holds one Galactic Worker `socket` claim per VPC it serves
([contract](../worker/contract.md#envoy-and-the-galactic-vrf-sidecar)).
Explicit flags take precedence over their corresponding environment variables,
then compiled defaults. Node identity is an exception: when the resolved value
is empty, the legacy `NODE_NAME` is used even if `--node-name` was explicitly
set empty.
See [VPC ingress observability](../observability/vpc-ingress.md)
for its operation and metrics, and [logging](../observability/logging.md) for
shared logging options.

The `config/galactic-vrf` kustomize Component adds the sidecar to a Deployment
labelled `galactic.datumapis.com/galactic-vrf: enabled`. It sets the node name,
pod namespace, Worker mounts, ports and security context. The consumer supplies
the attachment selector. See its
[README](../../config/galactic-vrf/README.md).

| Flag                      | Environment                                | Default                                  | Meaning                                                                                                                                                               |
| ------------------------- | ------------------------------------------ | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--node-name`             | `GALACTIC_VRF_NODE_NAME`, then `NODE_NAME` | none                                     | Required. The node the pod runs on. The sidecar picks the proxy attachment whose `status.node` is this node, and resolves the node's BGPRouter.                       |
| `--pod-namespace`         | `GALACTIC_VRF_POD_NAMESPACE`               | none                                     | Required. The proxy pod's namespace, which holds its VPCAttachments.                                                                                                  |
| `--attachment-selector`   | `GALACTIC_VRF_ATTACHMENT_SELECTOR`         | none                                     | Required, and not empty. A label selector for the proxy's own VPCAttachments in the pod's namespace.                                                                  |
| `--namespace`             | `GALACTIC_VRF_NAMESPACE`                   | `galactic-system`                        | Namespace of the node's BGPRouter.                                                                                                                                    |
| `--worker-socket`         | `GALACTIC_VRF_WORKER_SOCKET`               | `/run/galactic-worker/worker.sock`       | The Worker's unix socket.                                                                                                                                             |
| `--worker-token-file`     | `GALACTIC_VRF_WORKER_TOKEN_FILE`           | `/var/run/secrets/galactic-worker/token` | The projected ServiceAccount token, audience `galactic-worker`.                                                                                                       |
| `--metrics-port`          | `GALACTIC_VRF_METRICS_PORT`                | `9182`                                   | Metrics listener port, 1–65535.                                                                                                                                       |
| `--health-port`           | `GALACTIC_VRF_HEALTH_PORT`                 | `9183`                                   | Port for `/healthz` and `/readyz`. The sidecar is ready once this pod holds every VPC's claim and has configured its pod end.                                         |
| `--teardown-grace-period` | `GALACTIC_VRF_TEARDOWN_GRACE_PERIOD`       | `30s`                                    | Grace before removing undesired routes and VRFs; must be positive.                                                                                                    |
| `--sweep-interval`        | `GALACTIC_VRF_SWEEP_INTERVAL`              | `5s`                                     | Interval for checking pending teardowns and for syncing claims; positive and no greater than the grace period. The claim sync also runs on each Worker status change. |

EndpointSlices supply the desired backends. The sidecar writes no BGPVRFInstance
or BGPAdvertisement: Worker writes the VRF instance for any VPC with claims and
publishes the advertisement for each claim's addresses. The gateway prefix
(`--gateway-prefix`) and gateway address derivation are gone. NSO creates the
proxy's per-VPC VPCAttachment, with the gateway address in
`spec.interface.addresses`.
