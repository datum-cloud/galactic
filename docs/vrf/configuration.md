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
| `--in-pod-encapsulation`  | `GALACTIC_VRF_IN_POD_ENCAPSULATION`        | `false`                                  | Encapsulate traffic to backends on other nodes inside the pod. See [in-pod encapsulation](#in-pod-encapsulation).                                                     |

EndpointSlices supply the desired backends. The sidecar writes no BGPVRFInstance
or BGPAdvertisement: Worker writes the VRF instance for any VPC with claims and
publishes the advertisement for each claim's addresses. The gateway prefix
(`--gateway-prefix`) and gateway address derivation are gone. NSO creates the
proxy's per-VPC VPCAttachment, with the gateway address in
`spec.interface.addresses`.

## In-pod encapsulation

By default (`--in-pod-encapsulation=false`) the sidecar sends every
connection over the routed link Worker gives each claim, into the VPC's VRF on
the host, where the host's datapath encapsulates traffic to a backend on
another node. For each claim the sidecar creates the VPC's VRF in the pod
(its table from the sidecar range, starting at `0x10000`), enslaves the
link's pod end to it, assigns the gateway address, and installs one default
route, through the pod end to the host end's link-local address, with the
gateway as its source and protocol `0x47`. It replaces any other default route
in that table and removes the per-backend `/128` routes of protocol `0x47`.
EndpointSlices give only the claims' destinations: the route Store, its
startup inventory and sweep, and the node source address lookup do not run.

At startup the sidecar removes, once, the in-pod encapsulation an earlier
sidecar left: the `ivs<table>` and `ivp<table>` veth pairs, the main-table
redirect routes and kernel seg6 routes into a sidecar VRF, and every row in
the sidecar's key range of the node's shared `vrf_table`,
`ifindex_vrf_table`, `egress_route_table` and `tp_iface_table` maps. Host
rows are never touched. A failure, such as maps it cannot open, is logged and
startup continues.

The prune removes every in-pod encapsulation row on the node, not only this
pod's. Before turning in-pod encapsulation off on one sidecar, switch every
sidecar on that node together. The Component's rollout (`maxSurge: 0`)
replaces one proxy pod per node at a time.

`--in-pod-encapsulation=true` keeps the earlier datapath: the sidecar watches
EndpointSlices, creates each VPC's VRF with a default route into an in-pod
SRv6 encapsulation (`usid_egress` on the `ivs<table>`/`ivp<table>` veth pair),
and routes only Local backends over the routed link. Use it only on nodes
whose primary CNI forwards SRv6 packets a pod encapsulated; a CNI that checks
a pod's source address, such as Cilium, drops them. The setting is slated for
removal, together with the in-pod datapath.

With in-pod encapsulation off, the sidecar does not serve its startup, sweep,
datapath and node source metrics
([VPC ingress observability](../observability/vpc-ingress.md)); readiness and
the `worker_*` claim metrics report its state. The prune removes every
in-pod encapsulation row in the node's shared maps, not only this pod's, so
every sidecar on a node must run with the same setting.
