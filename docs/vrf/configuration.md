# VPC ingress sidecar configuration

`galactic-vrf` reconciles VPC ingress in the gateway pod's network namespace.
Explicit flags take precedence over their corresponding environment variables,
then compiled defaults. Node identity is an exception: when the resolved value
is empty, `NODE_NAME` is used even if `--node-name` was explicitly set empty.
See [VPC ingress observability](../observability/vpc-ingress.md)
for its operation and metrics, and [logging](../observability/logging.md) for
shared logging options.

| Flag                      | Environment                                | Default           | Meaning                                                                                                                                               |
| ------------------------- | ------------------------------------------ | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--metrics-port`          | `GALACTIC_VRF_METRICS_PORT`                | `9182`            | Metrics listener port, 1–65535.                                                                                                                       |
| `--teardown-grace-period` | `GALACTIC_VRF_TEARDOWN_GRACE_PERIOD`       | `30s`             | Grace before removing undesired routes and VRFs; must be positive.                                                                                    |
| `--sweep-interval`        | `GALACTIC_VRF_SWEEP_INTERVAL`              | `5s`              | Interval for checking pending teardowns; positive and no greater than the grace period.                                                               |
| `--node-name`             | `GALACTIC_VRF_NODE_NAME`, then `NODE_NAME` | empty             | Node identity for return-path gateway advertisements. An empty resolved value disables the publisher only if `NODE_NAME` is also empty.               |
| `--namespace`             | `GALACTIC_VRF_NAMESPACE`                   | `galactic-system` | Namespace for BGP router, VRF and advertisement resources.                                                                                            |
| `--gateway-prefix`        | `GALACTIC_VRF_GATEWAY_PREFIX`              | empty             | Reserved, byte-aligned IPv6 CIDR for derived per-VPC gateway addresses. Empty disables address provisioning; it takes effect only with node identity. |
| `--api-socket`            | `GALACTIC_VRF_API_SOCKET`                  | empty             | Absolute path of a unix socket to dial the Kubernetes API through. Empty uses the in-cluster address. See [below](#api-through-a-local-socket).       |

Reserve gateway address space disjoint from all tenant IPAM pools. EndpointSlices
supply desired workload endpoints; the optional publisher reads BGP routing
resources and writes advertisements. A prefix alone cannot enable publication.

## API through a local socket

By default the sidecar reaches the Kubernetes API at the in-cluster address, so
its pod needs network access to the API server. A pod's network policy applies
to every container in it, so Envoy gets the same access.

Set `--api-socket` to a unix socket mounted into the pod, served by a per-node
proxy, and the pod can drop API access. The sidecar dials every API connection
through the socket and changes nothing else: it keeps the in-cluster host, CA,
TLS server name and its ServiceAccount token. The proxy must forward bytes to
the API server unchanged. It must not terminate TLS or add credentials. The API
server still authenticates the sidecar's own ServiceAccount, so its RBAC is
unchanged. The sidecar ignores `HTTPS_PROXY` and similar variables for API
traffic while the socket is set, since the socket already leads to the API
server.

The socket need not exist when the sidecar starts. Client-go retries, and the
connection succeeds once the proxy is serving.
