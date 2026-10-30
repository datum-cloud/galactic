# Application metrics

This map identifies the metrics endpoints of commands in `cmd/` and links to
metric names, types, labels and meanings in their canonical references. Ports
below are binary defaults unless a deployment override is stated. A metric
registered conditionally or labeled by an event may be absent until the feature
is enabled or the event occurs. An absent series does not by itself mean a
healthy component. The [scrape map](README.md#where-the-metrics-come-from)
identifies the shipped PodMonitors.

Controller-runtime managers expose their own reconciliation and workqueue
metrics alongside Go and process metrics. The application references below
cover Galactic-specific metrics. [Netlink listing metrics](netlink.md) count
only operations performed in the process serving the endpoint.

| Application                | Endpoint and metric reference                                                                                                                                                                                                                                   |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic-cni`             | `run` serves port 9180: [VPC dataplane and attachment traffic](vpc-dataplane.md), [egress pool](egress-pool.md), [VPC ingress return and EndpointSlice repair](vpc-ingress.md), [netlink](netlink.md). `init` has no metrics server.                            |
| `galactic-veth`            | CNI invocation has no scrape endpoint. Node-level datapath metrics are exported by `galactic-cni`, not this short-lived process.                                                                                                                                |
| `galactic-tap`             | CNI invocation has no scrape endpoint. Node-level datapath metrics are exported by `galactic-cni`.                                                                                                                                                              |
| `galactic-ipam`            | CNI invocation has no scrape endpoint.                                                                                                                                                                                                                          |
| `galactic-route`           | CNI invocation has no scrape endpoint.                                                                                                                                                                                                                          |
| `galactic-bgp`             | CNI invocation has no scrape endpoint. The router's BGP and route metrics are described in [routing](routing.md).                                                                                                                                               |
| `galactic-router`          | Port 9179: [tenant routing and private service routes](routing.md#tenant-routing--galactic_router_), [traffic policy](traffic-policy.md), and [netlink](netlink.md). Route reflector mode does not run the private-service controller.                          |
| `galactic-gateway`         | Port 8081: [gateway datapath and dispatcher](gateway.md) and [netlink](netlink.md). A scrape object is not shipped for this component.                                                                                                                          |
| `galactic-nat`             | Port 9182: [NAT translation, shard state, dispatcher and uplinks](nat.md), and [netlink](netlink.md).                                                                                                                                                           |
| `galactic-vrf`             | Port 9182 by default, in the ingress pod network namespace: [VPC ingress](vpc-ingress.md) and [netlink](netlink.md). A scrape object is not shipped for this component.                                                                                         |
| `galactic-controller`      | Port 9184 by default: cell role exposes [instance attachment](vpc-attachments.md) and, with `--edge`, [Edge core](edge.md) metrics. The fabric role runs a separate manager and does not register those cell collectors. Both serve controller-runtime metrics. |
| `galactic-edge`            | Port 9186: node-side [Edge foundation](edge.md) and [netlink](netlink.md) metrics.                                                                                                                                                                              |
| `fabric-config-agent`      | `watch` serves port 9343: [underlay configuration](routing.md#underlay-config--fabric_router_) and [activation metrics](../fabric-routing/operations.md#metrics-and-alerts).                                                                                    |
| `fabric-router-controller` | `run` serves port 8080 by default (the supplied deployment uses 9185): [fabric routing](../fabric-routing/operations.md#metrics-and-alerts). Fleet state is collected by the elected leader. Other CLI operations do not serve metrics.                         |
| `fabric-api`               | `node` and `gateway` serve [Fabric API metrics](fabric-api.md), default ports 9345 and 9347 respectively; `certsync`, `janitor` and `query` have no metrics endpoint.                                                                                           |
| `galactic-usid`            | Identifier conversion CLI; no metrics endpoint.                                                                                                                                                                                                                 |
| `masque-authority`         | `serve`, `ledger` and `grant` do not serve a metrics endpoint.                                                                                                                                                                                                  |
| `masque-provider`          | `--health-listen` serves port 9188 by default: [CONNECT-IP and MASQUE adapter metrics](masque.md).                                                                                                                                                              |

The FRR exporter is a separate sidecar in the `fabric-router` pod rather than a
command in `cmd/`. Its [underlay metrics](routing.md#underlay--frr_) are
scraped separately from the config agent and the optional Fabric API sidecar.
