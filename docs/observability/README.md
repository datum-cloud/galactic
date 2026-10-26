# Observability

Metrics, scrape configuration and shipped alert rules. Use the subsystem reference for metric names, labels and interpretation.

- [VPC dataplane — `galactic_usid_*`](vpc-dataplane.md)
- [Tenant egress pool — `galactic_cni_egress_*`](egress-pool.md)
- [VPC ingress — `galactic_ingress_sidecar_*`](vpc-ingress.md)
- [Edge load balancer — `galactic_edge_*`](gateway.md)
- [Galactic Edge foundation — `galactic_edge_foundation_*`](edge.md)
- [Traffic policy — `galactic_cni_traffic_policy_*`](traffic-policy.md)
- [Routing](routing.md)
- [NAT66 / NAT64 — `galactic_nat_*`](nat.md)
- [Fabric looking glass — `fabric_api_*`](fabric-api.md)
- [Shipped alerts](alerts.md)

## Where the metrics come from

The dataplane and fabric-router DaemonSets use `hostNetwork: true`, so
their metric ports are bound on the node itself. `galactic-vrf` runs as a sidecar in the ingress
proxy's pod instead, which has its own network namespace, so it shares
the 9182 default with `galactic-nat` without clashing, even on the edge
nodes that run both. `galactic-controller`, `fabric-router-controller` and
the fabric-api gateway are Deployments, scraped per pod.

| Area                    | Component                                                 | Metric prefix                                                 | Port           | `job` from `config/monitoring/`          |
| ----------------------- | --------------------------------------------------------- | ------------------------------------------------------------- | -------------- | ---------------------------------------- |
| VPC dataplane           | `galactic-cni` (`credential-refresh`, the datapath owner) | `galactic_usid_*`                                             | 9180           | `galactic-cni`                           |
| Tenant egress pool      | `galactic-cni`                                            | `galactic_cni_egress_*`                                       | 9180           | `galactic-cni`                           |
| VPC ingress             | `galactic-vrf`                                            | `galactic_ingress_sidecar_*`                                  | 9182 (default) | none shipped                             |
| VPC ingress return path | `galactic-cni` (`credential-refresh`)                     | `galactic_sidecar_return_*`                                   | 9180           | `galactic-cni`                           |
| VPC ingress backends    | `galactic-cni` (`credential-refresh`)                     | `galactic_endpointslice_repair_*`                             | 9180           | `galactic-cni`                           |
| Edge load balancer      | `galactic-gateway`                                        | `galactic_edge_*`, controller-runtime                         | 8081           | none shipped                             |
| Tenant routing (GoBGP)  | `galactic-router`, `galactic-router-rr`                   | `galactic_router_*`, controller-runtime                       | 9179           | `galactic-router` / `galactic-router-rr` |
| Private service routes  | `galactic-router` (plain mode only)                       | `galactic_service_route_*`                                    | 9179           | `galactic-router`                        |
| Traffic policy          | `galactic-router` with `GALACTIC_ROUTER_TRAFFIC_POLICY`   | `galactic_cni_traffic_policy_*`                               | 9179           | `galactic-router`                        |
| Traffic policy webhook  | `galactic-controller`                                     | controller-runtime                                            | 9184           | `galactic-controller`                    |
| Galactic Edge (core)    | `galactic-controller --role=cell --edge`                  | `galactic_edge_foundation_*`                                  | 9184           | `galactic-controller`                    |
| Galactic Edge (node)    | `galactic-edge`                                           | `galactic_edge_foundation_*`, controller-runtime              | 9186           | `galactic-edge`                          |
| Underlay routing (FRR)  | `fabric-router` `frr-exporter` sidecar                    | `frr_*`                                                       | 9342           | `fabric-router`                          |
| Underlay config         | `fabric-router` `fabric-config-agent`                     | `fabric_router_*`                                             | 9343           | `fabric-config-agent`                    |
| Fabric routing (API)    | `fabric-router-controller`                                | `galactic_fabric_routing_*` (leader only), controller-runtime | 9185           | `fabric-router-controller`               |
| Fabric looking glass    | `fabric-api` node sidecar                                 | `fabric_api_node_*`, `fabric_api_*`                           | 9345           | `fabric-api-node`                        |
| Fabric looking glass    | `fabric-api` cell gateway                                 | `fabric_api_gateway_*`, `fabric_api_*`                        | 9347           | `fabric-api-gateway`                     |
| NAT66 / NAT64           | `galactic-nat` (one per egress shard)                     | `galactic_nat_*`                                              | 9182           | `galactic-nat`                           |

`config/monitoring/` ships PodMonitors for `galactic-cni`,
`galactic-router`, `fabric-router` (including the opt-in fabric-api
sidecar), `fabric-router-controller`, the fabric-api gateway,
`galactic-nat`, `galactic-controller` and `galactic-edge`. Scraping
`galactic-vrf` or `galactic-gateway` needs a scrape object of your own. Copy the shipped
PodMonitors' relabeling of `__meta_kubernetes_pod_node_name` into `node`:
every galactic metric is per node, and `node` is the label you group and
alert by. `fabric-router-controller`'s fleet series name the node each
deployment or router targets themselves, and their `namespace` is the
object's, which its PodMonitor keeps with `honorLabels`.

The eBPF-backed metrics (`galactic_usid_*`, `galactic_cni_egress_shard_*`,
`galactic_edge_*`, `galactic_edge_foundation_gate_drops_total`, `galactic_nat_*`) are read from BPF maps at scrape time,
and a pod restart that reloads the program resets them. Always use
`rate()` / `increase()`, never raw counter values.
