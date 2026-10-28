# Observability

Metrics, scrape configuration, shipped alert rules and log format. Use the subsystem reference for metric names, labels and interpretation.

- [VPC dataplane — `galactic_usid_*`](vpc-dataplane.md)
- [Tenant egress pool — `galactic_cni_egress_*`](egress-pool.md)
- [VPC ingress — `galactic_ingress_sidecar_*`](vpc-ingress.md)
- [Edge load balancer — `galactic_edge_*`](gateway.md)
- [Galactic Edge foundation — `galactic_edge_foundation_*`](edge.md)
- [Traffic policy — `galactic_cni_traffic_policy_*`](traffic-policy.md)
- [Routing](routing.md)
- [NAT66 / NAT64 — `galactic_nat_*`](nat.md)
- [Fabric looking glass — `fabric_api_*`](fabric-api.md)
- [Netlink listings — `galactic_netlink_dump_*`](netlink.md)
- [Shipped alerts](alerts.md)
- [Logging](logging.md)

## Adding a metric

Create every metric with the constructors in
[`go.miloapis.com/instrumentation/metrics`](https://github.com/milo-os/instrumentation),
and register a collector that reads state at scrape time with its
`metrics.MustRegister`. Both put the metric on controller-runtime's registry,
which every controller-runtime manager serves. `galactic-cni`,
`fabric-config-agent` and the fabric-api node sidecar, which serve metrics
without a manager, serve that registry with the library's `metrics.Handler`.

A metric created when its package loads is exported by every binary that
links the package. Where only some of them should export it, create it in a
constructor the binary calls at startup instead. The library's registry keeps
a series across calls, so a constructor that tests call repeatedly starts its
vectors over, and creates a function metric, which the library allows only
once per process, on its first call.

The tests in `internal/instrumentation` enforce the rule in the unit suite:

- `TestAdopted` runs the library's adoption check, which fails on a metric
  registered outside the library and on a logger the library didn't build.
- `TestNoMetricsOutsideLibrary` fails on any metric constructor or registry
  from `client_golang`'s `prometheus` package, including one passed in as a
  `prometheus.Registerer`.
- `TestMetricsLint` checks the name of every library metric created when a
  package loads against Prometheus conventions. It imports each package that
  defines one, and `TestLintLinksEveryMetric` fails when a package is missing
  from that list or creates a metric in a command's `main` package.
- Each command that serves `/metrics` has a `TestMetricsScrape`, which fails
  when two registries export the same series. `TestEveryBinaryHasScrapeTest`
  requires one for every new command, but can't tell whether the test scrapes
  the handler the command serves; reviewers check that. Where a command
  creates its metrics at startup rather than when a package loads, its test
  first creates them through the same function the command calls, and also
  runs the library's lint, which `TestMetricsLint` can't reach.

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
deployment or router targets in `target_node`, and the object's namespace
in `resource_namespace`.

The eBPF-backed metrics (`galactic_usid_*`, `galactic_cni_egress_shard_*`,
`galactic_edge_*`, `galactic_edge_foundation_gate_drops_total`, `galactic_nat_*`) are read from BPF maps at scrape time,
and a pod restart that reloads the program resets them. Always use
`rate()` / `increase()`, never raw counter values.
