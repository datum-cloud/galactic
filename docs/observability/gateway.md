# Edge load balancer — `galactic_edge_*`

See [scraping and component ports](README.md#where-the-metrics-come-from) and [shipped alerts](alerts.md).

`galactic-gateway`'s XDP DSR load balancer on gateway-role edge nodes.
Every gateway node serves every VIP identically (anycast), so the same
series appear on each one. Direct server return keeps no per-flow state,
so there is no connection table to report. See
[ARCHITECTURE-GATEWAY.md](../agents/ARCHITECTURE-GATEWAY.md).

| Metric                                                  | Type    | Labels                              | Meaning                                                                                              |
| ------------------------------------------------------- | ------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `galactic_edge_rule_packets_total`                      | counter | `proto`, `port`, `vip`, `vpc`       | Packets that matched the VIP, port and protocol, whatever happened to them next                      |
| `galactic_edge_rule_bytes_total`                        | counter | same                                | Bytes of those packets                                                                               |
| `galactic_edge_rule_dropped_packets_total`              | counter | same                                | Matched packets the datapath then dropped, such as for no backends. A subset of `rule_packets_total` |
| `galactic_edge_rule_backends`                           | gauge   | same                                | Backends registered for the VIP                                                                      |
| `galactic_edge_rule_seconds_since_last_packet`          | gauge   | same                                | Seconds since a packet last matched the VIP. Absent until the first one                              |
| `galactic_edge_return_packets_total`                    | counter | `vip`, `vpc`                        | Replies sourced from the VIP that this node forwarded past the kernel (`edge_return`)                |
| `galactic_edge_return_bytes_total`                      | counter | same                                | Bytes of those replies                                                                               |
| `galactic_edge_return_dropped_packets_total`            | counter | same                                | Replies sourced from the VIP that the datapath dropped. A subset of `return_packets_total`           |
| `galactic_edge_drops_total`                             | counter | `reason`                            | Packets `edge_lb` and `edge_return` dropped, by reason                                               |
| `galactic_edge_neigh_fallbacks_total`                   | counter | none                                | Packets `edge_lb` handed to the kernel to resolve the next hop. Not counted as drops                 |
| `galactic_edge_control_plane_drops_total`               | counter | `rule`, `reason` (`quota_exceeded`) | Rule applications refused before they reached the datapath                                           |
| `galactic_edge_dispatch_lease_renewals_total`           | counter | `slot`, `result`                    | Renewals of the gateway's XDP dispatcher slot leases. Dispatch mode only                             |
| `galactic_edge_dispatch_lease_expiry_timestamp_seconds` | gauge   | `slot`                              | Unix time each lease, as last renewed, expires. Dispatch mode only                                   |

- `proto` is `tcp`, `udp`, or the protocol number for anything else.
- `vpc` is empty until the process has applied a rule that owns the VIP,
  as after a restart before the first reconcile. A VIP address used by
  rules of more than one VPC has an empty `vpc` on its return series, since
  the return counters can't be split between them.
- The per-VIP counters survive re-registration, such as a reconcile that
  only changes the backend list. The return series read zero, not absent,
  on a node with no compute tier behind it.
- `galactic_edge_drops_total` reasons: `empty_backend_list`,
  `no_encap_config`, `fib_no_neigh`, `fib_unreachable`, `fib_frag_needed`,
  `fib_lookup_failed`, `adjust_head_failed`, `no_egress_ifindex`,
  `redirect_failed`, `return_hop_limit`, `icmp_rate_limited`, plus
  `unknown_<n>` for an index the binary has no name for.
- `fib_no_neigh` counts only replies `edge_return` forwards and ICMP errors
  the gateway sends. A load-balanced packet whose next hop has no neighbor
  entry goes to the kernel, which resolves the neighbor and forwards it, and
  is counted in `galactic_edge_neigh_fallbacks_total` instead. That counter
  rises briefly after a link or node rejoins the fabric. Steady growth means
  neighbor entries keep expiring or a next hop does not answer, and the
  kernel drops what it cannot resolve. The counter records the handoff, not
  delivery: these packets cross the node's netfilter FORWARD hook, unlike the
  XDP path, so a host firewall that drops forwarded traffic drops them too.

The port also serves controller-runtime's metrics for the
`NetworkGateway`/`NetworkService` reconcilers.

```promql
# Requests per second per VIP and port
sum by (vpc, vip, port, proto) (rate(galactic_edge_rule_packets_total[5m]))

# VIPs with no backends
max by (vip, port, proto) (galactic_edge_rule_backends) == 0

# Drops by reason
sum by (node, reason) (rate(galactic_edge_drops_total[5m])) > 0

# Rules refused by quota
sum by (node, rule) (increase(galactic_edge_control_plane_drops_total[1h])) > 0
```
