# NAT66 / NAT64 — `galactic_nat_*`

See [scraping and component ports](README.md#where-the-metrics-come-from) and [shipped alerts](alerts.md).

One `galactic-nat` pod per egress shard; every value is per shard.

| Metric                                                   | Type      | Labels                                                                      | Meaning                                                                                                                                |
| -------------------------------------------------------- | --------- | --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic_nat_conns`                                     | gauge     | `family` (`nat66`, `nat64`)                                                 | Rows in the connection table, expired sessions included. A session holds two rows                                                      |
| `galactic_nat_sessions`                                  | gauge     | `family`, `proto` (`tcp`, `udp`, `icmp`)                                    | Live sessions: one per session within its idle timeout                                                                                 |
| `galactic_nat_conn_table_oldest_row_age_seconds`         | gauge     | none                                                                        | Seconds since the least recently seen session, expired ones included, last translated a packet. Meaningful only on a near-full table   |
| `galactic_nat_conn_table_max_entries`                    | gauge     | none                                                                        | Table capacity in rows, shared by both families                                                                                        |
| `galactic_nat_drops_total`                               | counter   | `reason`                                                                    | Packets dropped by the NAT datapath                                                                                                    |
| `galactic_nat_packets_total`                             | counter   | `family`, `direction` (`outbound`, `return`), `action` (`redirect`, `tx`)   | Packets the shard translated and queued for transmit. Every combination is reported, zero included                                     |
| `galactic_nat_bytes_total`                               | counter   | same                                                                        | Bytes of those packets: the translated IP packet, without Ethernet or the SRv6 outer header                                            |
| `galactic_nat_datapath_enabled`                          | gauge     | none                                                                        | 1 when the datapath is turned on by configuration, 0 when it is turned off                                                             |
| `galactic_nat_datapath_attached`                         | gauge     | none                                                                        | 1 once the datapath has loaded and attached, 0 before that or while turned off                                                         |
| `galactic_nat_programmed`                                | gauge     | none                                                                        | 1 while the datapath holds an EgressShard identity, 0 while it claims no packet                                                        |
| `galactic_nat_uplink_covered`                            | gauge     | `interface`                                                                 | 1 for each resolved uplink the datapath translates on, 0 for one it misses. Absent while turned off                                    |
| `galactic_nat_family_enabled`                            | gauge     | `family`                                                                    | 1 when the programmed identity has a masquerade address for the family                                                                 |
| `galactic_nat_info`                                      | gauge     | `shard_sid`, `nat64_prefix`, `xdp_attach`, `version`                        | Always 1. Empty `shard_sid` and `nat64_prefix` while unprogrammed; `xdp_attach="off"` while turned off                                 |
| `galactic_nat_masquerade_ports_in_use`                   | gauge     | `family`, `address`, `proto`                                                | Distinct masquerade ports live sessions hold on the address, toward any destination                                                    |
| `galactic_nat_masquerade_destination_ports_max`          | gauge     | `family`, `address`, `proto`                                                | The most ports live sessions hold toward any single destination address and port. New flows to it fail as this nears the range         |
| `galactic_nat_masquerade_port_range`                     | gauge     | none                                                                        | Ports (or ICMP Echo Identifiers) available toward each destination: 28000                                                              |
| `galactic_nat_dispatch_lease_renewals_total`             | counter   | `slot`, `result` (`success`, `error`)                                       | Renewals of the shard's XDP dispatcher slot lease. Dispatch mode only                                                                  |
| `galactic_nat_dispatch_lease_expiry_timestamp_seconds`   | gauge     | `slot`                                                                      | Unix time the lease, as last renewed, expires. Dispatch mode only                                                                      |
| `galactic_nat_session_creates_total`                     | counter   | `family`, `proto`                                                           | New sessions the shard opened, one masquerade port claim each                                                                          |
| `galactic_nat_masquerade_claim_probes_total`             | counter   | `family`, `proto`, `probes` (`1`..`8`)                                      | Those claims by how many probes each took. Rising multi-probe shares mean busy destinations are filling                                |
| `galactic_nat_uplink_resolve_errors_total`               | counter   | none                                                                        | Failed re-resolutions of the uplinks after a link or route change; the shard keeps its previous coverage                               |
| `galactic_nat_uplink_rx_queue_packets_total`             | counter   | `interface`, `driver`, `queue`                                              | Packets one NIC receive queue of an uplink received, from `ethtool -S`. Exported for `bnxt_en`, `ixgbe`, `ice`, `i40e`, `mlx5_core`    |
| `galactic_nat_uplink_rx_queue_discards_total`            | counter   | `interface`, `driver`, `queue`                                              | Packets one receive queue discarded before the datapath saw them. Reported only by drivers that count per queue: `bnxt_en` today       |
| `galactic_nat_uplink_queue_driver_stat_total`            | counter   | `interface`, `driver`, `queue`, `stat`                                      | One of a queue's other driver counters, under its `ethtool -S` name. `bnxt_en` only, see below                                         |
| `galactic_nat_uplink_info`                               | gauge     | `interface`, `driver`, `driver_version`, `firmware_version`, `kernel`       | Always 1. Names each uplink's driver and NIC firmware versions and the node's kernel release                                           |

Caveats for the translated traffic and state series:

- `outbound` is tenant traffic the shard decapsulated and translated toward
  the internet; `return` is a reply translated back and encapsulated toward
  the tenant. `tx` means the packet left over the uplink it arrived on,
  `redirect` over another one.
- Messages the shard sends on its own behalf (Packet Too Big, Fragmentation
  Needed, echo replies to its own address) and packets it passes on
  unclaimed are not translations and are not counted.
- The counters live in a pinned map, so they outlive a pod restart, like
  `galactic_nat_drops_total`.
- A shard can be attached and programmed and still translate nothing, when
  its uplinks never hand it the traffic. Compare
  `galactic_nat_packets_total{direction="outbound"}` with the compute nodes'
  `galactic_cni_egress_shard_packets_total` for its `shard_sid`
  (`GalacticNatNotTranslating`).
- Cardinality: 8 series each for packets and bytes, one `uplink_covered`
  series per uplink, and one `info` series per shard.

Caveats for the masquerade port series:

- A port is claimed per destination address and port, not per masquerade
  address, so the same port can serve many destinations at once.
  `galactic_nat_masquerade_ports_in_use` can sit near the range on a healthy
  shard that talks to many destinations;
  `galactic_nat_masquerade_destination_ports_max` is what predicts exhaustion.
- A claim probes 8 of the range's ports, so a destination fails new flows well
  before it is full: about 0.4% of new flows at half full, 17% at 80%
  (`GalacticNatPortsNearExhaustion` warns at half full).
- Every protocol of every address the programmed identity serves is reported,
  zero included, except when the session clock cannot be read: then only the
  range is reported, rather than zeros that would read as an idle shard. An
  address a re-programmed identity replaced is reported while live sessions
  still hold its ports.
- Both are read from the session table walk at scrape time, like
  `galactic_nat_sessions`, so they are approximate on a churning table.

Caveats for session creation:

- `galactic_nat_session_creates_total` is the sum of
  `galactic_nat_masquerade_claim_probes_total` over `probes`. A claim that
  finds no port is a `*_pat_exhausted` drop, and a claim that adopts a live
  session's lost port opens no new session; neither is counted.
- With a share u of a destination's ports held, a claim needs more than k
  probes with probability of roughly u^k (the probes walk consecutive ports,
  and held ports cluster, so it is an estimate). The share of claims needing more than one
  probe therefore estimates how full the destinations taking new flows are,
  before `galactic_nat_masquerade_destination_ports_max` names the worst one
  and long before `*_pat_exhausted` drops start.
- Cardinality: 6 creates series and 48 probe series per shard.

The `EgressShard` reconciler's controller-runtime metrics
(`controller_runtime_reconcile_total{controller="egressshard"}`,
`controller_runtime_reconcile_errors_total`, `workqueue_*`) are served on the
same port, from the same registry.

The dispatcher lease series are registered in dispatch mode only. The
edge gateway exports the same pair as `galactic_edge_dispatch_lease_*` for
its two slots; no shipped alert reads the gateway's yet.

Caveats for the session table:

- Expired sessions keep their rows until the LRU evicts them or a new claim
  reuses their port, so `galactic_nat_conns` sits near capacity on any busy
  shard. That is normal. Use `galactic_nat_sessions` for live sessions.
- Live sessions are at risk only when the table is full and its oldest row is
  younger than the longest session timeout, 7440 s for established TCP. The
  table's LRU evicts in approximate order, so the age is an estimate.
- The table is a self-evicting LRU, so the counts can move without traffic
  changing.

| Reason group          | Values                                                                                                                                                                            | Meaning                                                                                                         |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Port exhaustion       | `nat66_pat_exhausted`, `nat64_pat_exhausted`                                                                                                                                      | No free port on the shard's public address; tenants see failed connections                                      |
| Shard availability    | `nat64_shard_unavailable`                                                                                                                                                         | NAT64 had no shard to send to                                                                                   |
| Return-path misses    | `nat66_no_return_conn`, `nat64_no_return_conn`, `nat66_icmp_no_conn`, `nat64_icmp_no_conn`, `icmp_unsolicited`                                                                    | Inbound packets with no matching session; background noise is normal, a jump after a restart means lost state   |
| Malformed             | `nat66_malformed_forward`, `nat66_malformed_return`, `nat64_malformed_forward`, `nat64_malformed_return`, `nat66_icmp_malformed`, `nat64_icmp_malformed`, `icmp_untranslatable`   | Packets that couldn't be translated                                                                             |
| IPv4 limits (NAT64)   | `nat64_v4_fragment`, `nat64_v4_options`, `nat64_non_global_dest`                                                                                                                  | Unsupported IPv4 fragments or options, or a non-global destination                                              |
| Forwarding            | `fib_lookup_failed`, `fib_no_neigh`, `fib_unreachable`, `fib_frag_needed`, `adjust_head_failed`, `no_egress_ifindex`, `redirect_failed`, `hop_limit_exceeded`                     | Route, neighbor or redirect failure after translation                                                           |
| Rate limit            | `icmp_rate_limited`                                                                                                                                                               | ICMP errors suppressed by the rate limiter                                                                      |

Caveats for the uplink queue counters:

- `galactic_nat_uplink_queue_driver_stat_total` carries `bnxt_en`'s other
  per-ring counters: transmit packets, discards and errors, `rx_errors`,
  `rx_buf_errors`, `rx_resets` and `missed_irqs`. A ring's receive and transmit
  share one completion ring, so comparing a stalled ring's transmit rate with
  its siblings' shows whether transmit stopped along with receive.
- `galactic_nat_uplink_info` is exported for every uplink, whatever its
  driver, so per-queue behavior can be matched against driver, firmware and
  kernel versions across nodes.

```promql
# Live sessions per family
sum by (node, family) (galactic_nat_sessions)

# Idle live sessions being evicted: table full, oldest row younger than the TCP timeout
# (GalacticNatSessionTableEvictingLive)
sum by (node) (galactic_nat_conns) / on (node) max by (node) (galactic_nat_conn_table_max_entries) > 0.9
  and on (node) max by (node) (galactic_nat_conn_table_oldest_row_age_seconds) < 7440

# Port exhaustion or no shard
sum by (node, reason) (rate(galactic_nat_drops_total{reason=~".*_pat_exhausted|nat64_shard_unavailable"}[5m])) > 0

# New flows dropped for want of a port, held for 15 minutes (GalacticNatPortExhausted)
sum by (node, reason) (increase(galactic_nat_drops_total{reason=~"nat(66|64)_pat_exhausted"}[10m])) > 0

# Drop rate by reason
sum by (node, reason) (rate(galactic_nat_drops_total[5m])) > 0

# Translated packets per shard and direction
sum by (node, direction) (rate(galactic_nat_packets_total[5m]))

# Share of the shard's own traffic it dropped (GalacticNatForwardDropRatio)
sum by (node) (rate(galactic_nat_drops_total{reason=~"nat(66|64)_pat_exhausted|nat(66|64)_malformed_forward|redirect_failed|no_egress_ifindex|adjust_head_failed"}[10m]))
  / (sum by (node) (rate(galactic_nat_drops_total{reason=~"nat(66|64)_pat_exhausted|nat(66|64)_malformed_forward|redirect_failed|no_egress_ifindex|adjust_head_failed"}[10m]))
     + sum by (node) (rate(galactic_nat_packets_total[10m])))

# Busiest destination per masquerade address, as a share of the range (GalacticNatPortsNearExhaustion)
max by (node, family, address, proto) (galactic_nat_masquerade_destination_ports_max)
  / on (node) group_left () max by (node) (galactic_nat_masquerade_port_range)

# Share of new sessions whose port claim needed more than one probe
sum by (node, family) (rate(galactic_nat_masquerade_claim_probes_total{probes!="1"}[10m]))
  / sum by (node, family) (rate(galactic_nat_session_creates_total[10m]))

# Seconds left on the dispatcher lease, by the node's clock
galactic_nat_dispatch_lease_expiry_timestamp_seconds - time()

# No successful lease renewal in two minutes (GalacticNatDispatchLeaseExpiring)
changes(galactic_nat_dispatch_lease_renewals_total{result="success"}[2m]) == 0

# Shards turned on but not programmed, and uplinks not covered
galactic_nat_datapath_enabled == 1 and on (node) galactic_nat_programmed == 0
galactic_nat_uplink_covered == 0

# Discard share per uplink receive queue (#673)
rate(galactic_nat_uplink_rx_queue_discards_total[5m])
  / (rate(galactic_nat_uplink_rx_queue_discards_total[5m]) + rate(galactic_nat_uplink_rx_queue_packets_total[5m]))

# Transmit rate on each uplink ring, to compare a stalled ring with its siblings (#673)
sum by (node, interface, queue) (
  rate(galactic_nat_uplink_queue_driver_stat_total{stat=~"tx_(ucast|mcast|bcast)_packets"}[5m])
)
```
