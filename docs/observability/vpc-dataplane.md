# VPC dataplane — `galactic_usid_*`

See [scraping and component ports](README.md#where-the-metrics-come-from) and [shipped alerts](alerts.md).

The SRv6 uSID datapath on every node, forwarding packets between the fabric
and tenant VRFs.

### Traffic

Each node keeps one VRF per VPC, so every series below is one VPC on one
node, keyed by its uSID (Block, Argument). `vpc_attachment` names the
attachment that registered the VRF last, not each attachment's own traffic.
`vrf_interface` is the name of the VPC's VRF device on the node, as
`ip link` shows it.

| Metric                                        | Type      | Labels                                                                                       | Meaning                                                                           |
| --------------------------------------------- | --------- | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `galactic_usid_vrf_forwarded_packets_total`   | counter   | `block`, `argument`, `vrf_table_id`, `vpc`, `vpc_attachment`, `vrf_interface`, `direction`   | Packets forwarded into (`ingress`) or out of (`egress`) the VRF                   |
| `galactic_usid_vrf_forwarded_bytes_total`     | counter   | same                                                                                         | Tenant bytes of those packets: the IP header and payload, in both directions      |
| `galactic_usid_vrf_dropped_packets_total`     | counter   | same                                                                                         | Packets dropped after the datapath resolved them to the VRF, by direction         |
| `galactic_usid_vrf_packets_total`             | counter   | `block`, `argument`, `vrf_table_id`, `vpc`, `vpc_attachment`, `vrf_interface`                | Inbound packets that matched the VRF, counted before any later drop               |
| `galactic_usid_vrf_bytes_total`               | counter   | same                                                                                         | Bytes of those packets, measured as the whole tunneled frame with outer headers   |

What each `direction` counts:

| `direction`   | Counted when                                                                                                                                                                      |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ingress`     | `usid_ingress` decapsulates a packet and redirects it to an attachment, or another attachment on the same node sends one to it                                                    |
| `egress`      | a tenant packet is encapsulated toward another node or an egress shard, sent unencapsulated out the public uplink (a VIP reply), or delivered to another attachment on the node   |

- A packet counts once, when the datapath has committed to forwarding it.
  Traffic the datapath hands to the kernel to route (no matching egress
  route) and fail-open paths are not counted.
- A packet too big for the fabric, answered with a Packet Too Big or
  Fragmentation Needed, counts as neither forwarded nor dropped; see
  `galactic_usid_pmtu_packets_total`.
- Traffic between two attachments of one VPC on the same node counts once
  as `egress` and once as `ingress` on that VPC's series, when it is handed
  to the kernel for delivery, so the kernel can still drop it. Traffic to the
  sender's own gateway address counts in neither; traffic to another
  attachment's gateway address in the same VPC counts as delivered.
- A private service route delivering to another attachment on the node
  counts `egress` on the sender's VPC and `ingress` on the receiver's, which
  may be a different VPC.
- A GSO or GRO super-packet counts as one packet carrying all its bytes.
- Drop reasons are in `galactic_usid_drops_total`, which has no VRF.
  `galactic_usid_vrf_dropped_packets_total` has the VRF but no reason, and
  covers drops in decapsulation, delivery, encapsulation and the PMTU check,
  including inbound private service tunnels. Outbound private service route
  drops (`service_route_*` from the sending attachment) and failed
  public-uplink redirects appear only in `galactic_usid_drops_total`.
- The two older series keep their meaning: inbound only, claimed before any
  drop, and the full frame. Prefer the `forwarded` series for throughput.
- Registering a VRF again never resets its counters. They reset when the
  datapath reloads, or when the VRF's rows are removed and created again,
  which `rate()` copes with.
- `vpc`, `vpc_attachment` and `vrf_interface` are empty when the VPC
  attribution map has no entry for that Argument. Treat `vpc=""` traffic as
  unattributed and watch for it.
- Cardinality is one series per active Argument per node for the older pair,
  at most 4095 per Block, and twice that for each `direction` metric.

```promql
# Throughput per VPC and direction, bits/s
sum by (vpc, direction) (rate(galactic_usid_vrf_forwarded_bytes_total[5m])) * 8

# Top 10 VPCs on a node by outbound packet rate
topk(10, sum by (node, vpc) (rate(galactic_usid_vrf_forwarded_packets_total{direction="egress"}[5m])))

# Share of a VPC's packets dropped after the datapath claimed them
sum by (vpc, direction) (rate(galactic_usid_vrf_dropped_packets_total[5m]))
  / (sum by (vpc, direction) (rate(galactic_usid_vrf_forwarded_packets_total[5m]))
     + sum by (vpc, direction) (rate(galactic_usid_vrf_dropped_packets_total[5m])))

# Traffic the datapath can't attribute to a VPC
sum by (node) (rate(galactic_usid_vrf_forwarded_bytes_total{vpc=""}[5m]))
```

### Per-attachment traffic

Each VPC attachment has a host-side link on the node. These series read that
link's kernel byte counters at scrape time, so each series is one attachment's
own traffic, unlike the per-VRF series above. The collector registers when the
datapath starts, so the series appear on the same `galactic-cni` port as
`galactic_usid_*`.

| Metric                                         | Type    | Labels                                      | Meaning                                                                                                              |
| ---------------------------------------------- | ------- | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `galactic_vpc_attachment_receive_bytes_total`  | counter | `vpc`, `vpc_attachment`, `host_interface`   | Bytes delivered to the instance through this attachment, read from the host-side link's transmit counter            |
| `galactic_vpc_attachment_transmit_bytes_total` | counter | same                                        | Bytes sent by the instance through this attachment, read from the host-side link's receive counter                  |

- `vpc` and `vpc_attachment` are the unpadded base62 IDs, as in the series
  above. `host_interface` is the name of the host-side link, as `ip link`
  shows it.
- Direction is from the instance's side. `receive` is what the host link
  transmits toward the instance, and `transmit` is what the host link
  receives from it.
- The counters are link-layer frame bytes. They run about 14 bytes per packet
  above `galactic_usid_vrf_forwarded_bytes_total`, which counts the IP packet
  without the Ethernet header. The host link also counts frames the VRF
  counters never see, such as ARP, Neighbor Discovery, and other link-local
  traffic, and frames the datapath drops, so the gap is larger than the
  per-packet header difference.
- The counters reset when the link is recreated, which `rate()` copes with.
  A series disappears with its link.
- A link the kernel reports no statistics for is skipped. If the scrape can't
  list links, the collector reports an invalid metric, and the `/metrics`
  endpoint on port 9180 returns HTTP 500 for that scrape. Every
  `galactic-cni` series is missing from that scrape, not only these, and `up`
  is 0. `galactic_netlink_dump_*` shows whether link listings were interrupted;
  see [Netlink listings](netlink.md).
- Cardinality is two series per attachment on the node.

```promql
# Throughput per attachment as the instance receives it, bits/s
sum by (vpc, vpc_attachment) (rate(galactic_vpc_attachment_receive_bytes_total[5m])) * 8
```

### Drops

`galactic_usid_drops_total{reason}` (counter) counts packets the uSID
datapath dropped, inbound and outbound. Every named reason is always
emitted, at zero when unused, plus `unknown_<n>` for an index the binary
has no name for.

| Reason group       | Values                                                                                                                           | Usually means                                                                                     |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Unknown SID        | `unknown_function`, `unknown_argument`                                                                                           | Traffic for a VRF or Argument this node no longer, or never, registered: stale routes elsewhere   |
| Malformed          | `malformed_inner`, `unknown_inner_version`, `unexpected_nexthdr`, `unsupported_behavior`, `strip_failed`                         | Bad or unsupported packets; a sustained rate is a bug                                             |
| FIB / forwarding   | `fib_lookup_failed`, `fib_no_neigh`, `fib_unreachable`, `fib_frag_needed`, `redirect_failed`                                     | Kernel route or neighbor missing for the inner destination                                        |
| Egress             | `egress_route_encap_failed`, `egress_route_fib_lookup_failed`, `egress_route_redirect_failed`, `public_uplink_redirect_failed`   | Tenant traffic leaving the node couldn't be encapsulated or sent                                  |
| Service routes     | `service_route_denied`, `service_route_redirect_failed`                                                                          | A private service route refused the sender, or its redirect to the target failed                  |
| IPv4 VIP           | `vip_xlat_failed`, `vip_ipv4_fragment`, `vip_udp_no_checksum`, `vip_ipv4_backend`, `vip_ttl_exceeded`                            | An IPv4 VIP packet was untranslatable; `vip_ipv4_backend` means a pre-translation router          |

```promql
sum by (node, reason) (rate(galactic_usid_drops_total[5m])) > 0
```

### SID capacity

| Metric                                             | Type    | Labels    | Meaning                                                  |
| -------------------------------------------------- | ------- | --------- | -------------------------------------------------------- |
| `galactic_usid_block_arguments_used`               | gauge   | `block`   | Arguments (VRF entries) registered in the Block          |
| `galactic_usid_block_argument_utilization_ratio`   | gauge   | `block`   | `arguments_used / 4095`, the usable capacity per Block   |

```promql
max by (node, block) (galactic_usid_block_argument_utilization_ratio) > 0.8
```

### MTU handling

| Metric                                      | Type      | Labels     | Meaning                                                                     |
| ------------------------------------------- | --------- | ---------- | --------------------------------------------------------------------------- |
| `galactic_usid_tcp_mss_clamp_syns_total`    | counter   | `result`   | TCP SYNs the MSS clamp examined                                             |
| `galactic_usid_tcp_mss_clamp_limit_bytes`   | gauge     | `family`   | MSS that SYNs are clamped to; `0` means clamping is off for that family     |
| `galactic_usid_pmtu_packets_total`          | counter   | `result`   | Tenant packets too big for the fabric once encapsulated                     |
| `galactic_usid_pmtu_limit_bytes`            | gauge     | none       | Largest tenant packet the egress encapsulates; `0` means the check is off   |

`galactic_usid_tcp_mss_clamp_syns_total` result values:

- **Clamping worked:** `clamped_ipv4`, `clamped_ipv6`, `within_limit`.
- **SYN crossed the fabric unclamped:** `no_mss_option`,
  `skipped_extension_header`, `malformed_options`, `rewrite_failed`,
  `walk_limit`.

`galactic_usid_pmtu_packets_total` result values:

- **Tenant got an ICMP error back:** `too_big_sent_ipv6`,
  `frag_needed_sent_ipv4`.
- **Dropped without an ICMP error (black-hole risk):** `dropped_no_df`,
  `dropped_icmp_error`, `rate_limited`, `no_gateway`, `build_failed`.

```promql
# SYNs that crossed unclamped
sum by (node, result) (rate(galactic_usid_tcp_mss_clamp_syns_total{result!~"clamped_.*|within_limit"}[5m]))

# PMTU drops with no ICMP error, the case that stalls connections silently
sum by (node, result) (rate(galactic_usid_pmtu_packets_total{result!~"too_big_sent_ipv6|frag_needed_sent_ipv4"}[5m]))

# Clamp off for a family
galactic_usid_tcp_mss_clamp_limit_bytes == 0
```

### Host-only ports

| Metric                                     | Type    | Labels | Meaning                                                                  |
| ------------------------------------------ | ------- | ------ | ------------------------------------------------------------------------ |
| `galactic_usid_host_only_port_drops_total` | counter | none   | TCP packets to a tap's host-only port not sent to its link-local address |

A tap that lists [host-only ports](../cni/conflist-reference.md#host-only-ports)
refuses TCP to them from anything but its node. A rising count means something
on the VPC is trying to reach a guest's agent port.

### Datapath lifecycle

| Metric                                         | Type      | Labels                                                 | Meaning                                                              |
| ---------------------------------------------- | --------- | ------------------------------------------------------ | -------------------------------------------------------------------- |
| `galactic_usid_datapath_load_events_total`     | counter   | `result` (`success`, `failure`)                        | BPF program load attempts                                            |
| `galactic_usid_datapath_attach_events_total`   | counter   | `interface`, `action` (`attach`, `detach`), `result`   | TC ingress attach/detach, including every netlink-driven re-attach   |

```promql
increase(galactic_usid_datapath_load_events_total{result="failure"}[15m]) > 0
increase(galactic_usid_datapath_attach_events_total{result="failure"}[15m]) > 0

# Re-attach churn: a flapping interface
sum by (node, interface) (increase(galactic_usid_datapath_attach_events_total{action="attach"}[1h])) > 5
```

### Host link repair

`galactic-cni` checks every 30 seconds for a Galactic host link, a tap or the
host end of a veth, with no VRF master. Such a link's VRF was deleted under
it, so its guest's traffic is routed in the main table, outside its VPC. The
repair enslaves it back to its VPC's VRF and restores the addresses, routes
and neighbor entries the move drops. A link whose VPC has no VRF is only
counted. See [host link repair](../cni/architecture.md#host-link-repair).

| Metric                                           | Type      | Labels   | Meaning                                                                               |
| ------------------------------------------------ | --------- | -------- | ------------------------------------------------------------------------------------- |
| `galactic_cni_host_links_masterless`             | gauge     | none     | Host links still without a VRF master after the last pass                             |
| `galactic_cni_host_link_reenslaved_total`        | counter   | none     | Host links the repair found without a VRF master and enslaved back to their VRF       |
| `galactic_cni_host_link_repair_failures_total`   | counter   | none     | Repair passes that failed; one that could not list links leaves the gauge as it was   |

`GalacticHostLinkMasterless` fires when the gauge stays above zero for 10
minutes. Any increase of the counter means a VRF was deleted with a link still
in it, which garbage collection no longer does, so it is worth a look even
when the repair succeeded.

```promql
max by (node) (galactic_cni_host_links_masterless) > 0
increase(galactic_cni_host_link_reenslaved_total[1h]) > 0
```
