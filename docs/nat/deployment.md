# Deploying egress translation

This guide describes the installation order for NAT66/NAT64 shards. Run it first in an isolated environment. Each deployment supplies its own underlay routing, masquerade addresses and uplink configuration; applying RBAC alone starts no shard.

## Placement

`galactic-nat` runs on every `galactic.datumapis.com/node: edge` node that
also carries `galactic.datumapis.com/nat: enabled`, one DaemonSet per
cluster, alongside `galactic-vrf` and, on nodes that opt into it,
`galactic-gateway` (see [docs/node-labels.md](../node-labels.md)). An edge
node without `nat=enabled`, a compute node, an unlabeled node and a
control-plane node never run a shard. A shard there is one hop from the
transit its masquerade addresses are originated into. Compute nodes run no
shard: each compute node's tenant egress is SRv6-encapsulated toward its own
site's edge shards (`GALACTIC_CNI_EGRESS_SHARD_SIDS`, [configuration](configuration.md#shard-membership-galactic-cni-side)).

`galactic-nat` used to run on compute nodes, one shard each. It moved because
an edge node is where both a masquerade address and its replies belong; the
move is also why it now shares that node's XDP hook with the gateway (see
`GALACTIC_NAT_XDP_ATTACH`, in the configuration reference).

## Installation order

1. Install the Galactic CRDs from `config/crd/`, including `EgressShard`, and establish the fabric underlay and tenant router on each target edge node.
2. Label each target with `galactic.datumapis.com/node=edge` and `galactic.datumapis.com/nat=enabled`. Keep its `galactic=router` and fabric labels as required by its routing deployment.
3. Apply `kubectl apply -k config/galactic-nat/` for the ServiceAccount and RBAC. Its kustomization intentionally excludes the DaemonSet base.
4. Create an overlay using `config/galactic-nat/base/`. Supply uplink settings for the deployment. On a node sharing XDP with the gateway, set `GALACTIC_NAT_XDP_ATTACH=dispatch`; the base default is `direct`. Apply the completed overlay with `kubectl apply -k <overlay-directory>` before checking shard readiness.
5. Create one `EgressShard` targeting each node, with unique SID and masquerade addresses and the required NAT64 prefixes. Arrange return routing for its public `/128` and `/32` addresses. Use [the API and configuration reference](configuration.md#egressshard-crd-galacticdatumapiscomv1alpha1) and the [lab overlays](../../deploy/containerlab/resources/galactic-nat/) as worked inputs.
6. Configure tenant nodes' shard membership and NAT64 prefixes using [the CNI settings](configuration.md#shard-membership-galactic-cni-side). Start with ordered mode unless [hashed-mode acceptance](active-active-rollout.md) is satisfied.
7. Verify shard readiness and real traffic in both directions before admitting workloads that depend on this egress path.

Deleting a shard tears down its sessions. For planned removal, drain it first and wait for a session count you accept losing. The [active/active rollout guide](active-active-rollout.md) describes draining and rollback; it is not a session-replication mechanism.

## Verifying

```sh
kubectl get egressshard -n galactic-system -o wide
kubectl get bgpadvertisement -n galactic-system | grep nat66
```

Metrics, exposed on `GALACTIC_NAT_METRICS_PORT` (`9182` by default):

| Metric                                                 | Type    | Labels                                               | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ------------------------------------------------------ | ------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic_nat_conns`                                   | Gauge   | `family`                                             | Rows in this shard's `nat_conn_table`, expired sessions included. A session holds two rows. Expect it near capacity on a busy shard; see [Session table](configuration.md#session-table).                                                                                                                                                                                                                                                                                               |
| `galactic_nat_sessions`                                | Gauge   | `family`, `proto`                                    | Live sessions, one per session within its idle timeout. `proto` is `tcp`, `udp` or `icmp`. Every series is reported, at zero when empty.                                                                                                                                                                                                                                                                                                                                                |
| `galactic_nat_conn_table_oldest_row_age_seconds`       | Gauge   | —                                                    | Seconds since the least recently seen session in the table, expired ones included, last translated a packet. On a near-full table it approximates how long an idle session lasts before the LRU evicts it; on a table with room it only grows. Absent while the table holds no sessions.                                                                                                                                                                                                |
| `galactic_nat_conn_table_max_entries`                  | Gauge   | —                                                    | Capacity of `nat_conn_table` in rows, read from the loaded map.                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `galactic_nat_drops_total`                             | Counter | `reason`                                             | Packets dropped by the `nat_ingress` program, by reason. Cumulative for the life of the *node*, not the process: the counters live in a map pinned under `natattach.PinDir`, which a restarting shard reuses as-is. Always read it as a delta — an absolute value includes every transient the node has ever seen, and zeroing it takes `bpftool map update` against the pin directly.                                                                                                  |
| `galactic_nat_packets_total`                           | Counter | `family`, `direction`, `action`                      | Packets the shard translated and queued for transmit. `direction` is `outbound` (tenant to internet) or `return` (internet to tenant), `action` is `tx` (out the uplink it arrived on) or `redirect` (out another). Messages the shard sends on its own behalf (Packet Too Big, Fragmentation Needed, echo replies) are not translations and are not counted. Every combination is reported, at zero when unused. Cumulative for the life of the node, like `galactic_nat_drops_total`. |
| `galactic_nat_bytes_total`                             | Counter | `family`, `direction`, `action`                      | Bytes of the packets in `galactic_nat_packets_total`: the translated IP packet, without the Ethernet header or the SRv6 outer header a return packet carries.                                                                                                                                                                                                                                                                                                                           |
| `galactic_nat_datapath_enabled`                        | Gauge   | —                                                    | 1 when `GALACTIC_NAT_DATAPATH_ENABLED` turns the datapath on, 0 when it is off.                                                                                                                                                                                                                                                                                                                                                                                                         |
| `galactic_nat_datapath_attached`                       | Gauge   | —                                                    | 1 once startup has loaded the program and attached it to the uplinks or the XDP dispatcher. 0 before that, and while the datapath is turned off.                                                                                                                                                                                                                                                                                                                                        |
| `galactic_nat_programmed`                              | Gauge   | —                                                    | 1 while `shard_config_table` holds an EgressShard identity, 0 while the shard claims no packet.                                                                                                                                                                                                                                                                                                                                                                                         |
| `galactic_nat_uplink_covered`                          | Gauge   | `interface`                                          | 1 for each resolved uplink the datapath translates on, 0 for one it misses, whose traffic leaves untranslated. Absent while the datapath is turned off.                                                                                                                                                                                                                                                                                                                                 |
| `galactic_nat_family_enabled`                          | Gauge   | `family`                                             | 1 when the programmed identity has a masquerade address for that family (`shardAddressIPv6` for `nat66`, `shardAddressIPv4` for `nat64`).                                                                                                                                                                                                                                                                                                                                               |
| `galactic_nat_info`                                    | Gauge   | `shard_sid`, `nat64_prefix`, `xdp_attach`, `version` | Always 1. `shard_sid` and `nat64_prefix` are empty while unprogrammed, and `xdp_attach` is `off` while the datapath is turned off.                                                                                                                                                                                                                                                                                                                                                      |
| `galactic_nat_masquerade_ports_in_use`                 | Gauge   | `family`, `address`, `proto`                         | Distinct masquerade ports (or ICMP Echo Identifiers) live sessions hold on the address, toward any destination. A port is claimed per destination address and port, so this can approach the range on a healthy shard; see the next series for exhaustion. Every protocol of every served address is reported, zero included.                                                                                                                                                           |
| `galactic_nat_masquerade_destination_ports_max`        | Gauge   | `family`, `address`, `proto`                         | The most ports live sessions hold toward one destination address and port. A claim probes 8 of the range's candidates, so new flows to that destination fail with probability about (this / range)^8: 0.4% at half full.                                                                                                                                                                                                                                                                |
| `galactic_nat_masquerade_port_range`                   | Gauge   | —                                                    | Ports available toward each destination, `NAT_PAT_PORT_RANGE` (28000).                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `galactic_nat_dispatch_lease_renewals_total`           | Counter | `slot`, `result`                                     | Renewals of the shard's XDP dispatcher slot lease, `success` or `error`. Present in dispatch mode only.                                                                                                                                                                                                                                                                                                                                                                                 |
| `galactic_nat_dispatch_lease_expiry_timestamp_seconds` | Gauge   | `slot`                                               | Unix time the slot's lease, as last renewed, expires. The dispatcher skips the slot once it passes. Present in dispatch mode only.                                                                                                                                                                                                                                                                                                                                                      |
| `galactic_nat_session_creates_total`                   | Counter | `family`, `proto`                                    | New sessions opened, each a masquerade port (or ICMP Echo Identifier) the shard claimed. A claim that found no port is a `*_pat_exhausted` drop instead, and one that adopted a live session's lost port is not counted. Every combination is reported, zero included.                                                                                                                                                                                                                  |
| `galactic_nat_masquerade_claim_probes_total`           | Counter | `family`, `proto`, `probes`                          | Those claims by how many of the 8 candidates each probed. With a share u of a destination's ports held, a claim needs more than k probes with probability of roughly u^k, so a rising share above `probes="1"` is the earliest sign destinations are filling.                                                                                                                                                                                                                           |
| `galactic_nat_uplink_resolve_errors_total`             | Counter | —                                                    | Times re-resolving the uplinks after a link or route change failed. The shard keeps its previous coverage, so uplinks that appeared since stay uncovered until a later resolution succeeds.                                                                                                                                                                                                                                                                                             |
| `galactic_nat_uplink_rx_queue_packets_total`           | Counter | `interface`, `driver`, `queue`                       | Packets one NIC receive queue of an uplink received, from the driver's `ethtool -S` statistics. Exported for `bnxt_en`, `ixgbe`, `ice`, `i40e` and `mlx5_core`; any other driver exports nothing.                                                                                                                                                                                                                                                                                       |
| `galactic_nat_uplink_rx_queue_discards_total`          | Counter | `interface`, `driver`, `queue`                       | Packets one NIC receive queue of an uplink discarded before the datapath saw them, so `galactic_nat_drops_total` never counts them. Only drivers that count discards per queue report it: `bnxt_en` today.                                                                                                                                                                                                                                                                              |

The same port also serves the `EgressShard` reconciler's controller-runtime
metrics (`controller_runtime_reconcile_total{controller="egressshard"}`,
`controller_runtime_reconcile_errors_total`, `workqueue_*`), registered in the
same registry as the series above.

`config/monitoring/podmonitor-galactic-nat.yaml` scrapes every shard as
`job="galactic-nat"` with a `node` label.

A full table alone is not a problem. The table is evicting live sessions
when it is full and its oldest row is younger than the longest session
timeout, 7440 s: idle established TCP sessions are then evicted before they
expire. `GalacticNatSessionTableEvictingLive` in
`config/monitoring/prometheusrule.yaml` fires on this query after 15
minutes:

```promql
sum by (node) (galactic_nat_conns) / on (node) max by (node) (galactic_nat_conn_table_max_entries) > 0.9
  and on (node) max by (node) (galactic_nat_conn_table_oldest_row_age_seconds) < 7440
```

Drop reasons currently defined (`internal/plumbing/ebpf/natprog/dropreason.go`):

| Reason                                                                             | Meaning                                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nat66_no_return_conn`, `nat64_no_return_conn`                                     | A TCP or UDP reply matched no live session.                                                                                                                                                                                                     |
| `nat66_malformed_return`, `nat64_malformed_return`                                 | A reply too short to parse, or not TCP or UDP.                                                                                                                                                                                                  |
| `nat66_malformed_forward`, `nat64_malformed_forward`                               | A tenant packet too short to parse, or of a protocol the family does not translate.                                                                                                                                                             |
| `nat66_pat_exhausted`, `nat64_pat_exhausted`                                       | Every port or Echo Identifier in the probe held by a live session. `GalacticNatPortExhausted` fires after 15 minutes of them.                                                                                                                   |
| `nat64_v4_fragment`, `nat64_v4_options`                                            | An IPv4 reply that was fragmented or carried options.                                                                                                                                                                                           |
| `nat64_shard_unavailable`                                                          | A NAT64 packet reached a shard with no IPv4 masquerade address.                                                                                                                                                                                 |
| `nat64_non_global_dest`                                                            | A tenant packet, Echo included, to a NAT64 address whose embedded IPv4 address is not globally reachable (RFC 6890 special-purpose, multicast or reserved).                                                                                     |
| `nat66_icmp_malformed`                                                             | An ICMPv6 message, or the packet an ICMPv6 error quotes, too short to parse.                                                                                                                                                                    |
| `nat66_icmp_no_conn`                                                               | An Echo Reply, or an ICMPv6 error, that matched no live session.                                                                                                                                                                                |
| `icmp_untranslatable`                                                              | A well-formed ICMP message the shard has no translation for: an ICMP type it does not handle, an ICMPv4 error RFC 7915 says to drop, a tenant sending anything but an Echo Request, or an error quoting a packet the shard could not have sent. |
| `icmp_unsolicited`                                                                 | An Echo Request addressed to a masquerade address itself, with the echo responder off.                                                                                                                                                          |
| `nat64_icmp_malformed`                                                             | An ICMPv4 message, or the packet an ICMPv4 error quotes, too short to parse; or a tenant's ICMPv6 bound for a NAT64 address that is.                                                                                                            |
| `nat64_icmp_no_conn`                                                               | An ICMPv4 Echo Reply, or an ICMPv4 error, that matched no live session.                                                                                                                                                                         |
| `icmp_rate_limited`                                                                | A reply the echo responder would have sent, refused by the per-CPU token bucket.                                                                                                                                                                |
| `fib_no_neigh`, `fib_unreachable`, `fib_frag_needed`, `fib_lookup_failed`          | The shard translated a packet and could not resolve where to send it.                                                                                                                                                                           |
| `adjust_head_failed`, `hop_limit_exceeded`, `no_egress_ifindex`, `redirect_failed` | The shard translated a packet and could not transmit it.                                                                                                                                                                                        |

A tenant can ping through NAT66: its Echo Request is translated like a UDP
datagram, the Echo Identifier masqueraded in the port's place, and the
ICMPv6 errors the internet sends back about its flows — Destination
Unreachable, Packet Too Big, Time Exceeded, Parameter Problem — reach it
rewritten to describe the packet it sent. A ping to a NAT64-synthesized
address works too: the shard translates ICMPv6 Echo to ICMPv4 Echo and back.
A reply that fits the internet path but not the fabric once the shard
re-encapsulates it — 40 bytes bigger over NAT66, 60 over NAT64 — is still
dropped and counted as `fib_frag_needed`, but its sender now hears why: the
shard sends it a Packet Too Big, or a Fragmentation Needed over NAT64, from
the masquerade address, carrying the fabric route's MTU less those bytes.
TCP rarely needs this, since the fabric's MSS clamp keeps its segments small
enough; UDP and ICMP do.

ICMPv4 errors about a tenant's NAT64 flows reach it as the ICMPv6 errors RFC
7915 section 4.2 maps them to, quoted packet translated too, from the
reporting router's address synthesized into the prefix the flow used — so
traceroute names each IPv4 hop, and a Fragmentation Needed arrives as a
Packet Too Big for 20 bytes more than the IPv4 MTU. The quote is carried
whole unless the ICMPv6 packet would exceed 1280 bytes or the message
carries RFC 4884 extensions; then it is cut to the first 8 bytes of the
quoted transport header, which is all the kernel matches an error on.

The `fib_*` reasons and the three after them all mean the same class of
thing: the shard translated a packet and then could not get rid of it.
Every leg of this datapath resolves its own next hop and transmits from
the driver, forward and return alike — see the constraint below — so the
kernel's output path is doing none of that work and none of its failures
are the kernel's to report.

```sh
kubectl exec -n galactic-system <galactic-nat-pod> -- \
  wget -qO- http://localhost:9182/metrics | grep galactic_nat_
```

Confirm the eBPF program is attached (in dispatch mode, in the dispatcher's
egress slot) and
translating. On the `EgressShard` object, `Ready` should read
`DatapathAttached` and `Programmed` should read `AddressesProgrammed`. `Ready` reading `UplinksMissing` names the uplinks
whose traffic the shard is not translating:

```sh
kubectl get egressshard <name> -n galactic-system -o jsonpath='{.status.conditions}'
```
