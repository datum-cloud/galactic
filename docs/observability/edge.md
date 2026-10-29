# Galactic Edge foundation — `galactic_edge_foundation_*`

See [scraping and component ports](README.md#where-the-metrics-come-from) and [shipped alerts](alerts.md).

The attachment lifecycle and forwarding claims of the Galactic Edge
foundation (`config/galactic-edge/`), distinct from the edge load
balancer's `galactic_edge_*` above. Core's series come from
`galactic-controller --role=cell --edge`; every replica reads its cache at
scrape time, so aggregate them with `max`. Node series come from
`galactic-edge` on each edge node. No label names an attachment, pod,
route, prefix or address: `edge_provider` is an approved `EdgeProvider`'s name
or `unknown`, and `reason` is a condition reason or `Other`. Find the
objects behind a series with the Events and `kubectl` queries in
[the troubleshooting guide](../edge/troubleshooting.md).

| Metric                                            | Type    | Source | Labels                                   | Meaning                                                                                                 |
| ------------------------------------------------- | ------- | ------ | ---------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `galactic_edge_foundation_attachments`            | gauge   | core   | `edge_provider`, `state`, `reason`       | Attachments by the first lifecycle stage they have not passed, and the condition reason holding them    |
| `galactic_edge_foundation_routes`                 | gauge   | core   | `edge_provider`, `state`, `reason`       | Routes by claim state, and the condition reason holding them                                            |
| `galactic_edge_foundation_services`               | gauge   | core   | `edge_provider`, `policy`, `reason`      | Services whose traffic policy is `Resolved` or `Unresolved`, with the reason when unresolved            |
| `galactic_edge_foundation_state_collect_errors`   | gauge   | core   | none                                     | Kinds the last scrape could not list and left out                                                       |
| `galactic_edge_foundation_failures_total`         | counter | both   | `edge_role`, `stage`, `reason`           | Transitions into a failed stage, counted once per transition, not per retry. Each also records an Event |
| `galactic_edge_foundation_gate_closures_total`    | counter | node   | `edge_role`, `cause`                     | Open forwarding gates the agent closed, by cause. Each also records an Event on the route               |
| `galactic_edge_foundation_cleanup_failures_total` | counter | node   | `edge_role`                              | Host state releases and gate sweeps that failed and are retried                                         |
| `galactic_edge_foundation_links`                  | gauge   | node   | none                                     | Host links registered with the node's forwarding gate                                                   |
| `galactic_edge_foundation_gates`                  | gauge   | node   | `state` (`open`, `expired`, `closed`)    | Gates on the node. `expired` passed its deadline before the agent closed it                             |
| `galactic_edge_foundation_gate_drops_total`       | counter | node   | `check` (`ingress`, `egress`, `deliver`) | Packets dropped on an edge link because no open gate covered the address                                |
| `galactic_edge_foundation_scopes_lost`            | gauge   | node   | none                                     | VPC ownership scopes another writer took from this process                                              |
| `galactic_edge_foundation_node_collect_errors`    | gauge   | node   | none                                     | Gate table reads the last scrape could not make                                                         |

- Attachment `state`, in lifecycle order: `Admission`, `Allocation`,
  `Programming`, `Ready`, `Active`, then `Draining` and `Releasing`.
  `reason` is `Pending` while the stage's condition is unset, and
  `NotReady` for `Ready`, whose own reason the provider writes.
- Route `state`: `Unclaimed`, `Pending`, `Accepted` (with the `Published`
  condition's reason), `Published`, `Revoked` or `Released`.
- `edge_role`: `core` from `galactic-controller`, `node` from
  `galactic-edge`.
- `stage`: `Admission`, `Allocation`, `Programming`, `Policy`, `Route`.
- `cause`: `Expired` (no renewal extended the gate), `Released`,
  `Revoked`, `InstanceGone`, `AuthorityEnded`, `GrantCeiling`,
  `RouteGone` or `HolderMoved`.
- Packet drops by traffic policy on an edge link are
  `galactic_cni_traffic_policy_*` from `galactic-router`, labeled with the
  attachment.

```promql
# Attachments the foundation has admitted but not yet programmed, per provider
max by (edge_provider, reason) (galactic_edge_foundation_attachments{state="Programming"})

# Gates closing because providers stop renewing
sum by (node) (increase(galactic_edge_foundation_gate_closures_total{cause="Expired"}[1h]))
```
