# Traffic policy — `galactic_cni_traffic_policy_*`

See [scraping and component ports](README.md#where-the-metrics-come-from) and [shipped alerts](alerts.md).

Interface traffic policy decisions in the uSID datapath. The counters live in
per-CPU BPF maps the datapath writes; `galactic-router`, which allocates
every counter row and knows the rule, policy and interface it belongs to,
reads and labels them, so they are served on its port (9179) and scraped by
the `galactic-router` PodMonitor. The prefix names the datapath, not the
process. Only routers running with `GALACTIC_ROUTER_TRAFFIC_POLICY=true`
export them. See [traffic-policy/node.md](../traffic-policy/node.md).

| Metric                                                 | Type    | Labels                                                                                            | Meaning                                                                                 |
| ------------------------------------------------------ | ------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `galactic_cni_traffic_policy_rule_hits_total`          | counter | namespace, vpc, attachment, interface, interface_uid, direction, policy, policy_uid, rule, action | Packets evaluated with this rule as the winning rule                                    |
| `galactic_cni_traffic_policy_rule_bytes_total`         | counter | the same                                                                                          | Tenant IP bytes evaluated with this rule as the winning rule                            |
| `galactic_cni_traffic_policy_fallback_packets_total`   | counter | namespace, vpc, attachment, interface, interface_uid, direction, reason                           | Packets denied without a winning rule                                                   |
| `galactic_cni_traffic_policy_fallback_bytes_total`     | counter | the same                                                                                          | Tenant IP bytes denied without a winning rule                                           |
| `galactic_cni_traffic_policy_unattributed_drops_total` | counter | direction, reason                                                                                 | Policy denials whose interface or fallback row could not be resolved                    |
| `galactic_cni_traffic_policy_accounting_errors_total`  | counter | direction, action, reason                                                                         | Verdicts whose rule counter row was missing; the verdict stood, the count was lost      |
| `galactic_cni_traffic_policy_counter_read_errors`      | gauge   | none                                                                                              | Counter rows the last scrape could not read, and so left out rather than reporting zero |

- `direction` is `ingress` or `egress`; `action` is `allow` or `deny`.
- `reason` is one of `no_match`, `policy_unavailable`, `parse_error` or
  `classification_error`; `accounting_errors_total` uses
  `missing_rule_counter`.
- `interface_uid` is the VPCAttachment UID. For a Galactic Edge
  attachment, `namespace`, `attachment` and `interface_uid` are the
  EdgeAttachment's, `vpc` is its EdgeService's VPC and `interface` is its
  host link. `policy_uid` is the policy's
  UID, or `builtin:default-deny-all:v1` for a direction with no reference,
  which gets the built-in default. Its deny-all rule is a rule hit, not a
  fallback, so the default stays visible per interface and direction.
- One evaluation produces one outcome: a rule's hit and bytes, or one
  fallback pair. A packet between two managed interfaces is two
  evaluations, the sender's egress and the receiver's ingress.
- A hit is a policy decision, not forwarded traffic: an allowed packet
  dropped later still counts.
- Bytes are the tenant IP packet at the evaluation point, without Ethernet
  or outer SRv6. A GSO packet counts once, at its buffer length. A packet
  whose IP boundary cannot be found adds zero bytes.
- A rule keeps its series while its name and action stay the same within
  one policy and interface lifetime, so editing its match keeps counting.
  Rename a rule to start a fresh measurement. Rebinding another policy,
  removing a rule, flipping its action, or recreating the interface starts
  from zero.
- A node reboot or a datapath reload resets them. Use `rate()` or
  `increase()`.

```promql
# Rule hits per second, aggregated across nodes and interfaces.
sum by (namespace, policy, rule, direction, action) (
  rate(galactic_cni_traffic_policy_rule_hits_total[5m])
)

# Tenant bytes per second explicitly denied by a rule on each interface.
sum by (namespace, attachment, interface, interface_uid, direction, rule) (
  rate(galactic_cni_traffic_policy_rule_bytes_total{action="deny"}[5m])
)

# Failures and no-match denies, which are not attributed to a winning rule.
sum by (namespace, direction, reason) (
  rate(galactic_cni_traffic_policy_fallback_packets_total[5m])
)

# Interfaces still on the built-in default deny.
count by (namespace, attachment, direction) (
  galactic_cni_traffic_policy_rule_hits_total{policy_uid="builtin:default-deny-all:v1"}
)

# Counts the datapath lost or could not attribute.
sum by (node, direction, reason) (
  rate(galactic_cni_traffic_policy_unattributed_drops_total[5m])
  or rate(galactic_cni_traffic_policy_accounting_errors_total[5m])
) > 0
```
