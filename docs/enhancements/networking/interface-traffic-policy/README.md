---
status: provisional
stage: alpha
latest-milestone: "TBD"
---

# Interface traffic policy

- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-goals](#non-goals)
- [Proposal](#proposal)
  - [Fixed requirements](#fixed-requirements)
  - [Risks and mitigations](#risks-and-mitigations)
- [Design details](#design-details)
  - [API ownership](#api-ownership)
  - [Resource model](#resource-model)
  - [Rule language](#rule-language)
  - [Admission and explicit null](#admission-and-explicit-null)
  - [Default policy identity](#default-policy-identity)
  - [Binding transitions](#binding-transitions)
  - [Forwarding path classification](#forwarding-path-classification)
  - [Packet path audit](#packet-path-audit)
  - [Parser contract](#parser-contract)
  - [Link operation exceptions](#link-operation-exceptions)
  - [BPF maps](#bpf-maps)
  - [Publication and lifetime](#publication-and-lifetime)
  - [Lifecycle activation and continuity](#lifecycle-activation-and-continuity)
  - [Reconciliation and status](#reconciliation-and-status)
  - [Metrics](#metrics)
  - [Kernel requirements](#kernel-requirements)
- [Rollout](#rollout)
- [Delivery plan](#delivery-plan)
  - [Pull request sequence](#pull-request-sequence)
  - [Requirement checklist](#requirement-checklist)
- [Alternatives](#alternatives)

## Summary

A TrafficPolicy is an ordered list of Allow and Deny rules. Each VPC interface
binds one policy for traffic the workload receives (ingress) and, separately,
one for traffic the workload sends (egress). The CNI BPF datapath evaluates the
bound policy on every packet in that direction. An interface with no binding in
a direction uses a built-in policy whose only rule denies everything.

Policies are stateless. Allowing a request never allows its reply; the reply
needs its own rule in its own direction.

## Motivation

Every tenant interface today forwards whatever its VPC routes allow. A workload
that should only serve one private port can also reach the internet through a
NAT shard, and a workload that should only make outbound calls can receive
anything routed to it. Operators have no per-interface control and no record
of what was denied.

### Goals

- Give each interface independent ingress and egress policies.
- Deny by default, including while an interface is being created and while the
  control plane is unavailable.
- Let rules match the forwarding path (private VPC routing, a NAT shard, or a
  public service), the IP family, exact addresses or prefixes, the protocol,
  ports and ICMP type and code.
- Apply updates to running interfaces without restarting workloads.
- Count every packet against the rule that decided it.

### Non-goals

- Connection tracking or any implicit reply allowance.
- Policy attached to a whole VPC, VRF or namespace.
- Tiered precedence, merging of several policies, or deny-overrides-allow.
- SMTP or any other port-specific platform rule.
- Application-layer, DNS-name or rate-based matching.
- Provisioning NAT, VIPs or services. An Allow only permits use of forwarding
  that already exists.
- Interoperability with Kubernetes NetworkPolicy or with BGPPolicy, which is
  route-advertisement policy.

## Proposal

### Fixed requirements

These come from the product brief and are not open to redesign here.

| ID | Requirement                                                                                                                                   |
| -- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| R1 | Policy applies to one VPC interface. Two interfaces in one VPC and VRF can differ.                                                            |
| R2 | Each interface has an independent ingress policy and egress policy, named by the workload's direction.                                        |
| R3 | Neither direction creates permissions in the other. No connection tracking or synthesized replies.                                            |
| R4 | The default policy has exactly one rule, deny all, and applies to any direction without a binding.                                            |
| R5 | Rules are ordered Allow and Deny. First match wins. No match denies.                                                                          |
| R6 | Rules match path, protocol, optional source and destination addresses or prefixes, and ports. NAT access is an ordinary path match.           |
| R7 | Updates apply to existing interfaces without recreation, and one direction's update never changes the other.                                  |
| R8 | Missing enforcement state never allows. Failed same-identity updates keep the last good policy. Rebinding and deletion never keep old grants. |

### Risks and mitigations

| Risk                                                                 | Mitigation                                                                                                                                                                                |
| -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Default deny breaks every running workload on rollout                | Enforcement is off per node until an explicit enable, and operators bind policies first (see [Rollout](#rollout)).                                                                        |
| A path is misclassified and a narrow Allow matches the wrong traffic | Classification uses only trusted forwarding state. Any lookup that cannot finish is `classification_error`, which denies at the first rule that names a path.                             |
| A packet reaches a workload by a path that skips the check           | The [packet path audit](#packet-path-audit) names the check for every delivery mechanism, and the integration tests send traffic down each one.                                           |
| Snapshot or counter memory is reused while a packet still holds it   | Reuse waits for the kernel to free the old inner map, which happens only after every program that could hold it has finished (see [Publication and lifetime](#publication-and-lifetime)). |
| Verifier cost of the evaluation loop                                 | Evaluation is a separately verified global function using `bpf_loop`, so its cost does not grow with the rule count.                                                                      |

## Design details

### API ownership

Existing networking kinds live in `network.datumapis.com` (the network
repository) and `cloud.datumapis.com` (the cloud repository). Both repositories
are being folded into Galactic under `galactic.datumapis.com/v1alpha1`, with
every kind in `api/v1alpha1` of the Galactic module. New kinds therefore start
there. Adding them to the network module would deepen a dependency that is
being removed, and would need a companion release for every change.

VPC and VPCAttachment are owned by the cloud operator, which writes both the
spec and the status of every VPCAttachment. Galactic does not write either.
Bindings are therefore a separate Galactic kind rather than new fields on
VPCAttachment.

One VPCAttachment describes exactly one interface: its `spec.interface` is a
single object, and the cloud operator creates one VPCAttachment, and one
NetworkAttachmentDefinition of the same name, per NetworkInterface. The
attachment's namespace, name and UID identify an interface lifetime. An
ifindex is a node-local detail and never appears in the API.

### Resource model

Both kinds are namespaced. References are local names, so a policy is always
in the binding's namespace and there is no field that could name another
tenant's policy.

```yaml
apiVersion: galactic.datumapis.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: public-web-egress
  namespace: tenant-a
spec:
  rules:
    - name: https-through-nat
      action: Allow
      match:
        path: PublicNAT
        protocol: TCP
        destinationPorts:
          - start: 443
            end: 443
    - name: deny-all
      action: Deny
```

```yaml
apiVersion: galactic.datumapis.com/v1alpha1
kind: TrafficPolicyBinding
metadata:
  name: web-0-eth0          # must equal the VPCAttachment's name
  namespace: tenant-a
spec:
  ingressPolicyRef:
    name: private-web-ingress
  egressPolicyRef:
    name: public-web-egress
status:
  observedGeneration: 3
  ingress:
    policy: {name: private-web-ingress, uid: 6d1c...}
    conditions: [...]        # Resolved, Applied
  egress:
    policy: {name: public-web-egress, uid: 91fa...}
    conditions: [...]
  nodes:
    - node: dfw-compute-3
      ingress: {policyUID: 6d1c..., policyGeneration: 4, appliedAt: ...}
      egress: {policyUID: 91fa..., policyGeneration: 2, appliedAt: ...}
```

- The binding's name must equal the VPCAttachment's name, enforced by CEL. That
  makes "one binding per interface" a property of naming rather than a
  conflict to detect, so there is exactly one effective policy per interface
  and direction.
- Omitting a reference selects the built-in default for that direction only.
  Removing a reference restores the default for that direction only.
- A binding for an attachment that does not exist yet is accepted and waits.
  An attachment without a binding is denied in both directions.
- `status.ingress` and `status.egress` report the resolved policy identity and
  a `Resolved` condition. `status.nodes` reports what each node applied,
  separately from what the API asked for. Admission success is never reported
  as convergence.

### Rule language

| Field                                         | Type                                      | Meaning                                                                 |
| --------------------------------------------- | ----------------------------------------- | ----------------------------------------------------------------------- |
| `name`                                        | DNS label, unique in the policy           | Diagnostic and metric identity                                          |
| `action`                                      | `Allow` or `Deny`                         | Deny drops; no ICMP is synthesized                                      |
| `match`                                       | object, optional                          | All present fields are ANDed; absent means a catch-all                  |
| `match.path`                                  | `Private`, `PublicNAT` or `PublicService` | Absent means any path                                                   |
| `match.ipFamily`                              | `IPv4` or `IPv6`                          | Absent means both                                                       |
| `match.protocol`                              | `TCP`, `UDP`, `ICMP` or `ICMPv6`          | Absent means any IP protocol, allowed only without ports or ICMP fields |
| `match.sourceIPs`, `match.destinationIPs`     | 1 to 64 literal addresses, a set          | Exact /32 or /128                                                       |
| `match.sourceCIDRs`, `match.destinationCIDRs` | 1 to 64 prefixes, a set                   | Network address must have no host bits                                  |
| `match.sourcePorts`, `match.destinationPorts` | 1 to 16 `{start, end}` ranges             | Inclusive, 0 to 65535, TCP or UDP only, no overlap                      |
| `match.icmp`                                  | `{type, code?}`                           | ICMP or ICMPv6 only                                                     |

- Entries within one list are alternatives (OR). Different fields are ANDed.
- `sourceIPs` and `sourceCIDRs` are mutually exclusive, as are
  `destinationIPs` and `destinationCIDRs`. An IP list on one side with a CIDR
  list on the other is allowed. Several exact addresses and prefixes on one
  side need separate ordered rules.
- Source always means the packet's source and destination the packet's
  destination, in both directions.
- Every address and prefix must match `ipFamily` when it is set, and ICMP
  requires IPv4 while ICMPv6 requires IPv6. With no family set, a list may mix
  families, and a packet can only match entries of its own family. A rule never
  matches one side as IPv4 and the other as IPv6.
- An IPv4-mapped IPv6 literal stays IPv6. It is never unmapped into an IPv4
  match.
- IPv6 literals are canonicalized (RFC 5952) before duplicate checks. Zone
  identifiers, hostnames, `host:port` and prefix notation in an IP list are
  rejected.
- Absent means wildcard. An empty list and an explicit `null` are rejected.
- A policy holds at most 64 rules and compiles to at most 256 datapath entries.
  A rule compiles to the product of its source, destination and port
  alternatives, so the compiler counts entries and rejects a policy over the
  limit rather than truncating it. Rules are never reordered.
- A rule fully shadowed by an earlier rule is reported as a warning, not an
  error.
- Addresses and ports are stored in network byte order in the datapath. Ranges
  are compared after converting the packet's port to host order.

NAT64 is matched as the workload sees it. On egress, a packet to a synthesized
`64:ff9b::/96` address is IPv6, so an IPv4 literal does not match it. On
ingress, the reply reaches the workload as IPv6 from the synthesized address
and is matched as that. Outer SRv6 addresses and a shard's public masquerade
address are never substituted into these fields.

### Admission and explicit null

An experiment against kube-apiserver 1.33 established how the CRD pipeline
treats `null`:

- On a field without `nullable: true`, an explicit `null` is pruned before
  validation and stored as if omitted, so nothing can reject it.
- On a field with `nullable: true`, the `null` is stored. CRD CEL cannot see
  it: `has()` reports false for a null field, and a typed comparison with
  `null` does not compile.
- A JSON merge patch that sets a field to `null` removes the field, which is
  an intentional change to omission.

So every optional match field, and `match` itself, is declared
`nullable: true`, and a fail-closed validating webhook (`failurePolicy: Fail`)
rejects a `null` at any of them by inspecting the admitted object. Everything
CRD validation can express (enums, bounds, list types, mutual exclusion,
family consistency, the binding name rule) stays in the schema as well, so it
holds even for clients that bypass the webhook's checks. While the webhook is
down, writes fail rather than admit a null.

The webhook also parses every address and prefix again, since the schema only
checks strings, and enforces the reserved default name (next section).

### Default policy identity

The built-in default is named `default-deny-all` with one rule, `deny-all`,
action `Deny`. It is authoritative for every omitted reference and never needs
an API object. Its metric `policy_uid` is the reserved string
`builtin:default-deny-all:v1`, which is never a Kubernetes UID.

`galactic-controller --role=cell` also provisions a TrafficPolicy named
`default-deny-all` in each namespace that holds a VPCAttachment, so it can be
referenced explicitly. The webhook reserves that name: only the controller's
service account can create or delete it, and its spec must be exactly the one
catch-all Deny rule. If a conflicting object already exists the controller
reports a provisioning conflict on its own status, never adopts or overwrites
it, and omitted references keep using the built-in default. An explicit
reference to a conflicting object is unresolved and denied.

An explicit reference to the controller-owned object follows the ordinary
reference rules and reports the object's real UID. An omitted reference always
reports the synthetic identity, even while the object exists. Deleting the
object therefore changes nothing for omitted references and makes explicit
references unresolved.

### Binding transitions

Policy identity is the namespace plus the policy's API UID. Each interface and
direction moves independently.

| Event                                                               | Enforcement                                                          | Status                                              |
| ------------------------------------------------------------------- | -------------------------------------------------------------------- | --------------------------------------------------- |
| New interface, binding not yet resolved                             | Deny, `policy_unavailable`                                           | Pending                                             |
| Reference omitted or removed                                        | Publish the built-in default                                         | Default applied                                     |
| Valid update to the bound UID                                       | Old snapshot until the new one is fully published                    | Desired and applied generations reported separately |
| Admission rejects an update                                         | Unchanged                                                            | Error returned to the writer                        |
| Accepted update to the same UID fails to compile or install         | Keep last good, or deny if there is none                             | Installation failure with both generations; retried |
| Rebind to another UID                                               | Publish the new policy if it is ready, otherwise invalidate and deny | Pending or failed; never restores old grants        |
| Referenced policy confirmed deleted, including same-name recreation | Invalidate and deny until the new UID is installed                   | Unresolved, or pending for the new UID              |
| API outage or cache not synced                                      | Keep what is installed; new bindings stay denied                     | Stale discovery reported                            |
| Installed state lost                                                | Deny                                                                 | Repaired, or the interface is quarantined           |

Absence is established only by a synchronized informer or an authoritative
read. A timeout never counts as deletion.

Invalidation never depends on allocating anything. It deletes the binding's
outer-map entry, which makes the next evaluation deny with
`policy_unavailable`. If even that delete fails, the node agent sets the
interface's host link down (quarantine) and reports the failure.

### Forwarding path classification

| Path          | Egress (workload sends)                                                        | Ingress (workload receives)                                                          |
| ------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------ |
| Private       | Private VPC routing, same-node delivery, private services, kernel VRF fallback | Ordinary decapsulation, private service tunnel (next header 253), same-node delivery |
| PublicNAT     | A shard group sentinel, or an ordered route whose SID is a NAT shard's         | Decapsulated packet whose outer source is a NAT shard's SID                          |
| PublicService | Source VIP translation toward the public uplink (DSR reply)                    | Gateway delivery (nonzero uSID slot) or inbound VIP translation                      |

Classification uses forwarding state only, never whether an address looks
public.

- **Egress.** A new LPM map, `tp_route_class_table`, mirrors
  `egress_route_table`'s key and holds the route's class. Every writer of an
  egress route writes its class first and removes it last. A route with no
  class row, or a group sentinel whose group cannot be resolved, is
  `classification_error`. The existing route value is not enlarged, so the
  pinned route map keeps its layout.
- **Ingress, NAT.** The outer source of a NAT shard's reply is the shard's
  SID. The EgressShard controller already guarantees that a shard's Block and
  Node-ID are disjoint from every BGPRouter locator, so the top 64 bits of the
  outer source identify a shard. `tp_nat_locator_table` holds every
  EgressShard's locator, published by the installer from the EgressShard
  informer it already runs. Until that informer has synced, an encapsulated
  ingress packet is `classification_error`.
- **Trust.** Sender authenticity rests on the existing fabric trust model:
  `usid_ingress` already accepts any packet addressed to a local locator from
  the fabric uplink. A tenant cannot choose the outer header, because every
  tenant packet is encapsulated by the sending node's `usid_egress`, and a
  tenant packet that carries its own SRv6 header is encapsulated inside one.
  Nothing a tenant controls (inner addresses, ports, marks or its own SRH)
  selects a class.
- **Errors.** A rule with no `path` is evaluated normally when classification
  failed. The first rule that names a path ends evaluation with a
  `classification_error` deny, so a failed lookup can never skip an earlier
  rule and reach a broader Allow.

### Packet path audit

Hooks on a tenant interface, with `P` the configured filter priority:

| Hook                                  | Program               | Role                                                                     |
| ------------------------------------- | --------------------- | ------------------------------------------------------------------------ |
| Host-side tc ingress, priority P      | `usid_service_egress` | Private service requests and replies                                     |
| Host-side tc ingress, priority P+1    | `usid_egress`         | Everything else the workload sends                                       |
| Host-side tc egress, priority P (new) | `tp_deliver`          | Workload ingress for packets the kernel or a non-peer redirect transmits |
| Fabric uplink tc ingress              | `usid_ingress`        | Decapsulation and delivery                                               |

The egress check is a call to one global function, `tp_evaluate`, placed on
every exit that forwards workload data, with the class that exit implies.

| Mechanism                                                        | Where it is enforced                                                        | Path          |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------- | ------------- |
| Remote private encapsulation                                     | `usid_egress`, before `bpf_skb_adjust_room`                                 | Private       |
| NAT66 and NAT64, ordered and hashed                              | `usid_egress`, after the route and group are resolved, before encapsulation | PublicNAT     |
| VIP source translation to the public uplink                      | `usid_egress`, before the rewrite                                           | PublicService |
| Local pass-through route (same-node delivery and the kernel VRF) | `usid_egress`, before returning to the kernel                               | Private       |
| Route miss, multicast, link-local, missing source configuration  | `usid_egress`, before returning to the kernel                               | Private       |
| Private service request or reply, local or remote                | `usid_service_egress`, before the rewrite                                   | Private       |
| Packet Too Big that `usid_egress` sends back to the workload     | `tp_deliver`, as workload ingress                                           | Private       |

The ingress check sits on the receiving side:

| Mechanism                                                                                 | Where it is enforced                                                      | Path                  |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | --------------------- |
| Remote delivery to a veth by `bpf_redirect_peer`                                          | `usid_ingress`, after the FIB names the interface and before the redirect | From the outer header |
| Remote delivery to a tap by `bpf_redirect`, or to a cold neighbor by `bpf_redirect_neigh` | `usid_ingress`, as above, which then marks the packet evaluated           | From the outer header |
| Same-node delivery through the kernel VRF                                                 | `tp_deliver` on the receiver's host interface                             | Private               |
| Local private service delivery by `bpf_redirect_neigh`                                    | `tp_deliver`                                                              | Private               |
| Ingress sidecar delivery to a managed interface                                           | `tp_deliver`                                                              | Private               |

- `bpf_redirect_peer` moves the packet into the peer namespace without running
  the host device's tc egress, so `usid_ingress` must check before the
  redirect. Plain `bpf_redirect` and `bpf_redirect_neigh` transmit through the
  host device, so `tp_deliver` would see the same packet again.
- To check it once, `usid_ingress` sets a reserved mark value on the packets it
  has evaluated and sends by those helpers. `tp_deliver` skips a packet that
  carries exactly that value and clears it. A packet from a workload cannot
  carry it: crossing a veth's namespace boundary clears the mark, and a tap
  delivers with mark 0. The value is configurable
  (`GALACTIC_CNI_POLICY_MARK`), in case another host component uses the
  default.
- An unmanaged host interface never has `tp_deliver` attached, and
  `usid_egress` is only attached to managed interfaces. A managed interface
  with no identity row is therefore denied rather than treated as unmanaged.
- Deny is a real `TC_ACT_SHOT` before any fallback. A missing route is never
  used to mean deny.

### Parser contract

| Packet                                                                                            | Behavior                                                                                                                     |
| ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Well-formed IPv4 or IPv6                                                                          | Evaluate the rules                                                                                                           |
| IPv4 with MF set or a nonzero offset; IPv6 with any Fragment header, including an atomic fragment | `parse_error` drop before any rule                                                                                           |
| Truncated or malformed header, or a parser bound exceeded                                         | `parse_error` drop before any rule                                                                                           |
| Validated ARP or neighbor discovery on the allowlist                                              | Link operation, outside the rules and their metrics                                                                          |
| Any other non-IP frame, or invalid ARP                                                            | Link drop, counted separately                                                                                                |
| GSO skb                                                                                           | The same parse on the observable skb, counted once at its buffer length; never requires a checksum hardware has not computed |

Bounds and allowlists:

- IPv4: version 4, IHL from 5 to 15, total length at least the header and no
  more than the buffer. Options are skipped without interpretation; they never
  move or hide the transport header.
- IPv6: payload length no more than the buffer. Extension headers on the
  allowlist are Hop-by-Hop (0), Routing (43) and Destination Options (60), at
  most 4 of them and 256 bytes in total. Fragment (44), AH (51), Mobility
  (135), HIP (139), Shim6 (140) and the experimental values are `parse_error`.
  ESP (50) and No Next Header (59) end the chain as a protocol with no ports.
- TCP and UDP need the whole fixed header inside the IP packet. ICMP and
  ICMPv6 need their first 4 bytes.
- Ethernet padding after the IP total length is excluded from the byte count.

### Link operation exceptions

Only these frames bypass the rules, and only after validation.

| Frame                                                                                | Direction | Checks                                                                                                                                 |
| ------------------------------------------------------------------------------------ | --------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| ARP request or reply                                                                 | Both      | Ethernet/IPv4, hardware length 6, protocol length 4; on egress, the sender address is one of the interface's IPv4 addresses or 0.0.0.0 |
| Router Solicitation (133), Neighbor Solicitation (135), Neighbor Advertisement (136) | Egress    | Hop limit 255, code 0, valid length; source is link-local, one of the interface's addresses, or unspecified for DAD                    |
| Router Advertisement (134), Neighbor Solicitation, Neighbor Advertisement            | Ingress   | Hop limit 255, code 0, valid length                                                                                                    |

Everything else is ordinary tenant traffic: DHCP, DNS, other ICMP, multicast
and link-local data. Under default deny that includes Packet Too Big and other
ICMP errors, so a policy that allows TCP should usually allow ICMPv6 type 2
(and ICMP type 3 code 4 for IPv4) toward the workload. The user guide says so.

### BPF maps

Every map is new, so no existing pinned map changes layout.

| Map                        | Type                 | Key, value                                                                       | Writer                                                       |
| -------------------------- | -------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `tp_iface_table`           | HASH                 | ifindex, `{token, state}`                                                        | CNI ADD and DEL, repair                                      |
| `tp_binding_table`         | HASH_OF_MAPS         | `{ifindex, direction}`, inner snapshot                                           | galactic-router                                              |
| inner snapshot             | ARRAY, 257 entries   | 0: header `{token, counter_base, fallback_base, flags}`; 1-256: compiled entries | galactic-router, before insertion                            |
| `tp_route_class_table`     | LPM_TRIE             | `egress_route_table`'s key, class                                                | Every egress route writer                                    |
| `tp_nat_locator_table`     | HASH                 | shard Block and Node, nothing                                                    | Installer                                                    |
| `tp_rule_counters`         | PERCPU_ARRAY, 65,536 | counter ID, `{packets, bytes}`                                                   | Datapath                                                     |
| `tp_fallback_counters`     | PERCPU_HASH          | `{ifindex, token, direction, reason}`, `{packets, bytes}`                        | Rows created by CNI ADD; datapath updates existing rows only |
| `tp_unattributed_counters` | PERCPU_ARRAY         | `{direction, reason}`, `{packets, bytes}`                                        | Datapath                                                     |
| `tp_accounting_errors`     | PERCPU_ARRAY         | `{direction, action}`, count                                                     | Datapath                                                     |
| `tp_state`                 | ARRAY(1)             | enforcement mode, NAT locator sync flag                                          | Installer                                                    |

A compiled entry is 72 bytes: action, logical rule index, match flags, family,
protocol, path, ICMP type and code, source and destination prefixes with
lengths, and one source and one destination port range. Evaluation walks the
entries with `bpf_loop` and stops at the first match. The logical rule index
plus the snapshot's `counter_base` gives the counter row, so every entry a
rule expands to adds to that rule's one row.

The header's `token` must equal `tp_iface_table[ifindex].token`, which CNI
ADD sets from the interface incarnation token that `attachment_identity_table`
already rotates. A recycled ifindex has a new token, so it never inherits a
previous interface's snapshot.

### Publication and lifetime

**Switching a direction.**

1. Allocate counter rows and zero them, so every installed rule is visible
   with zero hits.
2. Create a new inner map and write its header and entries.
3. Insert it with one update of `tp_binding_table[{ifindex, direction}]`.

The two directions are separate keys, so neither update can overwrite the
other.

**Holding a snapshot.** An evaluation does one lookup in the outer map and
uses the returned inner map for the rest of the run. tc programs run inside an
RCU read-side critical section, and the kernel frees a replaced inner map only
after an RCU grace period. Since Linux 6.8 ("bpf: Defer the free of inner map
when necessary") it also waits for a tasks-trace grace period. So a packet
evaluates against exactly one complete snapshot, old or new, and the old one
lives until every evaluation that could hold it has finished.

**Retiring a snapshot and its counters.**

1. After the switch, the agent closes its own descriptor for the old inner
   map. It remembers the map ID and the counter rows that only the old
   snapshot referenced.
2. It retires those rows only once the kernel reports the map ID gone
   (`BPF_MAP_GET_FD_BY_ID` returns `ENOENT`). The kernel frees the map only
   after the grace periods above, so no program can still be counting into
   those rows.
3. Only then does it free the counter IDs for reuse.

A user-space reference count or a timer alone is not used. Counter rows have
their own allocator, and their lifetime is proved separately by this rule
rather than assumed from the outer map.

**Bound.** A counter ID is freed only by that rule, never by a timer. If
retiring snapshots pile up beyond 4 per binding (a kernel that never frees
them, or a leaked descriptor), further updates to that binding fail as an
installation failure, keep the last good snapshot, and are reported. Live
storage is never reused.

**Restart.** The outer map and the counter arrays are pinned. A restarted
agent rebuilds its allocator from the inner maps still referenced by the
outer map, and treats every counter row they do not reference as retirable.

**Counter continuity.** Within one interface lifetime, a rule's counter row is
keyed by its name and action. A new snapshot that keeps both reuses the row,
whatever its match or position. Renaming the rule or changing its action
starts a new row. Unbinding, removing a rule or changing its action ends the
interval at publication. Returning later starts a new row at zero, and a
retiring row is never revived. When an old and a new interval share labels,
only the new one is exported.

### Lifecycle activation and continuity

CNI ADD (both `galactic-veth` and `galactic-tap`):

1. Create the interface with its host side down. Down is the quarantine: no
   data crosses a down link, whether or not any program is attached.
2. Write the `tp_iface_table` row (state `pending`) and the fallback counter
   rows.
3. Attach `usid_service_egress`, `usid_egress` and `tp_deliver`, then read
   the filters back to verify them.
4. Set the host side up. With state `pending` and no binding row, every packet
   is denied as `policy_unavailable` until galactic-router publishes the
   built-in default or the bound policy.
5. Report success.

Any failure in steps 2 to 4 leaves the link down, rolls back only state
belonging to this interface lifetime, and fails the ADD.

Other operations:

- **CNI CHECK** reads the filters back as well as the map rows. A missing
  filter fails the check.
- **Repair** in `galactic-cni run` runs on start and on interface events. If
  it finds a managed interface with a missing filter it sets the link down
  before reattaching, and it never sets the link up again until verification
  passes.
- **Program upgrades** replace each filter in place with the same priority
  and handle. `cls_bpf` swaps the program pointer atomically, so there is no
  moment without a program. An upgrade never detaches first.
- **Agent crash.** tc filters, pinned maps and a down link all survive a
  crash. A restarted agent verifies identity, filters and map compatibility
  before setting any link up.
- **Map loss.** If a policy map has to be recreated because its shape
  changed, the loader removes the old pin only after every managed link has
  been set down. Repair restores state, then sets the links up.

A missing map row is handled by the present program, which denies. A missing
program is handled by the link being down. Continuity covers agent crashes,
loader and upgrade failures, and controlled map or program replacement. A
privileged user removing every filter by hand is outside this guarantee.

Revocation applies to every packet evaluated after publication in that
direction, including packets of existing flows. NAT sessions, shard pins,
cached routes and service entries are not exemptions. A packet already
evaluating against the old snapshot finishes under it.

### Reconciliation and status

**galactic-controller (`--role=cell`)** owns the API side:

- serves the validating webhook;
- provisions `default-deny-all`;
- resolves each binding's references and writes `status.ingress` and
  `status.egress`;
- surfaces validation and compile errors on the TrafficPolicy status.

**galactic-router** owns the node side, because it already watches
VPCAttachment and writes per-interface fail-closed maps. Its new
TrafficPolicyReconciler:

- watches TrafficPolicy, TrafficPolicyBinding and VPCAttachment;
- maps each attachment whose `status.node` is this node to its host ifindex
  and identity token;
- compiles each direction, publishes and retires snapshots as above;
- reports the applied identity and generation in `status.nodes`.

It reconciles on start, after every informer resync, and on a periodic sweep
that also removes outer-map rows for interfaces that no longer exist. It writes
no status on VPCAttachment.

A diagnostic command, `galactic-router policy show <namespace>/<attachment>`,
prints both bindings, the applied generations, the compiled entries and each
rule's counters. `galactic-router policy explain` evaluates a packet tuple,
direction and path against a policy file or a live binding using the Go
evaluator, and never touches live counters.

### Metrics

Exported from galactic-cni's existing `:9180/metrics` endpoint, which already
has a PodMonitor:

| Metric                                                 | Labels                                                                                            |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| `galactic_cni_traffic_policy_rule_hits_total`          | namespace, vpc, attachment, interface, interface_uid, direction, policy, policy_uid, rule, action |
| `galactic_cni_traffic_policy_rule_bytes_total`         | the same                                                                                          |
| `galactic_cni_traffic_policy_fallback_packets_total`   | namespace, vpc, attachment, interface, interface_uid, direction, reason                           |
| `galactic_cni_traffic_policy_fallback_bytes_total`     | the same                                                                                          |
| `galactic_cni_traffic_policy_unattributed_drops_total` | direction, reason                                                                                 |
| `galactic_cni_traffic_policy_accounting_errors_total`  | direction, action, reason                                                                         |

- `reason` on the fallback metrics is one of `no_match`,
  `policy_unavailable`, `parse_error` or `classification_error`.
- `interface_uid` is the VPCAttachment UID.
- The collector resolves labels from the snapshot metadata galactic-router
  writes beside each pinned binding, never from packet fields.
- Each evaluation produces exactly one outcome: a winning rule's hit and bytes,
  or one fallback pair.
- Bytes are the tenant IP packet at the evaluation point, without Ethernet or
  outer SRv6. A GSO skb counts once at its buffer length.
- A malformed packet whose IP boundary cannot be found adds zero bytes.
- A missing counter row keeps the verdict and increments
  `accounting_errors_total{reason="missing_rule_counter"}`.

### Kernel requirements

The design needs `HASH_OF_MAPS`, `LPM_TRIE`, `bpf_loop` (5.17), the tc egress
hook and the 6.8 fix to inner-map freeing. Production and staging run Talos
v1.13.10, whose kernel is 6.18.

The CNI preflight gains probes for `HASH_OF_MAPS`, `bpf_loop` and the
kernel version, which stands in for the 6.8 fix because that fix cannot be
probed directly. A node that fails them reports a capability error and refuses
new managed interfaces when enforcement is enabled. It never falls back to
forwarding without enforcement. This raises the minimum kernel for enforcement
to 6.8, which the pull requests call out.

## Rollout

Default deny is a deliberate behavior change. The enforcement mode in
`tp_state` is `off`, `audit` or `enforce`, set per node by
`GALACTIC_CNI_TRAFFIC_POLICY` and defaulting to `off` until the final change.

- `off` changes nothing. Maps and programs are loaded, but `tp_evaluate`
  returns immediately.
- `audit` evaluates and counts every packet but forwards as before. Operators
  use the counters to find interfaces whose traffic would be denied.
- `enforce` drops.

Operators move a site to `enforce` only after every running interface has
explicit bindings for the traffic it needs. Steady-state interfaces default to
deny in every mode except `off`. There is no legacy allow and no generated
reverse rule. `audit` is a measurement mode for migration, not a
compatibility allowance, and `enforce` is the only mode the steady state uses.

## Delivery plan

### Pull request sequence

Each PR builds and passes `task ci` against its declared base. Until the last
PR, enforcement stays `off` and nothing changes for any packet.

| # | PR                                                                                                                                                               | Depends on | Delivers                                     | Still inactive                             |
| - | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | -------------------------------------------- | ------------------------------------------ |
| 1 | This design                                                                                                                                                      | none       | Decisions, audit, lifetime argument, plan    | Everything                                 |
| 2 | `api/v1alpha1` TrafficPolicy and TrafficPolicyBinding, generated CRDs and API docs, CEL validation, envtest                                                      | 1          | The schema                                   | Nothing reads it                           |
| 3 | `galactic-controller --role=cell`: webhook, default provisioning, binding resolution status, manifests and RBAC                                                  | 2          | Admission and status                         | Datapath                                   |
| 4 | `internal/trafficpolicy`: Go evaluator and compiler with bounds                                                                                                  | 2          | Semantics oracle and entry layout            | Datapath                                   |
| 5 | BPF: maps, parser, `tp_evaluate`, classification maps and writers, publication package with retirement                                                           | 4          | Evaluation in tests against the Go evaluator | Mode `off` everywhere                      |
| 6 | Enforcement hooks, `tp_deliver`, ingress mark, link-down activation, CHECK and repair, preflight                                                                 | 5          | Every path in the audit is checked           | Mode `off` by default                      |
| 7 | galactic-router TrafficPolicyReconciler, node status, collector and metrics, `policy show` and `explain`                                                         | 3, 6       | Live updates and observability               | Mode `off` by default                      |
| 8 | Lab: containerlab policies for every fixture, positive and negative checks for each path, docs and rollout guide; the mode defaults to `enforce` in the lab only | 7          | End-to-end validation                        | Production stays `off` until infra opts in |

### Requirement checklist

| Requirement               | PRs        | Validation                                                                       |
| ------------------------- | ---------- | -------------------------------------------------------------------------------- |
| R1 per interface          | 2, 5, 6, 7 | Two interfaces in one VRF with different policies, same node and remote          |
| R2 independent directions | 2, 5, 7    | Binding one direction leaves the other at default                                |
| R3 no implicit replies    | 4, 5, 8    | Egress Allow leaves replies denied; ingress Allow leaves workload replies denied |
| R4 one-rule default       | 2, 3, 4    | Default has one rule and no SMTP rule                                            |
| R5 first match            | 4, 5       | BPF verdicts equal the Go evaluator on generated packets                         |
| R6 match fields           | 2, 4, 5    | Path, family, IP and CIDR, ports, ICMP tables                                    |
| R7 live updates           | 5, 7       | Concurrent publication shows only whole old or whole new verdicts                |
| R8 fail closed            | 5, 6, 7    | Every binding-transition row and fault-injection case                            |
| Path audit                | 6, 8       | Traffic down each mechanism in the audit, both allowed and denied                |
| Parser                    | 5          | Every parser-table row                                                           |
| Metrics                   | 5, 7       | Collector names, labels and types; exactly-once counting                         |

## Alternatives

- **References on VPCAttachment.** The cloud operator owns and rewrites that
  spec, and the cloud repository is being retired into Galactic.
- **A per-attachment on/off NAT switch (NetworkEgressPolicy).** It would
  conflict with policy, and the requirement makes NAT an ordinary path match.
- **A standalone tc program in front of `usid_egress`.** It would have to
  repeat every route and group lookup to classify the path, and could disagree
  with the program that forwards. Calling one evaluator from each forwarding
  exit uses the classification the forwarding decision already made.
- **Evaluating ingress only at host tc egress.** `bpf_redirect_peer` skips that
  hook, and giving up the peer redirect would cost every veth delivery a
  backlog round trip.
- **CEL-only null rejection.** Shown above not to work.
