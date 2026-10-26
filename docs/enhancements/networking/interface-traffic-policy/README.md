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

| Risk                                                                                      | Mitigation                                                                                                                                                                                                |
| ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Default deny breaks every running workload on rollout                                     | Enforcement is off per node until an explicit enable, and operators bind policies first (see [Rollout](#rollout)).                                                                                        |
| A path is misclassified and a narrow Allow matches the wrong traffic                      | Classification uses only trusted forwarding state. Any lookup that cannot finish is `classification_error`, which denies at the first rule naming a path that the packet otherwise matches.               |
| A packet reaches a workload by a path that skips the check                                | The [packet path audit](#packet-path-audit) names the check for every delivery mechanism, and the integration tests send traffic down each one.                                                           |
| Counter rows are reused while a packet still counts into them                             | Rows are freed only after the outer-map update returns, which the kernel guarantees waits for every program that could hold the old snapshot (see [Publication and lifetime](#publication-and-lifetime)). |
| Verifier cost and stack depth of the evaluation                                           | Evaluation is a separately verified global function that walks the snapshot with `bpf_for_each_map_elem`, so its cost does not grow with the rule count; the existing verifier budget test covers it.     |
| Dropping every fragment breaks workloads that rely on them, such as large UDP DNS answers | `audit` mode counts would-be fragment drops per interface before a site enforces, and the user guide calls the change out.                                                                                |

## Design details

### API ownership

The cloud and network API types now live in `api/cloud/v1alpha1` and
`api/network/v1alpha1` of the Galactic module. All of these types use
`galactic.datumapis.com/v1alpha1`. TrafficPolicy and TrafficPolicyBinding
remain in `api/v1alpha1` under the same group.

VPC and VPCAttachment are owned by the Galactic cell controller, which writes both the
spec and the status of every VPCAttachment. The node controller does not write either.
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
  name: web-0-eth0          # the VPCAttachment's name
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
      ingress:
        policy: {name: private-web-ingress, uid: 6d1c..., generation: 4}
        state: Applied               # Applied, Pending or Failed
        observedGeneration: 3        # the binding generation applied
        lastTransitionTime: ...
      egress:
        policy: {name: public-web-egress, uid: 91fa..., generation: 2}
        state: Applied
```

- The binding has no attachment field: it applies to the VPCAttachment with
  its namespace and name. That makes "one binding per interface" a property
  of naming rather than a conflict to detect, so there is exactly one
  effective policy per interface and direction.
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
- An IPv4-mapped IPv6 literal (`::ffff:192.0.2.1`) is rejected, as the
  Kubernetes IP validation library does. It is never unmapped into an IPv4
  match.
- IPv6 literals are canonicalized (RFC 5952) before the webhook's duplicate
  check. Zone
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
rejects a `null` at any of them by inspecting the admitted object. The enum
fields (`path`, `ipFamily`, `protocol`) need no webhook check: the schema's
enum already rejects a null there. Everything CRD validation can express
(enums, bounds, list types, mutual exclusion, family consistency) stays in the
schema as well, so it holds even for clients that bypass the webhook's checks.
While the webhook is down, writes fail rather than admit a null.

The CEL IP and CIDR functions the schema uses need Kubernetes 1.31 or later;
the schema is tested on 1.33 and 1.35, and edge clusters run 1.35.

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
| PublicNAT     | A shard group sentinel, or a route whose SID is a NAT shard's                  | Decapsulated packet whose outer source is a NAT shard's SID                          |
| PublicService | Source VIP translation toward the public uplink (DSR reply)                    | Gateway delivery (nonzero uSID slot) or inbound VIP translation                      |

Classification uses forwarding state only, never whether an address looks
public.

- **Egress.** The class comes from the same `egress_route_table` value the
  forwarding decision uses, in the same lookup, so a route rewritten in place
  can never be seen with a stale class:
  - a group sentinel (`link_ifindex == 0xFFFFFFFF`) is PublicNAT;
  - a route whose SID's top 64 bits are in `tp_nat_locator_table` is
    PublicNAT;
  - a local pass-through entry and every other route are Private.

  `tp_nat_locator_table` has one writer, the installer. It holds the locator of
  every configured shard SID (`GALACTIC_CNI_EGRESS_SHARD_SIDS`) and every
  EgressShard it has ever seen. Entries are only ever added while the agent
  runs, because the EgressShard controller already keeps shard locators
  disjoint from every BGPRouter locator, so a retained entry can never
  reclassify private traffic. A restart rebuilds the set before setting the
  synced flag in `tp_state`. Until the flag is set, an encapsulating egress
  route is `classification_error`.
- **Ingress, NAT.** The outer source of a NAT shard's reply is the shard's
  SID, so the same table classifies it. Until the flag is set, an
  encapsulated ingress packet is `classification_error`.
- **Trust.** Sender authenticity rests on the existing fabric trust model:
  `usid_ingress` already accepts any packet addressed to a local locator from
  the fabric uplink. A tenant cannot choose the outer header, because every
  tenant packet is encapsulated by the sending node's `usid_egress`, and a
  tenant packet that carries its own SRv6 header is encapsulated inside one.
  Nothing a tenant controls (inner addresses, ports, marks or its own SRH)
  selects a class.
- **Errors.** A rule with no `path` is evaluated normally when classification
  failed, and so is a rule with a `path` whose other fields do not match,
  since it could not decide the packet on any path. The first rule with a
  `path` whose other fields all match ends evaluation with a
  `classification_error` deny, so a failed lookup can never skip an earlier
  rule and reach a broader Allow.

### Packet path audit

**Interfaces.** `tp_iface_table` holds a row for every interface a Galactic
program can deliver to or is attached to, with a kind:

- `tenant`: a VPCAttachment interface. Policy applies.
- `infra`: the ingress sidecar's synthetic veth peers. They belong to the
  platform, carry no tenant identity, and are never evaluated; traffic they
  pass on to a tenant interface is checked at that interface.

A program that finds no row for an interface it is attached to, or that
`usid_ingress` is about to deliver to, denies as `policy_unavailable`
(unattributed). Missing state is never read as "unmanaged".

**Hooks on a tenant interface**, with `P` the configured filter priority:

| Hook                                  | Program               | Role                                                                     |
| ------------------------------------- | --------------------- | ------------------------------------------------------------------------ |
| Host-side tc ingress, priority P      | `usid_service_egress` | Private service requests and replies                                     |
| Host-side tc ingress, priority P+1    | `usid_egress`         | Everything else the workload sends                                       |
| Host-side tc egress, priority P (new) | `tp_deliver`          | Workload ingress for packets the kernel or a non-peer redirect transmits |
| Fabric uplink tc ingress              | `usid_ingress`        | Decapsulation and delivery                                               |

**Egress tuple.** The packet's addresses, protocol and ports are captured
once, at the top of the first program that sees the packet and before any
NPTv6 or VIP rewrite, so `sourceIPs` and `sourceCIDRs` always see the
workload's own address. The check itself runs at the exit, where the class is
known, using that captured tuple. It runs before `send_too_big`, so a denied
packet never produces a Packet Too Big quoting it, and exactly once per packet
even where the VIP path falls through to the route logic.

**Every exit of the egress programs:**

| Exit                                                                             | Today                            | With policy                                                                                                                                                                       |
| -------------------------------------------------------------------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bpf_skb_pull_data` fails                                                        | `UNSPEC` to the kernel           | Evaluate as Private: the capture reads with `bpf_skb_load_bytes`, which needs no pull, so a packet it cannot parse is a `parse_error` drop and one it can is decided by the rules |
| Not IPv4, IPv6 or ARP                                                            | `UNSPEC`                         | Link drop                                                                                                                                                                         |
| ARP                                                                              | `UNSPEC`                         | Link-operation allowlist, otherwise link drop                                                                                                                                     |
| `ifindex_vrf_table`, `vrf_table` or scratch miss                                 | `UNSPEC`                         | `policy_unavailable` drop when the tenant row is also missing; otherwise evaluate as Private and return `UNSPEC`                                                                  |
| Short IPv4 or IPv6 header                                                        | `UNSPEC`                         | `parse_error` drop                                                                                                                                                                |
| VIP source rewrite and redirect to the uplink                                    | Forwarded                        | Evaluate as PublicService first                                                                                                                                                   |
| VIP rewrite with no uplink configured                                            | Falls through to the route logic | Evaluated once, at the route exit, with the route's class                                                                                                                         |
| Multicast or link-local destination                                              | `UNSPEC`                         | Evaluate as Private                                                                                                                                                               |
| Neighbor discovery (133 to 137)                                                  | `UNSPEC`                         | Link-operation allowlist; otherwise evaluate as Private                                                                                                                           |
| Route miss                                                                       | `UNSPEC`                         | Evaluate as Private                                                                                                                                                               |
| Local pass-through route                                                         | `UNSPEC`                         | Evaluate as Private                                                                                                                                                               |
| No node source address configured                                                | `UNSPEC`                         | Evaluate with the route's class, then `UNSPEC`                                                                                                                                    |
| Group sentinel                                                                   | Resolved, then encapsulated      | Evaluate as PublicNAT before the group is resolved, so a denied packet moves no pin                                                                                               |
| Group sentinel, resolution failed after an Allow                                 | Drop                             | Drop, counted under its existing reason after the Allow's rule hit, like any later forwarding failure                                                                             |
| Remote route                                                                     | Encapsulated                     | Evaluate with the route's class                                                                                                                                                   |
| `usid_service_egress` parse failure or non-IP                                    | `UNSPEC` to `usid_egress`        | Handled by `usid_egress`                                                                                                                                                          |
| `usid_service_egress` non-TCP/UDP, or a service-route miss without a deny marker | `UNSPEC` to `usid_egress`        | Handled by `usid_egress`                                                                                                                                                          |
| Service request or reply, local or remote                                        | Rewritten and redirected         | Evaluate as Private before the rewrite                                                                                                                                            |
| Service deny marker or service policy denial                                     | Drop                             | Unchanged; the service policy's own drop, counted by it                                                                                                                           |

A packet that service policy drops has no traffic-policy outcome: the
private service checks run first, and traffic policy decides only a request or
reply they authorized, on the tuple captured before any rewrite. That is a
different policy's decision, already counted under its own reason.

**Workload ingress:**

| Mechanism                                                                                 | Where it is enforced                                                      | Path                  |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | --------------------- |
| Remote delivery to a veth by `bpf_redirect_peer`                                          | `usid_ingress`, after the FIB names the interface and before the redirect | From the outer header |
| Remote delivery to a tap by `bpf_redirect`, or to a cold neighbor by `bpf_redirect_neigh` | `usid_ingress`, as above, which then marks the packet evaluated           | From the outer header |
| Same-node delivery through the kernel VRF                                                 | `tp_deliver` on the receiver's host interface                             | Private               |
| Local private service delivery by `bpf_redirect_neigh`                                    | `tp_deliver`                                                              | Private               |
| Packet Too Big that `usid_egress` sends back to the workload                              | `tp_deliver`                                                              | Private               |
| Host-generated traffic, such as kernel ICMP errors                                        | `tp_deliver`                                                              | Private               |
| Delivery from the ingress sidecar                                                         | `tp_deliver`                                                              | Private               |

- `bpf_redirect_peer` moves the packet into the peer namespace without running
  the host device's tc egress, so `usid_ingress` must check before the
  redirect. Plain `bpf_redirect` and `bpf_redirect_neigh` transmit through the
  host device, so `tp_deliver` would see the same packet again.
- To check it once, `usid_ingress` sets a reserved mark value on the packets it
  has evaluated and sends by those two helpers. `tp_deliver` skips a packet
  that carries exactly that value and clears it. A workload cannot set it: a
  normal veth transmit between namespaces clears the mark, and a tap delivers
  with mark 0. A host component that uses the same mark value would collide,
  so the value is configurable (`GALACTIC_CNI_POLICY_MARK`) and the rollout
  guide has operators check it against the node's netfilter and routing
  rules.
- Kubelet probes reach a pod through its primary network, not a Galactic
  interface, so they never meet `tp_deliver`.
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
  allowlist are Hop-by-Hop (0), Destination Options (60), and Routing (43)
  only with segments left 0, at most 4 of them and 256 bytes in total. A
  Routing header with segments left could be re-forwarded to a destination
  other than the one evaluated, so it is `parse_error`. Fragment (44), AH
  (51), Mobility (135), HIP (139), Shim6 (140) and the experimental values are
  `parse_error`. ESP (50) and No Next Header (59) end the chain as a protocol
  with no ports.
- TCP and UDP need the whole fixed header inside the IP packet. ICMP and
  ICMPv6 need their first 4 bytes.
- Ethernet padding after the IP total length is excluded from the byte count.

Dropping every fragment is a behavior change: today fragments are forwarded
(the service path only drops them by marker). It is listed under
[Risks and mitigations](#risks-and-mitigations). In `audit` mode a fragment
is counted as a `parse_error` that would have been dropped, and forwarded.

### Link operation exceptions

Only these frames bypass the rules, and only after validation.

| Frame                                                                                | Direction | Checks                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------ | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ARP request or reply                                                                 | Both      | Ethernet/IPv4, hardware length 6, protocol length 4; on egress, the sender address is one of the interface's IPv4 addresses or 0.0.0.0, and the target is the gateway, the sender itself (gratuitous ARP) or one of the interface's addresses (an RFC 5227 probe) |
| Router Solicitation (133), Neighbor Solicitation (135), Neighbor Advertisement (136) | Egress    | Hop limit 255, code 0, valid length, no extension headers; source is link-local, one of the interface's addresses, or unspecified for DAD; destination is link-local unicast, in `ff02::/16`, or the interface's gateway address                                  |
| Router Advertisement (134), Neighbor Solicitation, Neighbor Advertisement            | Ingress   | Hop limit 255, code 0, valid length, no extension headers. The source is not checked: a hop limit of 255 already proves the message came from the link, and the host answers for the gateway from the gateway's own address                                       |

The destination check stops a workload from using a neighbor discovery type to
reach another tenant's routable address past its own egress policy. A message
the kernel forwarded has a hop limit below 255, so it fails the ingress check
and is evaluated as ordinary traffic.

Everything else is ordinary tenant traffic: DNS, other ICMP, multicast and
link-local data. Galactic does not serve DHCP, so there is nothing to except.
Under default deny that includes Packet Too Big and other ICMP errors, so a
policy that allows TCP should usually allow ICMPv6 type 2 (and ICMP type 3
code 4 for IPv4) toward the workload. The user guide says so.

### BPF maps

Every map is new, so no existing pinned map changes layout.

| Map                        | Type                 | Key, value                                                               | Writer                                                       |
| -------------------------- | -------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------ |
| `tp_iface_table`           | HASH                 | ifindex, `{policy_token, kind, state}`                                   | CNI ADD and DEL, the sidecar installer, repair               |
| `tp_iface_addr_table`      | HASH                 | `{ifindex, family, address}`, nothing                                    | CNI ADD and DEL, for the link-operation source checks        |
| `tp_binding_table`         | HASH_OF_MAPS         | `{ifindex, direction}`, inner snapshot                                   | galactic-router                                              |
| inner snapshot             | ARRAY, 257 entries   | 0: header `{policy_token, counter_base, count}`; 1-256: compiled entries | galactic-router, before insertion                            |
| `tp_nat_locator_table`     | HASH                 | shard Block and Node, nothing                                            | Installer                                                    |
| `tp_rule_counters`         | PERCPU_ARRAY, 16,384 | counter ID, `{packets, bytes}`                                           | Datapath                                                     |
| `tp_fallback_counters`     | PERCPU_HASH          | `{ifindex, policy_token, direction, reason}`, `{packets, bytes}`         | Rows created by CNI ADD; datapath updates existing rows only |
| `tp_unattributed_counters` | PERCPU_ARRAY         | `{direction, reason}`, `{packets, bytes}`                                | Datapath                                                     |
| `tp_accounting_errors`     | PERCPU_ARRAY         | `{direction, action}`, count; the one reason is a missing rule counter   | Datapath                                                     |
| `tp_link_drops`            | PERCPU_ARRAY         | direction, `{packets, bytes}`                                            | Datapath                                                     |
| `tp_state`                 | ARRAY(1)             | enforcement mode, NAT locator synced flag                                | Installer                                                    |

A compiled entry is 88 bytes: action, logical rule index, match flags, family,
protocol, path, ICMP type and code, one source and one destination port range,
and the source and destination prefixes each with its mask. The masks are
computed in user space so matching is a branch-free masked compare: compared
bit length by bit length, the verifier explored every length and the
evaluation alone cost about 13,000 instructions; with masks the whole of
`usid_egress` verifies in about 12,500, against 9,700 before the policy hooks
and a budget of 20,000. Evaluation walks the snapshot with
`bpf_for_each_map_elem` (5.13), which iterates the inner array in index order
and stops at the first match. The logical rule index
plus the snapshot's `counter_base` gives the counter row, so every entry a
rule expands to adds to that rule's one row.

**Policy token.** CNI ADD writes a random 64-bit `policy_token` into
`tp_iface_table` when it creates the interface, and nothing else changes it.
That is deliberately not the existing `attachment_identity_table` token,
which also rotates whenever programs are replaced. A snapshot header's token
must equal the interface row's token, so a recycled ifindex, whose row CNI ADD
rewrites, never inherits a previous interface's snapshot, while a program
upgrade leaves every binding valid.

**Stack.** `usid_egress` is already close to the 512-byte stack limit, which
is why `send_too_big` and `clamp_tcp_mss` are global functions. `tp_capture`
and `tp_decide` are global functions too, and keep the packet tuple and the
walk's state in a per-CPU scratch map rather than on the stack. The kernel
refuses to load any program whose deepest call chain passes 512 bytes, and
every kernel test loads the full datapath, so a change that crosses it fails
in CI.

### Publication and lifetime

**Switching a direction.**

1. Allocate counter rows and zero them, so every installed rule is visible
   with zero hits.
2. Create a new inner map and write its header and entries.
3. Insert it with one update of `tp_binding_table[{ifindex, direction}]`.

The two directions are separate keys, so neither update can overwrite the
other.

**Holding a snapshot.** An evaluation does one lookup in the outer map and
uses the returned inner map for the rest of the run. tc programs are
non-sleepable and run inside an RCU read-side critical section, so a packet
evaluates against exactly one complete snapshot, old or new.

**When the old snapshot is no longer in use.** An update or delete of a
map-in-map entry from user space calls `synchronize_rcu()` before the
syscall returns (`maybe_wait_bpf_programs()` in `kernel/bpf/syscall.c`, there
since Linux 4.20). The kernel added that wait precisely so user space would
know that every non-sleepable program that could have looked up the old inner
map has finished. So when the outer-map update returns, no program holds the
old snapshot or can write the counter rows only it referenced.

**Retiring counters.** After the update returns, the agent frees the counter
IDs that only the old snapshot referenced. A user-space reference count or a
timer is never the evidence; the synchronous wait is. Releasing the old inner
map's memory is the kernel's business: since Linux 6.8 ("bpf: Defer the free
of inner map when necessary") it is freed only after the grace periods that
also cover sleepable programs, which closed a use-after-free in older
kernels. The publication tests race updates against packets and check that
no packet is ever counted in a row after its ID is freed.

**Failure.** If the outer-map update fails, the old snapshot stays bound and
its counters stay live; the new inner map is closed and its rows freed. Live
storage is never reused.

**Restart.** The outer map and the counter arrays are pinned. A restarted
agent rebuilds its allocator from the inner maps still referenced by the
outer map, and treats every counter row they do not reference as free.

**Counter continuity.** Within one interface lifetime, a rule's counter row is
keyed by its name and action. A new snapshot that keeps both reuses the row,
whatever its match or position. Renaming the rule or changing its action
starts a new row. Unbinding, removing a rule or changing its action ends the
interval at publication. Returning later starts a new row at zero; a freed
row is zeroed before reuse and never revived with old counts.

### Lifecycle activation and continuity

The CNI chain is `galactic-veth` or `galactic-tap` (the master plugin, which
creates the interface and today brings both ends up), then `galactic-bgp`
(which registers the datapath and attaches `usid_service_egress` and
`usid_egress` through `attachreg.RegisterDatapath`). Activation follows that
order when the enforcement mode is `audit` or `enforce`:

1. **Master plugin.** Create the interface, bring the workload side up, and
   leave the host side down. Down keeps the workload's sent traffic, and any
   delivery that transmits through the host device, from moving.
2. **`galactic-bgp`.** Write the `tp_iface_table` row (kind `tenant`, state
   `pending`, a new `policy_token`) and the fallback counter rows; register
   the datapath; attach `tp_deliver`; read every filter back to verify it.
3. **`galactic-bgp`.** Set the host side up and report success. With state
   `pending` and no binding row, every packet in both directions is denied as
   `policy_unavailable` until galactic-router publishes the built-in default
   or the bound policy.

A failure in step 2 or 3 leaves the host side down, rolls back only state
belonging to this interface lifetime, and fails the ADD. If the node has no
SRv6 locator, `RegisterDatapath` registers nothing today and succeeds; with
enforcement on, `galactic-bgp` fails the ADD instead, since nothing would
enforce policy. The tap plugin's repair path, which brings a down tap back
up, first checks that the interface's `tp_iface_table` row is active and its
filters are present.

A down host link does not stop `bpf_redirect_peer` delivery, which only
checks the peer. Ingress to a veth is denied by the check inside
`usid_ingress`, which needs the binding row; a missing row denies there. So
there are two independent controls, used together:

- **Missing map rows** are handled by the programs that are present, which
  deny in both directions.
- **A missing tenant-interface program** is handled by the link being down:
  repair in `galactic-cni run` sets the host side down before reattaching,
  and up only after verification. `usid_ingress` lives on the uplink, not the
  tenant interface, so it is unaffected.

Other operations:

- **CNI CHECK** reads the filters back as well as the map rows. A missing
  filter fails the check.
- **Program upgrades** replace each filter in place with the same priority
  and handle. `cls_bpf` swaps the program pointer atomically, so there is no
  moment without a program. An upgrade never detaches first, and it never
  changes a `policy_token`, so bindings stay valid.
- **Agent crash.** tc filters, pinned maps and a down link all survive a
  crash. A restarted agent verifies identity, filters and map compatibility
  before setting any link up.
- **Map loss.** If a policy map has to be recreated because its shape
  changed, the loader removes the old pin only after every managed link has
  been set down and every binding is gone. Repair restores state, then sets
  the links up.
- **Last resort.** If the agent cannot publish an invalidation, it deletes the
  outer-map row, which denies both directions; if that also fails it sets the
  host link down, which stops egress and every non-peer delivery, and reports
  the interface as quarantined. A node whose map operations fail entirely
  cannot deny peer-redirect ingress; that is reported, not hidden.

Continuity covers agent crashes, loader and upgrade failures, and controlled
map or program replacement. A privileged user removing filters or maps by hand
is outside this guarantee.

In mode `off` none of these lifecycle changes apply: links come up as they do
today, CHECK ignores the new filter, and repair never sets a link down. The
`tp_iface_table` rows and filters are still written, so switching a node to
`audit` or `enforce` needs no interface recreation.

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
  and `policy_token`;
- compiles each direction, publishes and retires snapshots as above;
- reports the applied identity and generation in `status.nodes`.

It reconciles on start, on every watch event, and every five minutes. After a
restart it adopts each snapshot whose token, policy UID and generation still
match, so counters continue; one no attachment claims within a resync is
unbound and its rows freed. galactic-cni removes the outer-map rows of
interfaces that no longer exist. It writes no status on VPCAttachment. It runs
only when `GALACTIC_ROUTER_TRAFFIC_POLICY` is set, because it watches CRDs a
cluster may not have installed.

A diagnostic command, `galactic-router policy show <namespace>/<attachment>`,
prints both bindings, this node's status entry, the bound snapshots and each
rule's counters. `galactic-router policy explain` evaluates a packet tuple and
path against a policy file or a live policy with both the Go evaluator and the
compiled entries, fails if they disagree, and never touches live counters.

### Metrics

Exported from galactic-router's existing `:9179/metrics` endpoint, which
already has a PodMonitor. galactic-router allocates every counter row and
knows which rule, policy and interface it belongs to, so it is the one
process that can label a row without a second lookup table. The
`galactic_cni_` prefix names the datapath the counters belong to, not the
process that serves them. A row the collector cannot read is left out, not
reported as zero, and counted in the `galactic_cni_traffic_policy_counter_read_errors`
gauge.

| Metric                                                    | Labels                                                                                            |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `galactic_cni_traffic_policy_rule_hits_total`          | namespace, vpc, attachment, interface, interface_uid, direction, policy, policy_uid, rule, action |
| `galactic_cni_traffic_policy_rule_bytes_total`         | the same                                                                                          |
| `galactic_cni_traffic_policy_fallback_packets_total`   | namespace, vpc, attachment, interface, interface_uid, direction, reason                           |
| `galactic_cni_traffic_policy_fallback_bytes_total`     | the same                                                                                          |
| `galactic_cni_traffic_policy_unattributed_drops_total` | direction, reason                                                                                 |
| `galactic_cni_traffic_policy_accounting_errors_total`  | direction, action, reason                                                                         |

- `reason` on the fallback metrics is one of `no_match`,
  `policy_unavailable`, `parse_error` or `classification_error`.
- `interface_uid` is the VPCAttachment UID.
- The collector labels each row from what galactic-router installed, never
  from packet fields. After a restart, a row counts on in the kernel and is
  exported again once its interface is reconciled and its snapshot adopted.
- Each evaluation produces exactly one outcome: a winning rule's hit and bytes,
  or one fallback pair. The one exception is a packet captured while the mode
  was off and decided just after it turned on, at most one per CPU at the
  switch, which is forwarded and not counted.
- Bytes are the tenant IP packet at the evaluation point, without Ethernet or
  outer SRv6. A GSO skb counts once at its buffer length.
- A malformed packet whose IP boundary cannot be found adds zero bytes.
- A missing counter row keeps the verdict and increments
  `accounting_errors_total{reason="missing_rule_counter"}`.

**Cardinality.** A node exports, per tenant interface, one series pair per
installed rule per direction plus four fallback pairs per direction. A node
with 100 interfaces whose policies average 8 rules exports about
100 × 2 × (8 + 4) × 2 = 4,800 series. The limits (64 rules, 256 entries) cap
the worst case at 100 × 2 × 68 × 2 = 27,200, which PR 7 states as the
supported budget. `policy_uid` changes only on rebind or recreation, which
ends the old series by design.

### Kernel requirements

The design needs `HASH_OF_MAPS`, `bpf_for_each_map_elem` (5.13), the tc egress hook, the
synchronous map-in-map wait (4.20), and the 6.8 fix to inner-map freeing.

The CNI preflight gains probes for `HASH_OF_MAPS` and `bpf_for_each_map_elem`. The inner-map
fix cannot be probed, so the preflight also requires kernel 6.8 or later. That
check is deliberately conservative: it rejects a distribution kernel that
backported the fix, and an operator can override it with
`GALACTIC_CNI_TRAFFIC_POLICY_KERNEL_CHECK=false` after confirming the
backport. A node that fails them reports a capability error and, when the mode
is `audit` or `enforce`, refuses new managed interfaces. It never falls back to
forwarding without enforcement. This raises the minimum kernel for
enforcement to 6.8, which the pull requests call out.

## Rollout

Default deny is a deliberate behavior change. The enforcement mode in
`tp_state` is `off`, `audit` or `enforce`, set per node by
`GALACTIC_CNI_TRAFFIC_POLICY`. It defaults to `off`; only the containerlab lab
enforces by default. [docs/traffic-policy/rollout.md](../../../traffic-policy/rollout.md)
is the operator's step-by-step guide.

- `off` changes nothing. Maps and programs are loaded, but `tp_capture` and
  `tp_decide` return immediately.
- `audit` evaluates and counts every packet but forwards as before. Operators
  use the counters to find interfaces whose traffic would be denied.
- `enforce` drops.

Operators move a site to `enforce` only after every running interface has
explicit bindings for the traffic it needs. An interface created before the
release that adds the ingress side gets its policy row from `galactic-cni`
at startup, with a fresh token, so its bindings apply; its assigned addresses
are not known there, so until the workload is recreated its ARP and its
neighbor discovery from a global address are ordinary traffic rather than
link operations. Recreate such workloads before enforcing. Steady-state interfaces default to
deny in every mode except `off`. There is no legacy allow and no generated
reverse rule. `audit` is a measurement mode for migration, not a
compatibility allowance, and `enforce` is the only mode the steady state uses.

## Delivery plan

### Pull request sequence

Each PR builds and passes `task ci` against its declared base. Until the last
PR, enforcement stays `off` and nothing changes for any packet.

| # | PR                                                                                                                                                               | Depends on | Delivers                                            | Still inactive                             |
| - | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | --------------------------------------------------- | ------------------------------------------ |
| 1 | This design                                                                                                                                                      | none       | Decisions, audit, lifetime argument, plan           | Everything                                 |
| 2 | `api/v1alpha1` TrafficPolicy and TrafficPolicyBinding, generated CRDs and API docs, CEL validation, envtest                                                      | 1          | The schema                                          | Nothing reads it                           |
| 3 | `galactic-controller --role=cell`: webhook, default provisioning, binding resolution status, manifests and RBAC                                                  | 2          | Admission and status                                | Datapath                                   |
| 4 | `internal/trafficpolicy`: Go evaluator and compiler with bounds                                                                                                  | 2          | Semantics oracle and entry layout                   | Datapath                                   |
| 5 | BPF: maps, parser, `tp_capture` and `tp_decide`, egress classification, the checks at every egress exit, the publication package and counter allocator           | 4          | Egress enforcement, tested against the Go evaluator | Mode `off` by default; ingress unchecked   |
| 6 | Ingress: the check in `usid_ingress`, `tp_deliver`, the ingress mark, link-down activation, CHECK and repair, preflight                                          | 5          | Every path in the audit is checked                  | Mode `off` by default                      |
| 7 | galactic-router TrafficPolicyReconciler, node status, collector and metrics, `policy show` and `explain`                                                         | 3, 6       | Live updates and observability                      | Mode `off` by default                      |
| 8 | Lab: containerlab policies for every fixture, positive and negative checks for each path, docs and rollout guide; the mode defaults to `enforce` in the lab only | 7          | End-to-end validation                               | Production stays `off` until infra opts in |

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
