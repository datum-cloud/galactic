---
status: provisional
stage: alpha
latest-milestone: "TBD"
---

# Galactic Edge foundation and MASQUE provider

## Summary

Build galactic-edge as a reusable foundation for independently packaged
providers, with MASQUE as its first service. The foundation owns attachment
lifecycle, forwarding claims, authorized prefix reachability and cleanup.
Providers own their protocols and consume those capabilities through an
internal, versioned contract.

The first delivery is [MASQUE Connector for gVPC (#970)][epic]: IPv6
CONNECT-IP over HTTP/3 on UDP/443 and HTTP/2 over TLS on TCP/443. Each
connector receives a /96 and may subdivide it locally. The foundation routes
the aggregate prefix to its single active forwarding owner.

This proposal defines the shared architecture and implementation sequence.
It does not claim that the prototype packages already implement the complete
lifecycle or that their tests establish feature acceptance.

## Scope

Deliver packet attachments, per-connector ownership, aggregate prefix routing
and provider conformance together with the MASQUE service. A new provider
using that delivered capability must integrate through its own package and
configuration without core source, schema, image or deployment changes.
Additional capabilities require separate design and conformance work.

Public product APIs, plugin/portal integration and product client development
are outside this delivery. Internal control-plane contracts and independent
protocol clients used for testing remain required. Existing service
deployments, configuration and attachment paths are not migrated by this
work. Any conflict with their ownership must be resolved in the foundation
boundary before the affected path is enabled.

Feature acceptance ends with reproducible staging evidence. Operational
rollout is a separate plan.

## Architecture boundary

| Responsibility | Foundation                                                                                        | MASQUE provider                                                                                  |
| -------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Admission      | Approved provider identity, gVPC grants, capabilities, resource limits and authorization ceilings | Client credential validation and request-to-gVPC selection through the trusted admission adapter |
| Attachment     | Namespace verification, privileged programming, durable inventory, readback and release           | Consume the authorized packet interface without host-network administration                      |
| Ownership      | Exclusive connector claims, owner epochs, independent local expiry and replacement fencing        | Bind requests to claims and terminate protocol work when authority ends                          |
| Addressing     | Exclusive gVPC-scoped /96 grants and aggregate return routing                                     | Communicate the grant, enforce source ownership and demultiplex return packets                   |
| Policy         | Host-interface policy bindings and common authorization limits                                    | Request and packet policy in both directions on both transports                                  |
| Protocol       | No HTTP, QUIC or CONNECT-IP dependencies                                                          | TLS, listeners, datagrams, capsules, request cancellation and transport MTU                      |
| Diagnostics    | Attachment, claim, programming and route status                                                   | Connection failures, packet drops, transport behavior and traffic                                |

The core validates a provider's authority to assert identity and grants.
Provider registration describes supported capabilities; it does not grant
access to a tenant. Neither a requested prefix nor a provider's readiness
report can widen an admitted claim.

## Shared foundation

### Host-managed attachments

Provision one attachment for a service pod and gVPC using a dedicated veth
into the canonical host gVPC VRF. The pod peer and packet interface belong to
an isolated pod VRF. Shared maps contain host ifindexes and canonical host
table identifiers; namespace-local identifiers may collide across pods.

Resolve Pod UID, node and live sandbox identity through a trusted node-local
mechanism. Hold and verify namespace handles through provisioning, reject
sandbox replacement and use immutable ownership records for cleanup. The
protocol process receives only the interface or descriptor it needs; it does
not supply arbitrary host paths or program shared routes.

Install explicit return routes through the attachment's next hop and
neighbor. Route the connector's aggregate /96, rather than resolving a
neighbor for each client-managed address. Preserve unreachable defaults so
missing tenant state cannot fall through to management networking. Register
the host interface with the existing datapath and policy mechanisms and read
back programmed state before reporting readiness.

Attachment MTU must accommodate the fabric's supported tenant packet size.
A narrower tunnel path needs correct ICMPv6 Packet Too Big or explicit tunnel
failure behavior. Test the complete SRv6 and pod path: a successful route
write or TUN test alone does not prove this behavior.

### Inventory and mutation authority

Create a durable attachment reference before programming resources and retain
it through drain and cleanup. GC, repair and restart reconciliation use that
inventory. An attachment with no advertisement or active request is still a
live reference while preparing. Names and reused interface indexes are not
authority to adopt or delete resources.

The implementation must inventory every writer that can affect the new
attachments or their shared dependencies:

| Resource or operation                                    | Required ownership integration                                                           |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Canonical gVPC table/SID and host interface registration | Preserve existing consumers; serialize changes to shared entries                         |
| Attachment links, neighbors and pod routes               | Verify sandbox and immutable attachment identity before mutation                         |
| Effective routes and egress map entries                  | Preserve candidate provenance and desired revision through install, retry and withdrawal |
| Installer refresh and map fill                           | Refuse stale snapshots that would resurrect removed state or erase a replacement         |
| GC and datapath repair                                   | Account for durable attachment references, including partially programmed attachments    |
| Service advertisements and router replay                 | Validate claim epoch and finite validity independently of API progress                   |

For each resource, all writers must honor the ownership boundary or be
proven unable to mutate it. A separate interface name or a new controller is
not sufficient isolation from maintenance paths.

`internal/edge/ownership` provides a candidate cross-process commit primitive:
prepare outside a file lock, then check owner/generation/revision and hold
that lock through mutation. Failed or interrupted commits require complete
snapshot reconciliation. Ownership transfer invalidates old tickets before
the new owner commits. This becomes an effective fence only when every
affected writer participates. The resource scope and integration points are
F1 deliverables; adopting all existing node state is not a prerequisite.

### Forwarding claims and expiry

Each connector has one active forwarding owner. Keep connector identity,
request identity, attachment identity, holder instance and claim epoch
separate. Reconnecting creates a new request; it cannot independently acquire
a second owner for the same connector. Define prefix retention and handoff
semantics before implementation, including HTTP/2 fallback.

The claim authority must atomically acquire, renew, replace and release claims.
Credential and policy validity cap their lifetimes. A stale renewal, cleanup
or withdrawal cannot extend authority or remove a replacement's state.

`internal/edge/claim` provides a finite-lease algorithm with monotonic holder
deadlines and drift-aware takeover waiting. It does not supply a production
store, kernel expiry enforcement or route withdrawal. F1 must select the
store, authoritative scope, renewal strategy and clock assumptions. Batching
renewals may reduce load but must preserve per-connector ownership and
revocation; instance liveness alone is insufficient.

A replacement may activate only after acknowledged old-path fencing,
guaranteed expiry under documented assumptions, or independent enforcement
of the new epoch. An atomic API update does not stop a partitioned old owner.
Federated status alone must never authorize cross-cell takeover; any such
handoff needs the same authoritative fencing proof.

| Bound                          | Required enforcement                                                                        |
| ------------------------------ | ------------------------------------------------------------------------------------------- |
| Local packet expiry            | Stops both forwarding directions even if the provider is paused or partitioned              |
| Local advertisement withdrawal | A surviving router withdraws expired service reachability without API or publisher progress |
| Remote convergence             | Measured separately under stated routing and connectivity assumptions                       |

Expiry is scheduled against applied runtime state, independently of watch
progress. Replaying a claim cannot restart its lifetime. After restart,
authority that cannot be revalidated stays disabled. Packet-path and route
expiry remain mandatory even when the protocol worker also reacts to a lease
notification.

### Internal provider contract

Finalize the resource representation, API group/scope and process packaging
in F1. The following are required roles, not prescribed public API kinds:

- Operator-approved provider identity, supported contract/capability versions
  and a provider-owned configuration reference.
- Immutable service, gVPC, instance, pod and attachment references with
  explicit authorization and placement.
- Idempotent attachment provision, readback, readiness, drain and release,
  with separate authority for core programming and provider readiness.
- Connector prefix grants and finite forwarding claims, with UID/epoch-safe
  release and authorized route contributions.
- Publication only after current authorization, programming generation,
  provider readiness and route acknowledgement agree.

Providers cannot select arbitrary host tables, ifindexes or next hops. Core
code does not import provider implementations or dispatch on protocol names.
Configuration schemas remain provider-owned. Packet I/O stays outside the
control-plane RPC path.

Ship the delivered contract, a minimal adapter example and conformance
fixtures. Prove reuse with an independently packaged test provider against
fixed core artifacts. It must exercise the real attachment and claim lifecycle;
a mock-only exercise does not establish extensibility. This proof covers the
initial packet/prefix capability, not every possible future provider.

## MASQUE provider

Serve [CONNECT-IP (RFC 9484)][connect-ip] over HTTP/3 and HTTP/2. HTTP/3 uses
QUIC datagrams; HTTP/2 uses TLS over TCP and the
[Capsule Protocol (RFC 9297)][capsules]. HTTP/2 fallback establishes a new
tunnel and follows the same admission, prefix, policy and ownership contract.
Prove it with UDP/443 blocked. The server capability does not imply automatic
fallback in an existing product client.

Authentication resolves a principal and each request selects exactly one
authorized gVPC. Multiple requests may share an outer connection but retain
separate claims, cancellation and cleanup. Credential expiry or access
revocation stops active forwarding within the specified bound.

Communicate the authorized /96 to the client. Accept client-managed addresses
and subdivisions within it, reject sources outside it and return traffic using
a gVPC-scoped prefix lookup. Prefix allocation belongs behind the foundation
contract; the HTTP server must not become a second allocation authority.

Apply gVPC traffic policy at attachment interfaces and session policy in both
directions. Keep policy updates effective for active connectors. Bound capsule
parsing, packet parsing, buffers, queues and request counts; malformed packets
or missing policy must not widen access.

Every supported path carries 1280-byte inner IPv6 packets in both directions.
Validate path changes and oversized packets, including a path unable to carry
the minimum. Observe connection failures, policy drops, claim expiry, resource
usage and route status. Measure capacity separately for HTTP/3 and HTTP/2.

## Implementation sequence

| Package                               | Engineer deliverable                                                                                               | Acceptance                                                                                            | Existing work               |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------- | --------------------------- |
| F1 — Contracts and ownership boundary | Internal provider contract, resource-writer inventory, claim state machine, reconnect semantics and numeric limits | Reviewed decisions and executable failure scenarios, with no unresolved competing writer              | #945–#948; #972             |
| F2 — Feasibility                      | Target attachment/policy fixtures and independent protocol tests for both transports                               | Overlapping tenants, bidirectional packets, 1280-byte inner packets and blocked-UDP fallback pass     | #949–#952, #954; #973–#974  |
| F3 — Attachment lifecycle             | Provider admission, durable inventory, verified provisioning, readiness, GC/repair and safe release                | Partial provisioning, restart, stale cleanup and namespace replacement tests pass                     | #945, #947, #949–#952; #975 |
| F4 — Claims and prefix routing        | Authoritative claims, independent local expiry, /96 route contributions and affected-writer integration            | No overlapping forwarding owners; bounded expiry/withdrawal; stale updates cannot damage replacements | #945–#946, #950; #976, #978 |
| F5 — Provider conformance             | Independently packaged packet provider and reproducible conformance suite                                          | Attach, forward, drain, replace and expire against fixed core artifacts without core changes          | New foundation work         |
| M1 — MASQUE service                   | Client admission, prefix handling, bidirectional policy, HTTP/3 and HTTP/2                                         | Independent clients pass on both transports using the shared foundation                               | #954; #977, #979–#981       |
| M2 — Feature acceptance               | MTU, diagnostics, capacity and integrated staging tests                                                            | All epic criteria and F5 conformance pass with recorded evidence                                      | #982–#985                   |

F1 and F2 experiments progress together. F3 depends on the attachment proof;
F4 depends on F3 and the ownership decisions. F5 and M1 can proceed in
parallel against the delivered core. Protocol development can use contract
fixtures earlier, but final M2 acceptance uses the integrated foundation.

The MASQUE epic owns service acceptance. Foundation work must explicitly
track provider-contract implementation, integration of all affected writers
and F5 conformance. These responsibilities must not disappear into a generic
attachment task.

## Acceptance evidence

Set the lease duration, renewal cadence, clock assumptions, revocation bound,
local withdrawal deadline, connector counts, throughput targets and resource
budgets before implementing or qualifying the corresponding behavior.
Values are decision deliverables, not inferred guarantees from a prototype.
Include control-plane write rates, replay load and expiry backlogs as well as
packet throughput and memory. Reserve capacity for drain and replacement.

| Environment                      | Required evidence                                                                        |
| -------------------------------- | ---------------------------------------------------------------------------------------- |
| Unit tests and race detector     | Admission, state transitions, stale epochs, cleanup ordering and bounded cancellation    |
| Privileged kernel tests          | VRFs, TUNs, host-only map keys, policy enforcement, real routes and failure isolation    |
| Target Talos/Cilium staging node | Namespace acquisition, privileges, hook ordering and integrated feature behavior         |
| Independent protocol clients     | CONNECT-IP traffic and minimum MTU over HTTP/3 and HTTP/2, including blocked UDP/443     |
| Fixed-core provider fixture      | Independent packaging and full delivered-capability lifecycle without core modifications |

Record revisions, environment versions, commands, expected/observed results
and measured bounds. Skipped privileged tests and successful handshakes are
not substitutes for packet evidence. Same-library client/server tests remain
useful regression coverage but do not establish independent interoperability.

[epic]: https://github.com/datum-cloud/galactic/issues/970
[connect-ip]: https://www.rfc-editor.org/rfc/rfc9484
[capsules]: https://www.rfc-editor.org/rfc/rfc9297
