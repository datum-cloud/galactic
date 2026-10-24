# Looking Glass backend service contract

Status: proposed implementation contract for [#1042](https://github.com/datum-cloud/galactic/issues/1042),
under [#1041](https://github.com/datum-cloud/galactic/issues/1041).
This document specifies required future behavior. It does not announce an
available API, validated capacity, or measured failure bound. Implementation is
tracked in #1043–#1047 and qualification in #1048; enabling customer execution
requires those gates. Baseline inspected: Galactic `6da52240`.

The consumer and backend reviewers must approve this contract before dependent
milestones freeze their wire schema. Changes to the decisions below require a
contract update and corresponding acceptance cases, not undocumented defaults.

## Scope and existing behavior

Galactic executes bounded diagnostics in one cell's fabric-router network
context. The customer service owns authentication, project IAM, location
placement, session revocation detection, durable single-use claims, and delivery
to the customer. A project identifier received by Galactic is trusted
attribution from that service, not proof of the customer's permission.
Backend duplicate suppression cannot implement a durable single-use session.

Reuse the four existing diagnostic implementations, discovery, and shared
executor. Keep node RPCs unary; stream completed router outcomes, not individual
traceroute hops. Existing operator `FabricGatewayService.Query/ListNodes`, node
`FabricService.Execute/Info`, and the [FabricQuery API](api.md) retain their wire
schemas and result meanings. FabricQuery retains its existing persistence and
resume semantics; customer requests have no such persistence or replay.

Today, `api/fabric/v1/fabric.proto` exposes only unary methods;
`internal/fabric/gateway/runner.go` collects all outcomes before returning;
`identity/identity.go` recognizes gateway, node, and operator roles only.
The executor has local concurrency/queue limits and project round robin; nodes
pace packets locally. None establishes the new service or aggregate guarantees.
The existing discovery returns pod candidates, including duplicates, rather than
the unique-router accounting specified below.

## Service and identity

Publish a separate `fabric.service.v1` protobuf package at
`api/fabric/service/v1/service.proto`, with Go import
`go.datum.net/galactic/api/fabric/service/v1`. The intended service surface is:

```proto
service LookingGlassService {
  rpc GetCapabilities(GetCapabilitiesRequest) returns (GetCapabilitiesResponse);
  rpc RunDiagnostic(RunDiagnosticRequest) returns (stream DiagnosticEvent);
}
```

This is a service declaration excerpt, not a compilable schema. The field
contract below is normative input to schema generation in #1044. Reuse the public
`fabric.v1.Observation`, `Query`, and `Budgets` messages; do not expose Go
`internal/` types or add streaming semantics to an existing unary method.

Use the URI SAN
`spiffe://fabric-api.datumapis.com/cell/<cell>/service/<service-name>`.
Require the cell's trust bundle, valid certificate lifetime, exactly one
fabric-api identity, matching cell, and a configured service-name allowlist.
An authenticated service can call only these two methods. It cannot call
operator Query/ListNodes or node Execute/Info. Existing roles gain no direct
service-method permission. Apply authorization to unary and streaming RPCs,
including on reused TLS connections; cap a stream at certificate expiration.
Certificate rotation follows the existing reload/overlapping-CA mechanism.

A follower authenticates the original caller before forwarding once to the
leader over same-cell gateway mTLS. A separate gateway-only forwarding method
carries a typed envelope: original service URI, cell, project ID, request ID,
canonical request, original admission time, and absolute deadline. It is not a
customer-callable method. The leader validates the envelope, role, cell,
allowlist, and deadline again. Strip incoming forwarding metadata; never trust
caller-provided operator or service headers. Reject a second forwarding hop.
The gateway identity is a trusted deputy; compromise of that identity is outside
this isolation guarantee. Do not automatically retry a failed forward.

## Requests, capabilities, and results

`GetCapabilitiesRequest` contains `cell` and `api_major=1`. Its response contains
`cell`, `api_major`, `contract_revision`, `enabled`, `policy_revision`, the four
operation/family combinations enabled by cell policy, required features,
effective limits from this document, and `generated_at`. It reveals no node
addresses or credentials. Cap it at 64 KiB, a 2 s deadline, 1 call/s with burst 2
per authenticated service per replica, and 8 concurrent calls per replica.
The initial feature names are `router-outcomes`, `terminal-coverage`, and
`aggregate-probe-budgets`; all three are required to advertise an enabled v1
service. `contract_revision` is the implementing release commit SHA and
`policy_revision` is the digest of effective service policy and limits.
It does not probe routers or reserve diagnostic capacity. Cache for at most
30 s. Capabilities advertise policy, not current router availability. Validate
again on execution; policy changes may reject a previously advertised request.

`RunDiagnosticRequest` fields:

| Field               | Meaning and validation                                                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `api_major`         | Must be 1; incompatible majors fail before execution.                                                                                |
| `cell`              | Required; exact match with authenticated identity and serving cell.                                                                  |
| `project_id`        | Required opaque canonical project UID supplied by the service, ASCII `[A-Za-z0-9._:-]`, 1–128 bytes; not a project display name.     |
| `request_id`        | Required UUID identifying this backend attempt; unique within service, project, and cell.                                            |
| `expires_at`        | Required UTC timestamp; future and at most 120 s after first gateway receipt. Forwarding never extends it.                           |
| `query`             | One supported operation, target, and address family as below.                                                                        |
| `nodes`             | Optional unique node names, at most 32; empty selects all eligible routers within the fan-out bound. Unknown names fail validation.  |
| `budgets`           | Optional lower response/path/community limits; values exceeding advertised limits fail validation. Zero selects advertised defaults. |
| `required_features` | Set of capability names needed by the caller; unknown or unsupported requirements fail before work.                                  |

Use the minimum of request expiration, transport deadline, and certificate
expiration. A client should supply a 30 s deadline unless it needs a longer
bounded allowance for discovery and delivery; there is no implicit deadline extension. Reject
oversized/unknown enum inputs, controls, ambiguous identifiers, and unsupported
operations before reserving work. Normalize numeric targets exactly once and
pass the canonical value to nodes. Do not resolve DNS in the backend.

| Operation   | Inputs                                                                                                                         | Successful observation                                                                                        |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| RouteLookup | Bare IPv4/IPv6 address for longest match, or prefix with no host bits for exact match; family inferred or explicitly matching. | Router-local paths and separately sampled zebra installation; no matching route is a successful empty result. |
| BGPSummary  | Empty target; explicit IPv4 or IPv6 family required.                                                                           | Peer states and counters; a down peer is data.                                                                |
| Ping        | Numeric unicast address, matching/inferred family; no hostname, zone, or IPv4-mapped IPv6 form.                                | Three ICMP echo attempts, source/destination, replies, loss and RTT.                                          |
| Traceroute  | Same target rules as Ping.                                                                                                     | At most 20 hops, one ICMP probe per hop, source/destination, reached flag and hop observations.               |

Reject ASPath, Community, LargeCommunity, arbitrary commands, and caller-selected
probe sources. Ping/traceroute use at most 64 payload bytes per packet and a 1 s
reply wait. Apply the existing public destination policy at gateway and node:
special-use and deployment-denied platform/management ranges are forbidden;
IPv6 must be in the allowed global-unicast space. Operator allow exceptions
never apply to service traffic. Route visibility is independently gated by the
service's cell policy; project IAM and customer visibility decisions remain
upstream launch prerequisites, not inferred from certificate possession.

### Stream grammar and coverage

Each event has `request_id`, consecutive `sequence` starting at 1, and exactly
one of `snapshot`, `outcome`, or `complete`. A stream has one snapshot first,
zero or more outcomes in completion order, and at most one complete last.
The server finishes a fully delivered stream with gRPC OK, including when its
terminal diagnostic result is partial or failed. Transport failure or missing
complete means incomplete delivery, never success inferred from EOF alone.

Before admission, take one logical discovery snapshot of the configured
fabric-router pod inventory in the cell. Record `snapshot_id`, `captured_at`,
and the list resourceVersion; certify identities from the corresponding cert
pod read. These reads are not an atomic Kubernetes multi-resource snapshot.
Do not refresh membership or substitute a replacement pod during the run.

Group scheduled fabric-router pods by node name, including those without a
sidecar, usable address, running container, or certificate. Select one usable
pod per router deterministically: newest creation time, then pod name. Retain
other candidates only as diagnostic metadata; duplicate pods do not increase
expected coverage. Unscheduled pods have no router identity and are reported
as an inventory warning count. Nodes with no fabric-router pod are outside
this inventory; coverage must not claim all physical routers in the cell.

Apply explicit `nodes` selection before the fan-out cap; otherwise use sorted
node names. The snapshot records every unique router as selected or omitted,
with a reason (`NotRequested`, `NoSidecar`, `PodTerminating`, `PodNotRunning`,
`SidecarNotRunning`, `NoHostIP`, `NoCertificatePod`, or `NodeBudget`). A selected
router includes its frozen pod UID. Do not expose dial addresses or certificate
pod names to the service. Cap the inventory at 256 unique routers and 64 KiB
serialized snapshot; fail with `InventoryTooLarge` rather than silently
truncating membership. This does not change legacy FabricQuery discovery.

Let E be snapshot routers, S selected routers, and O omitted routers.
At terminal completion, every selected router has exactly one outcome:

```text
E = S + O
S = successful + failed
E = successful + failed + omitted
```

Send the snapshot before dispatching node jobs. Reserve queue capacity first,
so failure to admit cannot produce an apparently admitted snapshot. If snapshot
delivery fails, release that capacity and dispatch nothing. Outcome sequence
reflects completion handoff order; simultaneous completions may appear in either
order, but a slow router must not delay a completed router.

An outcome contains node name, frozen pod UID, completion time, and exactly one
observation or typed failure. An observation retains router ID, ASN, sample time,
duration, and its operation's result. Sample time is the start of that router's
read/probe, not the snapshot time; errors before sampling have no fabricated
sample time. Unreachable nodes and selected work canceled before dispatch are
failed, not omitted. A capability missing on a selected node is also a failure.

`complete` repeats snapshot ID and counts, has `finished_at`, `truncated_routers`,
and a terminal reason: `Succeeded`, `PartialResults`, `ExecutionFailed`,
`NoNodesAvailable`, `DeadlineExceeded`, `Cancelled`, `OwnershipLost`, or
`OutputLimitExceeded`. Cancellation/deadline/ownership/output-limit reasons take
precedence. Otherwise no selected routers gives `NoNodesAvailable`; zero
successful gives `ExecutionFailed`; any failed, omitted, or truncated result
gives `PartialResults`; the remainder is `Succeeded`. Empty inventory has all
counts zero and `NoNodesAvailable`.

Packet loss, unreachable ICMP replies, and silent hops are successful diagnostic
observations. `truncated=true` also remains a successful observation, but warns
that its payload is incomplete. Zebra read errors retain their existing nested
installation error while the BGP observation stands. Neither truncation nor an
installation error may silently become an empty complete result.

A connected client may receive synthesized cancellation failures and complete
while the deadline allows; a disconnected client cannot be promised either.
On an interrupted stream, preserve delivered observations, mark remaining
selected routers unknown to the consumer, and report only locally known counts.
Never fabricate the server's final coverage. There is no resume cursor or result
retrieval RPC.

## Errors and retries

Use `google.rpc.ErrorInfo` with domain `fabric-api.datumapis.com`. Its reason is
a stable machine-readable string; messages are sanitized and at most 256 bytes.
Router failures carry equivalent typed fields in their outcome. Errors must
not echo target addresses, credentials, or raw FRR text into routine logs.

| Condition/reason                                                           | gRPC status before snapshot              | Retry guidance                                                   |
| -------------------------------------------------------------------------- | ---------------------------------------- | ---------------------------------------------------------------- |
| Missing/invalid TLS identity                                               | UNAUTHENTICATED or TLS handshake failure | Repair credentials; no automatic execution retry.                |
| `Unauthorized`                                                             | PERMISSION_DENIED                        | Repair role, cell or policy.                                     |
| `InvalidQuery`, `DestinationNotAllowed`                                    | INVALID_ARGUMENT                         | Correct the request.                                             |
| `VersionUnsupported`, `QueryTypeUnavailable`, `ServiceDisabled`            | FAILED_PRECONDITION                      | Refresh capabilities/configuration.                              |
| `Throttled`, `QueueFull`, `NodeBusy`                                       | RESOURCE_EXHAUSTED                       | Include RetryInfo; new authorized attempt only.                  |
| `InventoryTooLarge`, `ResponseTooLarge`                                    | RESOURCE_EXHAUSTED                       | Lower scope/output or change configuration; not a rate throttle. |
| `DuplicateRequest`, `DuplicateConflict`                                    | ALREADY_EXISTS                           | Do not replay or treat this as a saved result.                   |
| `LimiterUnavailable`, `OwnershipLost`, `NodeUnreachable`, `FRRUnavailable` | UNAVAILABLE                              | Resolve availability; outcome may be unknown.                    |
| `DeadlineExceeded`                                                         | DEADLINE_EXCEEDED                        | No automatic retry.                                              |
| `Cancelled`                                                                | CANCELLED                                | No automatic retry.                                              |
| `ProbeSourceUnavailable`, `FRRVersionUnsupported`                          | FAILED_PRECONDITION                      | Repair node capability.                                          |
| `MalformedResponse`, `Internal`, `ProbeFailed`                             | INTERNAL                                 | Investigate backend; no automatic retry.                         |

Existing node reasons, including `Timeout`, remain intact in router failures;
translate only the service-level deadline into `DeadlineExceeded`. After the
snapshot, operational failures should be outcomes/complete where delivery is
possible; the table's transport status applies when no stream can be delivered.
Unknown reasons must be rendered as backend failures, not packet loss.

For throttling include `google.rpc.RetryInfo.retry_delay` and bounded ErrorInfo
metadata `scope` (cell/project/destination/queue) and `execution_started=false`.
Never include another project's identity or destination. Token shortage delay
is the maximum deficit/rate across depleted buckets, rounded up to milliseconds;
queue or concurrency refusal uses 1 s advisory delay. Recovery reports the
remaining recovery delay. Guidance is not a reservation or permission to retry.
A service may start a new attempt only under its own session/IAM policy, with a
new request ID and fresh charges. It must never replay an interrupted attempt.

Disable application and configured gRPC retries/hedging for customer execution,
including the runner's existing cheap-read retry. No response bytes is not proof
that execution did not occur. The admission owner records the attempt key and
canonical argument digest until `expires_at + 2 s`; identical duplicates are
`DuplicateRequest`, changed arguments `DuplicateConflict`. Bound this cache at
4096 entries/2 MiB and fail closed when full; never evict live keys to admit more.
This volatile cache may be lost on restart. Node duplicate suppression is also
volatile and is an optimization only.

## Admission, execution, and aggregate accounting

### One cell authority and recovery

Use the existing elected gateway as the single cell scheduler and limiter.
Followers forward; they never maintain independent execution buckets. Keep
bucket state in bounded leader memory, not Kubernetes session objects or a new
external datastore. Use an uncached election Lease read before each admission
and node dispatch to confirm holder UID/epoch and unexpired ownership. Define
epoch as Lease object UID plus the complete holderIdentity (including its unique
process-election suffix); recreating a Lease or acquiring it again must produce
a new epoch. Never reuse a previous holderIdentity after ownership uncertainty. Bound
that read to 1 s; any failure refuses new work and cancels active service work.
A stale cached leader boolean alone cannot authorize dispatch.

Every process start, leadership acquisition, limiter-state loss, or return from
an uncertain ownership interval enters a **125 s recovery hold**, even on a new
cell. Do not restore work or carry queued customer requests across epochs.
At the end, require a fresh valid Lease read, initialize all buckets empty, and
refill from that instant. A key first seen later starts with at most
min(burst, rate × time since that instant); a safely evicted, fully refilled key
can be recreated full. Release of the old Lease does not waive the hold.
Changing limits also cancels service work and enters recovery; rolling updates
therefore have an explicit diagnostic availability cost.

The hold exceeds the 120 s maximum request lifetime plus the combined 2 s
clock-skew and scheduling allowance. No prior-epoch request may be dispatched
with a new deadline. All bucket burst/rate ratios must be at most 120 s; then
the hold also clears the largest possible prior token debt. No traffic is
admitted by the authority during recovery, including aggregate-budget probes
from alternate interfaces. This conservative recovery is chosen over a durable
reservation datastore or independent replica buckets: it needs no new storage
service and avoids resetting available tokens at failover. Faster recovery
requires a separately reviewed durable accounting design.

An old gateway isolated from the API cannot obtain new dispatch checks. Nodes
also validate the current epoch via an uncached Lease read before accepting a
probe permit; stale or unverifiable permits fail closed. Previously started
calls expire within the bounds below. A delayed old process must recheck its
absolute deadline and ownership before every dispatch. These rules, together
with the recovery hold, prevent simultaneous old/new-epoch execution.

### Charging and scheduling

Apply request admission token buckets after authentication and shape validation
but before discovery; each token-admitted RunDiagnostic consumes one cell and one project request
token atomically, even if later validation, discovery, or dispatch fails. If
either bucket is short, reject without debiting either; never go into negative
credit. Register the attempt key before discovery and before accepting jobs;
all later failures retain its tombstone through expiration.
Project buckets are keyed by canonical project UID across all authorized service
identities. Never use the common service account as the fairness key.

After snapshot construction, admit all selected node jobs to the bounded shared
executor atomically or refuse the request. Charge one node-job unit per selected
router; omitted routers cost no node execution or packets. Maintain FIFO within
a project and round robin between project queues. Retain separate operator
principal queues and FabricQuery's trusted project queues; a FabricQuery and a
service request for the same project use the same fairness key. A project may
hold at most two node slots; direct operator principals have the same cap.
The shared executor has eight slots total. Keep the existing two-slot ceiling
for legacy expensive queries, which this service cannot submit. Queue admission
counts reserved snapshot-delivery slots toward the same limits.

Immediately before dispatch of each probe node job, atomically reserve its
worst-case packet count from cell, project (when present), and destination
buckets together. Charge Ping 3 and Traceroute 20. Insufficient credit fails
that selected router with `Throttled` without dispatching it. Never refund
unused, timed-out, rejected, canceled, or deduplicated attempts: conservatively
charged work must not become a retry bypass. A route read costs one node slot
and no packet credit. Three selected traceroute routers cost at most 60 packets;
32 cost at most 640. Actual early termination can only reduce that traffic.

Destination keys are the canonical IPv4 /32 or IPv6 /128 **and** containing
IPv4 /24 or IPv6 /64. Charge both, independent of project and operation. Limits
are cell-wide, not global across cells. Rotating projects cannot evade them;
rotating hosts within one prefix still consumes its prefix budget. Avoid a
claim of global internet destination protection from a cell-local mechanism.

Use bounded maps (4096 project keys, 16384 destination/prefix keys, 4 MiB total
bucket-state storage). A key may be discarded only when fully refilled and no
active/queued work references it. On capacity exhaustion reject new keys with
`LimiterUnavailable`; never evict debt. Persist no diagnostic payload in these
maps. Expose aggregate counts rather than key-valued metrics.

### Alternate callers and node enforcement

Cell and destination packet buckets include service, operator gateway,
FabricQuery, and direct operator-node probes. Project packet buckets apply to
service and FabricQuery; direct operators use their own principal bucket with
the same rates. Every probe, including direct-node Execute, must obtain a
single-node, single-attempt permit from the active cell authority. For direct
operators, the node requests it on an authenticated node-only internal RPC;
the service has no access to that RPC. That admission uses the same executor
and global packet buckets. Keep a remote execution reservation until a node
acknowledges completion or its absolute expiry plus 2 s. Cancellation or a lost
RPC response alone must not free remote concurrency credit; otherwise repeated
disconnects could exceed the eight-job limit. This applies to gateway-originated
node calls too. Local RPC workers may exit immediately while a bounded timer
retains the reservation. Never wait indefinitely for a release callback.

A permit binds epoch, request/attempt ID, node identity, canonical destination,
operation, packet allowance, and a deadline at most 30 s away. Carry permits
only on internal RPCs, authenticated by gateway mTLS; direct-node permit
responses are accepted only from that gateway. No caller-supplied permit
metadata is trusted. A node consumes a permit once and enforces its allowance
and deadline locally. Keep consumed permit IDs through expiry + 2 s in a
separate bounded set (4096 entries, 2 MiB); fail closed at capacity, never evict
a live permit to make room. The existing response-dedup cache is insufficient
because it can evict completed entries. After node restart or lost
permit-consumption state,
refuse permits for 32 s, then validate epoch and expiration before accepting
new ones; never reuse a surviving permit. Unsupported/old nodes fail closed
for aggregate-budget probes when the feature is enabled.

Keep the existing node-wide packet pacing and destination checks as additional
limits. Per-node pacing alone cannot substitute for aggregate charging.
Previously valid operator and FabricQuery probes can now be throttled, or refused
while the authority is unavailable; this is an intentional operational
compatibility change requiring rollout notice. Legacy wire schemas, observation
meanings, and direct operator destination exceptions remain unchanged. Legacy
reads need no packet permit. Do not silently exempt direct operator probes and
still advertise an aggregate ceiling.

### Initial defaults and hard bounds

Values below are proposed initial settings, subject to measured qualification.
Rates are tokens per second; packet rates count worst-case **reservations**, not
instantaneous emissions. Capacity reductions may be configured; increases
require boundary/load qualification. A changed configuration is rejected unless
all cross-field constraints hold.

| Limit                                                | Initial value / hard bound                      |
| ---------------------------------------------------- | ----------------------------------------------- |
| Service enabled                                      | false until qualification and explicit opt-in   |
| Request tokens, cell                                 | 2/s, burst 8                                    |
| Request tokens, project                              | 0.2/s, burst 2                                  |
| Live service streams, cell / project                 | 16 / 2, including queued and draining streams   |
| Shared active node jobs / per project                | 8 / 2                                           |
| Shared queued node jobs / per project                | 256 / 32                                        |
| Node job queue wait                                  | 10 s, inside all existing deadlines             |
| Selected routers / inventory routers                 | 32 / 256                                        |
| Packet tokens, cell                                  | 100/s, burst 640                                |
| Packet tokens, project or direct operator            | 20/s, burst 640                                 |
| Packet tokens, destination host                      | 20/s, burst 640                                 |
| Packet tokens, destination prefix                    | 40/s, burst 640                                 |
| Maximum request lifetime / node queue plus execution | 120 s / 30 s                                    |
| Request message / snapshot / complete                | 64 KiB / 64 KiB / 64 KiB                        |
| Observation payload / full outcome event             | 128 KiB / 144 KiB                               |
| Total serialized events per stream                   | 5 MiB, excluding transport framing              |
| Buffered completed outcomes per stream               | 2, at most 288 KiB                              |
| Blocked enqueue or network send                      | 2 s                                             |
| Live attempt keys / storage                          | 4096 / 2 MiB                                    |
| Bucket keys / storage                                | 4096 project + 16384 destination/prefix / 4 MiB |
| Error message                                        | 256 bytes                                       |
| Route paths / communities per path                   | 8 / 64 for each community kind                  |

Check that each packet burst can fund at least one maximum-cost node job (20),
all rates are positive, burst/rate is at most 120 s, project caps do not exceed
cell caps, node time fits request lifetime, and output reserves cover the
maximum selected-router count. These defaults can fund 32 traceroute node jobs, but the per-project slot
cap and 10 s queue deadline can produce failed outcomes even in a lightly
loaded cell. A fan-out ceiling is not a completion guarantee. Consumers should
select a smaller router subset when complete long-running probe coverage is
needed. Qualification must report this default behavior, not hide queue timeouts
as omitted routers or silently extend deadlines.

For any reservation interval of length T, a bucket permits at most B + rT
packets. Dispatch-to-final-packet delay is bounded by 32 s under the failure
assumptions below. Therefore packets actually emitted in an arbitrary interval
of length T are bounded by **B + r(T + 32)**, also bounded by each node's local
pacer. For the destination-host default, a 1 s interval has an upper bound of
640 + 20 × 33 = 1300 packets across the cell. This is deliberately not a promise
of 20 packets in every wall-clock second. Qualification measures reservations
and emissions separately. A tighter instantaneous destination limit requires
central per-packet pacing and a revised contract. Because one node job
reserves and completes its packets within 32 s, the same envelope covers
failover: the 125 s quiet hold exceeds both emission delay and token debt.
Do not reset a node permit deadline on retries or transport reconnection.

## Cancellation, delivery, and failure assumptions

Deadlines cover discovery, admission, queueing, execution, and delivery. Freeze
each node deadline at enqueue: minimum of request expiration and now + 30 s;
its queue wait also ends at 10 s. A permit may only shorten that deadline.
Stop scheduling and cancel node contexts on cancellation, stream failure,
shutdown, service disable, deadline, or loss of ownership. Disabling service
cancels existing service work and rejects new runs; legacy diagnostics remain
subject to their shared budgets and routing is unaffected.

Release confirmed-complete execution credit before attempting result delivery;
retain uncertain remote reservations as described above. Bound completion queues;
if enqueue or send blocks for 2 s, cancel the request and close its stream. Do
not silently drop outcomes, spawn unbounded send goroutines, or keep executing
because a consumer stopped reading. Use a transport implementation that can
abort a blocked write; timing only the producer's select is insufficient.
Each selected node job may temporarily hold one 144 KiB encoded outcome during
handoff, even after releasing execution credit. Cap service job goroutines at
16 × 32 = 512: at most 72 MiB of encoded producer payload plus 4.5 MiB in
completion queues. Require implementations to account for decoded protobuf
allocations separately and measure peak RSS; these are not total process RSS
bounds. Cap incoming diagnostic RPCs at 32 per replica, follower forwarding
streams at 16 per replica, and accepted service TLS connections at 64 per
replica. Admission occurs before spawning job goroutines. Bound transport
receive windows and read/write buffers to 64 KiB each per connection/stream,
with at most one writer per stream. Followers apply the same two-event buffer
and 2 s write bounds. Reject excess connections/RPCs rather than buffering them.
Snapshots and terminal records each have their own 64 KiB bound.
The 5 MiB stream cap is cumulative output, not an allocation target.
Reserve space for failure outcomes and complete; with these limits,
32 × 144 KiB + 2 × 64 KiB = 4736 KiB, below 5 MiB. If encoding still cannot fit,
cancel with `OutputLimitExceeded`; a transport failure still means incomplete
delivery. Diagnostic results never enter Kubernetes status or routine logs for
this service. Existing FabricQuery persistence is unaffected.

The following are acceptance targets, not measured claims:

| Trigger                                                              | Required bound and clock origin                                                                                                                                        |
| -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Explicit cancellation or healthy transport disconnect notification   | Queued work removed and local workers/buffers released within 2 s of receipt; reachable node probes stop within 2 s. Uncertain remote credit lasts until expiry + 2 s. |
| Blocked client write or full result queue                            | Abort within 2 s of blocking; local cleanup within another 2 s.                                                                                                        |
| Silent connection blackhole                                          | Detect within 10 s using transport liveness; local cleanup within another 2 s.                                                                                         |
| Explicit ownership loss, API read failure, shutdown, service disable | Stop new service admissions/dispatches immediately on detection; reachable work canceled within 2 s.                                                                   |
| Isolated node or unreachable cancellation channel                    | Last packet no later than node absolute deadline + 2 s skew/scheduling allowance; at most 32 s after its dispatch.                                                     |
| Queued job                                                           | Dispatch or fail within 10 s of enqueue, or earlier enclosing deadline.                                                                                                |
| Gateway paused/crashed without delivering cancellation               | No new packet after the already-issued node deadline + 2 s; replacement admits nothing during its 125 s recovery hold.                                                 |

Assume authenticated components are non-Byzantine, the Kubernetes API provides
consistent uncached Lease reads/CAS election, pairwise wall-clock skew is at
most 1 s, and runnable deadline checks execute within 1 s. Use monotonic timers
for local durations. Nodes recheck deadlines immediately before each send,
including after a process pause. Clock jumps beyond the assumption or an
unresponsive kernel invalidate a wall-clock guarantee; fail closed when clock
health is unknown, alarm, and record the qualification failure rather than
claiming the bound. The 2 s allowance includes skew plus scheduling delay.

A lost node process sends nothing; a paused process must not resume sending
expired work. Cancelling an FRR socket read does not promise to cancel work
already running inside bgpd. The service permits only bounded route/summary
reads, never full-table searches; routing-impact qualification remains required.
Session revocation reaches Galactic only when its caller cancels; no bound here
includes upstream revocation detection or federation latency.

## Wire examples

The JSON below uses protobuf JSON field spelling for the proposed messages;
timestamps and UUIDs are illustrative. #1044 must validate these fixtures with
the generated descriptor and publish the finalized schema alongside them.
A request received at 12:00:00 with the following expiration has 30 s remaining:

```json
{
  "apiMajor": 1,
  "cell": "example-cell",
  "projectId": "project-a",
  "requestId": "b74e19ee-926f-43dc-b03d-c29550a827ab",
  "expiresAt": "2026-10-24T12:00:30Z",
  "query": {"type": "QUERY_TYPE_PING", "target": "1.1.1.1", "addressFamily": "ADDRESS_FAMILY_IPV4"},
  "requiredFeatures": ["router-outcomes", "terminal-coverage", "aggregate-probe-budgets"]
}
```

A mixed result stream (one JSON object per protobuf event):

```json
[
  {"requestId":"b74e19ee-926f-43dc-b03d-c29550a827ab","sequence":1,"snapshot":{"snapshotId":"snap-1","capturedAt":"2026-10-24T12:00:00Z","resourceVersion":"100","routers":[{"node":"router-a","podUid":"pod-a","selected":true},{"node":"router-b","podUid":"pod-b","selected":true},{"node":"router-c","selected":false,"omittedReason":"NoCertificatePod"}]}},
  {"requestId":"b74e19ee-926f-43dc-b03d-c29550a827ab","sequence":2,"outcome":{"node":"router-a","podUid":"pod-a","completedAt":"2026-10-24T12:00:03Z","observation":{"node":"router-a","routerId":"192.0.2.1","asn":64512,"sampleTime":"2026-10-24T12:00:00Z","duration":"3s","ping":{"source":"192.0.2.1","destination":"1.1.1.1","sent":3,"received":0,"replies":[{"sequence":1,"timeout":true},{"sequence":2,"timeout":true},{"sequence":3,"timeout":true}]}}}},
  {"requestId":"b74e19ee-926f-43dc-b03d-c29550a827ab","sequence":3,"outcome":{"node":"router-b","podUid":"pod-b","completedAt":"2026-10-24T12:00:04Z","failure":{"reason":"NodeUnreachable","message":"Router did not answer"}}},
  {"requestId":"b74e19ee-926f-43dc-b03d-c29550a827ab","sequence":4,"complete":{"snapshotId":"snap-1","finishedAt":"2026-10-24T12:00:04Z","expected":3,"successful":1,"failed":1,"omitted":1,"truncatedRouters":0,"reason":"PartialResults"}}
]
```

Here 100% loss is one successful observation. If delivery stops after sequence
2, the consumer knows one success, one omission and one unresolved selected
router; it must not invent sequence 4 or retry router-b automatically.

A pre-execution throttle uses a gRPC status with standard details:

```json
{
  "code": 8,
  "message": "Project admission budget exhausted",
  "details": [
    {"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"Throttled","domain":"fabric-api.datumapis.com","metadata":{"scope":"project","execution_started":"false"}},
    {"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"5s"}
  ]
}
```

## Publication, compatibility, and rollout

#1044 publishes protobuf sources, their transitive imports, generated Go client
and server types, and a descriptor set with imports in a versioned Galactic
release asset named `fabric-service-api-<version>.tar.gz`, containing
`proto/` sources and imports, `fabric-service-v1.pb` (descriptor set with imports),
and `README.md` with the matching Go module version and generation instructions.
Publish `SHA256SUMS` alongside it. Commit generated Go artifacts using
`task generate:proto`;
never hand-edit them. Consumers pin a release tag or commit of
`go.datum.net/galactic`, import only `api/fabric/service/v1`, `api/fabric/v1`, and
standard protobuf/gRPC packages, or generate another language client from the
published descriptor/source bundle. No internal canonicalizer, error parser,
identity helper, or Kubernetes client is required to call the service.
The release must link these artifacts and their checksums. The source path
alone is not proof that this publication gate has passed.

Within major v1, add optional fields/features only; reserve deleted field
numbers/names and never repurpose enums. Unknown optional fields are ignored;
unknown outcome reasons remain failures. A client requiring a new feature names
it in `required_features`; the server refuses if unavailable. An unknown event
variant prevents the client from claiming complete coverage. Breaking request,
identity, counting, or execution semantics require a new API major. Alpha
implementation must not advertise v1 capabilities until these rules pass.

Roll out node permit support first, then gateway authority/streaming support,
then enable the aggregate budget policy for all probe paths, and finally opt in
service identities. Old nodes cannot be selected for service work; missing
permit support is an explicit capability failure. Keep customer execution off
through mixed-version qualification. A rollback disables service and cancels
active runs first; retain aggregate enforcement until probes are quiescent and
an operator explicitly returns to legacy policy. Removing permit enforcement
must not leave a service advertising aggregate guarantees.

No service endpoint is exposed publicly by this contract. Configure it alongside
the internal gateway listener with distinct method authorization. #1047 defines
validated configuration keys and operational commands from these semantics.
Metrics use bounded labels (operation, reason, traffic class, limiter scope),
never project IDs, request IDs, destinations, node UIDs, or result contents.
Routine logs may contain sanitized attempt metadata but not diagnostic output,
targets, or raw remote error text. Service disable affects diagnostics only.

## Acceptance matrix and evidence

Every row is required. #1042 supplies specifications and examples; later owners
supply executable tests and measured evidence. No row is satisfied by this
proposal, readiness checks, or skipped tests alone.

| ID / owner  | Scenario                                                                                          | Required evidence                                                                                                  |
| ----------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| A1 / #1043  | Valid service; missing, expired, wrong-role, wrong-cell credentials; rotated CA/cert              | Only allowed same-cell service methods succeed, including reused connections and streams.                          |
| A2 / #1043  | Forged project/forward headers, direct forward RPC, second-hop forward                            | Rejected before execution; trusted typed attribution survives one authenticated forward.                           |
| A3 / #1044  | All four diagnostics and both supported families                                                  | Typed results decode with an independently built public-API client; no internal imports.                           |
| A4 / #1044  | One fast and one blocked router                                                                   | Fast outcome delivered while the other is pending; one outcome per selected router.                                |
| A5 / #1044  | Duplicate pods, missing sidecar/cert, explicit subset, fan-out cap, empty inventory, >256 routers | Deterministic fixed membership; exact coverage arithmetic; explicit overflow failure.                              |
| A6 / #1044  | Loss, silent hops, no route, truncated paths, zebra failure                                       | Observations remain distinguishable from backend failure; truncation affects terminal reason.                      |
| A7 / #1044  | Old/new client, unsupported feature/enum/major                                                    | No accidental authorization or silent semantic downgrade; published descriptor fixtures decode.                    |
| A8 / #1045  | Bursts and sustained competing projects, including FabricQuery sharing a project                  | Measured admission/node-slot ceilings, FIFO/round robin progress, per-project caps, bounded queues.                |
| A9 / #1045  | Ping/trace fan-out, mixed projects and addresses in one destination prefix                        | Reservations obey every B+rT envelope; actual emitted packets obey B+r(T+32); no refunds/retry bypass.             |
| A10 / #1045 | Operator gateway, direct-node operator, FabricQuery and service probes combined                   | All contribute to aggregate cell/destination ceilings; direct exceptions do not bypass charging.                   |
| A11 / #1045 | Replica changes, lost buckets, saturated key maps, failed API reads                               | Single authority, 125 s hold, empty-bucket restart, no debt eviction, no unbounded fallback.                       |
| A12 / #1046 | Cancel during discovery/queue/execute; shutdown/disable; blackholed connection                    | Timings measured from specified triggers; no work continues past node deadline + 2 s.                              |
| A13 / #1046 | Consumer stops reading; maximum-sized outcomes on all streams                                     | Send/enqueue aborts and resource release meet bounds; output/buffers/goroutines stay bounded.                      |
| A14 / #1046 | Old owner API-isolated or paused then resumed; node restart; forwarded stream lost                | Expired/stale permits rejected, old work drains, no replacement replay or duplicate permit execution.              |
| A15 / #1047 | Invalid limits, config changes, clock-health failure, logging/metrics capture                     | Invalid configuration refused; recovery applied; no payload leakage or unbounded metric labels.                    |
| A16 / #1048 | Legacy operator/FabricQuery regression and upgrade/rollback                                       | Existing schemas/results remain usable; documented new probe throttling/availability behavior verified.            |
| A17 / #1048 | Real routers, independent client, combined failure and load suite                                 | Pinned artifacts, workload, clocks, limits, resource/packet captures and cleanup instructions permit reproduction. |

Qualification records p50/p95/max delivery and cancellation times, peak RSS,
goroutines, queue depth, bytes buffered, emitted packet counts, and limiter
charges. Initial routing-impact gate: no diagnostic-induced BGP session reset
or route loss, and p95 convergence no more than 10% slower than an otherwise
identical no-diagnostics control over at least 20 controlled convergence trials.
Record baseline variability; inability to distinguish a 10% regression is
inconclusive, not a pass. A supported target platform must pass the failure
bounds above; changing a bound or gate requires an explicit contract revision.
