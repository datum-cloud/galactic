# FabricQuery API Reference

`FabricQuery` is the internal contract between the federation hub and a cell's
fabric-api gateway: one object per public looking-glass query per resolved cell.
This page documents its spec, status, validation, semantics and error codes. For
how the gateway executes it see
[docs/agents/ARCHITECTURE-FABRIC-API.md](../agents/ARCHITECTURE-FABRIC-API.md); for
deploying it see [configuration.md](configuration.md).

The **public** `LookingGlassQuery` that tenants create is served by NSO and is out
of scope here. `FabricQuery` has no IAM entry and is not tenant-writable; it is
written by NSO on the federation hub, propagated by Karmada to one pinned member
cluster, and its status is written by that cell's gateway and returned by Karmada.

> Last verified: 2026-10-07 against `internal/fabric/api/v1alpha1/`,
> `internal/fabric/query/`, `internal/fabric/gateway/reconciler.go`,
> `internal/fabric/errcode/` and the generated CRD in `config/fabric-api/crd/`.

## Resource

| Property        | Value                                                                                                                                               |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Group, version  | `network.datumapis.com/v1alpha1`                                                                                                                    |
| Kind            | `FabricQuery`, list kind `FabricQueryList`                                                                                                          |
| Scope           | Namespaced (the project's mapped namespace on the hub)                                                                                              |
| Short name      | `fq`                                                                                                                                                |
| Subresources    | `status`                                                                                                                                            |
| Printer columns | `TYPE`, `TARGET`, `SITE`, `COMPLETE`, `REASON`, `AGE`                                                                                               |
| Spec            | Immutable (`self == oldSelf`)                                                                                                                       |
| Allowed verbs   | The gateway: get, list, watch, and update/patch on `fabricqueries/status`. The janitor: list, delete. NSO owns create and spec lifecycle on the hub |

The Go types live in `internal/fabric/api/v1alpha1` until the `network` repository
ships the kind; `config/fabric-api/crd/` is a generated copy for the lab and tests
only, and infra owns the CRD in every cell. Regenerate with `task generate:crd`.

NSO sets two labels on every object so a janitor could find requests without
reading specs: `network.datumapis.com/fabric-request-id` (the request ID) and
`network.datumapis.com/fabric-expires-at` (the expiration, Unix seconds). The cell
gateway and janitor in this repository read `spec`, not the labels.

## Spec

| Field                 | Type            | Required | Validation and meaning                                                                                                                                                |
| --------------------- | --------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `requestID`           | string          | Yes      | 1 to 128 characters matching `^[A-Za-z0-9][A-Za-z0-9._-]*$`. Identifies the request across retries; with the node and type it is the nodes' duplicate-suppression key |
| `source.uid`          | string          | Yes      | At most 64 characters. The public query's UID                                                                                                                         |
| `source.cluster`      | string          | Yes      | At most 253. The project control plane                                                                                                                                |
| `source.namespace`    | string          | Yes      | At most 63                                                                                                                                                            |
| `source.name`         | string          | Yes      | At most 253                                                                                                                                                           |
| `query.type`          | enum            | Yes      | `RouteLookup`, `ASPath`, `Community`, `LargeCommunity`, `BGPSummary`, `Ping`, `Traceroute`                                                                            |
| `query.target`        | string          | See CEL  | At most 255 bytes; the canonical target (see [Targets](#targets-and-address-family))                                                                                  |
| `query.addressFamily` | enum            | Yes      | `IPv4` or `IPv6`. Always explicit in a stored object                                                                                                                  |
| `query.hostname`      | string          | No       | At most 253. Probe destination as the tenant wrote it, for display only; cells never resolve it                                                                       |
| `site`                | string          | Yes      | 1 to 63. The location the cell serves; a gateway executes only its own site                                                                                           |
| `clusterName`         | string          | Yes      | 1 to 253. The Karmada member cluster the query is pinned to; a gateway executes only its own cluster                                                                  |
| `nodeSelector`        | `LabelSelector` | No       | Restricts execution to fabric-router pods on matching nodes. Operator-set only; NSO never copies a tenant value here                                                  |
| `budgets`             | object          | No       | Lowers result limits; see [Budgets](#budgets)                                                                                                                         |
| `expiresAt`           | time            | Yes      | Absolute expiration. Nothing executes after it                                                                                                                        |

CEL rules on the CRD:

- `spec` is immutable: `self == oldSelf`.
- `query.target` is required and non-empty for every type except `BGPSummary`,
  where it must be absent or empty.
- `query.hostname` is allowed only when `query.type` is `Ping` or `Traceroute`.

The gateway revalidates every object it executes, because the CRD is not the only
trust boundary. A spec that passes the schema is still `Rejected` (see
[Conditions](#conditions)) if:

- the query is not already in canonical form (`Canonicalize` of the query must
  equal the query as written: for example an IPv6 target must be in its compressed
  lower-case form, a community without leading zeros, a hostname lower-case);
- a probe's `query.target` is not a numeric address in the query's family (the
  gateway never resolves names; NSO pins the address and may keep the hostname in
  `query.hostname`); or
- `expiresAt` is more than 120 seconds plus one minute after the object's creation
  or after now.

### Budgets

`spec.budgets` can only lower limits. A zero or absent field takes the cell's
ceiling, and a value above the ceiling is lowered to it; the gateway also applies
its own configured ceilings (`--max-nodes`, `--max-object-bytes`,
`--max-node-response-bytes`).

| Field                   | Schema range | Ceiling | Bounds                                                  |
| ----------------------- | ------------ | ------- | ------------------------------------------------------- |
| `maxNodes`              | 0 to 32      | 32      | Nodes one query executes on in the cell                 |
| `maxNodeResponseBytes`  | 0 to 131072  | 128 KiB | One node's serialized response                          |
| `maxObjectBytes`        | 0 to 393216  | 384 KiB | The serialized `FabricQuery`, status included           |
| `maxPrefixes`           | 0 to 100     | 100     | Prefix observations kept per node                       |
| `maxPathsPerPrefix`     | 0 to 8       | 8       | Paths kept per prefix (the best path is always kept)    |
| `maxCommunitiesPerPath` | 0 to 64      | 64      | Communities, and separately large communities, per path |

Each node's response allowance is derived from the object budget before fan-out, so
the node response ceiling is not an entitlement for every node. If the assembled
object still exceeds `maxObjectBytes`, the gateway shrinks the largest
observation first and marks it truncated; see
[Truncation](#matched-matchedisexact-and-truncated).

## Targets and address family

All three hops that accept a query (NSO's admission, the cell gateway, the node
sidecar) run the same canonicalization, so a query means the same thing at each.
It never resolves DNS.

Common rules: at most 255 bytes, printable ASCII only (a control character,
non-ASCII character or invalid UTF-8 is `InvalidTarget`), and an unknown type is
`InvalidType`.

| Type             | Target                                                                                                                                                                                                                                                                                                                                                            | Family                                               |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `RouteLookup`    | Required. A CIDR prefix with no host bits set, or a bare IPv4 or IPv6 address. IPv4-mapped IPv6 addresses and zones are rejected rather than guessed at                                                                                                                                                                                                           | Inferred from the literal                            |
| `ASPath`         | Required. An AS-path expression of at most 128 bytes using only digits and `^ $ _ . * + ? [ ] ( ) \| -`. No spaces and no letters, so it is always one FRR token. `_` stands for an AS boundary. `^$` (the empty path) is valid. It must compile as a POSIX extended expression with `_` substituted; FRR's own compile result is still authoritative at the node | Not inferred: the explicit family, else IPv4         |
| `Community`      | Required. `AA:NN` with each half 0 to 65535 in digits only, or a well-known name (`no-export`, `no-advertise`, `local-AS`, `no-peer`, `blackhole`, `graceful-shutdown`, `accept-own`; matched case-insensitively and canonicalized). Leading zeros are removed                                                                                                    | Not inferred: the explicit family, else IPv4         |
| `LargeCommunity` | Required. `GA:LD1:LD2` with each part 0 to 4294967295 in digits only. Leading zeros are removed                                                                                                                                                                                                                                                                   | Not inferred: the explicit family, else IPv4         |
| `BGPSummary`     | Forbidden (`TargetForbidden` if present)                                                                                                                                                                                                                                                                                                                          | Not inferred: the explicit family, else IPv4         |
| `Ping`           | Required. An IPv4 or IPv6 address (no IPv4-mapped form, no zone), or a fully qualified hostname: at least two RFC 1123 labels, lower-cased with a trailing dot removed, final label not all digits. In a `FabricQuery` it must already be numeric                                                                                                                 | Inferred from a literal address; a hostname has none |
| `Traceroute`     | As `Ping`                                                                                                                                                                                                                                                                                                                                                         | As `Ping`                                            |

Family inference: a literal address or prefix sets the family. An explicit
`addressFamily` that conflicts with a literal target is `AddressFamilyConflict`.
In every other case, including ASNs, communities, summaries and hostnames, the
explicit family is used, defaulting to `IPv4`. A stored `FabricQuery` always has
`addressFamily` set. The family also selects the BGP table (`show bgp ipv4|ipv6
unicast ...`) or the probe's address family.

The validation codes are `InvalidType`, `InvalidTarget`, `TargetRequired`,
`TargetForbidden`, `AddressFamilyConflict`, `InvalidAddressFamily`,
`DestinationNotAllowed` and `NumericDestinationRequired`. Over gRPC every one
except `DestinationNotAllowed` travels as `InvalidQuery`, with the specific code
in the `ErrorInfo` metadata under the key `queryCode` and at the start of the message.

### Probe destinations

Whether a numeric destination may be probed is a separate decision from syntax.
The node checks it against the destination policy for the caller's role; see
[configuration.md](configuration.md#destination). In short, a public probe may
target only IPv6 global unicast (`2000::/3`) and non-special-use IPv4, minus any
`--deny-prefixes`. Routing visibility does not authorize an active probe to every
visible prefix.

## Lookup semantics

A `RouteLookup` runs `show bgp <afi> unicast <target> json` on bgpd:

| Target         | `routes.lookupKind` | Behaviour                                                                                                                  |
| -------------- | ------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| A CIDR prefix  | `Exact`             | Matches only that prefix. An absent prefix is a successful empty answer: `matched: 0`, `matchedIsExact: true`, no prefixes |
| A bare address | `LongestMatch`      | Returns the most specific prefix covering the address. With a default-only table the match can be the default route        |

`ASPath`, `Community` and `LargeCommunity` return `lookupKind: Search`; see
[Searches and the index](#searches-and-the-index).

**BGP selection and zebra installation are separate evidence.**

- `paths[].best` describes the source router's own BGP choice among the paths it
  holds. Each path belongs to its observation; nothing is deduplicated across
  nodes and there is no location-wide best path.
- `prefixes[].installation` is zebra's evidence for the same prefix, read with
  `show ip|ipv6 route <prefix> json`, with its own `sampleTime`. `present` is false
  when zebra holds no route. A failure to read it is recorded in the evidence
  (`errorCode`, `errorMessage`) and the BGP answer stands. Routes (at most 8) carry
  `protocol`, `selected`, `installed`, `distance`, `metric` and next hops with
  `active`, `fib` and `blackhole`.
- Installation evidence is attached to `RouteLookup` only, not to searches.
- Neither claims end-to-end reachability or XDP forwarding behaviour, and FRR holds
  platform routes, not tenant VRF routes: an address can resolve through a
  default route, and an absent prefix does not imply an absent tenant overlay route.

Routing fields are shown as-is: ASNs, router IDs, next hops, communities and peer
names are not filtered. `asPath` is the string FRR printed, `asPathSegments`
preserves segment type (`as-sequence`, `as-set`, `as-confed-sequence`,
`as-confed-set`) and order, `origin` is the BGP ORIGIN attribute and `originASN` is
the originating AS (0 when local or ambiguous).

### Searches and the index

By default a node answers `ASPath`, `Community` and `LargeCommunity` from a local
index of bgpd's selected routes (kept from a BMP stream), not by asking FRR to scan
its table; see [configuration.md](configuration.md#search-index). Consequences for
the answer:

- **Selected path only.** Each returned prefix carries the router's selected path,
  with `best: true`. A search matches that path's attributes. FRR's own search lists
  any path that matches, so an indexed search can return fewer prefixes than FRR's.
  `matched` is exact and counts prefixes whose selected path matches. Installation
  evidence is not attached to searches.
- **`routes.index`** reports the index's freshness at the time of the search:

  | Field        | Meaning                                                          |
  | ------------ | ---------------------------------------------------------------- |
  | `syncedAt`   | When the current BMP session's initial table completed           |
  | `lastUpdate` | When the index last applied a route change                       |
  | `version`    | Route changes applied since the sidecar started; only grows      |
  | `routes`     | Prefixes the index holds, both families                          |

  `index` is absent when FRR answered the search (`--search-source=frr`) and on
  lookups.
- **Not synced is not an empty answer.** Until the index has bgpd's full table, and
  while the BMP session is down, the node returns `QueryTypeUnavailable` and
  never a partial result and never a scan of bgpd.
- Results are the first matches in prefix order, at most `maxPrefixes`, with
  `truncated: true` when more matched.

## Status

The gateway writes status twice: a start marker, then one terminal result. A
terminal status is immutable.

| Field                | Meaning                                                                                               |
| -------------------- | ----------------------------------------------------------------------------------------------------- |
| `requestID`          | Echo of `spec.requestID`, so aggregation can check it                                                 |
| `producerCluster`    | The cluster that wrote the status; aggregation refuses any producer other than `spec.clusterName`     |
| `observedGeneration` | The generation the status describes                                                                   |
| `attempt`            | Executions started. It rises only when a gateway replaces one that stopped before persisting a result |
| `startTime`          | When execution started (the start marker)                                                             |
| `completionTime`     | Set on every terminal outcome, including rejection and expiry                                         |
| `nodes`              | The fixed node snapshot taken when execution started (at most 64 entries, selected nodes first)       |
| `observations`       | One entry per executed node, sorted by node name (at most 32)                                         |
| `coverage`           | Accounting of every node discovered                                                                   |
| `conditions`         | `Accepted`, `Complete` and `Failed` (at most 8 entries)                                               |

### Node snapshot

`status.nodes[]` has `name`, `pod`, `podUID`, `hostIP`, `certificatePod`,
`selected` and, for a node not executed on, `omittedReason`. `certificatePod` is
the pod whose identity the node's sidecar presents: the node's `fabric-api-certs`
pod, which the gateway pins when it dials. The list is keyed by node name and
bounded at 64 entries with selected nodes first; omitted nodes past the bound are
counted in `coverage` but not listed. Every fabric-router pod carrying the fabric-api
container is recorded, so a node that could not be executed on is accounted for
instead of silently dropped. Pod `Ready` is not consulted. Reasons:

| `omittedReason`     | Meaning                                                                            |
| ------------------- | ---------------------------------------------------------------------------------- |
| `PodTerminating`    | The pod has a deletion timestamp                                                   |
| `PodNotRunning`     | The pod's phase is not `Running`                                                   |
| `NoHostIP`          | The pod has no `hostIP` yet                                                        |
| `SidecarNotRunning` | The `fabric-api` container is not running                                          |
| `DuplicatePod`      | A second pod on a node that already has a selected pod, as during a rolling update |
| `NoCertificatePod`  | The node has no Running `fabric-api-certs` pod, so there is no identity to dial    |
| `NodeBudget`        | More usable nodes than `maxNodes`; selection is in node-name order                 |

### Coverage

| Field        | Meaning                                                                                                   |
| ------------ | --------------------------------------------------------------------------------------------------------- |
| `expected`   | Nodes discovered, not counting `DuplicatePod` duplicates                                                  |
| `omitted`    | Expected nodes not executed on (any omission reason except `DuplicatePod`)                                |
| `successful` | Nodes that returned an observation                                                                        |
| `failed`     | Nodes that returned an error, or whose answer was replaced by `ResponseTooLarge` to fit the object budget |

The start marker carries `expected` and `omitted` with `successful` and `failed` at
zero. At a terminal outcome, `expected` equals `successful` plus `failed` plus
`omitted`.

### Observations

Each `observations[]` entry is one router's answer, or its error.

| Field                  | Meaning                                                                                                                        |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `node`                 | The Kubernetes node name                                                                                                       |
| `sampleTime`           | When the node read FRR or began the probe                                                                                      |
| `durationMilliseconds` | How long the node took                                                                                                         |
| `errorCode`            | Set when the node produced no answer; see [Error codes](#error-codes). Absent on success                                       |
| `errorMessage`         | At most 256 bytes                                                                                                              |
| `routerID`, `asn`      | The router's BGP router ID and AS, read from `show bgp summary json`                                                           |
| `frrVersion`           | The FRR version the sidecar read                                                                                               |
| `matched`              | See below                                                                                                                      |
| `matchedIsExact`       | Whether `matched` is an exact count                                                                                            |
| `truncated`            | The result was shaped down to a budget                                                                                         |
| `routes`               | `RouteLookup` and searches: `lookupKind`, `prefixes[]` (at most 100) and, for a search answered from the node's index, `index` |
| `summary`              | `BGPSummary`: `routerID`, `asn`, `peers[]` (at most 256), `totalPeers`, `establishedPeers`                                     |
| `ping`                 | `Ping`: `source`, `destination`, `sent`, `received`, `replies[]`, `rttMinMicroseconds`, `...Avg...`, `...Max...`               |
| `traceroute`           | `Traceroute`: `source`, `destination`, `reached`, `hops[]` (at most 20, each with at most 3 `probes[]`)                        |

Exactly one of `routes`, `summary`, `ping` or `traceroute` is set on a success.
Each prefix has `prefix`, `paths[]` (at most 8), `totalPaths`, and `installation`.
A path has `best`, `multipath`, `valid`, `selectionReason`, `asPath`,
`asPathSegments`, `origin`, `originASN`, `localPref`, `med`, `weight`, `local`,
`aggregated`, `communities`, `largeCommunities` (each at most 64) with
`totalCommunities` and `totalLargeCommunities`, `nextHops[]`, `peerAddress`,
`peerRouterID`, `peerHostname`, `peerType` and `lastUpdate`.

A peer reported down, ping packet loss and a traceroute hop with no reply are
diagnostic data, not execution failures: a down peer appears with its `state`, loss
appears as `sent` greater than `received` and `timeout: true` replies, and a silent
hop is a probe with `timeout: true`. Only `echo-reply` counts toward `received`.
A traceroute stops when the destination answers (`reached: true`), when a router
answers unreachable, packet-too-big or parameter-problem, or at 20 hops. A probe's
`source` is the node's per-family source address and `destination` the numeric
address actually probed.

### `matched`, `matchedIsExact` and `truncated`

- `matched` counts **matching prefixes** for a route lookup or search, not paths. For
  an indexed search it counts prefixes whose selected path matches.
  For `BGPSummary`, `Ping` and `Traceroute` it is unset; use `totalPeers` and
  `establishedPeers`, `sent` and `received`, and `reached` and the hop count.
- It is an exact total only after a complete, valid FRR response has been parsed.
  Then `matchedIsExact` is true and `matched` is set. Otherwise `matched` is
  omitted and `matchedIsExact` is false. A route lookup returns `matched` 0 or 1;
  a search returns the number of prefixes FRR reported.
- `truncated: true` means a valid response was shaped down to a budget. `matched`
  keeps the full count, `totalPaths`, `totalCommunities` and
  `totalLargeCommunities` keep the full per-path counts, and what is present is a
  prefix of the whole. Shaping order at the node: drop prefixes from the end
  (keeping one), then keep only the best path of each prefix, then drop
  communities, then drop summary peers. The gateway applies a final pass when
  assembling the object: it removes route prefixes, then summary peers, then
  traceroute hops from the largest observation until the object fits.
- A byte cap that prevents parsing returns `ResponseTooLarge` as the node's error,
  never an invented partial JSON answer. If even the smallest form of an
  observation does not fit the object budget, the gateway replaces it with a
  `ResponseTooLarge` error and adjusts `coverage`.
- Individual empty results, errors and coverage are preserved even when large
  successes are truncated.

## Conditions

`Accepted`, `Complete` and `Failed` are always written together, each with
`observedGeneration` and the same `reason` and `message`. Messages are at most 1024
characters. Before the gateway first writes status there are no
conditions.

| Outcome                                                                          | Accepted                                   | Complete | Failed                               | Reason             |
| -------------------------------------------------------------------------------- | ------------------------------------------ | -------- | ------------------------------------ | ------------------ |
| Start marker written; executing on the snapshot                                  | True                                       | False    | False                                | `Running`          |
| Every expected node answered, including empty answers; none truncated or omitted | True                                       | True     | False                                | `Succeeded`        |
| At least one node answered, and one or more failed, was omitted or was truncated | True                                       | True     | False                                | `PartialResults`   |
| No node answered, the request had not expired and no node timed out              | True                                       | True     | True                                 | `ExecutionFailed`  |
| The snapshot has no selectable node                                              | True                                       | True     | True                                 | `NoNodesAvailable` |
| The request expired, or a node timed out, with at least one node failed          | True                                       | True     | True if no node answered, else False | `DeadlineExceeded` |
| The request expired before this cell executed it                                 | True if it had already started, else False | True     | True                                 | `DeadlineExceeded` |
| The spec failed the gateway's revalidation                                       | False                                      | True     | True                                 | `Rejected`         |

`Pending` is part of the shared reason vocabulary (the public API uses it for
"resolving placement, destination or execution capacity") but the gateway never
writes it: an object the gateway has not yet reached has no conditions.

The terminal reason is chosen in this order, so a timeout takes precedence:

1. **`DeadlineExceeded`**, if the request had expired when the result was persisted
   or any node's error was `Timeout`, and at least one node failed. Even when some
   nodes answered, a node that timed out yields `DeadlineExceeded` (with
   `Failed=False`), not `PartialResults`.
2. **`ExecutionFailed`**, if no node produced an answer.
3. **`PartialResults`**, if some node failed, was really omitted (a duplicate pod
   does not count), or any observation was truncated.
4. **`Succeeded`** otherwise.

`NoNodesAvailable` and `Rejected` write status without executing. For
`NoNodesAvailable`, `status.nodes` and `coverage` still list the discovered nodes
and why each was omitted. A `Rejected` message has the form
`<code>: <detail>`, for example `InvalidQuery: InvalidTarget: ...`.

Once `Complete` is True the gateway never touches the object again, so late status
cannot reopen it. A failed peer, a down BGP session, ping loss and a silent
traceroute hop never set `Failed`: failure means the requested operation could not
run or produce its bounded typed answer.

## Error codes

Codes appear in `observations[].errorCode` and `installation.errorCode`, in
`Rejected` messages, and over gRPC as a `google.rpc.ErrorInfo` reason in the domain
`fabric-api.datumapis.com`. Over gRPC every failure is a status; success is an
`Observation`.

| Code                     | gRPC status           | Meaning                                                                                                                                                                    |
| ------------------------ | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `FRRUnavailable`         | `Unavailable`         | The daemon's vty socket could not be reached                                                                                                                               |
| `FRRVersionUnsupported`  | `FailedPrecondition`  | The running FRR is not a release the parsers have fixtures for (only 10.7)                                                                                                 |
| `CommandFailed`          | `FailedPrecondition`  | FRR rejected or failed the command, including a regular expression FRR cannot compile                                                                                      |
| `ResponseTooLarge`       | `ResourceExhausted`   | FRR's response exceeded 4 MiB, or the result did not fit the budget even when shaped                                                                                       |
| `MalformedResponse`      | `Internal`            | FRR's response was incomplete or not the expected JSON                                                                                                                     |
| `Timeout`                | `DeadlineExceeded`    | The deadline passed: waiting for a slot, reading FRR, or a node not answering in time                                                                                      |
| `ProbeSourceUnavailable` | `FailedPrecondition`  | No probe source for the family, or the source address could not be bound                                                                                                   |
| `ProbeFailed`            | `Internal`            | The probe socket failed while probing                                                                                                                                      |
| `DestinationNotAllowed`  | `InvalidArgument`     | The probe destination is refused by the caller's destination policy                                                                                                        |
| `InvalidQuery`           | `InvalidArgument`     | Any other validation failure; the specific validation code is in `ErrorInfo` metadata (`queryCode`) and at the start of the message                                        |
| `QueryTypeUnavailable`   | `FailedPrecondition`  | The type is not enabled on the node (expensive types by default), the search index is not synced with bgpd, or (`--search-source=frr`) the expensive-query breaker is open |
| `NodeBusy`               | `ResourceExhausted`   | The node's expensive-search or probe budget is full, a node execution slot did not free in time, or the cell queue is full                                                 |
| `DuplicateConflict`      | `AlreadyExists`       | A request ID was reused with different arguments                                                                                                                           |
| `Expired`                | `DeadlineExceeded`    | The request's absolute expiration has passed                                                                                                                               |
| `WrongNode`              | `FailedPrecondition`  | The request named another node                                                                                                                                             |
| `Unauthorized`           | `PermissionDenied`    | The caller's identity may not make this call                                                                                                                               |
| `NodeUnreachable`        | `Unknown` (by reason) | The gateway could not reach the node, or no leader is elected for a forwarded debug call                                                                                   |
| `Internal`               | `Internal`            | An unexpected failure                                                                                                                                                      |

Omitted nodes carry no error code: they are reported through
`status.nodes[].omittedReason` and `coverage`. A gRPC error
with no `ErrorInfo` is mapped as `Unavailable` to `NodeUnreachable`,
`DeadlineExceeded` or `Canceled` to `Timeout`, `Unauthenticated` or
`PermissionDenied` to `Unauthorized`, `ResourceExhausted` to `ResponseTooLarge`,
and anything else to `Internal`.

## Expiration and retention

- `spec.expiresAt` is absolute and at most 120 seconds from public creation. The
  gateway tolerates one extra minute, and rejects a spec further out.
- Nothing executes after it. The gateway finishes an unstarted, expired query as
  `DeadlineExceeded`; the node rejects an expired request with `Expired` and clamps
  its own deadline to it; every execution's context ends at `expiresAt`.
- A node's execution is bounded by 30 seconds, set before any queueing, and by the
  request's remaining time.
- An expired or deleted query is never re-executed. A terminal query is never
  touched again.
- A finished `FabricQuery` copy is deleted by the federation when NSO deletes the
  hub object, which the plan has NSO do on public deletion or about an hour after
  completion (NSO's behaviour, not verified here). The cell janitor deletes
  any copy still present once the later of `expiresAt` and `completionTime` is more
  than 75 minutes in the past (1h retention plus 15m grace). See
  [Cleanup](configuration.md#cleanup).

## Example

A route lookup for a prefix in the `dfw` cell, as NSO would write it on the hub.
Names, addresses and ASNs are illustrative.

```yaml
apiVersion: network.datumapis.com/v1alpha1
kind: FabricQuery
metadata:
  name: 6f1c2e8a-9b3d-4a57-8e10-2c4d5a6b7c8d-dfw
  namespace: project-example
  labels:
    network.datumapis.com/fabric-request-id: 6f1c2e8a-9b3d-4a57-8e10-2c4d5a6b7c8d-dfw
    network.datumapis.com/fabric-expires-at: "1791396120"
spec:
  requestID: 6f1c2e8a-9b3d-4a57-8e10-2c4d5a6b7c8d-dfw
  source:
    uid: 6f1c2e8a-9b3d-4a57-8e10-2c4d5a6b7c8d
    cluster: project-example-control-plane
    namespace: default
    name: lookup-198-51-100-0
  query:
    type: RouteLookup
    target: 198.51.100.0/24
    addressFamily: IPv4
  site: dfw
  clusterName: dfw
  budgets:
    maxPrefixes: 20
  expiresAt: "2026-10-07T18:02:00Z"
```

After execution the status looks like this, abbreviated. Two nodes were selected;
one answered and one could not reach FRR, so the result is partial:

```yaml
status:
  requestID: 6f1c2e8a-9b3d-4a57-8e10-2c4d5a6b7c8d-dfw
  producerCluster: dfw
  observedGeneration: 1
  attempt: 1
  startTime: "2026-10-07T18:00:01Z"
  completionTime: "2026-10-07T18:00:02Z"
  nodes:
    - name: dfw-worker
      pod: fabric-router-x7k2p
      podUID: 2f6c0d9e-5b1a-4c2e-9f3b-1a2b3c4d5e6f
      hostIP: 192.0.2.10
      certificatePod: fabric-api-certs-h2v9d
      selected: true
    - name: dfw-worker2
      pod: fabric-router-m4q8z
      podUID: 8a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d
      hostIP: 192.0.2.11
      certificatePod: fabric-api-certs-t6w3n
      selected: true
  observations:
    - node: dfw-worker
      sampleTime: "2026-10-07T18:00:01Z"
      durationMilliseconds: 14
      routerID: 192.0.2.10
      asn: 64512
      frrVersion: 10.7.1_git
      matched: 1
      matchedIsExact: true
      routes:
        lookupKind: Exact
        prefixes:
          - prefix: 198.51.100.0/24
            totalPaths: 1
            paths:
              - best: true
                valid: true
                asPath: "64496 64497"
                origin: IGP
                originASN: 64497
                nextHops:
                  - address: 192.0.2.1
                    accessible: true
                    used: true
            installation:
              sampleTime: "2026-10-07T18:00:01Z"
              present: true
              routes:
                - protocol: bgp
                  selected: true
                  installed: true
                  distance: 20
                  nextHops:
                    - address: 192.0.2.1
                      interface: eth0
                      active: true
                      fib: true
    - node: dfw-worker2
      errorCode: FRRUnavailable
      errorMessage: "FRRUnavailable: dial bgpd: connect: no such file or directory"
  coverage:
    expected: 2
    successful: 1
    failed: 1
    omitted: 0
  conditions:
    - type: Accepted
      status: "True"
      reason: PartialResults
      message: "1 of 2 expected nodes answered; truncated=false"
    - type: Complete
      status: "True"
      reason: PartialResults
      message: "1 of 2 expected nodes answered; truncated=false"
    - type: Failed
      status: "False"
      reason: PartialResults
      message: "1 of 2 expected nodes answered; truncated=false"
```

To wait for a result from a lab or a cell you can reach:

```sh
kubectl -n project-example wait --for=condition=Complete --timeout=90s \
  fabricquery/6f1c2e8a-9b3d-4a57-8e10-2c4d5a6b7c8d-dfw
kubectl -n project-example get fq   # TYPE, TARGET, SITE, COMPLETE, REASON, AGE
```

Writing a `FabricQuery` by hand is for the lab and for diagnosing a cell, as
`task verify:fabric-api` does: set `site` and `clusterName` to the gateway's own
values, a short `expiresAt`, and a canonical query. An object for another cluster is
left untouched.
