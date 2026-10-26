# fabric-api architecture

`fabric-api` executes bounded diagnostics against each fabric router's own view. It reads FRR through vty sockets, searches a BMP-fed index, and sends ICMP probes from the node's fabric address. It does not configure routing.

Use [deployment](deployment.md) to install it, [configuration](configuration.md) to look up flags and limits, [security](security.md) for identities and probe policy, and [the FabricQuery contract](api.md) for requests and results. The [Looking Glass service design](../designs/looking-glass-service.md) specifies future behavior beyond these operator and FabricQuery interfaces.

## Components and ownership

| Component             | Responsibility                                                                          | Location                                   |
| --------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------ |
| `fabric-api node`     | Reads FRR, maintains the search index, executes bounded probes                          | Sidecar in each opted-in fabric-router pod |
| `fabric-api gateway`  | Discovers nodes, schedules requests, writes FabricQuery status, serves operator queries | Leader-elected Deployment per cell         |
| `fabric-api certsync` | Copies validated credentials from the CSI volume to node-local tmpfs                    | Separate fabric-api-certs DaemonSet        |
| `fabric-api janitor`  | Deletes expired or retained FabricQuery copies with deletion preconditions              | CronJob per cell                           |
| `fabric-api query`    | Operator client for node and gateway RPCs                                               | Operator environment                       |

All use one image. The node sidecar shares FRR's pod-scoped `/run/frr` socket directory. The gateway has no FRR dependency. The image contains neither FRR, `vtysh`, a shell nor an eBPF program.

Galactic owns the internal FabricQuery types in `internal/fabric/api/v1alpha1`, the protobuf services and execution code. The public LookingGlassQuery API, placement, federation and customer authorization belong to the consuming services. Infra installs the production CRDs and per-cell issuer. The generated CRD under `config/fabric-api/crd` is used by the lab and schema tests. This ownership boundary does not promise a future repository move.

## Query execution

1. The gateway validates a FabricQuery's cell, immutable request, expiration, query type and budgets.
2. It discovers fabric-router pods and their node certificate pods, then writes a start marker containing the attempt and a fixed node snapshot.
3. Its executor schedules node RPCs fairly across principals (a service project, a FabricQuery source or an operator), within bounded queues and concurrency. Queue time counts against the node deadline. With `--aggregate-budgets`, the leader also charges every request and probe to cell, principal and destination budgets and hands each probe a permit bound to its election epoch; see [aggregate probe budgets](configuration.md#aggregate-probe-budgets).
4. Each node authenticates the caller, revalidates the request, applies destination policy and budgets, executes the operation, and shapes its result.
5. The gateway writes one bounded terminal status. Conflicting status writes retry without repeating the node RPCs. A completed query is never reopened.

The operator debug service reuses the executor without creating a FabricQuery. A follower forwards once to the leader. An operator querying through the gateway receives the public destination policy because the node sees the gateway identity; direct operator-to-node requests may use the configured operator exceptions.

### Discovery and recovery

Discovery records unusable pods and omission reasons instead of silently dropping them. During a rollout it selects one usable fabric-router pod per node and records duplicates. Pod readiness is not a selection requirement because FRR drives that condition. A node without a running certificate pod is omitted even if the sidecar still holds an unexpired certificate.

A nonterminal query with a matching observed generation and an existing snapshot resumes that snapshot with a new attempt after leader failover. It does not discover a different population midway through the request. Status arrays and observations remain bounded; coverage counts nodes that do not fit in the stored list.

The gateway writes a small start marker and one terminal result, not incremental result payloads. Cancellation stops local work but cannot prove that an FRR command already submitted stopped computing. Node duplicate suppression is an in-memory cache; restart or eviction can permit repeated execution. Exactly-once execution is not guaranteed.

## FRR reads and probes

Route lookups sample bgpd and zebra separately. A BGP best path and a kernel installation are distinct observations, neither of which proves end-to-end reachability. BGP summaries read one router's peer table. Ping and traceroute use raw ICMP sockets from the node's chosen fabric address.

FRR commands are built from closed, typed templates. There is no arbitrary-command RPC. A read-only socket mount does not make FRR's command protocol read-only; the command builder enforces that application boundary, and the sidecar remains trusted control-plane code.

The vty client frames a command with NUL and reads the terminating status. A warning containing complete JSON can be data, such as zebra's empty result for an absent route. A warning with non-JSON output is a command failure. Each command uses its own connection, requires complete valid JSON, and closes the connection when its byte cap is exceeded instead of persisting partial output.

Only FRR releases listed in `internal/fabric/frr` are accepted. Unsupported versions report diagnostics unavailable rather than guessing a parser. Add captured parser fixtures and support before upgrading the FRR image. Probe destinations must already be numeric and satisfy the caller's policy; hostname resolution belongs upstream.

Errors carry a typed reason in gRPC `ErrorInfo`, with a stable mapping into FabricQuery conditions and public errors. See [error codes](api.md#error-codes).

## Search index

AS-path, community and large-community searches are disabled unless explicitly enabled. Direct FRR table scans can occupy bgpd after a caller times out, so the default search source is a local index fed by bgpd's BMP Loc-RIB stream. [Dated load-test evidence](../archive/benchmarks/fabric-api-2026-10-07.md) supports that choice; [the test procedure](load-test.md) describes qualification for a candidate release.

The index holds each prefix's selected path. A search therefore need not match FRR's search over every path. Attributes are interned and reference-counted so matching work can be shared across prefixes. Results are ordered by prefix and include the total match count and snapshot metadata.

Each BMP session begins empty. An explicit End-of-RIB can complete synchronization; the supported FRR Loc-RIB stream also uses the documented rate-based initial-dump heuristic because it does not send that marker. Disconnect makes the index unsynced. Unsynced searches fail with `QueryTypeUnavailable`; they never fall back to an FRR scan. Overflow is counted and affects completeness rather than silently representing dropped updates as complete.

The station accepts one loopback connection. Loopback is the trust boundary: a local process could connect before bgpd and feed data, preventing bgpd's own session while it remains connected. This interface does not authenticate an untrusted local peer.

## Identity and routing isolation

Each connection uses a per-cell trust bundle and exactly one allowed URI SAN. The gateway discovers the certificate-pod identities allowed for a node, including a certificate pod being replaced during rotation. It checks the cell as well as the certificate chain. A service identity is restricted to the separately authorized Looking Glass service surface and cannot use operator or node methods.

Credentials reload atomically after validating identity, lifetime, key pair and trust. A bad renewal preserves the previous credentials until expiration; with no valid credentials, handshakes fail closed while the process keeps retrying. See [identities and certificates](security.md#identities-and-certificates) for the exact identity forms and rotation procedure.

The certificate CSI volume belongs to a separate pod because certificate issuance blocks pod startup. Placing it in fabric-router would let an issuer outage prevent FRR from starting. Certsync copies credentials to the node's tmpfs and the sidecar mounts them read-only. A broken issuer therefore stalls certificate acquisition, not FRR startup.

The sidecar has no readiness, startup or liveness probe that gates FRR. It exposes diagnostic availability through RPCs and metrics. A sidecar process crash can still affect aggregate pod readiness and rollout progress. An image change recreates the entire fabric-router pod, so sidecar releases must follow the [routing rollout procedure](operations.md#rollout).

The node runs with the socket group and only the raw-socket capability it needs. The gateway and janitor have separate identities: the gateway can update query status but cannot delete queries; the janitor can delete them but cannot execute diagnostics or write their status. The janitor uses UID/resource-version preconditions to avoid deleting a replacement object.

## Source and validation map

| Area                                           | Source                                                                                                | Validation                                                                |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Requests, canonicalization, destination policy | `internal/fabric/query`                                                                               | Unit tests for limits, families and policy                                |
| FRR protocol and parsing                       | `internal/fabric/frr`                                                                                 | Captured version-specific fixtures and framing/error tests                |
| ICMP execution                                 | `internal/fabric/probe`                                                                               | Fake sockets; opt-in real raw-socket tests                                |
| Trust, rotation, certificate copying           | `internal/fabric/identity`                                                                            | mTLS, bad renewal and overlapping CA tests                                |
| Node budgets and execution                     | `internal/fabric/node`                                                                                | RPC, shaping, deadline and duplicate-cache tests                          |
| Probe permits on the node                      | `internal/fabric/node` (`permit.go`)                                                                  | Single-use and refusal tests                                              |
| Discovery, scheduling, status and cleanup      | `internal/fabric/gateway`                                                                             | Reconcile, failover, fairness, bounded-result and service streaming tests |
| Aggregate admission, permits, delivery bounds  | `internal/fabric/gateway/limit`, `internal/fabric/gateway` (`admission.go`, `permit.go`, `stream.go`) | Bucket, attempt-key, Lease authority, admission and stream-bound tests    |
| BMP station and indexed searches               | `internal/fabric/index`                                                                               | Stream, synchronization and search tests; full-table load harness         |
| Schema                                         | `internal/fabric/api/v1alpha1`                                                                        | Envtest admission tests, requiring KUBEBUILDER_ASSETS                     |

The lab's `verify:fabric-api` task exercises node and gateway queries and FabricQuery completion. `verify:fabric-api-bootstrap` deliberately breaks certificate issuance to test the routing-isolation boundary. These require the lab; a unit-test run alone does not establish those outcomes. [Operational verification](operations.md#verifying) lists the commands and expected observations.
