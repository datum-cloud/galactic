# Shared network load balancer addresses and UDP ranges

This implements the Galactic side of network-services-operator issue #749. A shared IPv6 VIP can serve independent TCP or UDP listeners; UDP intervals preserve the destination port on the backend and the public source port on replies. Existing singleton services retain their scalar port and backend-port mapping. HTTP and ALB interval support is intentionally outside this implementation.

## Address authority and activation

`NetworkServiceAddress` holds the complete desired listener inventory independently of any serving route. Its allocation UID, VPC and VIP are immutable. Source generations cannot regress, and equal source generations cannot carry different inventories. Each grouped `NetworkService` identifies its listener and copies that inventory; missing, conflicted or stale inventories cannot serve. IPv6 lookup keys are canonicalized.

Every gateway installs an owned-VIP guard before programming listeners. Unknown TCP/UDP sockets and unsupported IPv6 extension/fragment parsing paths on owned VIPs drop; ICMPv6 remains available for neighbor discovery and PMTU/control traffic. Owned VIPs are blocked before a reconciliation and unblocked only after successful programming and orphan cleanup. A failed map update therefore cannot leave a stale match serving while BGP withdrawal propagates. Successful convergence renews a 30-second monotonic forwarding lease, with renewal every five seconds. A stopped or stalled gateway stops forwarding owned VIPs after at most that lease. The BGP runtime retains advertisement deadlines and checks expiry independently every second, so unrelated API reads, configuration validation errors, and controller retries do not suspend withdrawal. It preserves any route still claimed by an unexpired or unleased owner. Router capability freshness is required before serving. This bounds stale serving but does not provide instantaneous cross-node cutover. A reconciliation may cause a brief fail-closed packet gap; no cross-map atomic activation or zero-loss update is claimed.

One advertisement per address and gateway exists while any listener can serve and address programming is complete. Each listener still reports its own readiness. A newly created shared advertisement waits for legacy per-rule advertisements for the same VIP to disappear, including their routing finalizers. An unhealthy listener contributes a drop interval without withdrawing healthy siblings.

## Compact forwarding and return translation

A bounded classifier contains up to 16 intervals per VIP and protocol, including singleton descriptors. A range references one shared backend/Maglev row in a separate range backend map. It does not allocate a row per port. The interval records the expected backend-row generation, preventing an in-flight old classifier from using a replacement row with the same start port. Range rows are separate from legacy exact rows so old eBPF cannot accidentally interpret the first port as a singleton after downgrade.

Backend translation uses at most 16 ranges per translation lookup key. Both directions preserve the UDP port. Return ownership compares interval intersections within the backend address, protocol and VPC; a scalar port inside another owner's range conflicts. Disjoint intervals and TCP/UDP on the same numeric port remain independent. Bounds, descriptor counts and exposed-port quotas are checked before publication. The provisional production cap is 1,024 exposed ports per range and 4,096 per tenant in Galactic, in addition to NSO's configured exposed-port budget. These are conservative rollout limits, not throughput qualifications.

## Cleanup and restart

A grouped service cannot disappear until every current and historical gateway has a current-generation non-serving acknowledgment and generated backend bindings have disappeared. Before a service resumes serving at the same generation, the gateway persists an Unknown acknowledgment so an old False cannot authorize concurrent deletion. Address finalization also waits for all address advertisements and services to disappear. A clean gateway-stop receipt requires successful engine shutdown and a sweep of persisted orphan datapath entries, including after process restart. Unconfirmed cleanup remains Unknown and retains allocation protection.

NSO creates a durable hub authority for each coordinated allocation before publishing serving intents. Every cell registers its stable identity with that authority using an optimistic write before local programming. Retirement freezes the participant set, and NSO waits for a direct cleanup receipt from every registered cell at the terminal authority generation. Missing or removed cells remain required; federation's aggregate readiness is not release authority. Cells read the live hub authority, so a stale initial replica cannot authorize a new cell after retirement.

Each registered cell marks the allocation's address anchor permanently retired and waits for confirmed cleanup before acknowledging retirement. The retired anchor remains as a tombstone: an old publisher may finish an API request after leadership changes, but its intent cannot reopen that allocation. Generated backend bindings and coordinated BGP advertisements also verify their source allocation before programming, so delayed resource creation cannot bypass retirement. Retirement records are retained; they are not ordinary garbage-collection candidates. Reusing the IP requires a new allocation UID, and an acknowledged tombstone does not reserve the IP against that new owner. Cells need hub read/patch access to allocation authorities and their status subresource before these features are enabled.

The supported deployment runs one gateway process and one router process per node. Their DaemonSets explicitly use `maxSurge: 0`, stopping the old node writer before replacement. Per-node cleanup acknowledgments rely on this serialization; overlapping duplicate node daemons or force-deleting a pod while its process remains alive are not a supported handoff mechanism. The cross-process NSO publisher handoff is protected separately by durable retirement records.

Range binding cleanup contexts are persisted in `galactic.datum.net/range-contexts` before map writes. They survive process restart and VRF removal and limit deletion to the VRF contexts actually used by that binding. Range binding specs are immutable; changes create replacement bindings. The range sweeper rebuilds its live set from API objects after restart and removes orphan entries. Gateway map generation checks and retained pending rule/quota ownership cover partially failed publication and cleanup.

The production pinned-map wrapper delegates range operations and discovers a range map created after router startup. Discovery retains the existing singleton handle and registration ledger, and is serialized with map writes and handle closure.

## Capability and release order

The initial feature is IPv6 only. NSO's sharing and UDP-range admission gates default off. It requires current capability reports from every gateway in a selected cell before grouped services are emitted. Range forwarding additionally requires a matching current-generation backend binding, including the exact range; a Bound condition from an old router or a schema-pruned range cannot open the gate.

NSO publishes shared services and address anchors in project namespaces. Gateways must also enable `GALACTIC_GATEWAY_PROJECT_SERVICES`, set `GALACTIC_GATEWAY_NAMESPACE` to the trusted gateway namespace, and configure `GALACTIC_GATEWAY_PROJECT_VIP_PREFIXES` with the actual load-balancer allocation pools. Project serving defaults off. Both listener services and address anchors must pass the pool and namespace-local VPC ownership checks before acquiring forwarding state or owned-VIP guards. Disabling project serving withdraws previous advertisements and preserves cleanup receipts; terminal tombstones remain observable for retirement without acquiring guards.

Publish Galactic's API/controller/datapath commit first, then update NSO's Galactic dependency to that reachable commit. Install Galactic CRDs/RBAC, upgraded backend routers and gateways before enabling NSO admission. Do not enable gates until the full veth and tap workload paths and failure scenarios have been qualified in a disposable topology. During development, unpublished Galactic APIs require paired validation in an external workspace without committing machine-specific replaces:

```sh
mkdir /tmp/nlb-paired-validation
cd /tmp/nlb-paired-validation
go work init /path/to/network-services-operator /path/to/galactic
export GOWORK=/tmp/nlb-paired-validation/go.work
cd /path/to/network-services-operator
go test ./api/... ./internal/controller/... ./internal/webhook/... ./internal/networkagent/...
cd /path/to/galactic
# Linux, with LLVM 19 (or newer compatible BPF compiler) and generated BPF objects:
BPF2GO_CC=clang-19 task build:ebpf
go test ./api/... ./cmd/... ./internal/...
```

Before downgrading either controller or schemas, disable admission and drain or migrate **both shared singleton addresses and ranges** to legacy resources. Old NSO cannot safely track independent listener withdrawal even where the addressRefs field itself is recognized. Never prune active range fields, discard address anchors or clear teardown finalizers to bypass this ordering.

## Validation scope

Regression coverage includes API-server CEL admission and immutable/monotonic address identity, canonical address ownership, duplicate-anchor withdrawal, healthy-sibling advertisement, legacy advertisement handover, stale generations, activation receipts, backend interval conflicts, partial publication rollback and restart cleanup. Linux BPF fixtures exercise first/middle/last/outside range ports, same-start shrink, generation mismatch, blocked-VIP behavior, parser bypasses, preserved ports/payload and checksums in both translation directions.

The backend ingress fixture validates rewrite through the FIB lookup and intentionally stops without a route; it does not prove delivery through a tap or veth workload. The egress fixture uses a public uplink. A Linux 6.8 aarch64 Colima lookup/drop microbenchmark measured approximately 91–98 ns for a singleton, 90–108 ns for one interval, 111–120 ns for the last of 16 intervals, and 99–104 ns for a wide one-interval classifier (five repetitions of 100,000 runs). This is a lookup/drop microbenchmark, not forwarding throughput or production capacity. Live veth/tap topology, session affinity under application traffic, mixed-version rollout and full forwarding throughput remain release qualification requirements.

### Implementation validation (2026-10-26)

- Real Kubernetes 1.36.2 envtest: `go test ./api/network/v1alpha1 -count=1` passed with `KUBEBUILDER_ASSETS` set.
- The full Galactic `./api/... ./cmd/... ./internal/...` package set was crosscompiled for Linux/arm64 and run unprivileged in an isolated Linux container. Four environment-only package failures (missing iptables, missing container Go dependency cache, and macOS metadata copied into two fixture directories) were resolved by installing real dependencies in task RAM scratch, rerunning CONNECT-IP on the host, and removing only copied metadata. Affected packages then passed. Final controller, reconciliation and gateway suites also passed after lease integration.
- `go test -race ./internal/gateway ./internal/plumbing/ebpf/edgemap ./internal/plumbing/ebpf/vipxlatmap ./internal/plumbing/ebpf/edgemetrics` passed on the host.
- `GOOS=linux go vet ./api/... ./cmd/... ./internal/...` and full Go lint passed. Both CRD and gateway kustomize bundles rendered successfully.
- All four existing BPF programs generated with LLVM 19. Privileged Linux kernel tests and the bounded microbenchmarks above ran separately from ordinary unit tests.
- The prescribed full `task ci` pipeline, Kind end-to-end deployment, and full-package Linux race run were not completed. The Docker VM filesystem was full; task-specific RAM scratch enabled unit/kernel validation without deleting unrelated user data. YAML lint also reports existing repository/generated-file formatting differences; generated CRDs retain the repository generator's format.

The paired workspace supports validation of unpublished cross-repository changes. Standalone NSO validation and releases use a dependency pinned to the published Galactic commit; local replace directives must not be committed. No cluster deployment or production traffic change was performed.

### Adversarial review fixes (2026-10-27)

Permanent regressions cover runtime lease expiry during failed reconciliation, partial route publication, lease attachment/removal without route changes, real advertisement withdrawal finalizers, delayed binding and advertisement creation, clean gateway shutdown, stale address outcomes, tenant namespaces and full-length allocation names. The controller and GoBGP runtime packages passed under the Linux race detector; terminal API and binding-source admission passed against Kubernetes 1.36.2. Pinned-map discovery and closure races passed independently, and the CRD, controller, gateway and router manifests rendered successfully. The live-topology and throughput qualifications above remain required before enablement.
