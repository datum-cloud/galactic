# Shared network load balancer addresses and UDP ranges

This implements the Galactic side of network-services-operator issue #749. A shared IPv6 VIP can serve independent TCP or UDP listeners; UDP intervals preserve the destination port on the backend and the public source port on replies. Existing singleton services retain their scalar port and backend-port mapping. HTTP and ALB interval support is intentionally outside this implementation.

## Address authority and activation

`NetworkServiceAddress` holds the complete desired listener inventory independently of any serving route. Its allocation UID, VPC and VIP are immutable. Source generations cannot regress, and equal source generations cannot carry different inventories. Each grouped `NetworkService` identifies its listener and copies that inventory; missing, conflicted or stale inventories cannot serve. IPv6 lookup keys are canonicalized.

Every gateway installs an owned-VIP guard before programming listeners. Unknown TCP/UDP sockets and unsupported IPv6 extension/fragment parsing paths on owned VIPs drop; ICMPv6 remains available for neighbor discovery and PMTU/control traffic. Owned VIPs are blocked before a reconciliation and unblocked only after successful programming and orphan cleanup. A failed map update therefore cannot leave a stale match serving while BGP withdrawal propagates. Successful convergence renews a 30-second monotonic forwarding lease, with renewal every five seconds. A stopped or stalled gateway stops forwarding owned VIPs after at most that lease; independent router-side advertisement expiry withdraws its route on the next router pass (up to five additional seconds). Router capability freshness is required before serving. This bounds stale serving but does not provide instantaneous cross-node cutover. A reconciliation may cause a brief fail-closed packet gap; no cross-map atomic activation or zero-loss update is claimed.

One advertisement per address and gateway exists while any listener can serve and address programming is complete. Each listener still reports its own readiness. A newly created shared advertisement waits for legacy per-rule advertisements for the same VIP to disappear, including their routing finalizers. An unhealthy listener contributes a drop interval without withdrawing healthy siblings.

## Compact forwarding and return translation

A bounded classifier contains up to 16 intervals per VIP and protocol, including singleton descriptors. A range references one shared backend/Maglev row in a separate range backend map. It does not allocate a row per port. The interval records the expected backend-row generation, preventing an in-flight old classifier from using a replacement row with the same start port. Range rows are separate from legacy exact rows so old eBPF cannot accidentally interpret the first port as a singleton after downgrade.

Backend translation uses at most 16 ranges per translation lookup key. Both directions preserve the UDP port. Return ownership compares interval intersections within the backend address, protocol and VPC; a scalar port inside another owner's range conflicts. Disjoint intervals and TCP/UDP on the same numeric port remain independent. Bounds, descriptor counts and exposed-port quotas are checked before publication. The provisional production cap is 1,024 exposed ports per range and 4,096 per tenant in Galactic, in addition to NSO's configured exposed-port budget. These are conservative rollout limits, not throughput qualifications.

## Cleanup and restart

A grouped service cannot disappear until every current and historical gateway has a current-generation non-serving acknowledgment and generated backend bindings have disappeared. Before a service resumes serving at the same generation, the gateway persists an Unknown acknowledgment so an old False cannot authorize concurrent deletion. Address finalization also waits for all address advertisements and services to disappear. Unconfirmed cleanup remains Unknown and retains allocation protection.

Range binding cleanup contexts are persisted in `galactic.datum.net/range-contexts` before map writes. They survive process restart and VRF removal and limit deletion to the VRF contexts actually used by that binding. Range binding specs are immutable; changes create replacement bindings. The range sweeper rebuilds its live set from API objects after restart and removes orphan entries. Gateway map generation checks and retained pending rule/quota ownership cover partially failed publication and cleanup.

## Capability and release order

The initial feature is IPv6 only. NSO's sharing and UDP-range admission gates default off. It requires current capability reports from every gateway in a selected cell before grouped services are emitted. Range forwarding additionally requires a matching current-generation backend binding, including the exact range; a Bound condition from an old router or a schema-pruned range cannot open the gate.

Publish Galactic's API/controller/datapath commit first, then update NSO's Galactic dependency to that reachable commit. Install Galactic CRDs/RBAC, upgraded backend routers and gateways before enabling NSO admission. Do not enable gates until the full veth and tap workload paths and failure scenarios have been qualified in a disposable topology. The checked-in NSO dependency cannot resolve unpublished Galactic APIs; local paired validation uses an external workspace without committing machine-specific replaces:

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

The NSO half is validated against this checkout through an external workspace/modfile. Its normal dependency still needs a reachable Galactic commit before a standalone NSO build or release. No cluster deployment or production traffic change was performed.
