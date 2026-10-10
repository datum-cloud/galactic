# Architecture Review: egress-active-active
**Language:** go  |  **Reviewed:** 2026-10-09T20:36:23.650844+00:00

## Summary

Not ready for staging enablement signoff: fix rollback and shard-state publication defects, enforce pool compatibility, and complete privileged validation.

**6 findings:** 🔴 0 critical  🟠 3 high  🟡 3 medium  ⚪ 0 low


**Scope:** `f61103b2`, `69ebb6cc`, `c8830ea9` (`HEAD~3..HEAD`). Working tree was clean when review began. No earlier report exists in this directory. Review covers implementation, added tests, configuration, monitoring, docs and lab verification. No staging resources were changed.

**Decision:** Hold staging enablement signoff. The feature can proceed to an isolated validation environment after the high-priority fixes; this review does not certify the live staging environment or current CI run. Changes are opt-in and the deployment manifest still defaults to ordered mode. Estimated remediation is **medium**, principally because coherent BPF publication needs design and kernel validation.

### Validation evidence

| Check | Result and limit |
| --- | --- |
| `task build:ebpf` | Passed; all four datapaths regenerated, including both BPF endiannesses. Compilation does not prove kernel verifier acceptance. |
| `go build ./cmd/...` | Passed (exit 0); emitted a nonfatal warning about a read-only module stat cache. |
| `bin/golangci-lint run --timeout 5m` | Passed: `0 issues.` |
| Focused `go test -race -count=1 -v` | `egressroutemap`, `attachreg`, `metrics` passed. Root-gated cases skipped, including **all seven new TestGroupDatapath tests**. |
| Config and added installer tests | Passed. The full installer suite encountered sandbox restrictions on TCP/netlink sockets; this is not evidence of an application regression or a passing full suite. |
| Focused `go vet` | Passed for config, installer, egressroutemap, attachreg and metrics. |
| Failure-injection reproduction | Confirmed F05 in a temporary fake-map test: A starts at generation 1; replacing with B writes slot generation 2 but group publication fails; replacing with C also gets generation 2. Test removed after execution; source implementation unchanged. |
| Shell syntax; diff whitespace | `bash -n` and `git diff --check HEAD~3 HEAD` passed. |
| YAML formatter | Could not complete: `stat .git/**: not a directory` in this worktree. |
| Privileged BPF, containerlab, alert tests, full CI | Not completed. Docker socket access denied and review runs unprivileged. No promtool executable available. |
| Remote CI status | Unverified: GitHub API connection failed. |
| Live staging CRD, routing, scrape health and image availability | Unverified; no live staging evidence obtained. |

Logs from this review are in `/tmp/galactic-review-{datapath-tests,reproductions,lint,build}.log` for this workspace session.

### Staging acceptance gates

1. Fix F01 and F05 with iterator/write failure-injection tests. Resolve F06 with an explicit publication/snapshot contract and concurrency coverage. For F04, enforce compatible pool membership; a tightly controlled initial staging trial can also explicitly verify homogeneous shards, but this does not fix general admission behavior.
2. Install and verify the external `EgressShard` CRD version supporting `spec.drain` (the Go dependency now points to network commit `36ee528904ff`). A Go module bump does not update a cluster's schema. Verify a drain patch persists by reading it back. Confirm the updated CNI get/list/watch RBAC is deployed. Document these prerequisites in the rollout procedure.
3. Verify every candidate has unique advertised SID and masquerade addresses, supports the required NAT66/NAT64 families, and agrees on NAT64 prefix/well-known-prefix behavior. Test return routing through **each** shard before distributing tenants.
4. Require a green `task ci`, the separate privileged `task test:unit-root` job on the target kernel, and `task test:alerts`. Fix F02 before treating `verify:nat-active-active` as an acceptance gate.
5. Run a two-shard staging canary using `hashed`, `source`, the default `2h4m` pin idle, and pool minimum `2`. Exercise NAT66 **and NAT64**, TCP/UDP/ICMP, large packets and sustained sessions. The added lab script uses only IPv6 HTTP/NAT66; its flow phase uses pins off and its source phase uses 20 seconds, so it does not establish all default-mode behavior.
6. Check shard addition, actual BGP route withdrawal and restoration, explicit drain, CNI restart with existing pins, initial informer delay/API outage, all shards unavailable, and concurrent membership changes. A prohibit route validates local selection failure, not full BGP failure detection timing. Confirm sessions on a surviving shard continue; sessions on a failed shard are expected to break because NAT state is not replicated.
7. Verify the existing CNI PodMonitor produces `job="galactic-cni"` and correct node labels, the new rules are installed in the actual evaluator (infra centrally evaluates its own copy), and targets scrape successfully. Confirm active/minimum, per-shard traffic and drop counters. Do not interpret absent series as health.
8. Rehearse rollback: preserve the static SID list in the init-container configuration, switch to ordered on the new binary, verify no sentinel routes remain and the group is disabled, then roll back the binary. Mode changes can break sessions placed on a different shard. Delete only **after explicit drain and session quiescence**, not as the drain operation.

## Architecture

**Layers observed:** environment configuration → installer informer and netlink watch → egress shard group reconciliation → BPF map adapters → Prometheus collectors

**Dependency direction:** clean

```
EgressShard informer + netlink events -> debounced installer sweep -> shard maps + per-VRF route maps -> datapath
```

Reviewed the combined HEAD~3..HEAD change (33 files, 4,237 insertions and 161 deletions), surrounding CNI/NAT controller, resolver, loader, CI and deployment contracts. Dependency direction is coherent. See validation and staging gates below for limits of the evidence.

## Findings

### 🔴 P0 — Critical

No P0 findings.

### 🟠 P1 — High

#### [F01] Do not disable the group after a failed ordered-mode refresh
**Location:** `internal/installer/egressgroup.go:175-179`  |  **Category:** error-handling

**Problem:** g.refresh logs and discards Refresh's error, returning partial counters. Refresh decides all sentinel rewrites first and increments Ungrouped, leaving InGroup zero when every destination resolves. If iteration or any subsequent Put fails, some/all sentinel routes remain but ordered sweep still disables their group. This violates the promised rollback ordering.

**Risk:** Switching hashed to ordered during a transient map write/read failure drops all packets on the unconverted VRFs until a later successful sweep; sustained error makes the outage persistent.

**Before:**
```
result := g.refresh(table, foreignTableIDs, g.staticSIDs)
if result.InGroup == 0 { groups.Disable(egressroutemap.ClusterShardGroup) }
```
**After:**
```
result, err := g.refresh(table, foreignTableIDs, g.staticSIDs)
if err == nil && result.InGroup == 0 { groups.Disable(egressroutemap.ClusterShardGroup) }
```

#### [F04] Validate shard translation compatibility before adding it to the pool
**Location:** `internal/installer/egressgroup.go:310-326`  |  **Category:** config

**Problem:** Candidate selection accepts every Ready+Programmed SID without checking status.shardAddressIPv6, status.shardAddressIPv4, or status.nat64Prefix. The API/controller legitimately allows shards serving only one family; identityFromSpec only requires at least one masquerade address (egressshard_controller.go:394-397). Both default NAT66 and NAT64 routes now use this same pool. Adding a Ready NAT66-only shard therefore directs a fraction of NAT64 requests to a shard unable to translate them; a different NAT64 prefix has the same defect. Ordered mode could explicitly select compatible shards, but hashed mode silently broadens to every shard.

**Risk:** Partial deterministic tenant egress outage when a cluster contains valid but heterogeneous shards, including incremental rollout of an incompletely configured second shard.

**Before:**
```
if shard.Status.ShardSID == "" || !Programmed || !Ready { continue }
candidates = append(candidates, ShardCandidate{SID: sid, Draining: ...})
```
**After:**
```
Validate each candidate against the compute node's required NAT66/NAT64 families and NAT64 prefix; reject incompatible pool configuration with a surfaced error, or maintain eligible groups per translation route.
```

#### [F05] Reserve slot generations across failed group publication
**Location:** `internal/plumbing/ebpf/egressroutemap/shardgroup.go:291,356-361`  |  **Category:** concurrency

**Problem:** A new slot receives current group generation + 1, but slots are written before the group generation is committed. If the group Put fails, the changed slot is already visible to packets through the old Maglev table. Another candidate replacement before the next successful group publication receives the same generation. Pins created for the first replacement are then accepted for the second. The documented never-reused identity guarantee is false on partial failure.

**Risk:** A pin can silently follow an unrelated shard after partial reconciliation; draining replacements can inherit live pins and existing sessions can move unexpectedly.

**Before:**
```
nextGeneration := current.Generation + 1
value.Generation = nextGeneration
// write slots, then group; return on failure
```
**After:**
```
Allocate identities from durable monotonic state that includes partially published slots, and preserve uniqueness through retries and slot clearing. Add failure-injection tests across every write boundary.
```

### 🟡 P2 — Medium

#### [F02] Require successful new-tenant egress in the drain check
**Location:** `deploy/containerlab/scripts/verify-nat-active-active.sh:224-231`  |  **Category:** testing

**Problem:** The drain test only rejects observed packets on the drained shard. sources suppresses curl/tcpdump errors, and an empty capture produces seen=[]; the loop executes zero times and announces success. A regression blackholing all unpinned tenants during drain therefore passes this stage, while the existing A connection alone is checked for success.

**Risk:** The advertised end-to-end staging gate can certify broken drain behavior.

**Before:**
```
mapfile -t seen < <(sources "${t}" 3)
for addr in "${seen[@]}"; do ...; done
echo "ok ..."
```
**After:**
```
Require successful requests and exactly one captured source, matching the surviving shard's expected masquerade address, before reporting success.
```

#### [F03] Remove the claim that deleting a shard gracefully drains it
**Location:** `docs/nat/configuration.md:517-518`  |  **Category:** config

**Problem:** The new operator guide says deleting EgressShard drains it like spec.drain. EgressShardReconciler has no finalizer, withdraws advertisement on deletion (internal/controller/egressshard_controller.go:167-185), and excludes terminating shards from syncNode at line 220. Translation is cleared immediately rather than retained until sessions drain. Merely marking a terminating object as a draining candidate cannot change this lifecycle.

**Risk:** An operator using deletion as documented interrupts every session on that shard.

**Before:**
```
Deleting an EgressShard drains it the same way for as long as it takes to go.
```
**After:**
```
Set spec.drain=true, wait for sessions to reach zero, then delete. Deleting without this sequence immediately tears down the shard and its sessions.
```

#### [F06] Read a coherent shard snapshot during concurrent map updates
**Location:** `internal/plumbing/ebpf/prog/usid.c:1212-1228,3673-3680,3712-3736`  |  **Category:** concurrency

**Problem:** The group and shard maps are ordinary BPF ARRAY maps. Userspace updates modify the existing value in place, while the packet program retains pointers and reads flags/generation separately from SID, ifindex and MACs. A slot or next-hop update can interleave after validation but before route copying, so a packet can validate one identity and encapsulate with a different or mixed record. Ordered writes between maps do not make an individual array record atomic.

**Risk:** Transient packet loss or incorrect encapsulation during membership and next-hop changes. Existing sequential BPF_PROG_RUN tests cannot establish concurrency safety. This is source-supported, not reproduced on a kernel in this review.

**Before:**
```
shard = bpf_map_lookup_elem(...); // validate flags/generation
...
memcpy(route.sid, shard->sid, ...); route.link_ifindex = shard->link_ifindex;
```
**After:**
```
Publish immutable/versioned records or use a supported synchronization scheme that copies and validates one consistent snapshot; stress updates concurrently with real packet processing.
```

### ⚪ P3 — Low

No P3 findings.

## What's Working Well

- Configuration validates mode, hash, pin timeout, and minimum at startup rather than silently falling back.
- Unsynced informer state is distinguished from an empty candidate set.
- Informer and netlink events feed a bounded debounced sweep; periodic ticker backs up event delivery.
- Egress route sweeps preserve sidecar-owned namespace state.
- Docs explicitly require switching to ordered before rolling back to a binary predating group sentinels.
- New read-only EgressShard RBAC is scoped by resource and informer namespace.
- Metrics expose active/draining/unreachable state and selection outcomes; existing CNI PodMonitor is present.
- Added installer helper tests and config tests pass; verification script passes bash syntax check.
- go vet ./internal/config ./internal/installer passes.

## Refactor Plan

Each step is independently mergeable and must not break existing behavior.

### Step 1: Preserve refresh errors through rollback
*Addresses: F01*

**What:** Return the error from g.refresh and only disable groups after a complete successful conversion; add failure-injection coverage for iterator and route Put errors.

**Why now:** Rollback reliability is a staging safety prerequisite.

**Safe when:** Failed conversion leaves group enabled and old sentinel routes usable; successful retry converts routes then disables it.

### Step 2: Make shard publication and identity retry-safe
*Addresses: F05, F06*

**What:** Preserve unique slot identities through partial writes and implement coherent datapath snapshots.

**Why now:** Pin continuity depends on stable identity and consistent route reads.

**Safe when:** Fault injection cannot reuse identity, and concurrent packet/update stress shows no mixed route or invalid pin acceptance.

### Step 3: Enforce compatible translation identities
*Addresses: F04*

**What:** Validate status families and NAT64 prefix against local egress requirements before pool admission, with explicit error reporting and mixed-pool tests.

**Why now:** Ready alone does not mean the shard can serve every route moved to the common pool.

**Safe when:** A NAT66-only or differently prefixed shard cannot receive NAT64 traffic it does not support.

### Step 4: Make drain verification fail on absence of traffic
*Addresses: F02*

**What:** Check request success and require the expected surviving source address.

**Why now:** Readiness evidence must detect drops as well as wrong placement.

**Safe when:** A blackholed fresh tenant makes the script fail; a healthy surviving shard passes.

### Step 5: Correct deletion procedure
*Addresses: F03*

**What:** Document explicit drain, session wait, then delete; remove unsupported graceful-delete claim.

**Why now:** Operators need accurate lifecycle guidance before first staging rollout.

**Safe when:** Runbook matches reconciler lifecycle and no longer treats delete as graceful.

## Additional constraints and coverage observations

- Source placement is address-based, not load-aware. Roughly equal address counts do not imply equal byte rates when tenants vary in traffic volume.
- Pins are local to a compute node and bounded by a 65,536-entry LRU. Eviction after a membership change can move an active address; drain can persist indefinitely if an address keeps sending. This is not replicated NAT session state.
- Hash input includes the node-local Linux VRF table ID. `internal/plumbing/vrf/vrf.go` allocates these locally, so identical Maglev member sets alone do not guarantee the same placement for a VPC address on different compute nodes. Workload migration continuity needs separate validation; no cross-node pin transfer is implemented.
- Flow-mode fragment placement is tested for IPv4 in the selector, but existing NAT translation explicitly lacks full fragment handling. Do not advertise end-to-end fragment support based on the selector test.
- Current new installer tests cover candidate filtering, event matching and kick coalescing, not informer startup, actual sweep sequencing, partial failures or mode-transition races. Datapath tests are sequential; they do not test userspace/kernel update interleavings.
- The group-empty alert intentionally requires at least one member. A zero-candidate pool with existing sentinels instead relies on below-minimum or traffic-driven drop alerts. An informer that never initializes can leave enabled=0, suppressing the pool alerts; verify desired mode and startup logs separately.

For F06, the kernel documents that array lookup returns a pointer into shared array storage and requires synchronization for concurrent access: [Linux BPF array-map documentation](https://docs.kernel.org/bpf/map_array.html). `array_map_update_elem` copies into the existing element unless locking is explicitly requested: [Linux array-map implementation](https://github.com/torvalds/linux/blob/master/kernel/bpf/arraymap.c). These establish the map semantics; the packet-level interleaving is an inference from this change's reads and writes, not an observed live incident.
