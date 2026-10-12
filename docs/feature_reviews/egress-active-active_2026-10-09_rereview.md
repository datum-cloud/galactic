# Architecture Review: egress-active-active
**Language:** go  |  **Reviewed:** 2026-10-09T21:36:38.278824+00:00

## Summary

Not ready for staging enablement: snapshot publication is substantially improved, but rollback and translation-class routing still have correctness defects.

**6 findings:** 🔴 0 critical  🟠 4 high  🟡 2 medium  ⚪ 0 low


**Scope:** Current uncommitted changes relative to `c8830ea9`, including new untracked implementation files. HEAD has not advanced since the original review. Reviewed against the original report and the implementation prompt. The original report is preserved unchanged.

**Decision:** Hold staging enablement. The snapshot redesign addresses the original mutable-array and partial-publication problems, but four high-priority routing/transition findings remain. Estimated remediation is medium. No implementation files were changed by this review and no infrastructure was modified.

### Original findings disposition

| Original finding | Assessment |
| --- | --- |
| F01 — unsafe rollback after refresh errors | Error propagation fixed. Concurrent CNI registration is still unsafe (R01). |
| F02 — drain test accepts no traffic | Original vacuous pass fixed. Fresh-address allocation and the real-BGP failure scenario need correction (R04, R06). |
| F03 — deletion described as graceful drain | Fixed in the updated guide and deletion candidate filtering. |
| F04 — incompatible pool members | Per-class capability filtering added, but route selection can bypass it (R02, R03), and class reconfiguration can redirect to a different class (R05). |
| F05 — generation reuse after partial writes | Structurally addressed by atomic snapshot publication and persisted slot generation state. |
| F06 — torn shard records during updates | Structurally addressed by immutable map-in-map publication. Concurrent kernel test added; execution remains unverified here. |

### Validation and reproductions

- `task build:ebpf`: passed, all four datapaths regenerated.
- `go build ./cmd/...`: passed (exit 0), with a nonfatal read-only module stat-cache warning.
- Repository-wide `golangci-lint run --timeout 5m`: passed, **0 issues**.
- `go test -race -count=1 -v` for egressroutemap, attachreg and metrics: passed for runnable cases. Privileged packet/publication tests skipped, including the new concurrent-swap and publication-failure tests.
- Focused installer group/shard/egress/class tests: passed.
- Focused `go vet` for installer, egressroutemap, attachreg, metrics and attach: passed.
- `bash -n` for the acceptance script and `git diff --check`: passed.
- Three temporary Go overlay reproductions confirmed R01, R02 and R05 without modifying source files. These tests assert the defective behavior to establish the finding; their passing is not acceptance evidence.
- R01: inject a sentinel after the ordered sweep's scan. The group becomes disabled with one referencing route left.
- R02: a synced empty shard list converts three existing group routes back to a resolvable static shard.
- R05: remove the first NAT64 prefix from a two-prefix configuration. Its route remains on group 1, which now serves the second prefix and its different shard.
- R03 follows directly from the installed route set and longest-prefix-match lookup; existing single-family tests expect the missing specific prefix and do not exercise actual packet selection through the catch-all.
- No privileged kernel acceptance, containerlab scenario, promtool alert tests, full `task ci`, remote CI verification or live staging checks were completed in this review. A green lint/unit run does not close these gates.

Reproduction artifacts for this session: `/tmp/review-overlay.json`, `/tmp/review_regression_test.go`, `/tmp/review-class-overlay.json`, `/tmp/review_class_lifecycle_test.go`, and `/tmp/egress-rereview-class-repro.log`. Other checks are logged under `/tmp/egress-rereview-*.log`.

## Architecture

**Layers observed:** installer informer → translation-class groups → CNI registration → metrics → acceptance script

**Dependency direction:** clean

Translation-scoped groups are a sound direction; empty-class and transition semantics require correction.

## Findings

### 🔴 P0 — Critical

No P0 findings.

### 🟠 P1 — High

#### [R01] Closing groups does not exclude in-flight CNI sentinel writes
**Location:** `internal/plumbing/ebpf/attachreg/egressgroups.go:91-106`  |  **Category:** concurrency

**Problem:** A CNI ADD can read an open group and pause; ordered sweep closes it, scans/converts all visible routes and disables it; ADD then writes a sentinel referencing the disabled group. The post-write check only repairs afterward and may fail, encounter an empty static list, or never run if the process terminates. An error after a partial class install also returns before rechecking. Existing VRF routes can be affected by ADD/FillVRF, not just a not-yet-connected pod.

**Risk:** Rollback can still blackhole tenant routes while reporting no group routes and a disabled group. Original refresh error propagation is fixed but the requested concurrent-registration safety is not.

**Before:**
```
installGroupRoutesIn(...); stillOpen, err := groups.AnyOpen(); installOrderedEgress(...)
```
**After:**
```
Serialize sentinel publication and group closing/last scan with a cross-process registration barrier or equivalent protocol; retiring must wait for admitted writers. Test late publication and failed repair.
```

#### [R02] Empty hashed membership silently restores static shard routes
**Location:** `internal/installer/egressgroup.go:335-339`  |  **Category:** config

**Problem:** With no class having candidates, byClass is empty and WithShardGroups is omitted. Refresh interprets this as ordered mode and rewrites existing sentinels to the first resolvable static SID, even though the informer rejected it or removed its capabilities. Static SID resolution does not validate readiness or translation.

**Risk:** Hashed mode bypasses its admission and empty-group safeguards, sending traffic to unready, deleted-but-still-routable or incompatible shards. Group-empty metrics/alerts can also lose their route evidence.

**Before:**
```
if len(byClass) > 0 { opts = append(opts, WithShardGroups(groupFor)) }
```
**After:**
```
Always express hashed refresh semantics, including an empty class map; preserve or install explicit empty-class sentinels rather than invoking ordered fallback.
```

#### [R03] Skipping an unserved NAT64 prefix lets NAT66 default route catch it
**Location:** `internal/plumbing/ebpf/attachreg/egressgroups.go:155-158`  |  **Category:** config

**Problem:** When NAT66 has candidates but a configured NAT64 /96 has none, installGroupRoutesIn installs ::/0 and skips the /96. LPM lookup then selects the NAT66 group for packets to that configured NAT64 prefix. TestInstallVRFEgress_SingleFamilyDeployments/NAT66Only and MismatchedPrefix explicitly encode this unsafe route set.

**Risk:** NAT64 traffic is sent to shards not admitted to its translation class, defeating F04. New VRFs behave differently from existing VRFs whose empty NAT64 sentinel remains.

**Before:**
```
if !found || !status.Open() || status.Candidates == 0 { continue }
```
**After:**
```
Install an explicit rejecting/empty-group route for each configured but unserved NAT64 prefix, or fail attachment when the class is required. Exercise actual LPM selection against ::/0.
```

#### [R05] Do not reuse a translation-class group while old routes reference it
**Location:** `internal/installer/egressgroup.go:355-358; internal/plumbing/ebpf/egressroutemap/egressroute.go:767-771`  |  **Category:** config

**Problem:** Group IDs are the positions in the current configured prefix list. With [NAT66, P1, P2] published, removing P1 changes the list to [NAT66, P2] and overwrites group 1 with P2 before repairing existing routes. A route for P1 still names group 1. Refresh finds no configured class for P1 and deliberately leaves its sentinel untouched, so it now sends P1 traffic to P2-only shards. Old group 2 is never retired and remains a duplicate P2 group; FindClass and the sweep can pick different duplicates.

**Risk:** Configuration changes cause persistent cross-class routing and NAT64 outages. Removed classes also remain published and can retain stale members indefinitely.

**Before:**
```
for i, class := range g.classes { groups.Apply(uint32(i), ..., eligible) }
```
**After:**
```
Allocate stable class identities and reconcile retired classes explicitly. Do not reuse a group ID until every reference has been safely migrated or replaced with a fail-closed route. Test removal, reorder, replacement, and restart with old snapshots.
```

### 🟡 P2 — Medium

#### [R04] Fresh-address counter is lost in command substitutions
**Location:** `deploy/containerlab/scripts/verify-nat-active-active.sh:157-165`  |  **Category:** testing

**Problem:** Every fresh call is through $(fresh), which runs in a subshell. FRESH_N increments never persist in the parent, so every address has counter=1 and only one random byte distinguishes calls. About 17 calls in the full script give roughly 42% collision probability. Reused addresses still carry default-duration pins, and ip addr add failures can be hidden because the function continues to echo an address.

**Risk:** The acceptance gate intermittently fails for address collisions or tests already-pinned addresses as fresh tenants during drain/failure; it cannot reliably certify fresh selection.

**Before:**
```
a=$(fresh) # fresh increments FRESH_N locally and uses random.randrange(256)
```
**After:**
```
Allocate monotonically unique addresses in the parent shell or persistent state file; propagate addr-add errors and verify no address reuse. Avoid command substitution for the state mutation.
```

#### [R06] Withdraw every route source before measuring shard-unreachable convergence
**Location:** `deploy/containerlab/scripts/verify-nat-active-active.sh:337-340,515-516`  |  **Category:** testing

**Problem:** The real-BGP scenario removes only the fabric-router network statement for the shard /64. EgressShardReconciler independently advertises that same /64 as plain reachability through galactic-router EVPN (egressshard_controller.go:466-507,529 onward), and processEVPNPath installs it through the plain-route reconciler (runtime/gobgp/monitor.go:184-188). The node loopback remains reachable. The compute resolver can therefore keep finding the EVPN route and a healthy uplink neighbor; withdrawing the FRR origin alone does not establish shard unreachability.

**Risk:** The acceptance scenario can time out waiting for unreachable=1 on a correctly configured lab; it cannot be treated as proof of end-to-end failure detection.

**Before:**
```
originate "${SHARD_B}" no; wait_metric ... unreachable 1 300
```
**After:**
```
Use an isolated, reversible failure that removes all usable paths to that shard, or suppress both advertisement sources with reliable restoration. Assert the actual compute FIB lookup no longer resolves over a fabric uplink before measuring selection convergence.
```

### ⚪ P3 — Low

No P3 findings.

## What's Working Well

- Refresh errors now propagate and prevent disable after failed iterator/map write.
- Candidates check realized status families, NAT64 prefix and well-known-prefix support; terminating shards excluded.
- Drain documentation correctly requires explicit drain then quiescence before delete.
- Probe checks requests and capture counts, includes blackhole negative check and NAT64/UDP/ICMP coverage.
- Adds watch synchronization, desired mode, sweep failure metrics and staging rollback checklist.
- Immutable group snapshots combine membership, Maglev, generation and forwarding fields and publish via one ARRAY_OF_MAPS replacement.
- F05 partial slot publication is eliminated because failed create/write/swap attempts do not publish the new inner map.
- New kernel tests cover failure boundaries, restart pin retention, class isolation and concurrent snapshot swaps; these still require privileged execution.

## Refactor Plan

Each step is independently mergeable and must not break existing behavior.

### Step 1: Make group retirement exclude concurrent writers
*Addresses: R01*

**What:** Implement registration barrier and fault tests.

**Why now:** Rollback must be safe.

**Safe when:** No late writer can outlive disabled group.

### Step 2: Preserve fail-closed translation classes
*Addresses: R02, R03*

**What:** Keep hashed refresh semantics for empty classes and install explicit per-prefix failures.

**Why now:** Admission must apply to actual traffic.

**Safe when:** Zero candidates never sends traffic to static or another class.

### Step 3: Reconcile translation-class lifetime
*Addresses: R05*

**What:** Keep class-to-group identity stable and safely retire removed classes and routes.

**Why now:** Changing configuration must not reinterpret existing sentinel routes.

**Safe when:** Removal/reorder/replacement never forwards a route to a group for a different prefix.

### Step 4: Make fresh probes deterministic
*Addresses: R04*

**What:** Persist unique address allocation and check errors.

**Why now:** Acceptance must be repeatable.

**Safe when:** Repeated calls never reuse source addresses.

### Step 5: Make the BGP acceptance failure remove all usable paths
*Addresses: R06*

**What:** Account for both FRR and galactic-router advertisements; verify the compute FIB and reliably restore the failure.

**Why now:** A routing failover test must induce the failure it claims to measure.

**Safe when:** The test proves actual loss and recovery of reachability without a local prohibit-route shortcut.

## Remaining staging gates and review observations

Fix R01–R05 and correct the routing failure scenario before treating the lab script as an acceptance gate. Re-run privileged tests on the staging kernel, alert tests, full CI and the complete lab scenario. Confirm the external CRD, read-back of `spec.drain`, RBAC, unique per-shard addresses, per-class eligibility and actual central alert deployment. The new rollout checklist is useful documentation, not evidence those checks were performed.

The new script checks UDP outbound arrival but does not demonstrate translated UDP return traffic. Shard addition, initial first-sync delay and concurrent membership changes still need explicit execution evidence. Its rollback stage assumes the saved starting mode was ordered even though cleanup claims general restoration; make that precondition explicit or set ordered for the test and restore the original state separately.

Monitoring now exposes desired mode and watch sync, which is an improvement. Missing map-derived pool series and stale successful-sweep timestamps still need an operational check: early pinned-map open failures bypass SweepError, and there is no dedicated alert consuming the successful-sweep timestamp. Confirm those cases cannot appear healthy merely because the process answers scrapes.

Upgrade from the reviewed experimental mutable-array build is not explicitly migrated: the new outer map starts empty while existing sentinel routes/pins can remain, and obsolete map pins are removed. If that experimental build was ever enabled anywhere, require an ordered-mode transition before this upgrade or implement/test state migration. This is an additional deployment prerequisite, not a claim that the old experimental build was deployed.
