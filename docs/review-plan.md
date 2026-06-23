# Review Plan: Galactic Router Rewrite

## Overview

Review of the rewrite replacing `galactic-agent` with `galactic-router`. The changes remove ~1755 lines (agent, bootstrap, gobgp provider/server) and add ~3643 lines (router, controllers, reconcile, runtime, model, hash, frr). All original issues have been resolved; new test files have been added on this branch.

---

## Phase 1: Make It Compile (P0)

~~### 1.1 Add cosmos replace directive~~

**File:** `go.mod`

**Problem:** The code references new cosmos types (`BGPRouter`, `RouterRef`, `BGPPolicyDirection`, `BGPPeerState`, etc.) that exist in the local `../cosmos` repo but are not referenced by the pinned `go.mod` version. No `replace` directive exists.

**Action:** Add to `go.mod`:
```
replace go.miloapis.com/cosmos => ../cosmos
```

**Verification:** Run `go build ./...` and confirm zero errors.

**Status: DONE** — cosmos reference resolved (`go.miloapis.com/cosmos v0.0.0-20260622211233-0e38bdf25eac`). Also fixed missing `labels` import in `bgprouter_controller.go`.

---

## Phase 2: Fix Broken Tests (P0)

~~### 2.1 Delete `TestRouteDistinguisher` from CNI test~~

**File:** `internal/cni/cni_test.go`

**Problem:** `TestRouteDistinguisher` calls `routeDistinguisher()` which was deleted in the CNI refactor. The function was replaced by `routeTarget()`, which has an identical implementation.

**Action:** Delete the `TestRouteDistinguisher` function block (lines 114–181). The existing `TestRouteTarget` covers the same logic.

**Verification:** Run `go test ./internal/cni/ -run TestRouteTarget` — should pass.

**Status: DONE** — deleted `TestRouteDistinguisher` and its section header. All CNI tests pass.

---

## Phase 3: Remove Dead Code (P1)

~~### 3.1 Delete `internal/metrics/metrics.go`~~

**File:** `internal/metrics/metrics.go`

**Problem:** The file defines 11 Prometheus metric variables and a `MustRegister` function. Nothing in the codebase imports or calls this package. The metrics are never wired into any reconciler, runtime, or main.go.

**Action:** Delete the file. If metrics are desired later, re-implement with actual counter/gauge increments in the reconcile loop and runtime status path.

**Verification:** `go build ./...` should still succeed.

**Status: DONE** — `internal/metrics/` directory no longer exists.

~~### 3.2 Delete unused condition constants from `status.go`~~

**File:** `internal/controller/status.go`

**Problem:** The following constants are defined but never referenced in any controller:

| Constant | Reason |
|---|---|
| `ConditionDegraded` | Never set on BGPRouter |
| `ConditionPeersEstablished` | Never set on BGPRouter |
| `ConditionAccepted` | Never set on BGPPeer |
| `ConditionSessionIdle` | FSM conditions unused — `updatePeerStatuses` only sets `ConditionReady` |
| `ConditionSessionConnect` | Same |
| `ConditionSessionActive` | Same |
| `ConditionSessionOpenSent` | Same |
| `ConditionSessionOpenCfm` | Same (also a typo, see 3.3) |
| `ConditionSessionEstab` | Same |

The helper variables `fsmConditions` and `fsmStateToCondition` are also dead code.

**Action:** Remove the 9 unused constants, the `fsmConditions` slice, and the `fsmStateToCondition` map. Keep only the constants that are actually used: `ConditionReady`, `ConditionRuntimeAvailable`, `ConditionConfigApplied`, `ConditionAdvertised`, `ConditionPolicyApplied`.

**Verification:** `go vet ./internal/controller/` should show no unused imports.

**Status: DONE** — removed in cosmos API v3 migration; `setPeerReadyCondition` now sets a single `Ready` condition using `bgpv1alpha1.ConditionTypeReady`. The status.go file now only defines the used condition constants and `Reason*` strings.

~~### 3.3 Fix `ConditionSessionOpenCfm` typo~~

**File:** `internal/controller/status.go`

**Problem:** The constant is named `ConditionSessionOpenCfm` (truncated "Confirm") instead of `ConditionSessionOpenConfirm`. This is inconsistent with all other constant naming patterns and with the cosmos type `BGPPeerStateOpenConfirm`.

**Action:** Rename to `ConditionSessionOpenConfirm`. (This is only relevant if the FSM conditions are retained per recommendation 3.2 — if they are deleted, this is subsumed.)

**Status: DONE** — subsumed by 3.2; FSM conditions removed entirely.

---

## Phase 4: Fix EVPN Stub (P1)

~~### 4.1 Replace `buildEVPNPath` stub with proper error or implementation~~

**File:** `internal/runtime/gobgp/paths.go`

**Problem:** `buildEVPNPath` always returns `ErrMissingRouteDistinguisher`. This means every EVPN advertisement fails, the reconciler sets `Accepted=False` on the BGPAdvertisement, and the CNI's route creation is effectively useless. The error message is misleading — the issue is not a missing RD field, it's that the EVPN path builder is unimplemented.

**Action (short-term):** Replace the error with `errors.New("EVPN path construction is not yet implemented")` and update `ErrMissingRouteDistinguisher` to be a clear `NotImplemented` sentinel.

**Action (long-term):** Implement actual EVPN Type 5 IP Prefix path construction using `api.AddPath` with the SRv6 endpoint prefix, node IPv6 as next-hop, and route target communities.

**Verification:** After short-term fix, `go test ./internal/runtime/gobgp/` should pass. After long-term fix, EVPN advertisements should appear in GoBGP state.

**Status: DONE** — full EVPN Type 5 IP Prefix path construction implemented in `buildEVPNPaths` (commit `243f37e`). Builds Type 1 RD from router-ID, parses route target communities, constructs MpReachNLRI with EVPN NLRI, and applies via `AddPath`/`DeletePath`.

---

## Phase 5: Improve Controller Efficiency (P2)

~~### 5.1 Add field index for BGPRouter targetRef.name~~

**Files:** `internal/controller/indexer.go`, `internal/controller/node_controller.go`

**Problem:** `node_controller.go` lists all BGPRouters across all namespaces on every Node update, then filters in-process. This is O(n) across the entire cluster.

**Action:**
1. Add a field index constant `BGPRouterByTargetName` in `indexer.go`.
2. Register the index in `RegisterIndexes` using a getter that returns `obj.Spec.TargetRef.Name`.
3. In `nodeToRouterRequests`, replace the full `List` with `List` + `client.MatchingFields{BGPRouterByTargetName: node.Name}`.

**Verification:** Node controller should use indexed lookup instead of full list.

**Status: DONE** — `indexer.go` defines `BGPRouterByTargetName` and registers it in `RegisterIndexes`. `node_controller.go` uses `client.MatchingFields{BGPRouterByTargetName: node.Name}` (line 58).

~~### 5.2 Deduplicate peer/policy router-mapping logic~~

**Files:** `internal/controller/bgppeer_controller.go`, `internal/controller/bgppolicy_controller.go`

**Problem:** `peerToRouterRequests` and `policyToRouterRequests` implement identical logic:
1. Check `routerRef` → return direct request
2. Check `routerSelector` → list matching routers → return requests

**Action:** Extract a generic helper in a shared file (e.g., `internal/controller/routing.go`):
```go
func enqueueRoutersForTarget(ctx context.Context, c client.Client, namespace string, ref *RouterRef, sel *RouterSelector) []reconcile.Request
```
Both controllers should call this helper instead of duplicating the logic.

**Verification:** Both controllers should behave identically after the refactor. `go vet` should show no issues.

**Status: DONE** — `internal/controller/routing.go` contains `enqueueRoutersForTarget` with a `resource` parameter for log context. Both `bgppeer_controller.go` (line 43) and `bgppolicy_controller.go` (line 44) call it.

---

## Phase 6: Fix Error Messages (P2)

~~### 6.1 Return error from `resolveNodeIPv6` when nextHop is empty + EVPN ads present~~

**File:** `internal/reconcile/reconcile.go`

**Problem:** If the node has no IPv6 InternalIP, `resolveNodeIPv6` returns `""`. This is silently swallowed and later causes EVPN advertisements to fail with the misleading `ErrMissingRouteDistinguisher` error.

**Action:** In `BuildDesiredRouter`, after computing `nextHop`, check if any advertisement has EVPN address family and `nextHop` is empty. Return a clear error: `"node %s has no IPv6 InternalIP; EVPN advertisements require it"`.

**Verification:** A node without IPv6 should get a clear error in the BGPRouter status, not a misleading "MissingRouteDistinguisher".

**Status: DONE** — `BuildDesiredRouter` checks `nextHop == ""` with EVPN advertisements and returns `"node %s has no IPv6 InternalIP; EVPN advertisements require it"` (lines 91–94).

---

## Phase 7: Minor Cleanup (P3)

~~### 7.1 Fix bgppolicy controller name~~

**File:** `internal/controller/bgppolicy_controller.go`

**Problem:** Line 42 names the controller `"bgproutepolicy"` but the CRD kind is `BGPPolicy`.

**Action:** Change to `Named("bgppolicy")`.

**Status: DONE** — `Named("bgppolicy")` (line 33).

~~### 7.2 Add TODO on FRR stub~~

**File:** `internal/runtime/frr/frr.go`

**Problem:** The FRR runtime always returns `errNotImplemented`. The `fabric` role will always fail in production with no warning.

**Action:** Add a package-level comment:
```go
// NOTE: The fabric role is not yet implemented. Running galactic-router
// with ROUTER_ROLE=fabric will fail on the first reconcile.
```

**Status: DONE** — package comment added (lines 5–7).

~~### 7.3 Store hash in BGPRouter status for restart resilience~~

**File:** `internal/controller/bgprouter_controller.go`

**Problem:** The `lastHash` is stored in-memory (`sync.Map`). On pod restart, the hash is lost and the runtime gets re-applied even if nothing changed.

**Action:** Store the hash as a status field on BGPRouter (e.g., `Status.ConfigHash`) or as an annotation. On reconcile, compare the new hash against the stored value before applying.

**Verification:** Restart the router pod — the hash should be restored from status and no-op reconciles should be skipped.

**Status: DONE** — hash persisted as annotation `galactic.datum.net/config-hash` (line 31). Reconciler compares new hash against annotation before applying (line 125).

---

## Phase 8: New Tests (P1) — Review Required

Three new test files were added on this branch but are not yet committed. They should be reviewed and committed.

### 8.1 `internal/controller/controller_test.go` (1015 lines)

**Contents:**
- `fakeCache` / `fakeManager` — minimal controller-runtime interfaces for testing
- `TestRegisterIndexes` — verifies all 5 indexes register without error
- `TestRegisterIndexes_indexFunctions` — verifies each index function returns correct values (BGPPeer by secret, BGPPeer by router, BGPPolicy by router, BGPAdv by router, BGPRouter by target)
- `TestEnqueueRoutersForTarget_*` — 5 tests covering routerRef, routerSelector, both nil, no match, routerRef overrides selector
- `TestNodeToRouterRequests_*` — 4 tests covering no match, single router, multiple routers, cross-namespace scoping, invalid object, list error
- `TestSetRouterPhase_*` — 3 tests for Ready/Failed/Pending phases
- `TestSetPeerReadyCondition` — 8 test cases covering all FSM states (Established, OpenConfirm, OpenSent, Active, Connect, Idle with reasons, unknown)
- `TestSetAdvertisementCondition_*` — 2 tests for True/False conditions
- `TestSetPolicyCondition_*` — 2 tests for True/False conditions

**Review notes:**
- Test coverage is comprehensive. The `fakeCache`/`fakeManager` stubs are minimal but sufficient for the tested functions.
- The `fakeCache.IndexField` implementation keys by `fmt.Sprintf("%T/%s", obj, field)` to avoid collisions between types that share field names (e.g., BGPPeer, BGPPolicy, BGPAdvertisement all use `.spec.routerRef.name`).

### 8.2 `internal/runtime/frr/frr_test.go` (60 lines)

**Contents:**
- `TestApplyReturnsErrNotImplemented`
- `TestStatusReturnsEmptyAndErrNotImplemented`
- `TestStopReturnsNil`
- `TestNewRuntimeFactory`

**Review notes:**
- Small, focused tests for the FRR stub. Appropriate for a stub implementation.

### 8.3 `internal/reconcile/reconcile_test.go` (1163 lines)

**Contents:**
- Test helpers: `testScheme`, `fakeClient`, `testRouter`, `testNode`, `testPeer`, `testPeerSelector`, `testPolicy`, `testPolicySelector`, `testAdv`, `testAuthSecret`
- `TestBuildDesiredRouter` — 7 test cases including happy path, wrong node, wrong role, multi-role error, missing node, missing auth secret
- `TestBuildDesiredRouter_EVPNNoIPv6` — verifies error when EVPN ads present but node has no IPv6
- `TestBuildDesiredRouter_EVPNWithIPv6` — verifies successful build with IPv6
- `TestBuildDesiredRouter_AuthSecret` — verifies auth secret password resolution
- `TestGatherPeers` — 9 test cases: routerRef, routerSelector, matchExpressions, non-matching, invalid AFI, timers, auth secret, missing auth, invalid keepalive
- `TestGatherPolicies` — 6 test cases: routerRef, routerSelector, non-matching, invalid term config, term sorting, set actions
- `TestValidateAFI` — 6 test cases for valid/invalid AFI/SAFI combos
- `TestValidateAFIsAll` — 4 test cases
- `TestValidateTimers` — 7 test cases for holdTime/keepalive validation
- `TestResolveNodeIPv6` — 8 test cases covering IPv6 selection, IPv4 fallback, no addresses, node not found, multiple IPv6, IPv4 skip, external skip, invalid IP
- `TestPeerTargetsRouter` — 5 test cases
- `TestPolicyTargetsRouter` — 5 test cases

**Review notes:**
- Excellent coverage of the reconcile logic. The test helpers are well-structured and reusable.
- `TestBuildDesiredRouter_EVPNNoIPv6` directly validates the fix from Phase 6.1.
- `TestResolveNodeIPv6` is thorough — covers edge cases like multiple IPv6, external addresses, and invalid IPs.

---

## Verification Checklist

After all phases are complete and new tests are committed:

- [x] `go build ./...` — zero errors
- [x] `go test ./internal/cni/` — all tests pass
- [x] `go test ./internal/reconcile/` — all tests pass
- [x] `go test ./internal/controller/` — all tests pass
- [x] `go test ./internal/hash/` — all tests pass
- [x] `go vet ./...` — zero warnings
- [x] `task lint` — passes
- [x] `go fmt ./...` — no unformatted files
