# Review Plan: Galactic Router Rewrite

## Overview

Review of the rewrite replacing `galactic-agent` with `galactic-router`. The changes remove ~1527 lines (agent, bootstrap, gobgp provider/server) and add ~860 lines (router, controllers, reconcile, runtime, model, hash, metrics). The code has significant issues that must be resolved before it can be committed.

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

**Status: DONE** — also fixed missing `labels` import in `bgprouter_controller.go`.

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

### 3.1 Delete `internal/metrics/metrics.go`

**File:** `internal/metrics/metrics.go`

**Problem:** The file defines 11 Prometheus metric variables and a `MustRegister` function. Nothing in the codebase imports or calls this package. The metrics are never wired into any reconciler, runtime, or main.go.

**Action:** Delete the file. If metrics are desired later, re-implement with actual counter/gauge increments in the reconcile loop and runtime status path.

**Verification:** `go build ./...` should still succeed.

### 3.2 Delete unused condition constants from `status.go`

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

**Status: DONE** — removed in cosmos API v3 migration; `setPeerReadyCondition` now sets a single `Ready` condition using `bgpv1alpha1.ConditionTypeReady`.

### 3.3 Fix `ConditionSessionOpenCfm` typo

**File:** `internal/controller/status.go`

**Problem:** The constant is named `ConditionSessionOpenCfm` (truncated "Confirm") instead of `ConditionSessionOpenConfirm`. This is inconsistent with all other constant naming patterns and with the cosmos type `BGPPeerStateOpenConfirm`.

**Action:** Rename to `ConditionSessionOpenConfirm`. (This is only relevant if the FSM conditions are retained per recommendation 3.2 — if they are deleted, this is subsumed.)

**Status: DONE** — subsumed by 3.2; FSM conditions removed entirely.

---

## Phase 4: Fix EVPN Stub (P1)

### 4.1 Replace `buildEVPNPath` stub with proper error or implementation

**File:** `internal/runtime/gobgp/paths.go`

**Problem:** `buildEVPNPath` always returns `ErrMissingRouteDistinguisher`. This means every EVPN advertisement fails, the reconciler sets `Accepted=False` on the BGPAdvertisement, and the CNI's route creation is effectively useless. The error message is misleading — the issue is not a missing RD field, it's that the EVPN path builder is unimplemented.

**Action (short-term):** Replace the error with `errors.New("EVPN path construction is not yet implemented")` and update `ErrMissingRouteDistinguisher` to be a clear `NotImplemented` sentinel.

**Action (long-term):** Implement actual EVPN Type 5 IP Prefix path construction using `api.AddPath` with the SRv6 endpoint prefix, node IPv6 as next-hop, and route target communities.

**Verification:** After short-term fix, `go test ./internal/runtime/gobgp/` should pass. After long-term fix, EVPN advertisements should appear in GoBGP state.

---

## Phase 5: Improve Controller Efficiency (P2)

### 5.1 Add field index for BGPRouter targetRef.name

**Files:** `internal/controller/indexer.go`, `internal/controller/node_controller.go`

**Problem:** `node_controller.go` lists all BGPRouters across all namespaces on every Node update, then filters in-process. This is O(n) across the entire cluster.

**Action:**
1. Add a field index constant `BGPRouterByTargetName` in `indexer.go`.
2. Register the index in `RegisterIndexes` using a getter that returns `obj.Spec.TargetRef.Name`.
3. In `nodeToRouterRequests`, replace the full `List` with `List` + `client.MatchingFields{BGPRouterByTargetName: node.Name}`.

**Verification:** Node controller should use indexed lookup instead of full list.

### 5.2 Deduplicate peer/policy router-mapping logic

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

---

## Phase 6: Fix Error Messages (P2)

### 6.1 Return error from `resolveNodeIPv6` when nextHop is empty + EVPN ads present

**File:** `internal/reconcile/reconcile.go`

**Problem:** If the node has no IPv6 InternalIP, `resolveNodeIPv6` returns `""`. This is silently swallowed and later causes EVPN advertisements to fail with the misleading `ErrMissingRouteDistinguisher` error.

**Action:** In `BuildDesiredRouter`, after computing `nextHop`, check if any advertisement has EVPN address family and `nextHop` is empty. Return a clear error: `"node %s has no IPv6 InternalIP; EVPN advertisements require it"`.

**Verification:** A node without IPv6 should get a clear error in the BGPRouter status, not a misleading "MissingRouteDistinguisher".

---

## Phase 7: Minor Cleanup (P3)

### 7.1 Fix bgppolicy controller name

**File:** `internal/controller/bgppolicy_controller.go`

**Problem:** Line 42 names the controller `"bgproutepolicy"` but the CRD kind is `BGPPolicy`.

**Action:** Change to `Named("bgppolicy")`.

### 7.2 Add TODO on FRR stub

**File:** `internal/runtime/frr/frr.go`

**Problem:** The FRR runtime always returns `errNotImplemented`. The `fabric` role will always fail in production with no warning.

**Action:** Add a package-level comment:
```go
// NOTE: The fabric role is not yet implemented. Running galactic-router
// with ROUTER_ROLE=fabric will fail on the first reconcile.
```

### 7.3 Store hash in BGPRouter status for restart resilience

**File:** `internal/controller/bgprouter_controller.go`

**Problem:** The `lastHash` is stored in-memory (`sync.Map`). On pod restart, the hash is lost and the runtime gets re-applied even if nothing changed.

**Action:** Store the hash as a status field on BGPRouter (e.g., `Status.ConfigHash`) or as an annotation. On reconcile, compare the new hash against the stored value before applying.

**Verification:** Restart the router pod — the hash should be restored from status and no-op reconciles should be skipped.

---

## Verification Checklist

After all phases are complete:

- [ ] `go build ./...` — zero errors
- [ ] `go test ./internal/cni/` — all tests pass
- [ ] `go test ./internal/reconcile/` — all tests pass
- [ ] `go test ./internal/controller/` — all tests pass
- [ ] `go test ./internal/hash/` — all tests pass
- [ ] `go vet ./...` — zero warnings
- [ ] `task lint` — passes
- [ ] `go fmt ./...` — no unformatted files
