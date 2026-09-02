# Implementation Plan — BGP Peer Session-State Kubernetes Events for `galactic-router`

- **Issue:** none filed yet. Left unnumbered rather than guessing a number — rename to
  `NNN-router-bgp-peer-session-events.md` once a tracking issue exists.
- **Status:** implemented, using this plan's recommended design (§2, option (b)) with the
  default answers to §6's open questions. Two deviations found during implementation, both
  reflected in the sections below rather than left as stale history: the emitter uses the
  modern `events.k8s.io/v1` recorder (`mgr.GetEventRecorder`), not the deprecated core
  `record.EventRecorder` this plan originally assumed — golangci-lint's `staticcheck`
  flags the deprecated one, and the modern API needed no more effort to use correctly; and
  that choice means the RBAC grant *was* new after all (`events.k8s.io`, not just the
  already-present core `""` `events` rule) — see §1 and §4 item 6.
- **Scope:** `galactic-router`'s `BGPPeer` session-state transitions only (Idle / Connect /
  Active / OpenSent / OpenConfirm / Established), surfaced as Kubernetes `Event` objects on
  the `BGPPeer` CR. `galactic-gateway`'s Active-Active BGP peering and every other
  reconciler in this repo (BGPRouter/BGPAdvertisement/BGPPolicy/BGPVRFInstance/GC) are out
  of scope — see [Out of scope](#5-out-of-scope).

See [ARCHITECTURE-ROUTER.md](../agents/ARCHITECTURE-ROUTER.md) — "Key Design Decisions"
(peer FSM logging via `internal/runtime/gobgp/peer_monitor.go`) and "Known Constraints"
(`peerStatusRequeue` doc comment: *"BGP FSM transitions are not Kubernetes events"*) — both
passages this plan touches directly; see [§4](#4-component-level-changes) item 6.

---

## 1. Problem statement

`internal/controller/bgprouter_controller.go` keeps `BGPPeer.Status.SessionState` and its
`Ready` condition current by polling `RuntimeManager.Status()` every `peerStatusRequeue`
(30s) and unconditionally overwriting them in `updatePeerStatuses` /
`setPeerReadyCondition` (`internal/controller/status.go:44`). There is no history: a
`kubectl get bgppeer` shows only the current state, and a `kubectl describe` shows no
timeline of when a session went Established, flapped, or dropped, and why. Operators have
to correlate `slog` lines (`internal/runtime/gobgp/peer_monitor.go:74`'s
`"bgp peer state transition"` log) across pod logs to reconstruct that history today, which
doesn't scale past a handful of nodes and isn't queryable with `kubectl` or standard
Kubernetes eventing/alerting tooling.

Separately, `internal/runtime/gobgp/peer_monitor.go` already does real-time,
per-transition, deduplicated FSM-state-change detection by subscribing to GoBGP's native
`WatchEvent(..., WatchPeer())` callback API — it just doesn't tell anything outside its own
package about a transition. This plan's job is almost entirely plumbing: get that
already-detected signal from the GoBGP-watch goroutine (which has no Kubernetes client) out
to something that has one, and turn it into `Eventf` calls against the `BGPPeer` object.

No controller in this repo raised a Kubernetes Event before this plan (confirmed by a
full-repo grep for `EventRecorder`/`Eventf`/`record.Event`) — this was a first-of-its-kind
addition. `config/galactic-router/rbac.yaml` already granted `events: create, patch` on the
core (`""`) API group as standard, never-exercised kubebuilder manager-role boilerplate —
but that covers only the deprecated `record.EventRecorder` path
(`mgr.GetEventRecorderFor`). golangci-lint's `staticcheck` (enabled with `checks: all` in
`.golangci.yaml`) flags that API as deprecated, so the implementation uses the modern
`events.k8s.io/v1` recorder (`mgr.GetEventRecorder`) instead, which **does** need a new RBAC
grant — `events.k8s.io`/`events`, added alongside the pre-existing core-group rule rather
than replacing it.

## 2. Recommended design: real-time, watcher-driven, Established-transitions only

Two designs were considered; this plan recommends the second.

- **(a) Poll-based, inside `updatePeerStatuses`.** Diff `peer.Status.SessionState` (old,
  still on the fetched object) against `ps.SessionState` (new, from runtime status) right
  before `setPeerReadyCondition` overwrites it, and `Eventf` on a change. Simplest — no new
  plumbing, `BGPRouterReconciler` already has both objects and a K8s client. But it inherits
  the same blind spot the `peerStatusRequeue` doc comment already warns about: *"a
  transition ... can miss one entirely if it reverts between two polls"* — a peer that flaps
  Established → Idle → Established within one 30s window produces zero events, which
  defeats a lot of the point of adding events in the first place (flap visibility is the
  main thing an operator wants from this feature).
- **(b) Watcher-based, from `peer_monitor.go`'s existing `onPeerUpdate`.** Every real
  transition GoBGP reports is already caught, deduplicated, and logged there — recommend
  reusing that exact signal for Events instead of building a second, weaker detector. This
  is the design below.

Concretely:

1. `onPeerUpdate` (`internal/runtime/gobgp/peer_monitor.go:74`) gains a second output beyond
   its `slog.Info` call: an **observer callback**, invoked with the same data it already
   computes (`router` key, peer `addr`, `prev`/`next` `model.BGPPeerState`,
   `disconnectReason`/`disconnectMessage` when leaving Established). The callback is
   optional (nil-checked) so existing/new unit tests that don't wire one up are unaffected.
2. The callback fires **on every deduplicated transition** (reusing the existing dedup —
   repeated identical states and `PEER_EVENT_END_OF_INIT` are already filtered upstream),
   but the reconciler-side handler only calls `Eventf` for the two transitions an operator
   actually cares about:
   - **entering** Established → `Normal` / reason `SessionEstablished`
   - **leaving** Established → `Warning` / reason `SessionDown`, message includes
     `disconnectReason`/`disconnectMessage` when GoBGP supplied them
   - every other FSM hop (Idle↔Connect↔Active↔OpenSent↔OpenConfirm while never having
     reached Established — normal churn during initial connection setup or backoff) is
     intentionally **not** emitted as an Event. Kubernetes' own event-aggregation only
     collapses identical `(reason, message)` pairs within a window; a message carrying
     `from`/`to` state would defeat that on every hop, so an un-gated "emit on every
     transition" policy would flood `kubectl get events` for any peer that isn't up yet.
     This is the main judgment call in this plan — see
     [open question 1](#6-open-questions-still-needed-before-this-is-buildable).
3. Because `onPeerUpdate` runs on the shared GoBGP-watch goroutine
   (`startPeerMonitor`/`watchPeerEvents`, `peer_monitor.go:35,50`), the observer callback
   must not block that goroutine on a Kubernetes API call. The reconciler-side
   implementation should hand the transition to a small buffered worker (a bounded channel +
   single consumer goroutine is enough at this event rate) rather than call `List`/`Eventf`
   inline from within `onPeerUpdate`'s call stack.
4. GoBGP's watcher identifies peers by neighbor **address**, not by the `BGPPeer` CR's
   name — `internal/model.PeerStatus` and `onPeerUpdate` both key on `addr`. Resolving
   address → `*bgpv1alpha1.BGPPeer` for the `Eventf` target requires the same
   routerRef/routerSelector lookup + `normalizeIP` matching `updatePeerStatuses` already does
   (`bgprouter_controller.go:266-306`). Extract that into a shared helper
   (`peersForRouter(ctx, router) []*bgpv1alpha1.BGPPeer` or similar) used by both the
   existing poll path and the new observer path, instead of duplicating it. If no matching
   `BGPPeer` is found (e.g. it's been deleted but GoBGP hasn't been reconfigured yet), skip
   and log at `V(1)`, matching the existing skip-and-log pattern at
   `bgprouter_controller.go:311`.

This keeps `BGPPeer.Status`/conditions on their existing poll-driven path (unchanged) while
making Events real-time and independent of `peerStatusRequeue`'s cadence — the two
mechanisms end up on genuinely different, appropriate cadences: status reflects "current
state as of the last poll," events capture "this specific transition happened."

## 3. What an event looks like

```
LAST SEEN   TYPE      REASON              OBJECT             MESSAGE
30s         Normal    SessionEstablished  bgppeer/dfw-rr-1    BGP session with 2607:ed40:1fb::1 (AS 65010) transitioned to Established.
2m          Warning   SessionDown         bgppeer/dfw-rr-1    BGP session with 2607:ed40:1fb::1 (AS 65010) went from Established to Idle (reason: hold timer expired).
```

`involvedObject` is the `BGPPeer` (matches where an operator would already be looking via
`kubectl describe bgppeer`), not the owning `BGPRouter` — see
[open question 2](#6-open-questions-still-needed-before-this-is-buildable) for whether to
also mirror onto the router.

## 4. Component-level changes

1. **`internal/model`** (or a small new file alongside it) — add a `PeerStateChange` struct
   (router key, peer address, `from`/`to` `model.BGPPeerState`, disconnect reason/message,
   timestamp) and a `PeerStateObserver` interface with one method,
   `ObservePeerStateChange(PeerStateChange)`. Living in `model` (not `controller`) avoids an
   import cycle, since `internal/runtime/gobgp` cannot import `internal/controller`.
2. **`internal/runtime`** (the `RuntimeManager` interface/factory) — add a way to register a
   `PeerStateObserver` at construction (a `NewRuntimeFactory(..., observer)` parameter, or a
   setter called once from `cmd/galactic-router/root.go` before `mgr.Start`). Threaded down
   into `internal/runtime/gobgp.GoBGPRuntime`.
3. **`internal/runtime/gobgp/peer_monitor.go`** — `onPeerUpdate` calls the observer (if set)
   alongside its existing `slog.Info`, using the same `prev`/`next`/disconnect fields it
   already computes at line ~74-100.
4. **`internal/controller/bgprouter_controller.go`** and a new
   **`internal/controller/peer_events.go`**:
   - extract the routerRef+selector peer lookup out of `updatePeerStatuses`
     (`bgprouter_controller.go:266-306`) into a shared `peersForRouter` helper, used by both
     `updatePeerStatuses` and the new emitter below.
   - as-built: a standalone `PeerStateEventEmitter` type (not a field added directly to
     `BGPRouterReconciler`) implements both `model.PeerStateObserver` and controller-runtime's
     `manager.Runnable`, so the manager owns its worker goroutine's start/stop lifecycle the
     same way it owns every reconciler. `ObservePeerStateChange` only enqueues onto a bounded
     channel (the buffered-worker note in §2 item 3); `Start`'s loop drains it and resolves
     address → `*bgpv1alpha1.BGPPeer` via `peersForRouter`, then `Eventf` per the
     Established-only policy in §2 item 2.
5. **`cmd/galactic-router/root.go`** — as-built, this uses the modern
   `mgr.GetEventRecorder(appName)` (not `GetEventRecorderFor`; see §1 on why), constructs
   `PeerStateEventEmitter`, registers it with `mgr.Add(...)`, and passes it into
   `gobgp.NewRuntimeFactory(...)`'s new `observer` parameter — all before `runtimeMgr :=
   galacticruntime.NewRuntimeManager(factory)`, since the factory needed to already exist by
   then.
6. **`config/galactic-router/rbac.yaml`** — as-built addition this plan didn't originally
   call for (see §1): an `apiGroups: ["events.k8s.io"], resources: ["events"], verbs:
   ["create", "patch"]` rule, alongside the pre-existing (previously unused) core-group one.
7. **`docs/agents/ARCHITECTURE-ROUTER.md`** — update two passages this plan directly
   contradicts/extends:
   - the Key Design Decisions paragraph describing `peer_monitor.go` as purely a `slog`
     logger — note it now also drives `BGPPeer` Events.
   - the Known Constraints line *"BGP FSM transitions are not Kubernetes events"* — this
     plan makes that literally false for the Established/SessionDown cases; reword to state
     what's still poll-driven (`BGPPeer.Status`/conditions, unchanged) versus what's now
     real-time (Events), so the doc doesn't contradict the shipped behavior.
8. **Tests**:
   - `internal/runtime/gobgp/peer_monitor_test.go` — extend the existing table-driven
     `onPeerUpdate` tests with a spy `PeerStateObserver` and assert it's called with the
     expected `PeerStateChange`, alongside the existing `slog`-capture assertions.
   - as-built: a new `internal/controller/peer_events_test.go`, using
     `events.NewFakeRecorder` (the modern-API fake, matching the modern
     `events.EventRecorder` used in §1/item 5 above — `record.NewFakeRecorder` was this
     plan's original, since-superseded assumption) plus the existing `fake.NewClientBuilder()`
     pattern, in the style of `networkgateway_controller_test.go`'s fake-client tests. Covers:
     peer found vs. not-found (skip+log), `-> Established` (Normal/`SessionEstablished`),
     `Established -> Idle` with disconnect fields (Warning/`SessionDown`), a never-Established
     intermediate hop (no event, per the §2 policy), and the full `ObservePeerStateChange` →
     `Start` queue/worker pipeline end to end.

## 5. Out of scope

- Changing `BGPPeer.Status`/`Ready`-condition polling mechanism or `peerStatusRequeue`'s
  cadence — unchanged.
- Events for `BGPRouter`/`BGPAdvertisement`/`BGPPolicy`/`BGPVRFInstance` reconcile outcomes,
  or GC actions (`internal/gc`) — peer session state only, per the ask.
- `galactic-gateway`'s Active-Active BGP peering — a different reconciler
  (`internal/controller/networkgateway_controller.go`); could reuse the same
  `PeerStateObserver` plumbing as a fast-follow, but is a separate change.
- Any alerting/webhook/notification pipeline built on top of these Events — this plan only
  produces standard `v1.Event` objects; wiring a Prometheus event-exporter, Slack
  notification, etc. on top is a separate, consumer-side concern.
- Event retention/audit beyond the cluster's default `Event` TTL (1h on most clusters) — no
  separate log/audit trail.

## 6. Open questions still needed before this is buildable

1. **Should never-Established churn generate events too, rate-limited/flap-detected** (e.g.
   "peer X transitioned 5 times in 60s without reaching Established")? Recommend deferring
   to a v2 — the `slog` line already covers this today for anyone tailing logs, and adding
   flap-detection thresholds is its own design question (window size, threshold, whether
   it's per-peer configurable).
2. **`involvedObject`: `BGPPeer` only, or also mirror onto the owning `BGPRouter`?**
   Recommend `BGPPeer` only for v1 — `router.Status.Peers` (Total/Established counts) is
   already a coarse aggregate view; a full event stream on the router object for every peer
   under it would be noisy for routers with many peers (e.g. an `iad` route reflector).
3. **Recorder naming** — one shared `"galactic-router"` recorder for all
   `BGPRouterReconciler` event sources, or something more specific
   (`"galactic-router.bgppeer-session"`)? Recommend the simple shared name unless it proves
   confusing in practice; easy to change later since `Source.Component` isn't part of any
   external contract.
4. **Idle sub-reasons** (`ConnectionRefused`/`BackOff`/`HoldTimerExpired`/`Idle`, defined in
   `network/api/v1alpha1/peer_types.go:94-111`) — should the `SessionDown` Event's `Reason`
   field encode which one occurred (e.g. `SessionDownHoldTimerExpired`), or keep a single
   `SessionDown` reason with the detail only in the message? Recommend encoding it in the
   message only, so `Reason` stays a small stable enum `kubectl get events
   --field-selector` filtering can rely on.
5. Does this need a way to disable event emission for very large/noisy fleets? Nothing else
   in this reconciler is runtime-configurable via env var except `peerStatusRequeue` (a
   `const`, not configurable either) — recommend no new knob unless a real noise problem
   shows up.

## 7. Testing sketch

- **Unit** (`internal/runtime/gobgp/peer_monitor_test.go`): observer-fires assertions added
  to the existing table-driven `onPeerUpdate`/`bgpFSMStateToModel` tests, following the
  existing `peerEvent`/`captureSlog` fixture patterns.
- **Unit** (`internal/controller/bgprouter_controller_test.go`): `record.NewFakeRecorder` +
  `fake.NewClientBuilder()` covering the four cases listed in §4 item 7.
- **Manual/e2e** (`deploy/containerlab/`): force a peer flap (e.g. `ip link set down` on a
  fabric interface between two lab nodes, or a `frr-init` config edit that changes the
  neighbor's hold-timer expectations) and confirm with
  `kubectl get events --field-selector involvedObject.kind=BGPPeer,reason=SessionDown` and
  `kubectl describe bgppeer <name>` that both the Established and SessionDown events appear
  with correct timing and disconnect detail.

## 8. Rollout

No CRD schema changes. One small RBAC addition (`events.k8s.io`/`events`, §4 item 6 — not
the "already granted" core-group rule this plan originally assumed, see §1), and the change
is otherwise purely additive — no existing behavior, field, or API is removed or altered.
Shipped as a single PR with §6's default answers taken as final; no phased rollout or
migration needed. Verified with `task ci` (including `go test -race ./...` and
`golangci-lint run ./...`) plus this section's unit/table tests; the manual containerlab
flap test above is still recommended before merging to a real cluster, but wasn't run as
part of this implementation pass.
