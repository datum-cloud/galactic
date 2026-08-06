// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// debounceInterval coalesces a burst of netlink link/route change events
// (e.g. an interface flapping, or several routes updating as part of one
// routing-table change) into a single interface-set re-evaluation, instead
// of re-running ResolveInterfaces -- and possibly re-attaching -- once per
// individual netlink message. It is a package-level var (not a const) so
// tests can shrink it and exercise Watch's event-to-reaction path in
// milliseconds instead of real wall-clock time.
var debounceInterval = 250 * time.Millisecond

// linkSubscribeFn and routeSubscribeFn are package-level override points --
// the same pattern interfaces.go uses for routeListFn/linkByIndexFn -- so
// tests can simulate real interface/route change events without a live
// netlink socket or root privileges: a fake implementation receives the
// exact channel Watch reads from and can push a synthetic
// netlink.LinkUpdate/netlink.RouteUpdate onto it whenever the test wants to
// simulate a change.
var (
	linkSubscribeFn  = netlink.LinkSubscribeWithOptions
	routeSubscribeFn = netlink.RouteSubscribeWithOptions
)

// resolveInterfacesFn is a package-level override point so Watch's own
// tests can control what a re-evaluation resolves to across successive
// calls (the "interface set changed" scenario this milestone exists for)
// without touching the real netlink route table. Production code always
// leaves this at its default, ResolveInterfaces, which has its own
// independent override vars (routeListFn/linkByIndexFn) exercised by
// interfaces_test.go.
var resolveInterfacesFn = ResolveInterfaces

// onReconcileDone is a test-only hook invoked once after every debounced
// re-evaluation (whether or not it changed anything, and whether or not
// ResolveInterfaces itself failed). It lets tests wait deterministically
// for a reconciliation attempt to finish instead of guessing with a sleep.
// Production code never overrides it.
var onReconcileDone = func() {}

// Watcher is a live handle onto a running Watch loop, returned by
// StartWatching alongside the objects/interfaces Start itself already
// returns. It exists so a caller outside this package -- specifically
// internal/installer's health-check ticker -- can (a) tell whether the
// watch loop is still actually running, and (b) ask it to re-evaluate the
// attachment set out of band, without needing to wait for the next
// netlink link/route event or a container restart (ecv's review of #283:
// "should a failed health check drive a reconcile before it fails the
// probe?" and "should a dead watcher fail health?").
type Watcher struct {
	alive atomic.Bool
	nudge chan struct{}
}

// newWatcher creates a Watcher in its not-yet-started state. alive is set
// true once the Watch loop it is passed to actually starts running, and
// false again once that loop exits for any reason (ctx canceled, or an
// unrecoverable error) -- see Watch's own use of it below.
func newWatcher() *Watcher {
	return &Watcher{nudge: make(chan struct{}, 1)}
}

// Alive reports whether the Watch loop this Watcher was passed to is
// still actually running. A Watch loop that has exited -- because its
// initial netlink subscriptions failed and StartWatching's spawning
// goroutine logged the error and gave up (watch.go's own doc comment),
// with no retry -- can no longer react to netlink events or Reconcile
// nudges at all, so a caller relying on it to self-heal drift (an
// externally cleared tc filter, a moved default route) needs to know that
// self-healing isn't happening anymore.
func (w *Watcher) Alive() bool {
	if w == nil {
		return false
	}
	return w.alive.Load()
}

// Reconcile asks the Watch loop to re-evaluate and re-assert the
// attachment set as soon as its next debounce interval elapses, the same
// path a real netlink link/route event drives. It is safe to call from any
// goroutine and safe to call when nothing is actually wrong -- attachOne/
// Detach are idempotent, so an unnecessary reconcile is a cheap no-op. A
// pending, not-yet-delivered nudge is not duplicated (the channel is
// buffered by exactly one and this send never blocks), so calling
// Reconcile repeatedly in a tight loop coalesces into a single
// re-evaluation, the same way a burst of netlink events already does via
// scheduleReevaluate's debounce timer reset.
func (w *Watcher) Reconcile() {
	if w == nil {
		return
	}
	select {
	case w.nudge <- struct{}{}:
	default:
	}
}

// logDegradedSubscription logs a netlink subscription channel closing
// (which Watch's select loop reacts to by setting that channel variable to
// nil and no longer selecting on it -- a nil channel case in a Go select
// simply never fires). Neither closure was previously logged at all
// (ecv's review of #283), which mattered most in the otherKindAlreadyNil
// case: once both the link and route subscriptions have closed, Watch's
// main select degrades to reacting only to ctx.Done() and the health-
// triggered nudge channel -- it can no longer notice any real interface or
// route change on its own -- and that transition passed completely
// silently before this.
func logDegradedSubscription(kind string, otherKindAlreadyNil bool) {
	if otherKindAlreadyNil {
		slog.Error("attach: watch: both netlink link and route subscriptions have now closed; " +
			"this watch loop can no longer react to interface or route changes on its own " +
			"(a health-triggered reconcile or ctx cancellation still work)")
		return
	}
	slog.Warn("attach: watch: netlink subscription closed", "kind", kind)
}

// Watch subscribes to netlink link and route change events and, for as
// long as ctx is not canceled, re-evaluates the eBPF uSID datapath's
// attachment set whenever one occurs (design plan §4.1: "re-evaluate on
// interface/route change events (netlink subscription), not just at
// startup" -- Milestone 3.2 of the implementation plan). It is meant to run
// in its own goroutine alongside the Start (or Load+Attach) call whose
// resolved interface set seeds initial.
//
// Change events are debounced (see debounceInterval) so a burst of related
// netlink messages triggers one re-evaluation, not one per message. Each
// re-evaluation calls ResolveInterfaces (via resolveInterfacesFn) again and
// reconciles the actually-attached state against it:
//   - every interface in the freshly-resolved set is (re-)attached to
//     program, not just ones newly present -- Attach's underlying
//     FilterReplace semantics make this idempotent and cheap, and it is
//     deliberately unconditional (not gated on the interface set having
//     changed at all) so that an external event that silently clears this
//     package's own tc filter without ever removing the interface from the
//     resolved set -- confirmed in a real deployment: the underlay routing
//     daemon (FRR) restarting bounced the interface, which cleared the
//     filter, but the interface never left the resolved set (still the
//     default-route interface), so a diff-only reconcile never noticed and
//     never healed it -- gets self-healed on the very next netlink event
//     instead of silently blackholing traffic until the pod restarts;
//   - every interface no longer present has this package's own tc filter
//     removed via Detach, so a downed or reassigned interface stops
//     silently forwarding into whatever VRF its Argument used to resolve
//     to.
//
// A failure to attach or detach one interface during a re-evaluation is
// logged and does not stop the watch loop or abandon that interface -- it
// is retried on the next re-evaluation for as long as the mismatch between
// the resolved set and the actually-attached set persists (see reconcile).
// A failure of ResolveInterfaces itself during a re-evaluation is likewise
// logged and skipped, leaving the previous attachment set in place rather
// than tearing anything down on a transient resolution error.
//
// Watch's w parameter, if non-nil, is marked alive for as long as Watch's
// loop is actually running (see Watcher's own doc comment) and receives an
// out-of-band re-evaluation trigger via its Reconcile method -- passing
// nil is fine and disables both; production always passes the *Watcher
// StartWatching itself created.
//
// Watch returns nil when ctx is canceled. It returns a non-nil error only
// if establishing the initial netlink subscriptions themselves fails.
func Watch(ctx context.Context, program *ebpf.Program, initial []string, w *Watcher) error {
	if program == nil {
		return errors.New("attach: watch: program is nil")
	}

	// Buffered by one so the netlink library's own subscription goroutine
	// (see vishvananda/netlink's linkSubscribeAt/routeSubscribeAt) can hand
	// off one in-flight update without blocking forever if it races with
	// this function returning (ctx canceled) right as a message arrives.
	linkCh := make(chan netlink.LinkUpdate, 1)
	routeCh := make(chan netlink.RouteUpdate, 1)
	done := make(chan struct{})
	defer close(done)

	if err := linkSubscribeFn(linkCh, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			slog.Warn("attach: link change subscription error", "err", err)
		},
	}); err != nil {
		return fmt.Errorf("attach: watch: subscribe to link updates: %w", err)
	}
	if err := routeSubscribeFn(routeCh, done, netlink.RouteSubscribeOptions{
		ErrorCallback: func(err error) {
			slog.Warn("attach: route change subscription error", "err", err)
		},
	}); err != nil {
		return fmt.Errorf("attach: watch: subscribe to route updates: %w", err)
	}

	// Only now that both subscriptions are up does this loop actually start
	// reacting to events -- mark it alive, and guarantee it is marked dead
	// again on every return path (including a subscription failure above
	// would have already returned before this point, correctly never
	// claiming to be alive at all).
	if w != nil {
		w.alive.Store(true)
		defer w.alive.Store(false)
	}

	var nudge <-chan struct{}
	if w != nil {
		nudge = w.nudge
	}

	current := toSet(initial)

	var debounceTimer *time.Timer
	var debounceC <-chan time.Time
	scheduleReevaluate := func() {
		if debounceTimer == nil {
			debounceTimer = time.NewTimer(debounceInterval)
			debounceC = debounceTimer.C
			return
		}
		if !debounceTimer.Stop() {
			select {
			case <-debounceTimer.C:
			default:
			}
		}
		debounceTimer.Reset(debounceInterval)
		debounceC = debounceTimer.C
	}

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return nil

		case _, ok := <-linkCh:
			if !ok {
				linkCh = nil // subscription ended; stop selecting on it
				logDegradedSubscription("link", routeCh == nil)
				continue
			}
			scheduleReevaluate()

		case _, ok := <-routeCh:
			if !ok {
				routeCh = nil
				logDegradedSubscription("route", linkCh == nil)
				continue
			}
			scheduleReevaluate()

		case <-nudge:
			// An out-of-band request (Watcher.Reconcile, e.g. from a
			// failing health check) to re-evaluate -- routed through the
			// same debounce path a real netlink event uses, so a nudge
			// racing an actual event still coalesces into one
			// re-evaluation rather than two.
			scheduleReevaluate()

		case <-debounceC:
			debounceC = nil
			next, err := resolveInterfacesFn()
			if err != nil {
				slog.Warn("attach: re-evaluate interface set failed, keeping previous attachment", "err", err)
				onReconcileDone()
				continue
			}
			current = reconcile(program, current, toSet(next))
			onReconcileDone()
		}
	}
}

// StartWatching runs Start and, if it succeeds, launches Watch in its own
// goroutine (stopped when ctx is done) to keep the resolved interface set
// re-evaluated against netlink link/route change events for the life of the
// returned objects (design plan §4.1; Milestone 3.2). It is the production
// entry point internal/installer.Run uses -- Start alone (Milestone 3.1)
// only ever evaluates the interface set once, at startup.
//
// The returned *Watcher is StartWatching's caller's handle onto that
// background loop -- Alive reports whether it is still running, and
// Reconcile requests an out-of-band re-evaluation (see internal/installer's
// health-check ticker, which uses both: it fails health if the watch loop
// has died, and nudges a reconcile when the datapath's own health checks
// fail, on the chance the failure is something Watch's reconcile can heal
// without waiting for an unrelated netlink event or the liveness probe
// restarting the container -- ecv's review of #283).
//
// Canceling ctx stops the background watch loop; it does not Close objs --
// the caller still owns objs and must Close it itself, exactly as with
// Start (see the package doc comment for why that's safe against an
// already-attached filter).
func StartWatching(ctx context.Context, pinDir string) (
	objs *prog.UsidObjects, ifaces []string, watcher *Watcher, err error,
) {
	objs, ifaces, err = Start(pinDir)
	if err != nil {
		return nil, nil, nil, err
	}

	watcher = newWatcher()
	go func() {
		if werr := Watch(ctx, objs.UsidIngress, ifaces, watcher); werr != nil {
			slog.Error("attach: netlink-driven interface watch loop exited unexpectedly", "err", werr)
		}
	}()

	return objs, ifaces, watcher, nil
}

// toSet converts a slice of interface names into a set, for
// order-independent comparison across successive ResolveInterfaces calls.
func toSet(names []string) map[string]struct{} {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	return set
}

// diffSets returns, in sorted order (for deterministic logging and
// testing), the names present in next but not current (added) and present
// in current but not next (removed).
func diffSets(current, next map[string]struct{}) (added, removed []string) {
	for name := range next {
		if _, ok := current[name]; !ok {
			added = append(added, name)
		}
	}
	for name := range current {
		if _, ok := next[name]; !ok {
			removed = append(removed, name)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// reconcile brings the actual attachment state toward next, starting from
// current (the last-known actually-attached set), and returns the
// resulting actually-attached set.
//
// Every interface in next is (re-)attached unconditionally, not only ones
// added since current -- see Watch's doc comment above for why a
// diff-only reconcile (the original design) misses external drift that
// clears the tc filter without ever changing the resolved interface set.
// attachOne (FilterReplace) is idempotent, so re-asserting an
// already-correctly-attached interface is a cheap no-op.
//
// A per-interface attach or detach failure is logged and that interface is
// simply left out of (for a failed attach) or kept in (for a failed detach)
// the returned set -- which means it is retried again on the next
// reconcile, without any separate retry-tracking state.
func reconcile(program *ebpf.Program, current, next map[string]struct{}) map[string]struct{} {
	added, removed := diffSets(current, next)
	if len(added) != 0 || len(removed) != 0 {
		slog.Info("attach: interface set changed, re-evaluating attachment", "added", added, "removed", removed)
	}

	result := make(map[string]struct{}, len(current)+len(added))
	for name := range current {
		result[name] = struct{}{}
	}

	for name := range next {
		if err := attachOne(program, name); err != nil {
			slog.Warn("attach: failed to (re)attach resolved interface, will retry on next re-evaluation",
				"interface", name, "err", err)
			delete(result, name)
			continue
		}
		result[name] = struct{}{}
	}

	for _, name := range removed {
		if err := Detach([]string{name}); err != nil {
			slog.Warn("attach: failed to detach interface no longer resolved, will retry on next re-evaluation",
				"interface", name, "err", err)
			continue
		}
		delete(result, name)
	}

	return result
}
