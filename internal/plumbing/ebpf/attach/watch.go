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

// debounceInterval coalesces a burst of netlink link and route events, such as
// an interface flapping or several routes changing together, into a single
// interface-set re-evaluation rather than one per netlink message. A var, not a
// const, so tests can shrink it.
var debounceInterval = 250 * time.Millisecond

// linkSubscribeFn and routeSubscribeFn are override points so tests can
// simulate interface and route change events without a live netlink socket or
// root. A fake receives the channel Watch reads from and can push synthetic
// updates onto it.
var (
	linkSubscribeFn  = netlink.LinkSubscribeWithOptions
	routeSubscribeFn = netlink.RouteSubscribeWithOptions
)

// resolveInterfacesFn is an override point so Watch's tests can control what
// successive re-evaluations resolve to without touching the real route table.
// Production always leaves it at ResolveInterfaces, which has override vars of
// its own.
var resolveInterfacesFn = ResolveInterfaces

// onReconcileDone is a test-only hook invoked after every debounced
// re-evaluation, whether or not anything changed and whether or not resolution
// failed, so tests can wait deterministically instead of sleeping. Production
// never overrides it.
var onReconcileDone = func() {}

// Watcher is a live handle on a running Watch loop, returned by StartWatching.
// It lets a caller outside this package tell whether the loop is still running
// and ask it to re-evaluate the attachment set out of band, without waiting for
// the next netlink event or a container restart.
type Watcher struct {
	alive atomic.Bool
	nudge chan struct{}
}

// newWatcher creates a Watcher in its not-yet-started state. It is marked alive
// once the Watch loop it is passed to starts running, and dead again once that
// loop exits for any reason.
func newWatcher() *Watcher {
	return &Watcher{nudge: make(chan struct{}, 1)}
}

// Alive reports whether the Watch loop this Watcher was passed to is still
// running. A loop that exited, because its initial netlink subscriptions failed
// and nothing retries them, can no longer react to events or nudges, so a
// caller relying on it to heal drift needs to know that healing has stopped.
func (w *Watcher) Alive() bool {
	if w == nil {
		return false
	}
	return w.alive.Load()
}

// Reconcile asks the Watch loop to re-evaluate and re-assert the attachment set
// at its next debounce interval, the same path a real netlink event drives.
//
// Safe from any goroutine and safe when nothing is wrong, since attach and
// detach are idempotent. A pending nudge is not duplicated, the channel being
// buffered by one and the send never blocking, so repeated calls coalesce into
// one re-evaluation just as a burst of netlink events does.
func (w *Watcher) Reconcile() {
	if w == nil {
		return
	}
	select {
	case w.nudge <- struct{}{}:
	default:
	}
}

// logDegradedSubscription logs a netlink subscription channel closing, which
// Watch reacts to by nil-ing that channel so its select case never fires again.
// otherKindAlreadyNil says whether the other subscription is already gone,
// which is the case worth noticing: with both closed, the loop reacts only to
// context cancellation and out-of-band nudges and can no longer see any
// interface or route change on its own.
func logDegradedSubscription(kind string, otherKindAlreadyNil bool) {
	if otherKindAlreadyNil {
		slog.Error("attach: watch: both netlink link and route subscriptions have now closed; " +
			"this watch loop can no longer react to interface or route changes on its own " +
			"(a health-triggered reconcile or ctx cancellation still work)")
		return
	}
	slog.Warn("attach: watch: netlink subscription closed", "kind", kind)
}

// Watch subscribes to netlink link and route change events and, until ctx is
// canceled, re-evaluates the datapath's attachment set whenever one occurs. It
// is meant to run in its own goroutine alongside the call whose resolved
// interface set seeds initial. program is the loaded usid_ingress program to
// attach.
//
// Events are debounced, so a burst of related messages triggers one
// re-evaluation. Each re-evaluation resolves the interface set again and
// reconciles the attached state against it:
//   - Every interface in the fresh set is re-attached, not only newly present
//     ones. Attach is idempotent and cheap, and doing it unconditionally is
//     what heals an external event that clears this package's filter without
//     removing the interface from the resolved set. An underlay routing daemon
//     restarting bounces the interface and clears the filter while it remains
//     the default-route interface, which a diff-only reconcile never notices.
//   - Every interface no longer present has this package's filter removed, so a
//     downed or reassigned interface stops forwarding into whatever VRF its
//     Argument used to resolve to.
//
// A per-interface attach or detach failure is logged and retried on the next
// re-evaluation, for as long as the mismatch persists. A resolution failure is
// likewise logged and skipped, leaving the previous attachment set in place
// rather than tearing anything down on a transient error.
//
// w, when non-nil, is marked alive while this loop runs and supplies the
// out-of-band re-evaluation trigger. Passing nil disables both.
//
// Returns nil when ctx is canceled, and a non-nil error only if establishing
// the initial netlink subscriptions fails.
func Watch(ctx context.Context, program *ebpf.Program, initial []string, w *Watcher) error {
	if program == nil {
		return errors.New("attach: watch: program is nil")
	}

	// Buffered by one so netlink's own subscription goroutine can hand off an
	// in-flight update without blocking forever if it races with this function
	// returning as a message arrives.
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

	// Only now that both subscriptions are up does this loop react to events.
	// Mark it alive, and guarantee it is marked dead again on every return
	// path. A subscription failure returns above, so it never claims to be
	// alive at all.
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
			// An out-of-band request to re-evaluate, routed through the same
			// debounce path a netlink event uses, so a nudge racing a real
			// event coalesces into one re-evaluation.
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

// StartWatching runs Start and, on success, launches Watch in its own goroutine
// to keep the resolved interface set re-evaluated against netlink events for the
// life of the returned objects. pinDir is the bpffs directory to pin into. Start
// alone evaluates the interface set once, at startup.
//
// The returned *Watcher is the caller's handle on that loop: Alive reports
// whether it still runs, and Reconcile requests an out-of-band re-evaluation.
//
// Canceling ctx stops the loop but does not close the returned objects. The
// caller still owns and must close them, as with Start.
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

// diffSets returns the names present in next but not current, and present in
// current but not next, each sorted for deterministic logging and tests.
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

// reconcile brings the attached state toward next, starting from current, the
// last-known attached set, and returns the resulting attached set.
//
// Every interface in next is re-attached unconditionally rather than only those
// added since current, because a diff-only reconcile misses external drift that
// clears the filter without changing the resolved set. Attaching is idempotent,
// so re-asserting a correctly attached interface is a cheap no-op.
//
// A per-interface failure is logged, and that interface is left out of the
// returned set on a failed attach or kept in it on a failed detach, which
// retries it on the next reconcile with no separate retry state.
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
		if err := attachOne(program, name, filterName, netlink.HANDLE_MIN_INGRESS); err != nil {
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
