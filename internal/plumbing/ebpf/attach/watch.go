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
// Watch returns nil when ctx is canceled. It returns a non-nil error only
// if establishing the initial netlink subscriptions themselves fails.
func Watch(ctx context.Context, program *ebpf.Program, initial []string) error {
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
				continue
			}
			scheduleReevaluate()

		case _, ok := <-routeCh:
			if !ok {
				routeCh = nil
				continue
			}
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
// Canceling ctx stops the background watch loop; it does not Close objs --
// the caller still owns objs and must Close it itself, exactly as with
// Start (see the package doc comment for why that's safe against an
// already-attached filter).
func StartWatching(ctx context.Context, pinDir string) (objs *prog.UsidObjects, ifaces []string, err error) {
	objs, ifaces, err = Start(pinDir)
	if err != nil {
		return nil, nil, err
	}

	go func() {
		if werr := Watch(ctx, objs.UsidIngress, ifaces); werr != nil {
			slog.Error("attach: netlink-driven interface watch loop exited unexpectedly", "err", werr)
		}
	}()

	return objs, ifaces, nil
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
