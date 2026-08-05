// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// linkSubscribeFunc and routeSubscribeFunc name linkSubscribeFn's and
// routeSubscribeFn's function types, purely so the stub constructors below
// don't have to re-spell the full three-parameter signature inline.
type (
	linkSubscribeFunc  = func(chan<- netlink.LinkUpdate, <-chan struct{}, netlink.LinkSubscribeOptions) error
	routeSubscribeFunc = func(chan<- netlink.RouteUpdate, <-chan struct{}, netlink.RouteSubscribeOptions) error
)

// stubLinkSubscribe and stubRouteSubscribe return a linkSubscribeFn/
// routeSubscribeFn-shaped fake that, if trigger is non-nil, spawns a
// goroutine forwarding each value received on trigger as one synthetic
// update sent on the channel Watch is reading from. Neither the fake nor
// the goroutine it spawns touches netlink or the host network stack --
// Watch's own tests only need to prove Watch reacts correctly to *a*
// change event, not that vishvananda/netlink's own subscription plumbing
// works (that's netlink's own test suite's job).
func stubLinkSubscribe(trigger <-chan struct{}) linkSubscribeFunc {
	return func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, _ netlink.LinkSubscribeOptions) error {
		if trigger == nil {
			return nil
		}
		go func() {
			for {
				select {
				case <-done:
					return
				case _, ok := <-trigger:
					if !ok {
						return
					}
					select {
					case ch <- netlink.LinkUpdate{}:
					case <-done:
						return
					}
				}
			}
		}()
		return nil
	}
}

func stubRouteSubscribe(trigger <-chan struct{}) routeSubscribeFunc {
	return func(ch chan<- netlink.RouteUpdate, done <-chan struct{}, _ netlink.RouteSubscribeOptions) error {
		if trigger == nil {
			return nil
		}
		go func() {
			for {
				select {
				case <-done:
					return
				case _, ok := <-trigger:
					if !ok {
						return
					}
					select {
					case ch <- netlink.RouteUpdate{}:
					case <-done:
						return
					}
				}
			}
		}()
		return nil
	}
}

// withWatchTestDefaults overrides every one of Watch's package-level
// override points to hermetic no-op/no-event fakes and a short
// debounceInterval, restoring the originals on test cleanup. Individual
// tests then override whichever vars they need beyond these defaults.
func withWatchTestDefaults(t *testing.T) {
	t.Helper()

	origLink, origRoute := linkSubscribeFn, routeSubscribeFn
	origResolve := resolveInterfacesFn
	origDebounce := debounceInterval
	origHook := onReconcileDone
	t.Cleanup(func() {
		linkSubscribeFn, routeSubscribeFn = origLink, origRoute
		resolveInterfacesFn = origResolve
		debounceInterval = origDebounce
		onReconcileDone = origHook
	})

	linkSubscribeFn = stubLinkSubscribe(nil)
	routeSubscribeFn = stubRouteSubscribe(nil)
	resolveInterfacesFn = func() ([]string, error) { return nil, nil }
	debounceInterval = 10 * time.Millisecond
}

func TestWatch_NilProgramIsError(t *testing.T) {
	withWatchTestDefaults(t)

	err := Watch(context.Background(), nil, []string{testIfaceEth0})
	if err == nil {
		t.Fatal("Watch(nil program, ...) error = nil, want an error")
	}
}

func TestWatch_LinkSubscribeFailurePropagates(t *testing.T) {
	withWatchTestDefaults(t)

	wantErr := errors.New("simulated link subscribe failure")
	linkSubscribeFn = func(chan<- netlink.LinkUpdate, <-chan struct{}, netlink.LinkSubscribeOptions) error {
		return wantErr
	}

	err := Watch(context.Background(), fakeProgram, nil)
	if !errors.Is(err, wantErr) {
		t.Errorf("Watch() error = %v, want it to wrap %v", err, wantErr)
	}
}

func TestWatch_RouteSubscribeFailurePropagates(t *testing.T) {
	withWatchTestDefaults(t)

	wantErr := errors.New("simulated route subscribe failure")
	routeSubscribeFn = func(chan<- netlink.RouteUpdate, <-chan struct{}, netlink.RouteSubscribeOptions) error {
		return wantErr
	}

	err := Watch(context.Background(), fakeProgram, nil)
	if !errors.Is(err, wantErr) {
		t.Errorf("Watch() error = %v, want it to wrap %v", err, wantErr)
	}
}

// TestWatch_ContextCancelReturnsNil covers the no-events steady state: with
// no link/route changes at all, Watch must still return cleanly (nil, no
// hang, no leaked goroutine blocked forever) as soon as ctx is canceled.
func TestWatch_ContextCancelReturnsNil(t *testing.T) {
	withWatchTestDefaults(t)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- Watch(ctx, fakeProgram, []string{testIfaceEth0}) }()

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Watch() error = %v, want nil on ctx cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Watch() did not return after ctx was canceled")
	}
}

// TestDiffSets covers the pure added/removed set-diff logic Watch's
// reconcile step relies on, independent of any netlink or BPF interaction.
func TestDiffSets(t *testing.T) {
	tests := []struct {
		name        string
		current     []string
		next        []string
		wantAdded   []string
		wantRemoved []string
	}{
		{"NoChange", []string{testIfaceEth0}, []string{testIfaceEth0}, nil, nil},
		{"Added", []string{testIfaceEth0}, []string{testIfaceEth0, testIfaceEth1}, []string{testIfaceEth1}, nil},
		{"Removed", []string{testIfaceEth0, testIfaceEth1}, []string{testIfaceEth0}, nil, []string{testIfaceEth1}},
		{
			"AddedAndRemoved",
			[]string{testIfaceEth0}, []string{testIfaceEth1},
			[]string{testIfaceEth1}, []string{testIfaceEth0},
		},
		{"EmptyToEmpty", nil, nil, nil, nil},
		{"AllRemoved", []string{testIfaceEth0, testIfaceEth1}, nil, nil, []string{testIfaceEth0, testIfaceEth1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			added, removed := diffSets(toSet(tt.current), toSet(tt.next))
			sort.Strings(added)
			sort.Strings(removed)
			if !reflect.DeepEqual(added, tt.wantAdded) {
				t.Errorf("diffSets() added = %v, want %v", added, tt.wantAdded)
			}
			if !reflect.DeepEqual(removed, tt.wantRemoved) {
				t.Errorf("diffSets() removed = %v, want %v", removed, tt.wantRemoved)
			}
		})
	}
}

// fakeProgram is a zero-value, never-loaded *ebpf.Program used only to
// satisfy Watch's non-nil check in tests that never reach a real
// attach/detach call (because no trigger ever fires and/or
// resolveInterfacesFn keeps the resolved set unchanged from initial).
// Tests that actually exercise attachOne/Detach use a real loaded program
// instead (see TestWatch_ReEvaluatesAndReattachesOnInterfaceSetChange).
var fakeProgram = &ebpf.Program{}

// TestWatch_ReEvaluatesAndReattachesOnInterfaceSetChange is this milestone's
// exit criterion: a test simulating an interface-set change and confirming
// re-attachment without a process restart. It requires real root
// privileges to load/attach a BPF program and create an isolated test
// network namespace, so it is skipped (not silently passed) when not run as
// root.
//
// Setup: two dummy interfaces (A, B) in a fresh netns; the program is
// loaded and, standing in for whatever Start already did, Attach is called
// directly against A only (the "initial" resolved set). Watch is then run
// -- synchronously, on the same namespace-locked goroutine, since Watch's
// own netlink calls must run in the test netns and a plain "go Watch(...)"
// would run on a different, unswitched OS thread -- with:
//   - a fake link subscription that, when triggered, sends one
//     netlink.LinkUpdate to simulate "a link changed";
//   - resolveInterfacesFn stubbed to report [B] instead of [A], simulating
//     the underlying routing state having moved to a different interface;
//   - the onReconcileDone test hook used to wait deterministically for
//     Watch's reaction to finish, instead of guessing with a sleep.
//
// After Watch reacts (and is then stopped via ctx cancellation, driven by
// the same hook), B must carry the galactic uSID filter and A must not --
// confirming re-attachment happened without restarting anything.
func TestWatch_ReEvaluatesAndReattachesOnInterfaceSetChange(t *testing.T) {
	requireRoot(t)
	withWatchTestDefaults(t)

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-watch-test-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	const ifaceA = "usidwatchA"
	const ifaceB = "usidwatchB"

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	err = nsObj.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer handle.Close() //nolint:errcheck // best-effort cleanup

		for _, name := range []string{ifaceA, ifaceB} {
			dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
			if err := handle.LinkAdd(dummy); err != nil {
				return fmt.Errorf("add dummy link %q: %w", name, err)
			}
			if err := handle.LinkSetUp(dummy); err != nil {
				return fmt.Errorf("set dummy link %q up: %w", name, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("setup dummy interfaces: %v", err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		objs, err := Load(pinDir)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		defer func() { _ = objs.Close() }()

		if err := Attach(objs.UsidIngress, []string{ifaceA}); err != nil {
			return fmt.Errorf("initial attach to %q: %w", ifaceA, err)
		}

		trigger := make(chan struct{}, 1)
		linkSubscribeFn = stubLinkSubscribe(trigger)

		var resolveCalls int
		resolveInterfacesFn = func() ([]string, error) {
			resolveCalls++
			return []string{ifaceB}, nil
		}

		reconciled := make(chan struct{}, 4)
		onReconcileDone = func() {
			select {
			case reconciled <- struct{}{}:
			default:
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Drive the scenario from a separate (non-netns-bound) goroutine:
		// trigger the simulated link-change event, wait for Watch to have
		// reacted at least once, then stop the watch loop. None of this
		// driver goroutine's own work touches netlink, so it doesn't need
		// to be bound to the test netns -- only Watch's internal
		// attachOne/Detach calls do, and Watch runs synchronously below on
		// this namespace-locked goroutine.
		go func() {
			trigger <- struct{}{}
			select {
			case <-reconciled:
			case <-time.After(5 * time.Second):
			}
			cancel()
		}()

		if err := Watch(ctx, objs.UsidIngress, []string{ifaceA}); err != nil {
			return fmt.Errorf("watch: %w", err)
		}

		if resolveCalls == 0 {
			return errors.New("resolveInterfacesFn was never called -- the simulated link event never reached Watch")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("watch scenario: %v", err)
	}

	// Verify the re-attachment actually happened at the kernel level: B now
	// carries the filter, A no longer does.
	err = nsObj.Do(func(_ ns.NetNS) error {
		linkB, err := netlink.LinkByName(ifaceB)
		if err != nil {
			return fmt.Errorf("find link %q: %w", ifaceB, err)
		}
		filtersB, err := netlink.FilterList(linkB, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			return fmt.Errorf("list filters on %q: %w", ifaceB, err)
		}
		if len(filtersB) != 1 {
			return fmt.Errorf("filter count on %q = %d, want 1 (re-attached after the interface-set change)",
				ifaceB, len(filtersB))
		}

		linkA, err := netlink.LinkByName(ifaceA)
		if err != nil {
			return fmt.Errorf("find link %q: %w", ifaceA, err)
		}
		filtersA, err := netlink.FilterList(linkA, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			return fmt.Errorf("list filters on %q: %w", ifaceA, err)
		}
		if len(filtersA) != 0 {
			return fmt.Errorf("filter count on %q = %d, want 0 (detached after dropping out of the resolved set)",
				ifaceA, len(filtersA))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("post-watch verification: %v", err)
	}
}

// TestWatch_HealsExternallyClearedFilterWithoutSetChange reproduces the
// bug found investigating a live cluster where cross-region VPC pings had
// gone dark: the underlay routing daemon (FRR) restarted, bounced eth0,
// and that cleared this package's own tc-bpf ingress filter -- but eth0
// never left the resolved interface set (it was, and remained, the
// default-route interface), so the original diff-only reconcile (which
// only ever attached interfaces newly present in added) never noticed and
// never re-attached it, silently blackholing all traffic through that
// interface until the pod restarted.
//
// Setup: one dummy interface (A); Attach it once, then reach through to
// the kernel and remove the filter directly (netlink.FilterDel) to
// simulate the external drift, all without ever telling Watch the
// resolved set changed -- resolveInterfacesFn keeps reporting [A] on every
// call. A real diff-only reconcile would see added=nil, removed=nil and
// do nothing. reconcile must instead re-attach A anyway.
func TestWatch_HealsExternallyClearedFilterWithoutSetChange(t *testing.T) {
	requireRoot(t)
	withWatchTestDefaults(t)

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-watch-heal-test-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	const ifaceA = "usidhealA"

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	err = nsObj.Do(func(_ ns.NetNS) error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer handle.Close() //nolint:errcheck // best-effort cleanup

		dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: ifaceA}}
		if err := handle.LinkAdd(dummy); err != nil {
			return fmt.Errorf("add dummy link %q: %w", ifaceA, err)
		}
		return handle.LinkSetUp(dummy)
	})
	if err != nil {
		t.Fatalf("setup dummy interface: %v", err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		objs, err := Load(pinDir)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		defer func() { _ = objs.Close() }()

		if err := Attach(objs.UsidIngress, []string{ifaceA}); err != nil {
			return fmt.Errorf("initial attach to %q: %w", ifaceA, err)
		}

		// Simulate the external drift: clear the filter kernel-side without
		// going through this package's own Detach, so Watch's internal
		// bookkeeping still believes ifaceA is attached.
		link, err := netlink.LinkByName(ifaceA)
		if err != nil {
			return fmt.Errorf("find link %q: %w", ifaceA, err)
		}
		filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			return fmt.Errorf("list filters on %q: %w", ifaceA, err)
		}
		if len(filters) != 1 {
			return fmt.Errorf("filter count on %q = %d, want 1 before simulated drift", ifaceA, len(filters))
		}
		if err := netlink.FilterDel(filters[0]); err != nil {
			return fmt.Errorf("simulate external filter clear on %q: %w", ifaceA, err)
		}

		trigger := make(chan struct{}, 1)
		linkSubscribeFn = stubLinkSubscribe(trigger)

		resolveInterfacesFn = func() ([]string, error) { return []string{ifaceA}, nil }

		reconciled := make(chan struct{}, 4)
		onReconcileDone = func() {
			select {
			case reconciled <- struct{}{}:
			default:
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			trigger <- struct{}{}
			select {
			case <-reconciled:
			case <-time.After(5 * time.Second):
			}
			cancel()
		}()

		if err := Watch(ctx, objs.UsidIngress, []string{ifaceA}); err != nil {
			return fmt.Errorf("watch: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("watch scenario: %v", err)
	}

	err = nsObj.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(ifaceA)
		if err != nil {
			return fmt.Errorf("find link %q: %w", ifaceA, err)
		}
		filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			return fmt.Errorf("list filters on %q: %w", ifaceA, err)
		}
		if len(filters) != 1 {
			return fmt.Errorf(
				"filter count on %q = %d, want 1 (self-healed after external drift, with no interface-set change)",
				ifaceA, len(filters))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("post-watch verification: %v", err)
	}
}
