// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpattach

import (
	"context"
	"log/slog"
	"time"

	"github.com/vishvananda/netlink"
)

// debounceInterval coalesces a burst of netlink link and route events, such as
// BGP installing a full table or a bond enslaving a member, into one
// re-evaluation. A var so tests can shrink it.
var debounceInterval = 250 * time.Millisecond

// resyncInterval is how often the set is re-evaluated with no event at all. It
// is the backstop for an event netlink dropped, or a subscription that failed
// or closed, which would otherwise leave an uplink uncovered with nothing to
// notice. A var so tests can shrink it.
var resyncInterval = 30 * time.Second

// linkSubscribeFn and routeSubscribeFn are override points so tests can push
// synthetic events without a live netlink socket or root.
var (
	linkSubscribeFn  = netlink.LinkSubscribeWithOptions
	routeSubscribeFn = netlink.RouteSubscribeWithOptions
)

// OnNetlinkChange calls fn once at the start, then after every debounced burst
// of netlink link or route events and every resyncInterval with none, until
// ctx is done. Calls are serialized on the calling goroutine, which this
// blocks. It is how a caller keeps a Set current: fn resolves the interfaces
// again and hands them to Set.Reconcile.
//
// A subscription that cannot be established, or closes later, is logged and
// leaves the resync as the only trigger rather than ending the loop, so a
// netlink failure degrades how fast a change is noticed, never whether it is.
func OnNetlinkChange(ctx context.Context, fn func()) {
	// Buffered by one so netlink's own subscription goroutine can hand off an
	// in-flight update without blocking forever if it races with this
	// function returning.
	linkCh := make(chan netlink.LinkUpdate, 1)
	routeCh := make(chan netlink.RouteUpdate, 1)
	done := make(chan struct{})
	defer close(done)

	if err := linkSubscribeFn(linkCh, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) { slog.Warn("xdpattach: link change subscription error", "err", err) },
	}); err != nil {
		slog.Error("xdpattach: cannot subscribe to link changes; relying on periodic resync", "err", err)
		linkCh = nil
	}
	if err := routeSubscribeFn(routeCh, done, netlink.RouteSubscribeOptions{
		ErrorCallback: func(err error) { slog.Warn("xdpattach: route change subscription error", "err", err) },
	}); err != nil {
		slog.Error("xdpattach: cannot subscribe to route changes; relying on periodic resync", "err", err)
		routeCh = nil
	}

	resync := time.NewTicker(resyncInterval)
	defer resync.Stop()

	debounce := time.NewTimer(debounceInterval)
	defer debounce.Stop()
	// Armed from the start, so the set is re-evaluated once right away: an
	// event that arrived between the startup attach and this subscription
	// would otherwise wait for the first resync.
	debounceC := debounce.C
	schedule := func() {
		if debounceC != nil {
			return
		}
		debounce.Reset(debounceInterval)
		debounceC = debounce.C
	}

	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-linkCh:
			if !ok {
				slog.Warn("xdpattach: link change subscription closed; relying on periodic resync")
				linkCh = nil
				continue
			}
			schedule()
		case _, ok := <-routeCh:
			if !ok {
				slog.Warn("xdpattach: route change subscription closed; relying on periodic resync")
				routeCh = nil
				continue
			}
			schedule()
		case <-resync.C:
			schedule()
		case <-debounceC:
			debounceC = nil
			fn()
		}
	}
}
