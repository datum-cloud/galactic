// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"log/slog"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// tapCarrierLinkSubscribe is the netlink link subscription watchTapCarrier
// reads. A var so tests can feed it synthetic updates.
var tapCarrierLinkSubscribe = netlink.LinkSubscribeWithOptions

// tapCarrierResubscribeDelay is how long watchTapCarrier waits before
// subscribing again after its subscription fails or ends. A var so tests can
// shrink it.
var tapCarrierResubscribeDelay = 5 * time.Second

// signalEvery signals on trigger every interval until ctx is done, without
// blocking: a signal already pending covers this one.
func signalEvery(ctx context.Context, interval time.Duration, trigger chan<- struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			select {
			case trigger <- struct{}{}:
			default:
			}
		}
	}
}

// watchTapCarrier signals on trigger whenever a tap gains carrier, until ctx is
// done. A tap gains carrier when its VMM opens it, which is the moment its
// guest can start receiving Router Advertisements, so Run reconciles the radv
// actors on the signal instead of waiting for radvReconcileInterval.
//
// trigger should be buffered by one. A send never blocks: a signal already
// pending covers this one, since a reconcile looks at every recorded
// attachment. A failed or ended subscription is retried after
// tapCarrierResubscribeDelay; until then the reconcile ticker still serves
// every tap, only less promptly.
func watchTapCarrier(ctx context.Context, trigger chan<- struct{}) {
	for {
		if err := watchTapCarrierOnce(ctx, trigger); err != nil {
			slog.Warn("Failed to subscribe to tap carrier changes, will retry",
				"err", err, "retryIn", tapCarrierResubscribeDelay)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(tapCarrierResubscribeDelay):
		}
	}
}

// watchTapCarrierOnce runs one subscription until ctx is done or the
// subscription ends, returning an error only if subscribing failed.
func watchTapCarrierOnce(ctx context.Context, trigger chan<- struct{}) error {
	// Buffered so netlink's own goroutine can hand off an update in flight
	// as this function returns.
	updates := make(chan netlink.LinkUpdate, 16)
	done := make(chan struct{})
	defer close(done)

	if err := tapCarrierLinkSubscribe(updates, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			slog.Debug("Tap carrier subscription error", "err", err)
		},
	}); err != nil {
		return err
	}

	carrier := make(map[int32]bool)
	for {
		select {
		case <-ctx.Done():
			return nil
		case u, ok := <-updates:
			if !ok {
				slog.Warn("Tap carrier subscription ended, will resubscribe")
				return nil
			}
			if tapGainedCarrier(carrier, u) {
				select {
				case trigger <- struct{}{}:
				default:
				}
			}
		}
	}
}

// tapGainedCarrier reports whether u shows a tap gaining carrier, given the
// carrier state last seen per interface index, which it updates. A link is
// reported again on every change to any of its attributes, so only the
// transition counts. A tap seen for the first time with carrier counts as
// gaining it.
func tapGainedCarrier(carrier map[int32]bool, u netlink.LinkUpdate) bool {
	index := u.Index
	if u.Header.Type == unix.RTM_DELLINK {
		delete(carrier, index)
		return false
	}
	link := u.Link
	if link == nil || link.Type() != "tuntap" {
		return false
	}

	up := link.Attrs().RawFlags&unix.IFF_LOWER_UP != 0
	was := carrier[index]
	carrier[index] = up
	return up && !was
}
