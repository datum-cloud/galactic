// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/srv6"
)

// publicUplinkLinkSubscribe and publicUplinkNeighSubscribe are the netlink
// subscriptions watchPublicUplink reads. Vars so tests can feed them
// synthetic updates.
var (
	publicUplinkLinkSubscribe  = netlink.LinkSubscribeWithOptions
	publicUplinkNeighSubscribe = netlink.NeighSubscribeWithOptions
)

// publicUplinkDebounce coalesces a burst of link and neighbor changes, such as
// a bond losing every member at once, into one refresh. publicUplinkResubscribeDelay
// is how long watchPublicUplink waits before subscribing again after its
// subscription fails or ends. Vars so tests can shrink them.
var (
	publicUplinkDebounce         = 250 * time.Millisecond
	publicUplinkResubscribeDelay = 5 * time.Second
)

// startPublicUplinkWatch runs watchPublicUplink on attach.PinDir off the
// caller's goroutine, once the datapath is loaded.
func startPublicUplinkWatch(ctx context.Context, st ebpfDatapathState) {
	if st.objs == nil {
		return
	}
	go watchPublicUplink(ctx, attach.PinDir)
}

// watchPublicUplink keeps public_uplink_table on an uplink that can still
// reach the fabric, until ctx is done. usid_egress sends every DSR reply to
// that one next hop, so on a node with several uplinks, such as a compute node
// dual-homed to two edge nodes, the row must move the moment its uplink loses
// carrier or its neighbor, or every reply from this node's backends is lost
// with the edge node behind it. Every link change and IPv6 neighbor change
// refreshes the row (refreshPublicUplink), debounced. A failed or ended
// subscription is retried after publicUplinkResubscribeDelay; until then the
// datapath repair's GC tick still refreshes it, only less promptly.
func watchPublicUplink(ctx context.Context, pinDir string) {
	trigger := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-trigger:
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(publicUplinkDebounce):
			}
			select {
			case <-trigger:
			default:
			}
			changed, err := refreshPinnedPublicUplink(pinDir)
			if err != nil {
				slog.Warn("Cannot refresh this node's public uplink; DSR replies keep their current next hop",
					"err", err)
			} else if changed {
				slog.Info("Moved this node's DSR replies to another public uplink")
			}
		}
	}()

	for {
		if err := watchPublicUplinkOnce(ctx, trigger); err != nil {
			slog.Warn("Failed to subscribe to uplink changes, will retry",
				"err", err, "retryIn", publicUplinkResubscribeDelay)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(publicUplinkResubscribeDelay):
		}
	}
}

// watchPublicUplinkOnce runs one link and neighbor subscription until ctx is
// done or either ends, signalling trigger on every link change and every IPv6
// neighbor change. It returns an error only if subscribing failed.
func watchPublicUplinkOnce(ctx context.Context, trigger chan<- struct{}) error {
	done := make(chan struct{})
	defer close(done)

	links := make(chan netlink.LinkUpdate, 16)
	if err := publicUplinkLinkSubscribe(links, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) { slog.Debug("Uplink link subscription error", "err", err) },
	}); err != nil {
		return fmt.Errorf("subscribe to link updates: %w", err)
	}
	neighs := make(chan netlink.NeighUpdate, 64)
	if err := publicUplinkNeighSubscribe(neighs, done, netlink.NeighSubscribeOptions{
		ErrorCallback: func(err error) { slog.Debug("Uplink neighbor subscription error", "err", err) },
	}); err != nil {
		return fmt.Errorf("subscribe to neighbor updates: %w", err)
	}

	signal := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-links:
			if !ok {
				slog.Warn("Uplink link subscription ended, will resubscribe")
				return nil
			}
			signal()
		case u, ok := <-neighs:
			if !ok {
				slog.Warn("Uplink neighbor subscription ended, will resubscribe")
				return nil
			}
			if u.Family == netlink.FAMILY_V6 {
				signal()
			}
		}
	}
}

// refreshPinnedPublicUplink runs refreshPublicUplink on the
// public_uplink_table pinned under pinDir.
func refreshPinnedPublicUplink(pinDir string) (bool, error) {
	uplink, closer, err := egressroutemap.OpenPinnedPublicUplink(pinDir)
	if err != nil {
		return false, err
	}
	defer func() { _ = closer.Close() }()
	return refreshPublicUplink(uplink, srv6.ResolvePublicUplink)
}

// refreshPublicUplink rewrites uplink with the next hop resolve returns now,
// if it differs, and reports whether it did. A row never written is left for
// CNI ADD or the datapath repair to write: a node with no attachment sends no
// DSR reply. A resolve failure keeps the current row.
func refreshPublicUplink(uplink *egressroutemap.PublicUplink, resolve attachreg.UplinkResolver) (bool, error) {
	if _, _, _, ok, err := uplink.Get(); err != nil || !ok {
		return false, err
	}
	linkIndex, dmac, smac, err := resolve()
	if err != nil {
		return false, fmt.Errorf("resolve public uplink: %w", err)
	}
	return uplink.Update(linkIndex, dmac, smac)
}
