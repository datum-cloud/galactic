// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpattach

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
)

// ErrDispatcherInUse is ReleaseIdleDispatcher refusing to detach a dispatcher
// that another datapath's live slot still depends on.
var ErrDispatcherInUse = errors.New("xdpattach: the XDP dispatcher is serving another datapath")

// ReleaseIdleDispatcher detaches the node's XDP dispatcher under pinDir from
// ifaces, so a datapath switched back from dispatch to direct mode can attach
// its own program, and empties own, the caller's slots. It does nothing on a
// node that never ran the dispatcher.
//
// It refuses, with ErrDispatcherInUse, while any slot outside own is live and
// the dispatcher holds one of ifaces: that datapath runs from the dispatcher
// on the interface, and detaching it would cut its traffic. The live slots are
// read under the dispatch lock, which every Fill takes too, so no datapath can
// take a slot between the check and the release.
func ReleaseIdleDispatcher(ctx context.Context, pinDir string, ifaces []string, own ...xdpdispatch.Slot) error {
	if _, err := os.Stat(filepath.Join(pinDir, "links")); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	dispatcher, err := xdpdispatch.Open(ctx, pinDir)
	if err != nil {
		return fmt.Errorf("xdpattach: open the node's XDP dispatcher to release it: %w", err)
	}
	defer dispatcher.Close() //nolint:errcheck // our own descriptors; the pins are what matter

	lock, err := dispatcher.Lock(ctx)
	if err != nil {
		return err
	}
	defer lock.Unlock()
	live, err := dispatcher.LiveSlots()
	if err != nil {
		return err
	}
	others := slices.DeleteFunc(live, func(s xdpdispatch.Slot) bool { return slices.Contains(own, s) })

	for _, name := range ifaces {
		l, err := linkByNameFn(name)
		if err != nil {
			return fmt.Errorf("xdpattach: find interface %q: %w", name, err)
		}
		ifindex := l.Attrs().Index
		linked, err := dispatcher.Linked(ifindex)
		if err != nil {
			return err
		}
		if !linked {
			continue
		}
		if len(others) > 0 {
			return fmt.Errorf("%w: dispatcher slots %v are live on interface %q, so a direct attach would "+
				"cut that datapath's traffic; run in dispatch mode", ErrDispatcherInUse, others, name)
		}
		if err := lock.Release(ifindex); err != nil {
			return err
		}
		slog.Info("Released the idle XDP dispatcher from interface for a direct attach", "interface", name)
	}
	for _, slot := range own {
		if err := lock.Clear(slot); err != nil {
			return err
		}
	}
	return nil
}

// ClearDispatcherSlots empties slots in the node's XDP dispatcher under
// pinDir, for a datapath turned off, so the dispatcher passes its traffic on
// at once rather than once the slots' leases lapse. Every other slot, and the
// dispatcher itself, are left alone. It does nothing on a node that never ran
// the dispatcher.
func ClearDispatcherSlots(ctx context.Context, pinDir string, slots ...xdpdispatch.Slot) error {
	if _, err := os.Stat(filepath.Join(pinDir, "links")); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	dispatcher, err := xdpdispatch.Open(ctx, pinDir)
	if err != nil {
		return fmt.Errorf("xdpattach: open the node's XDP dispatcher: %w", err)
	}
	defer dispatcher.Close() //nolint:errcheck // our own descriptors
	lock, err := dispatcher.Lock(ctx)
	if err != nil {
		return err
	}
	defer lock.Unlock()
	for _, slot := range slots {
		if err := lock.Clear(slot); err != nil {
			return err
		}
	}
	return nil
}
