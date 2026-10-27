// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nldump lists links, addresses and routes over netlink without
// failing when another process changes them mid-dump.
//
// The kernel flags a dump interrupted when the state it walks changes while
// the dump runs, as it does whenever another process adds or removes a link,
// address or route. The package-level netlink list functions make a single
// attempt and return netlink.ErrDumpInterrupted, so any churn on the node
// fails the caller. These functions dump over a handle that retries
// internally, retry the whole dump a bounded number of times on top of that,
// and never return a partial result: an entry missing from an interrupted
// dump would look absent.
//
// Each call opens its own netlink socket in the calling thread's network
// namespace, with the same send and receive timeout, as the package-level
// functions do.
package nldump

import (
	"errors"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// dumpAttempts and dumpBackoff bound how long a dump keeps retrying when
// other processes keep interrupting it. Each attempt is itself up to 10 tries
// inside netlink, so this only matters under sustained churn; the pause lets
// a burst of changes finish before the next dump.
const (
	dumpAttempts = 5
	dumpBackoff  = 20 * time.Millisecond
)

// sleep is time.Sleep, replaced by tests.
var sleep = time.Sleep

// LinkList returns every link in the calling thread's network namespace.
func LinkList() ([]netlink.Link, error) {
	return dump(func(h *netlink.Handle) ([]netlink.Link, error) { return h.LinkList() })
}

// AddrList returns link's addresses of family, or every link's when link is
// nil. Errors other than an interrupted dump are returned as netlink returns
// them.
func AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return dump(func(h *netlink.Handle) ([]netlink.Addr, error) { return h.AddrList(link, family) })
}

// RouteListFiltered returns the routes of family that match filter on the
// fields filterMask selects, as netlink.RouteListFiltered does.
func RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return dump(func(h *netlink.Handle) ([]netlink.Route, error) {
		return h.RouteListFiltered(family, filter, filterMask)
	})
}

// dump runs list over a retrying rtnetlink handle, through retry.
func dump[T any](list func(*netlink.Handle) (T, error)) (T, error) {
	var zero T
	handle, err := netlink.NewHandleWithOptions(netlink.HandleOptions{RetryInterrupted: true}, unix.NETLINK_ROUTE)
	if err != nil {
		return zero, err
	}
	defer handle.Close() //nolint:errcheck // best-effort close of our own socket
	// A handle's own socket has no timeout, unlike the per-request socket the
	// package-level functions open, so a dump the kernel never finishes would
	// block forever.
	if err := handle.SetSocketTimeout(netlink.GetSocketTimeout()); err != nil {
		return zero, err
	}
	return retry(func() (T, error) { return list(handle) })
}

// retry calls list until it returns anything but netlink.ErrDumpInterrupted,
// at most dumpAttempts times, pausing longer after each interruption. The
// result of an interrupted attempt is discarded, never returned.
func retry[T any](list func() (T, error)) (T, error) {
	var zero T
	for attempt := 1; ; attempt++ {
		got, err := list()
		if err == nil {
			return got, nil
		}
		if !errors.Is(err, netlink.ErrDumpInterrupted) || attempt == dumpAttempts {
			return zero, err
		}
		sleep(time.Duration(attempt) * dumpBackoff)
	}
}
