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
// fails the caller. These functions retry an interrupted dump a bounded
// number of times and never return a partial result: an entry missing from an
// interrupted dump would look absent. Every interrupted attempt, and every
// dump still interrupted on its last attempt, is counted in the metrics
// MustRegister exposes, so churn is visible before it fails a caller.
//
// Each call opens its own netlink socket in the calling thread's network
// namespace, with the same send and receive timeout, as the package-level
// functions do.
package nldump

import (
	"errors"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// dumpRounds, triesPerRound and roundBackoff bound how long a dump keeps
// retrying when other processes keep interrupting it. The tries within a
// round run back to back, as netlink's own retry does; the pause after each
// round, longer each time, lets a burst of changes finish before the next.
const (
	dumpRounds    = 5
	triesPerRound = 10
	roundBackoff  = 20 * time.Millisecond
)

// labelKind names the listing kind, one of the kind* values.
const labelKind = "kind"

// Listing kinds, the values of labelKind.
const (
	kindLink    = "link"
	kindAddress = "address"
	kindRoute   = "route"
)

var (
	interrupted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "galactic",
		Subsystem: "netlink_dump",
		Name:      "interrupted_total",
		Help: "Netlink listing attempts the kernel interrupted because the state they walked changed, " +
			"by kind. Each is discarded and retried.",
	}, []string{labelKind})
	failures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "galactic",
		Subsystem: "netlink_dump",
		Name:      "failures_total",
		Help:      "Netlink listings still interrupted on their last attempt, which failed their caller, by kind.",
	}, []string{labelKind})
)

func init() {
	for _, kind := range []string{kindLink, kindAddress, kindRoute} {
		interrupted.WithLabelValues(kind)
		failures.WithLabelValues(kind)
	}
}

// MustRegister registers the interruption and failure counters against reg,
// panicking on a duplicate as the underlying registry does. The counters are
// process-wide, so a process registers them once, at startup.
func MustRegister(reg prometheus.Registerer) {
	reg.MustRegister(interrupted, failures)
}

// sleep is time.Sleep, replaced by tests.
var sleep = time.Sleep

// LinkList returns every link in the calling thread's network namespace.
func LinkList() ([]netlink.Link, error) {
	return dump(kindLink, func(h *netlink.Handle) ([]netlink.Link, error) { return h.LinkList() })
}

// AddrList returns link's addresses of family, or every link's when link is
// nil. Errors other than an interrupted dump are returned as netlink returns
// them.
func AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return dump(kindAddress, func(h *netlink.Handle) ([]netlink.Addr, error) { return h.AddrList(link, family) })
}

// RouteListFiltered returns the routes of family that match filter on the
// fields filterMask selects, as netlink.RouteListFiltered does.
func RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return dump(kindRoute, func(h *netlink.Handle) ([]netlink.Route, error) {
		return h.RouteListFiltered(family, filter, filterMask)
	})
}

// dump runs list over an rtnetlink handle, through retry.
func dump[T any](kind string, list func(*netlink.Handle) (T, error)) (T, error) {
	var zero T
	// The handle makes one attempt per call, so retry sees, and counts, every
	// interruption.
	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
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
	return retry(kind, func() (T, error) { return list(handle) })
}

// retry calls list until it returns anything but netlink.ErrDumpInterrupted,
// at most dumpRounds*triesPerRound times, pausing after each round. It counts
// every interrupted attempt, and a final one as a failure. The result of an
// interrupted attempt is discarded, never returned.
func retry[T any](kind string, list func() (T, error)) (T, error) {
	var zero T
	for attempt := 1; ; attempt++ {
		got, err := list()
		if err == nil {
			return got, nil
		}
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			return zero, err
		}
		interrupted.WithLabelValues(kind).Inc()
		if attempt == dumpRounds*triesPerRound {
			failures.WithLabelValues(kind).Inc()
			// netlink's own message counts only the handle's single try.
			return zero, fmt.Errorf("netlink %s dump still interrupted after %d attempts: %w", kind, attempt, err)
		}
		if attempt%triesPerRound == 0 {
			sleep(time.Duration(attempt/triesPerRound) * roundBackoff)
		}
	}
}
