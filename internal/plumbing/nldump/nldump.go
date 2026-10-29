// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nldump lists links, addresses, routes, neighbors and rules over
// netlink without failing when another process changes them mid-dump.
//
// The kernel flags a dump interrupted when the state it walks changes while
// the dump runs, as it does whenever another process adds or removes a link,
// address, route, neighbor or rule. The netlink list functions and Handle
// methods make a single attempt and return netlink.ErrDumpInterrupted, so any
// churn on the node fails the caller. These functions retry an interrupted
// dump a bounded number of times and never return a partial result: an entry
// missing from an interrupted dump would look absent. Every interrupted
// attempt, and every dump still interrupted on its last attempt, is counted
// in metrics created on the instrumentation library's registry when the
// package loads, so churn is visible before it fails a caller.
//
// Each package-level function opens its own netlink socket in the calling
// thread's network namespace, with the same send and receive timeout, as the
// package-level netlink functions do. On returns a Lister that lists over a
// handle the caller already holds instead, such as one opened in another
// network namespace.
package nldump

import (
	"errors"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"go.miloapis.com/instrumentation/metrics"
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
	kindLink     = "link"
	kindAddress  = "address"
	kindRoute    = "route"
	kindNeighbor = "neighbor"
	kindRule     = "rule"
)

var (
	interrupted = metrics.NewCounterVec(prometheus.CounterOpts{
		Namespace: "galactic",
		Subsystem: "netlink_dump",
		Name:      "interrupted_total",
		Help: "Netlink listing attempts the kernel interrupted because the state they walked changed, " +
			"by kind. Each is discarded and retried.",
	}, []string{labelKind})
	failures = metrics.NewCounterVec(prometheus.CounterOpts{
		Namespace: "galactic",
		Subsystem: "netlink_dump",
		Name:      "failures_total",
		Help:      "Netlink listings still interrupted on their last attempt, which failed their caller, by kind.",
	}, []string{labelKind})
)

func init() {
	for _, kind := range []string{kindLink, kindAddress, kindRoute, kindNeighbor, kindRule} {
		interrupted.WithLabelValues(kind)
		failures.WithLabelValues(kind)
	}
}

// sleep is time.Sleep, replaced by tests.
var sleep = time.Sleep

// LinkList returns every link in the calling thread's network namespace.
func LinkList() ([]netlink.Link, error) {
	return dump(Lister.LinkList)
}

// AddrList returns link's addresses of family, or every link's when link is
// nil. Errors other than an interrupted dump are returned as netlink returns
// them.
func AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return dump(func(l Lister) ([]netlink.Addr, error) { return l.AddrList(link, family) })
}

// RouteList returns the main-table routes of family through link, or through
// any link when link is nil, as netlink.RouteList does.
func RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return dump(func(l Lister) ([]netlink.Route, error) { return l.RouteList(link, family) })
}

// RouteListFiltered returns the routes of family that match filter on the
// fields filterMask selects, as netlink.RouteListFiltered does.
func RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return dump(func(l Lister) ([]netlink.Route, error) { return l.RouteListFiltered(family, filter, filterMask) })
}

// NeighList returns the neighbor entries of family on the link with index
// linkIndex, or on every link when linkIndex is 0, as netlink.NeighList does.
func NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	return dump(func(l Lister) ([]netlink.Neigh, error) { return l.NeighList(linkIndex, family) })
}

// RuleList returns the policy routing rules of family, as netlink.RuleList
// does.
func RuleList(family int) ([]netlink.Rule, error) {
	return dump(func(l Lister) ([]netlink.Rule, error) { return l.RuleList(family) })
}

// Lister runs the retrying listings over a netlink handle its caller owns, in
// whatever network namespace that handle was opened. It neither closes the
// handle nor changes its socket timeout.
type Lister struct {
	h *netlink.Handle
}

// On returns a Lister over h.
func On(h *netlink.Handle) Lister {
	return Lister{h: h}
}

// LinkList returns every link, as LinkList does.
func (l Lister) LinkList() ([]netlink.Link, error) {
	return retry(kindLink, l.h.LinkList)
}

// AddrList returns link's addresses of family, as AddrList does.
func (l Lister) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return retry(kindAddress, func() ([]netlink.Addr, error) { return l.h.AddrList(link, family) })
}

// RouteList returns the routes of family through link, as RouteList does.
func (l Lister) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return retry(kindRoute, func() ([]netlink.Route, error) { return l.h.RouteList(link, family) })
}

// RouteListFiltered returns the routes matching filter, as RouteListFiltered
// does.
func (l Lister) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return retry(kindRoute, func() ([]netlink.Route, error) { return l.h.RouteListFiltered(family, filter, filterMask) })
}

// NeighList returns the neighbor entries on linkIndex, as NeighList does.
func (l Lister) NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	return retry(kindNeighbor, func() ([]netlink.Neigh, error) { return l.h.NeighList(linkIndex, family) })
}

// RuleList returns the policy routing rules of family, as RuleList does.
func (l Lister) RuleList(family int) ([]netlink.Rule, error) {
	return retry(kindRule, func() ([]netlink.Rule, error) { return l.h.RuleList(family) })
}

// dump runs list over a Lister on a fresh rtnetlink handle in the calling
// thread's network namespace.
func dump[T any](list func(Lister) (T, error)) (T, error) {
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
	return list(On(handle))
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
