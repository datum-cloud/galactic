// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package routes holds the tenant routes galactic-router hands Worker
// through the Routes service. Worker records them here; the Fabric module
// writes them into egress_route_table and removes withdrawn ones.
//
// The table lives in memory only. galactic-router sends every route it holds
// whenever it opens a stream, so a Worker restart loses nothing it needs, and
// a route the table has never heard of is never removed from the datapath
// except by an explicit withdrawal.
package routes

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Key names a tenant route: a prefix in one VPC.
type Key struct {
	VPC    string
	Prefix netip.Prefix
}

// Route is one tenant route.
type Route struct {
	Key
	// TableID is the kernel VRF table galactic-router resolved for the VPC.
	TableID uint32
	// SID is the IPv6 SID the route encapsulates toward. A withdrawal of a
	// route the table never held has no SID.
	SID netip.Addr
}

// Withdrawal is a withdrawn route whose removal from the datapath the Fabric
// module has not confirmed yet, or has confirmed (Removed).
type Withdrawal struct {
	Route
	Removed bool
	// removedAt is when the removal was confirmed.
	removedAt time.Time
}

// removedRetention is how long a confirmed withdrawal is kept for status.
const removedRetention = time.Hour

// Table is the set of tenant routes by VPC and the routes withdrawn from it.
// It is safe for concurrent use.
type Table struct {
	// now is the clock, time.Now outside tests.
	now       func() time.Time
	mu        sync.Mutex
	routes    map[string]map[netip.Prefix]Route
	withdrawn map[string]map[netip.Prefix]Withdrawal
}

// New returns an empty table.
func New() *Table {
	return &Table{
		now:       time.Now,
		routes:    map[string]map[netip.Prefix]Route{},
		withdrawn: map[string]map[netip.Prefix]Withdrawal{},
	}
}

// Apply records upserts and withdrawals, in that order, and returns the VPCs
// whose routes changed, sorted. An upsert replaces the route with the same
// key and clears its withdrawal. A withdrawal of a held route keeps the
// route's table and SID, so only the row written for it is removed; a
// withdrawal of a route the table never held has no SID.
func (t *Table) Apply(upserts []Route, withdrawals []Key) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := map[string]struct{}{}
	for _, r := range upserts {
		r.Prefix = r.Prefix.Masked()
		if cur, ok := t.routes[r.VPC][r.Prefix]; ok && cur == r {
			continue
		}
		if t.routes[r.VPC] == nil {
			t.routes[r.VPC] = map[netip.Prefix]Route{}
		}
		t.routes[r.VPC][r.Prefix] = r
		delete(t.withdrawn[r.VPC], r.Prefix)
		changed[r.VPC] = struct{}{}
	}
	for _, k := range withdrawals {
		k.Prefix = k.Prefix.Masked()
		r, held := t.routes[k.VPC][k.Prefix]
		if !held {
			if w, ok := t.withdrawn[k.VPC][k.Prefix]; ok && !w.Removed {
				continue
			}
			r = Route{Key: k}
		}
		delete(t.routes[k.VPC], k.Prefix)
		if len(t.routes[k.VPC]) == 0 {
			delete(t.routes, k.VPC)
		}
		if t.withdrawn[k.VPC] == nil {
			t.withdrawn[k.VPC] = map[netip.Prefix]Withdrawal{}
		}
		t.withdrawn[k.VPC][k.Prefix] = Withdrawal{Route: r}
		changed[k.VPC] = struct{}{}
	}
	t.pruneLocked()
	out := make([]string, 0, len(changed))
	for v := range changed {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Routes returns vpc's routes, sorted by prefix.
func (t *Table) Routes(vpc string) []Route {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Route, 0, len(t.routes[vpc]))
	for _, r := range t.routes[vpc] {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return lessPrefix(out[i].Prefix, out[j].Prefix) })
	return out
}

// Withdrawn returns vpc's withdrawals, sorted by prefix.
func (t *Table) Withdrawn(vpc string) []Withdrawal {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Withdrawal, 0, len(t.withdrawn[vpc]))
	for _, w := range t.withdrawn[vpc] {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return lessPrefix(out[i].Prefix, out[j].Prefix) })
	return out
}

// ConfirmRemoved marks the withdrawals in removed as removed from the
// datapath, provided each is still withdrawn with the same table and SID. A
// removed withdrawal is kept for removedRetention so status can report the
// destination's route as withdrawn rather than never learned.
func (t *Table) ConfirmRemoved(removed []Route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, r := range removed {
		w, ok := t.withdrawn[r.VPC][r.Prefix]
		if ok && w.Route == r {
			w.Removed, w.removedAt = true, t.now()
			t.withdrawn[r.VPC][r.Prefix] = w
		}
	}
}

// pruneLocked drops confirmed withdrawals older than removedRetention.
func (t *Table) pruneLocked() {
	now := t.now()
	for vpc, ws := range t.withdrawn {
		for p, w := range ws {
			if w.Removed && now.Sub(w.removedAt) > removedRetention {
				delete(ws, p)
			}
		}
		if len(ws) == 0 {
			delete(t.withdrawn, vpc)
		}
	}
}

// Forget drops every route and withdrawal of vpc, for a VPC whose host VRF is
// gone and whose rows went with it.
func (t *Table) Forget(vpc string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.routes, vpc)
	delete(t.withdrawn, vpc)
}

// HasWork reports whether vpc has a route or an unconfirmed withdrawal.
func (t *Table) HasWork(vpc string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.routes[vpc]) > 0 {
		return true
	}
	for _, w := range t.withdrawn[vpc] {
		if !w.Removed {
			return true
		}
	}
	return false
}

// Covering returns the route of vpc with the longest prefix containing addr,
// and the withdrawal with the longest prefix containing it.
func (t *Table) Covering(vpc string, addr netip.Addr) (Route, bool, Withdrawal, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var (
		route   Route
		haveR   bool
		withdr  Withdrawal
		haveW   bool
		addrUnm = addr.Unmap()
	)
	for p, r := range t.routes[vpc] {
		if p.Contains(addrUnm) && (!haveR || p.Bits() > route.Prefix.Bits()) {
			route, haveR = r, true
		}
	}
	for p, w := range t.withdrawn[vpc] {
		if p.Contains(addrUnm) && (!haveW || p.Bits() > withdr.Prefix.Bits()) {
			withdr, haveW = w, true
		}
	}
	return route, haveR, withdr, haveW
}

func lessPrefix(a, b netip.Prefix) bool {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c < 0
	}
	return a.Bits() < b.Bits()
}
