// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srcfilter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"sync"

	"github.com/vishvananda/netlink"
)

// ErrNoFabricRoutes means a pass found no route naming a fabric peer. A pass
// that finds none leaves the allow-list as it is rather than emptying it, since
// losing every route at once is far more often a routing daemon restarting than
// a node with no peers.
var ErrNoFabricRoutes = errors.New("no fabric peer routes inside the SR domain prefixes")

// Options configures a Reconciler.
type Options struct {
	Settings Settings
	// MinPrefixLen is the shortest route that becomes an entry.
	// DefaultMinPrefixLen when zero.
	MinPrefixLen int
	Target       Target
	// Slots assigns uplink slots. StableSlots when nil.
	Slots SlotAssigner
	// Routes lists the main table's IPv6 routes.
	Routes func() ([]netlink.Route, error)
	// Links lists every link on the host.
	Links func() ([]netlink.Link, error)
	// Uplinks returns the names of the interfaces the datapath is attached
	// to.
	Uplinks func() ([]string, error)
	// OwnLocator returns this node's own locator, or the zero Prefix when it
	// has none yet. Nil means none.
	OwnLocator func(ctx context.Context) (netip.Prefix, error)
}

// Result reports what one pass did.
type Result struct {
	Entries   int
	Added     int
	Updated   int
	Removed   int
	Unbound   int
	Changed   bool
	State     State
	SlotCount int
}

// Reconciler keeps a Target's allow-list, uplink slots and state in step with
// the host's routes. It is safe for concurrent use; passes are serialized.
type Reconciler struct {
	opts Options

	mu     sync.Mutex
	state  State
	loaded bool
}

// New returns a Reconciler for opts. It returns an error when a required
// field is missing or the mode is off, since an off filter needs no
// reconciler.
func New(opts Options) (*Reconciler, error) {
	switch {
	case opts.Target == nil:
		return nil, errors.New("srcfilter: target is required")
	case opts.Routes == nil || opts.Links == nil || opts.Uplinks == nil:
		return nil, errors.New("srcfilter: routes, links and uplinks sources are required")
	case opts.Settings.Mode == ModeOff:
		return nil, errors.New("srcfilter: mode is off")
	case len(opts.Settings.DomainPrefixes) == 0:
		return nil, errors.New("srcfilter: at least one SR domain prefix is required")
	}
	if opts.MinPrefixLen == 0 {
		opts.MinPrefixLen = DefaultMinPrefixLen
	}
	if opts.Slots == nil {
		opts.Slots = StableSlots
	}
	if opts.OwnLocator == nil {
		opts.OwnLocator = func(context.Context) (netip.Prefix, error) { return netip.Prefix{}, nil }
	}
	return &Reconciler{opts: opts}, nil
}

// Reconcile runs one pass: it resolves uplinks, slots and routes, computes the
// allow-list and applies it, writing new and changed entries before removing
// stale ones. The Target is marked populated only after a pass completes with
// no error, and its generation is bumped whenever a pass changes anything.
//
// On the first pass the configured mode is written straight away, keeping
// whatever populated flag and allow-list the Target already holds, so a mode
// change takes effect even while routes cannot be read.
//
// Any failure to read inputs, and a pass that finds no fabric routes, returns
// an error without touching the allow-list, so the previous one stays in
// force.
func (r *Reconciler) Reconcile(ctx context.Context) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.loadState(); err != nil {
		return Result{}, err
	}

	uplinkNames, err := r.opts.Uplinks()
	if err != nil {
		return Result{State: r.state}, fmt.Errorf("srcfilter: resolve uplinks: %w", err)
	}
	links, err := r.opts.Links()
	if err != nil {
		return Result{State: r.state}, fmt.Errorf("srcfilter: list links: %w", err)
	}
	uplinks, err := uplinkIndexes(uplinkNames, links)
	if err != nil {
		return Result{State: r.state}, err
	}
	currentSlots, err := r.opts.Target.UplinkSlots()
	if err != nil {
		return Result{State: r.state}, fmt.Errorf("srcfilter: read uplink slots: %w", err)
	}
	slots, err := r.opts.Slots(uplinks, currentSlots)
	if err != nil {
		return Result{State: r.state}, fmt.Errorf("srcfilter: assign uplink slots: %w", err)
	}
	own, err := r.opts.OwnLocator(ctx)
	if err != nil {
		return Result{State: r.state}, fmt.Errorf("srcfilter: resolve own locator: %w", err)
	}
	routes, err := r.opts.Routes()
	if err != nil {
		return Result{State: r.state}, fmt.Errorf("srcfilter: list routes: %w", err)
	}

	desired := computeDesired(desiredInput{
		routes:       routes,
		links:        links,
		slots:        slots,
		ownLocator:   own,
		domain:       r.opts.Settings.DomainPrefixes,
		minPrefixLen: r.opts.MinPrefixLen,
		binding:      r.opts.Settings.Binding,
		extra:        r.opts.Settings.ExtraSources,
	})
	res := Result{Entries: len(desired.entries), Unbound: desired.unbound, SlotCount: len(slots), State: r.state}
	if desired.fromRoutes == 0 {
		return res, fmt.Errorf("srcfilter: %w", ErrNoFabricRoutes)
	}

	slotsChanged := !maps.Equal(slots, currentSlots)
	if slotsChanged {
		if err := r.opts.Target.SyncUplinkSlots(slots); err != nil {
			return res, fmt.Errorf("srcfilter: sync uplink slots: %w", err)
		}
	}
	if err := r.syncAllow(desired.entries, &res); err != nil {
		return res, err
	}

	res.Changed = slotsChanged || res.Added+res.Updated+res.Removed > 0
	if res.Changed || !r.state.Populated {
		next := State{Mode: r.opts.Settings.Mode, Populated: true, Generation: r.state.Generation + 1}
		if err := r.opts.Target.SetState(next); err != nil {
			return res, fmt.Errorf("srcfilter: set state: %w", err)
		}
		r.state = next
	}
	res.State = r.state
	return res, nil
}

// loadState reads the Target's state once and writes the configured mode if
// it differs.
func (r *Reconciler) loadState() error {
	if r.loaded {
		return nil
	}
	st, err := r.opts.Target.State()
	if err != nil {
		return fmt.Errorf("srcfilter: read state: %w", err)
	}
	if st.Mode != r.opts.Settings.Mode {
		prev := st.Mode
		st.Mode = r.opts.Settings.Mode
		st.Generation++
		if err := r.opts.Target.SetState(st); err != nil {
			return fmt.Errorf("srcfilter: set mode %s: %w", st.Mode, err)
		}
		slog.Info("SRv6 source filter mode changed", "from", prev.String(), "to", st.Mode.String(),
			"populated", st.Populated)
	}
	r.state, r.loaded = st, true
	return nil
}

// syncAllow makes the Target's allow-list exactly desired, writing before
// deleting. A failed write skips every delete, so the list only ever holds a
// superset of the old and new sets.
func (r *Reconciler) syncAllow(desired []Entry, res *Result) error {
	current, err := r.opts.Target.ListAllow()
	if err != nil {
		return fmt.Errorf("srcfilter: list allow entries: %w", err)
	}
	have := make(map[netip.Prefix]Entry, len(current))
	for _, e := range current {
		have[e.Prefix.Masked()] = e
	}
	want := make(map[netip.Prefix]struct{}, len(desired))

	var errs []error
	for _, e := range desired {
		want[e.Prefix] = struct{}{}
		old, ok := have[e.Prefix]
		if ok && old.IfaceMask == e.IfaceMask && old.AnyIface == e.AnyIface {
			continue
		}
		if err := r.opts.Target.PutAllow(e); err != nil {
			errs = append(errs, fmt.Errorf("put %s: %w", e.Prefix, err))
			continue
		}
		if ok {
			res.Updated++
		} else {
			res.Added++
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("srcfilter: write allow entries: %w", errors.Join(errs...))
	}

	for _, e := range current {
		p := e.Prefix.Masked()
		if _, ok := want[p]; ok {
			continue
		}
		if err := r.opts.Target.DeleteAllow(p); err != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", p, err))
			continue
		}
		res.Removed++
	}
	if len(errs) > 0 {
		return fmt.Errorf("srcfilter: remove stale allow entries: %w", errors.Join(errs...))
	}
	return nil
}

// uplinkIndexes resolves uplink names against links. A name with no link is
// skipped; none resolving is an error.
func uplinkIndexes(names []string, links []netlink.Link) ([]uint32, error) {
	byName := make(map[string]int, len(links))
	for _, l := range links {
		byName[l.Attrs().Name] = l.Attrs().Index
	}
	out := make([]uint32, 0, len(names))
	for _, n := range names {
		if idx, ok := byName[n]; ok && idx > 0 {
			out = append(out, uint32(idx))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("srcfilter: none of the uplinks %v exist on this host", names)
	}
	return out, nil
}

// Disable writes mode off to target, keeping its generation moving. The
// allow-list is left as it is.
func Disable(target Target) error {
	st, err := target.State()
	if err != nil {
		return fmt.Errorf("srcfilter: read state: %w", err)
	}
	if st.Mode == ModeOff && !st.Populated {
		return nil
	}
	if err := target.SetState(State{Mode: ModeOff, Generation: st.Generation + 1}); err != nil {
		return fmt.Errorf("srcfilter: set mode off: %w", err)
	}
	return nil
}
