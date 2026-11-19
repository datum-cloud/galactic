// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fabric is Galactic Worker's Fabric delivery module. It delivers to
// destinations on other nodes through the existing SRv6 encapsulator and the
// tenant routes galactic-router learns from EVPN.
//
// The module is the single writer of the tenant routes in egress_route_table
// for every VPC scope Worker owns. galactic-router hands it each route it
// learns through the Routes service; the module writes the route under the
// VPC's fence, re-resolves its underlay next hop when routes or neighbors
// change, and removes it only when galactic-router withdraws it. It never
// touches an entry it did not learn from galactic-router, such as CNI's
// pass-through entries, egress shard entries or Galactic Edge's entries.
//
// The tenant routes of a VPC are shared by every claim in it. A claim's
// Fabric destinations own no entries: the module reports, per destination,
// whether the entry usid_egress would match for each of the destination's
// addresses leads to the destination's node (forward), and whether this node
// decapsulates the VPC's SID into the VPC's table (return).
//
// A route whose next hop stops resolving keeps the entry already written for
// it rather than losing it, so a shorter entry, such as the VPC's default
// toward an egress shard, never catches traffic meant for the unreachable
// node. A route that cannot be written yet, because no entry exists or its
// SID changed, is retried on the next route or neighbor event or periodic
// resync; until then its traffic matches whatever entry it matched before,
// as when galactic-router writes it, and its destinations report why. Neither
// fails the scope's commit, so one unreachable node never stops the VPC's
// other destinations from being programmed.
package fabric

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/routes"
)

// Name is the module's name.
const Name = "fabric"

// Config configures a Module.
type Config struct {
	// Routes is the tenant route table the Routes service records into.
	Routes *routes.Table
	// Datapath is the host state the module reads and writes.
	Datapath Datapath
	// OwnLocator returns this node's SRv6 locator, or the zero prefix while
	// it has none.
	OwnLocator func(ctx context.Context) (netip.Prefix, error)
	Log        *slog.Logger
}

// written is what the module last wrote for a route.
type written struct {
	table uint32
	sid   netip.Addr
}

// hop identifies an underlay next hop a route's entry uses.
type hop struct {
	link    int
	gateway netip.Addr
}

// Module is the Fabric delivery module.
type Module struct {
	cfg Config

	mu sync.Mutex
	// desired is each scope's claims from its last Plan, which Read reports
	// on.
	desired map[string][]module.Claim
	// written is what Apply last wrote for each route, so a route whose
	// VPC's table moved has its old entry removed.
	written map[routes.Key]written
	// failed is the last write error of each route not yet written.
	failed map[routes.Key]error
	// sids and hops index each VPC's routes by SID and by the next hop
	// their entries used, so a route or neighbor event requeues only the
	// VPCs it touches.
	sids map[string]map[netip.Addr]struct{}
	hops map[string]map[hop]struct{}
}

var _ module.Module = (*Module)(nil)

// New returns a Fabric module.
func New(cfg Config) (*Module, error) {
	if cfg.Routes == nil || cfg.Datapath == nil || cfg.OwnLocator == nil {
		return nil, errors.New("fabric: routes, datapath and own locator are required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	cfg.Log = cfg.Log.With("module", Name)
	return &Module{
		cfg:     cfg,
		desired: map[string][]module.Claim{},
		written: map[routes.Key]written{},
		failed:  map[routes.Key]error{},
		sids:    map[string]map[netip.Addr]struct{}{},
		hops:    map[string]map[hop]struct{}{},
	}, nil
}

// Name implements module.Module.
func (m *Module) Name() string { return Name }

// Mode implements module.Module.
func (m *Module) Mode() workerv1alpha1.Mode { return workerv1alpha1.Mode_MODE_FABRIC }

// Capabilities implements module.Module. Both capabilities need the pinned
// uSID maps.
func (m *Module) Capabilities() []module.Capability {
	caps := []module.Capability{
		{Name: workerv1alpha1.CapabilityFabricSRv6, Available: true},
		{Name: workerv1alpha1.CapabilityFabricRoutes, Available: true},
	}
	if err := m.cfg.Datapath.Loaded(); err != nil {
		for i := range caps {
			caps[i].Available = false
			caps[i].Reason = workerv1alpha1.ReasonDatapathNotLoaded
			caps[i].Message = err.Error()
		}
	}
	return caps
}

// removal is one entry the change removes.
type removal struct {
	table  uint32
	prefix netip.Prefix
	sid    netip.Addr
	// withdrawal is set when removing it confirms a withdrawal.
	withdrawal *routes.Route
	// moved is set when it is the old entry of a route whose table moved.
	moved *routes.Key
}

// change is the Fabric module's change for one scope.
type change struct {
	vpc     string
	writes  []routes.Route
	removes []removal
}

// Empty implements module.Change.
func (c *change) Empty() bool { return len(c.writes) == 0 && len(c.removes) == 0 }

// Plan implements module.Module. It records desired for Read and plans the
// scope's tenant routes: it writes each route whose entry is missing, leads
// elsewhere or has an out-of-date next hop, and removes each withdrawn route's
// entry. A route recorded for another table than the VPC's current one, or
// toward this node's own locator, is skipped.
func (m *Module) Plan(ctx context.Context, scope module.Scope, desired []module.Claim) (module.Change, error) {
	vpc := scope.VPC
	m.mu.Lock()
	if len(desired) > 0 {
		m.desired[vpc] = desired
	} else {
		delete(m.desired, vpc)
	}
	wrote := false
	for k := range m.written {
		if k.VPC == vpc {
			wrote = true
			break
		}
	}
	m.mu.Unlock()

	ch := &change{vpc: vpc}
	if len(desired) == 0 && !wrote && !m.cfg.Routes.HasWork(vpc) {
		return ch, nil
	}
	table, ok, err := m.cfg.Datapath.TableID(vpc)
	if err != nil {
		return nil, fmt.Errorf("fabric: read VPC %s table: %w", vpc, err)
	}
	if !ok {
		// No VRF, so no table to write into. A withdrawn route's entry is
		// still removed from the table it was recorded for.
		m.planWithdrawals(ch, vpc, 0)
		return ch, nil
	}
	own, err := m.cfg.OwnLocator(ctx)
	if err != nil {
		return nil, fmt.Errorf("fabric: read this node's locator: %w", err)
	}

	sids := map[netip.Addr]struct{}{}
	hops := map[hop]struct{}{}
	m.mu.Lock()
	prev := make(map[routes.Key]written, len(m.written))
	for k, w := range m.written {
		if k.VPC == vpc {
			prev[k] = w
		}
	}
	m.mu.Unlock()

	for _, r := range m.cfg.Routes.Routes(vpc) {
		if err := m.planRoute(ch, r, table, own, prev, sids, hops); err != nil {
			return nil, err
		}
	}

	m.planWithdrawals(ch, vpc, table)

	m.mu.Lock()
	m.sids[vpc], m.hops[vpc] = sids, hops
	m.mu.Unlock()
	return ch, nil
}

// planRoute plans one tenant route of ch's VPC, whose current table is table:
// it skips a route recorded for another table or toward own, the node's own
// locator, removes the entry a route left in its VPC's earlier table, and
// writes the route unless this incarnation wrote its own entry and that entry
// still leads to its SID over a current next hop. It records the route's SID
// and next hop in sids and hops.
func (m *Module) planRoute(ch *change, r routes.Route, table uint32, own netip.Prefix,
	prev map[routes.Key]written, sids map[netip.Addr]struct{}, hops map[hop]struct{}) error {
	switch {
	case r.TableID != table:
		skipped(reasonTableMismatch)
		m.cfg.Log.Debug("skipping a tenant route recorded for another table than the VPC's",
			"vpc", ch.vpc, "prefix", r.Prefix, "routeTable", r.TableID, "table", table)
		return nil
	case own.IsValid() && own.Contains(r.SID):
		skipped(reasonOwnLocator)
		m.cfg.Log.Debug("skipping a tenant route toward this node's own locator", "vpc", ch.vpc, "prefix", r.Prefix)
		return nil
	}
	sids[r.SID] = struct{}{}
	if w, ok := prev[r.Key]; ok && w.table != table {
		// The SID carries the remote node's Argument for this VPC, so the
		// old table's entry is removed only while it is this route's.
		k := r.Key
		ch.removes = append(ch.removes, removal{table: w.table, prefix: r.Prefix, sid: w.sid, moved: &k})
	}
	row, have, err := m.cfg.Datapath.Lookup(table, r.Prefix)
	if err != nil {
		return fmt.Errorf("fabric: read entry %s in table %d: %w", r.Prefix, table, err)
	}
	next, hopErr := m.cfg.Datapath.NextHop(r.SID)
	if hopErr == nil || errors.Is(hopErr, egressroutemap.ErrNeighborUnresolved) {
		if gw, ok := netip.AddrFromSlice(next.Gateway); ok {
			hops[hop{link: next.LinkIndex, gateway: gw.Unmap()}] = struct{}{}
		}
	}
	// The lookup is longest-prefix, so a shorter entry toward the same
	// SID can answer for the route; only an entry this incarnation
	// wrote for the route's own prefix counts. After a restart every
	// route is written once again.
	w, wroteIt := prev[r.Key]
	current := wroteIt && w.table == table && w.sid == r.SID &&
		have && !row.PassThrough && !row.Sentinel && sameSID(row.SID, r.SID)
	switch {
	case !current && errors.Is(hopErr, egressroutemap.ErrNoUplinkRoute):
		// Writing would fail; whatever entry the route has is kept.
		m.setFailed(r.Key, hopErr)
	case !current:
		ch.writes = append(ch.writes, r)
	case hopErr == nil && !sameHop(row, next):
		ch.writes = append(ch.writes, r)
	default:
		// Current, or a next hop that does not resolve now: the entry
		// is kept as it is.
	}
	return nil
}

// planWithdrawals plans removing the entry of each withdrawn route not yet
// confirmed removed: from the table it was recorded for, and from table, the
// VPC's current one, when that differs and is not 0. A withdrawal with no
// recorded table is removed from table only. A removal names the route's SID
// when it is known, which carries the remote node's Argument for this VPC, so
// it never removes another VPC's entry from a table that moved to it.
func (m *Module) planWithdrawals(ch *change, vpc string, table uint32) {
	for _, w := range m.cfg.Routes.Withdrawn(vpc) {
		if w.Removed {
			continue
		}
		t := w.TableID
		if t == 0 {
			t = table
		}
		if t == 0 {
			continue
		}
		route := w.Route
		ch.removes = append(ch.removes, removal{table: t, prefix: w.Prefix, sid: w.SID, withdrawal: &route})
		if table != 0 && t != table {
			ch.removes = append(ch.removes, removal{table: table, prefix: w.Prefix, sid: w.SID})
		}
	}
}

// Apply implements module.Module. It writes and removes entries one at a
// time. A route that fails is recorded for Read and retried by a later
// pass; it does not fail the commit. An error is returned only when the
// datapath is not loaded.
func (m *Module) Apply(_ context.Context, scope module.Scope, c module.Change) error {
	ch, ok := c.(*change)
	if !ok || ch.vpc != scope.VPC {
		return fmt.Errorf("fabric: change for another scope than %s", scope.VPC)
	}
	if err := m.cfg.Datapath.Loaded(); err != nil {
		return fmt.Errorf("fabric: datapath not loaded: %w", err)
	}
	var confirmed []routes.Route
	for _, rm := range ch.removes {
		if err := m.cfg.Datapath.Remove(rm.table, rm.prefix, rm.sid); err != nil {
			m.cfg.Log.Warn("removing a tenant route failed; retrying", "vpc", ch.vpc, "prefix", rm.prefix,
				"table", rm.table, "error", err)
			continue
		}
		m.cfg.Log.Debug("removed a tenant route", "vpc", ch.vpc, "prefix", rm.prefix, "table", rm.table,
			"sid", rm.sid)
		m.mu.Lock()
		switch {
		case rm.withdrawal != nil:
			confirmed = append(confirmed, *rm.withdrawal)
			delete(m.written, rm.withdrawal.Key)
			delete(m.failed, rm.withdrawal.Key)
		case rm.moved != nil:
			if w, ok := m.written[*rm.moved]; ok && w.table == rm.table {
				delete(m.written, *rm.moved)
			}
		}
		m.mu.Unlock()
	}
	m.cfg.Routes.ConfirmRemoved(confirmed)
	for _, r := range ch.writes {
		if err := m.cfg.Datapath.Write(r.TableID, r.Prefix, r.SID); err != nil {
			m.setFailed(r.Key, err)
			m.cfg.Log.Info("writing a tenant route failed; retrying on the next route or neighbor change",
				"vpc", ch.vpc, "prefix", r.Prefix, "sid", r.SID, "error", err)
			continue
		}
		m.cfg.Log.Debug("wrote a tenant route", "vpc", ch.vpc, "prefix", r.Prefix, "table", r.TableID, "sid", r.SID)
		m.mu.Lock()
		m.written[r.Key] = written{table: r.TableID, sid: r.SID}
		delete(m.failed, r.Key)
		m.mu.Unlock()
	}
	return nil
}

func (m *Module) setFailed(k routes.Key, err error) {
	m.mu.Lock()
	m.failed[k] = err
	m.mu.Unlock()
}

// Read implements module.Module. It reports every Fabric destination of the
// claims of the scope's last Plan.
func (m *Module) Read(ctx context.Context, scope module.Scope) (module.State, error) {
	vpc := scope.VPC
	m.mu.Lock()
	claims := m.desired[vpc]
	m.mu.Unlock()
	out := module.State{}
	if len(claims) == 0 {
		return out, nil
	}
	table, haveTable, err := m.cfg.Datapath.TableID(vpc)
	if err != nil {
		return nil, fmt.Errorf("fabric: read VPC %s table: %w", vpc, err)
	}
	own, err := m.cfg.OwnLocator(ctx)
	if err != nil {
		return nil, fmt.Errorf("fabric: read this node's locator: %w", err)
	}
	returnErr := errors.New("the VPC has no host VRF yet")
	if haveTable {
		returnErr = m.cfg.Datapath.ReturnPath(ctx, vpc)
	}
	for _, c := range claims {
		states := map[string]module.DestinationState{}
		for _, d := range c.Destinations {
			st := m.readDestination(vpc, table, haveTable, own, d)
			st.Generation = c.Generation
			// Return readiness depends only on this node decapsulating the
			// VPC's SID, whatever the forward path's state.
			st.ReturnReady = returnErr == nil
			st.Ready = st.ForwardReady && st.ReturnReady
			if st.ForwardReady && returnErr != nil {
				st.Reason = workerv1alpha1.ReasonReturnPathNotProgrammed
				st.Message = returnErr.Error()
			}
			states[d.ID] = st
		}
		out[c.Key] = states
	}
	return out, nil
}

// readDestination reports one destination's Programmed and ForwardReady, and
// the reason for the first that is false.
func (m *Module) readDestination(vpc string, table uint32, haveTable bool, own netip.Prefix,
	d module.Destination) module.DestinationState {
	st := module.DestinationState{}
	fail := func(reason, msg string) module.DestinationState {
		st.Reason, st.Message = reason, msg
		return st
	}
	switch {
	case own.IsValid() && own == d.Locator:
		return fail(workerv1alpha1.ReasonRouteMismatch, "the destination is on this node")
	case len(d.Addresses) == 0:
		return fail(workerv1alpha1.ReasonDestinationAddressUnknown, "the destination's attachment records no address")
	case !haveTable:
		return fail(workerv1alpha1.ReasonPending, "the VPC has no host VRF yet")
	}
	type check struct {
		sid netip.Addr
		row egressroutemap.Row
	}
	checks := make([]check, 0, len(d.Addresses))
	for _, addr := range d.Addresses {
		route, haveRoute, wd, haveWd := m.cfg.Routes.Covering(vpc, addr)
		switch {
		case !haveRoute && haveWd:
			return fail(workerv1alpha1.ReasonRouteWithdrawn,
				fmt.Sprintf("the route %s covering %s was withdrawn", wd.Prefix, addr))
		case !haveRoute:
			return fail(workerv1alpha1.ReasonForwardRouteMissing, fmt.Sprintf("no tenant route covers %s", addr))
		case !d.Locator.Contains(route.SID):
			return fail(workerv1alpha1.ReasonRouteMismatch,
				fmt.Sprintf("the route %s covering %s leads to %s, outside the destination's locator %s",
					route.Prefix, addr, route.SID, d.Locator))
		}
		row, have, err := m.cfg.Datapath.Lookup(table, netip.PrefixFrom(addr, addr.BitLen()))
		if err != nil {
			return fail(workerv1alpha1.ReasonProgrammingFailed, err.Error())
		}
		if !have || row.PassThrough || row.Sentinel || !sameSID(row.SID, route.SID) {
			m.mu.Lock()
			ferr := m.failed[route.Key]
			m.mu.Unlock()
			if ferr != nil {
				reason := hopReason(ferr)
				if reason == "" {
					reason = workerv1alpha1.ReasonProgrammingFailed
				}
				return fail(reason, fmt.Sprintf("the route %s is not written: %v", route.Prefix, ferr))
			}
			return fail(workerv1alpha1.ReasonPending, fmt.Sprintf("the route %s is not written yet", route.Prefix))
		}
		checks = append(checks, check{sid: route.SID, row: row})
	}
	st.Programmed = true
	for _, c := range checks {
		next, err := m.cfg.Datapath.NextHop(c.sid)
		if err != nil {
			reason := hopReason(err)
			if reason == "" {
				reason = workerv1alpha1.ReasonUnderlayUnreachable
			}
			return fail(reason, err.Error())
		}
		if !sameHop(c.row, next) {
			return fail(workerv1alpha1.ReasonNeighborUnresolved,
				fmt.Sprintf("the entry toward %s carries an out-of-date next hop", c.sid))
		}
	}
	st.ForwardReady = true
	return st
}

// hopReason maps a next hop resolution error to a contract reason, or "".
func hopReason(err error) string {
	switch {
	case errors.Is(err, egressroutemap.ErrNoUplinkRoute):
		return workerv1alpha1.ReasonUnderlayUnreachable
	case errors.Is(err, egressroutemap.ErrNeighborUnresolved):
		return workerv1alpha1.ReasonNeighborUnresolved
	}
	return ""
}

func sameSID(a net.IP, b netip.Addr) bool {
	got, ok := netip.AddrFromSlice(a)
	return ok && got.Unmap() == b.Unmap()
}

func sameHop(row egressroutemap.Row, next egressroutemap.NextHop) bool {
	return row.LinkIndex == next.LinkIndex && bytes.Equal(row.DMAC, next.DMAC) && bytes.Equal(row.SMAC, next.SMAC)
}

// affectedByRoute returns the VPCs whose routes an underlay route change for dst
// touches: those with a SID dst contains, or every VPC with routes when dst
// is a default route.
func (m *Module) affectedByRoute(dst netip.Prefix) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for vpc, sids := range m.sids {
		if dst.Bits() == 0 {
			out = append(out, vpc)
			continue
		}
		for sid := range sids {
			if dst.Contains(sid) {
				out = append(out, vpc)
				break
			}
		}
	}
	return out
}

// affectedByNeighbor returns the VPCs whose entries use the next hop gateway
// on link.
func (m *Module) affectedByNeighbor(link int, gateway netip.Addr) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	h := hop{link: link, gateway: gateway.Unmap()}
	for vpc, hops := range m.hops {
		if _, ok := hops[h]; ok {
			out = append(out, vpc)
		}
	}
	return out
}
