// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	ctrl "sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/edge/ownership"
	"go.datum.net/galactic/internal/edge/provider"
	"go.datum.net/galactic/internal/edge/route"
	"go.datum.net/galactic/internal/plumbing/ebpf/forwardgatemap"
)

// GateTable is the node's forwarding gate (internal/plumbing/ebpf/forwardgatemap).
type GateTable interface {
	// Link returns ifindex's own address, if it is a registered edge link.
	Link(ifindex uint32) (netip.Addr, bool, error)
	// Gates returns every gate on ifindex.
	Gates(ifindex uint32) (map[netip.Prefix]forwardgatemap.Gate, error)
	// Set writes prefix's gate on ifindex.
	Set(ifindex uint32, prefix netip.Prefix, g forwardgatemap.Gate) error
	// Delete removes prefix's gate on ifindex.
	Delete(ifindex uint32, prefix netip.Prefix) error
	// Links returns every registered edge link and its own address.
	Links() (map[uint32]netip.Addr, error)
	// DeleteLink removes ifindex's gates and its link row.
	DeleteLink(ifindex uint32) error
}

// gateLink is a registered edge link: its ifindex, VPC and gates.
type gateLink struct {
	index uint32
	vpc   string
	rows  map[netip.Prefix]forwardgatemap.Gate
}

// gateLinks returns every registered edge link on the node, by the UID of
// the attachment whose ID it carries, whether or not that attachment still
// exists: its gates close like any other's until the attachment pass releases
// it.
func (a *Agent) gateLinks() (map[string]*gateLink, error) {
	observed, err := hostattach.List(a.Host)
	if err != nil {
		return nil, fmt.Errorf("list attachment links: %w", err)
	}
	links := map[string]*gateLink{}
	for _, l := range observed {
		vpc, uid, ok := hostattach.ParseLinkID(l.ID)
		if !ok || l.HostIndex == 0 {
			continue
		}
		if _, registered, err := a.Gates.Link(uint32(l.HostIndex)); err != nil {
			return nil, err
		} else if !registered {
			continue
		}
		rows, err := a.Gates.Gates(uint32(l.HostIndex))
		if err != nil {
			return nil, err
		}
		links[uid] = &gateLink{index: uint32(l.HostIndex), vpc: vpc, rows: rows}
	}
	return links, nil
}

// verdict is what one route's gate becomes.
type verdict struct {
	// set is the gate to write; nil leaves the row as it is (keep) or, with
	// remove, deletes it.
	set    *forwardgatemap.Gate
	remove bool
	// closed is the accepted epoch to record closed once the gate is.
	closed int64
}

// GateRoute decides the forwarding gate of one route accepted on this node
// and commits it. A gate is opened or extended only from fresh reads, in this
// order: the holder's instance lease, then the route, then the attachment,
// service and provider. So a renewal it applies started before it read the
// route still accepted, and a revocation recorded before that read is seen:
// a gate never outlives a revocation, deletion or takeover by more than the
// lease duration from when it was recorded.
//
// A gate's deadline is the renewal's start, on the holder's and this node's
// CLOCK_BOOTTIME, plus the lease duration, capped by the grant's validUntil
// less the cell's maximum skew. It is extended only by a renewal newer than
// the one the gate already holds, so a restarted agent never extends a
// deadline from what it held before. A gate whose deadline passed, or whose
// holder released, was revoked or lost its authority, is closed and kept
// closed until the route's closedEpoch records it, then removed; an epoch at
// or below closedEpoch is never opened again.
//
// It reports whether the route's prefix opened or closed on its link, so the
// caller can provision or prune the link's host routes, and when the gate
// next needs deciding: before its deadline.
func (a *Agent) GateRoute(ctx context.Context, key ctrl.ObjectKey) (bool, time.Duration, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Gates == nil {
		return false, 0, nil
	}
	var cached galacticv1alpha1.EdgeRoute
	if err := a.Client.Get(ctx, key, &cached); err != nil {
		return false, 0, ctrl.IgnoreNotFound(err)
	}
	acc := cached.Status.Accepted
	if acc == nil || acc.Node != a.NodeName {
		return false, 0, nil
	}
	prefix, err := netip.ParsePrefix(cached.Spec.Prefix)
	if err != nil {
		return false, 0, nil
	}
	links, err := a.gateLinks()
	if err != nil {
		return false, 0, err
	}
	l := links[acc.AttachmentUID]
	row, hasRow := forwardgatemap.Gate{}, false
	if l != nil {
		row, hasRow = l.rows[prefix]
	}
	v := a.decide(ctx, &cached, row, hasRow, l != nil)
	changed := false
	if l != nil && (v.set != nil && (!hasRow || *v.set != row) || v.remove && hasRow) {
		// Host routes follow open gates, and a gate that expired on its own
		// may still have its routes until the attachment pass prunes them:
		// any row not already closed may be routed.
		now := a.bootClock()
		wasRouted := hasRow && row.Deadline > 0
		isOpen := v.set != nil && v.set.Deadline > now
		if err := a.commitGate(l, prefix, v); err != nil {
			if errors.Is(err, ownership.ErrResyncRequired) {
				// The scope's next commit must be the attachment pass's
				// snapshot; this gate is decided again after it.
				return true, time.Second, nil
			}
			return false, 0, err
		}
		changed = wasRouted != isOpen
	}
	if v.closed != 0 {
		if err := a.recordIfClosed(ctx, &cached, l, prefix, v.closed); err != nil {
			if errors.Is(err, ownership.ErrResyncRequired) {
				return true, time.Second, nil
			}
			return changed, 0, err
		}
		return changed, time.Second, nil
	}
	return changed, a.nextDecision(v, row, hasRow), nil
}

// nextDecision is how long until the route's gate needs deciding again:
// before it expires, and at least every third of the lease.
func (a *Agent) nextDecision(v verdict, row forwardgatemap.Gate, hasRow bool) time.Duration {
	after := a.Params.Duration / 3
	deadline := time.Duration(0)
	switch {
	case v.set != nil:
		deadline = v.set.Deadline
	case hasRow && !v.remove:
		deadline = row.Deadline
	}
	if until := deadline - a.bootClock(); deadline > 0 && until > 0 && until < after {
		after = until
	}
	return after
}

// recordIfClosed writes the route's closedEpoch at epoch once confirmClosed
// finds no gate carrying the prefix open, under the scope of the holder's
// VPC: its link's, or else its attachment's.
func (a *Agent) recordIfClosed(ctx context.Context, rt *galacticv1alpha1.EdgeRoute, l *gateLink,
	prefix netip.Prefix, epoch int64) error {
	vpc := ""
	if l != nil {
		vpc = l.vpc
	} else {
		acc := rt.Status.Accepted
		var att galacticv1alpha1.EdgeAttachment
		err := a.Client.Get(ctx, ctrl.ObjectKey{Namespace: rt.Namespace, Name: acc.Attachment}, &att)
		switch {
		case err == nil && string(att.UID) == acc.AttachmentUID:
			vpc = att.Status.VPC
		case err != nil && !apierrors.IsNotFound(err):
			return err
		}
	}
	closed, err := a.confirmClosed(vpc, prefix, epoch)
	if err != nil || !closed {
		return err
	}
	return a.recordClosed(ctx, ctrl.ObjectKeyFromObject(rt), epoch)
}

// decide is the route's gate verdict from fresh reads. row is the gate on the
// accepted attachment's registered link, if it has one; linked reports
// whether there is such a link.
func (a *Agent) decide(ctx context.Context, cached *galacticv1alpha1.EdgeRoute, row forwardgatemap.Gate,
	hasRow, linked bool) verdict {
	keep := verdict{}
	// The lease first: a renewal read before the route can only have
	// started before the route was read still accepted.
	var inst galacticv1alpha1.EdgeInstance
	instKey := ctrl.ObjectKey{Namespace: cached.Namespace, Name: cached.Status.Accepted.Instance}
	instErr := a.APIReader.Get(ctx, instKey, &inst)
	if instErr != nil && !apierrors.IsNotFound(instErr) {
		return keep
	}
	var lease claim.Record
	leased := false
	if instErr == nil {
		var err error
		if lease, leased, err = provider.ReadLease(ctx, a.APIReader, &inst); err != nil {
			return keep
		}
	}
	var rt galacticv1alpha1.EdgeRoute
	switch err := a.APIReader.Get(ctx, ctrl.ObjectKeyFromObject(cached), &rt); {
	case apierrors.IsNotFound(err):
		return verdict{remove: true}
	case err != nil:
		return keep
	}
	acc := rt.Status.Accepted
	if acc == nil || acc.Node != a.NodeName || rt.UID != cached.UID ||
		acc.AttachmentUID != cached.Status.Accepted.AttachmentUID || rt.Spec.Prefix != cached.Spec.Prefix {
		// Moved since the cache saw it; this link's row is no longer its.
		return verdict{remove: true}
	}
	if acc.Epoch <= rt.Status.ClosedEpoch {
		// Closed and recorded: never opened again.
		return verdict{remove: true}
	}
	nowBoot := a.bootClock()
	closeGate := verdict{closed: acc.Epoch}
	if hasRow {
		// Kept closed, not removed, until closedEpoch records it, so a
		// restart cannot mistake the epoch for one never opened.
		closeGate.set = &forwardgatemap.Gate{RenewStart: row.RenewStart, Epoch: uint64(acc.Epoch)}
	}
	if a.ended(&rt, &inst, apierrors.IsNotFound(instErr), row, hasRow, nowBoot) {
		return closeGate
	}
	auth, ref, err := route.Check(ctx, a.APIReader, &rt, route.HolderOfAccepted(acc), a.now(), a.Params.MaxSkew)
	switch {
	case err != nil:
		return keep
	case ref != nil:
		return closeGate
	case !linked:
		// No registered link yet: nothing to open.
		return keep
	}
	if !leased || lease.Released || lease.Incarnation != acc.InstanceIncarnation ||
		int64(lease.Epoch) != acc.InstanceEpoch {
		// The first read predates the one Check passed on; the next
		// renewal decides.
		return keep
	}
	start := lease.RenewStart
	deadline := start + a.Params.Duration
	if !auth.NotAfter.IsZero() {
		ceiling := nowBoot + auth.NotAfter.Sub(a.now())
		if ceiling <= nowBoot {
			return closeGate
		}
		deadline = min(deadline, ceiling)
	}
	switch {
	case start <= 0 || start > nowBoot || deadline <= nowBoot:
		// A start from the future is not on this clock, and a renewal
		// already expired opens nothing.
		return keep
	case !hasRow || row.Epoch != uint64(acc.Epoch) || start > row.RenewStart:
		return verdict{set: &forwardgatemap.Gate{Deadline: deadline, RenewStart: start, Epoch: uint64(acc.Epoch)}}
	}
	return keep
}

// ended reports whether the accepted holder's gate must close whatever its
// authority: core revoked it, the holder released it, its deadline passed,
// or its instance is gone or of another boot or node.
func (a *Agent) ended(rt *galacticv1alpha1.EdgeRoute, inst *galacticv1alpha1.EdgeInstance, instGone bool,
	row forwardgatemap.Gate, hasRow bool, nowBoot time.Duration) bool {
	acc := rt.Status.Accepted
	c := rt.Spec.Claim
	return !meta.IsStatusConditionTrue(rt.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted) ||
		(c != nil && c.Epoch == acc.Epoch && c.Released) ||
		(hasRow && row.Epoch == uint64(acc.Epoch) && row.Deadline <= nowBoot) ||
		instGone || inst.Spec.BootID != a.BootID || inst.Spec.NodeName != a.NodeName
}

// commitGate writes one gate verdict in a commit of the link's VPC scope.
func (a *Agent) commitGate(l *gateLink, prefix netip.Prefix, v verdict) error {
	err := a.commit(ownership.VPCScope(l.vpc), func() error {
		if v.set != nil {
			return a.Gates.Set(l.index, prefix, *v.set)
		}
		return a.Gates.Delete(l.index, prefix)
	})
	if err != nil {
		return fmt.Errorf("commit gate %s on link %d: %w", prefix, l.index, err)
	}
	return nil
}

// commit runs mutate in an incremental commit of scope with this process's
// ticket. A stale ticket means a writer that does not own the scope, such as
// garbage collection, wrote it since: the scope is still this process's, so
// the commit runs again from a fresh ticket. Only losing the scope to
// another owner marks it lost.
func (a *Agent) commit(scope string, mutate func() error) error {
	var err error
	for range 2 {
		var t ownership.Ticket
		if t, err = a.ticket(scope); err != nil {
			return err
		}
		var next ownership.Ticket
		next, err = a.Ownership.Commit(t, mutate)
		if err == nil {
			a.tickets[scope] = next
			return nil
		}
		delete(a.tickets, scope)
		if !errors.Is(err, ownership.ErrStale) {
			break
		}
	}
	if errors.Is(err, ownership.ErrNotOwner) || errors.Is(err, ownership.ErrTransitioning) {
		a.markLost(scope)
	}
	return err
}

// confirmClosed reports whether no gate on the node carries prefix open at
// epoch, checked inside a commit of the VPC's scope. A process another one
// fenced cannot commit, so it never confirms a gate its successor holds open.
// The check spans every edge link, not only the holder's, so a link missed
// while listing still counts; a gate of another VPC with the same prefix and
// epoch only delays the confirmation. vpc is empty only when the holder's
// attachment is gone, which no agent opens a gate for again.
func (a *Agent) confirmClosed(vpc string, prefix netip.Prefix, epoch int64) (bool, error) {
	now := a.bootClock()
	closed := false
	check := func() error {
		closed = false
		links, err := a.Gates.Links()
		if err != nil {
			return err
		}
		for ifindex := range links {
			rows, err := a.Gates.Gates(ifindex)
			if err != nil {
				return err
			}
			if g, ok := rows[prefix]; ok && g.Epoch == uint64(epoch) && g.Deadline > now {
				return nil
			}
		}
		closed = true
		return nil
	}
	if vpc == "" {
		return closed, check()
	}
	if err := a.commit(ownership.VPCScope(vpc), check); err != nil {
		return false, fmt.Errorf("confirm gate %s closed at epoch %d: %w", prefix, epoch, err)
	}
	return closed, nil
}

// recordClosed writes the route's closedEpoch, once confirmClosed found its
// gate closed.
func (a *Agent) recordClosed(ctx context.Context, key ctrl.ObjectKey, epoch int64) error {
	var rt galacticv1alpha1.EdgeRoute
	if err := a.APIReader.Get(ctx, key, &rt); err != nil {
		return ctrl.IgnoreNotFound(err)
	}
	acc := rt.Status.Accepted
	if acc == nil || acc.Epoch != epoch || acc.Node != a.NodeName || rt.Status.ClosedEpoch >= epoch {
		return nil
	}
	before := rt.DeepCopy()
	rt.Status.ClosedEpoch = epoch
	patch := ctrl.MergeFromWithOptions(before, ctrl.MergeFromWithOptimisticLock{})
	if err := a.Client.Status().Patch(ctx, &rt, patch); err != nil {
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("record route %s closed at epoch %d: %w", key, epoch, err)
	}
	return nil
}

// SweepGates removes expired gates that no route accepted on this node
// claims: those of routes since deleted or accepted elsewhere. A live gate is
// left to expire, since nothing extends it, so a route the cache has not yet
// seen keeps its gate. It also removes the link row of an ifindex no edge
// link holds any more, as when a pod's deletion took its link with it. An
// edge link created before the sweep runs on a reused number does not depend
// on it: the agent clears that number's rows before registering the link.
func (a *Agent) SweepGates(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Gates == nil {
		return nil
	}
	var routes galacticv1alpha1.EdgeRouteList
	if err := a.Client.List(ctx, &routes); err != nil {
		return fmt.Errorf("list EdgeRoutes: %w", err)
	}
	claimed := map[string]map[netip.Prefix]bool{}
	for i := range routes.Items {
		acc := routes.Items[i].Status.Accepted
		p, err := netip.ParsePrefix(routes.Items[i].Spec.Prefix)
		if acc == nil || acc.Node != a.NodeName || err != nil {
			continue
		}
		if claimed[acc.AttachmentUID] == nil {
			claimed[acc.AttachmentUID] = map[netip.Prefix]bool{}
		}
		claimed[acc.AttachmentUID][p] = true
	}
	links, err := a.gateLinks()
	if err != nil {
		return err
	}
	rows, err := a.Gates.Links()
	if err != nil {
		return err
	}
	observed, err := hostattach.List(a.Host)
	if err != nil {
		return err
	}
	held := map[uint32]bool{}
	for _, l := range observed {
		held[uint32(l.HostIndex)] = true
	}
	var errs []error
	for ifindex := range rows {
		if !held[ifindex] {
			errs = append(errs, a.Gates.DeleteLink(ifindex))
		}
	}
	now := a.bootClock()
	for uid, l := range links {
		for p, g := range l.rows {
			if g.Deadline > now || claimed[uid][p] {
				continue
			}
			err := a.commitGate(l, p, verdict{remove: true})
			if err != nil && !errors.Is(err, ownership.ErrResyncRequired) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// openPrefixes returns the prefixes with an open gate on the attachment's
// registered host link: the prefixes its host routes carry.
func (a *Agent) openPrefixes(link hostattach.ObservedAttachment, address string) []netip.Prefix {
	if a.Gates == nil || link.HostIndex == 0 {
		return nil
	}
	addr, ok, err := a.Gates.Link(uint32(link.HostIndex))
	if err != nil || !ok || addr.String() != address {
		return nil
	}
	rows, err := a.Gates.Gates(uint32(link.HostIndex))
	if err != nil {
		return nil
	}
	now := a.bootClock()
	var out []netip.Prefix
	for p, g := range rows {
		if g.Deadline > now {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(x, y netip.Prefix) int {
		if c := x.Addr().Compare(y.Addr()); c != 0 {
			return c
		}
		return x.Bits() - y.Bits()
	})
	return out
}
