// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/ownership"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/sources"
	"go.datum.net/galactic/internal/worker/store"
)

// errOwnedElsewhere is a scope another writer owns. Worker does not take it:
// moving a legacy writer's scope to Worker is that writer's transfer step.
var errOwnedElsewhere = errors.New("worker: another writer owns the scope")

func (w *Worker) runReconciler(ctx context.Context) {
	for {
		vpc, quit := w.queue.Get()
		if quit {
			return
		}
		start := time.Now()
		err := w.Reconcile(ctx, vpc)
		observeReconcile(err, time.Since(start))
		if err != nil {
			w.log.Info("reconcile failed; retrying", "vpc", vpc, "error", err)
			w.queue.AddRateLimited(vpc)
		} else {
			w.queue.Forget(vpc)
		}
		w.queue.Done(vpc)
	}
}

// destEval is the resolution of one destination.
type destEval struct {
	ref      *workerv1alpha1.Destination
	id       string
	mode     workerv1alpha1.Mode
	resolved bool
	// capReason is set when the destination resolved but its capability is
	// unavailable.
	capReason, capMsg string
	reason, msg       string
}

// claimEval is one claim's evaluation in a reconcile pass.
type claimEval struct {
	key       module.ClaimKey
	owner     string
	gen       uint64
	releasing bool
	dests     []destEval
}

// snapshotScope copies the claims of a scope.
func (w *Worker) snapshotScope(vpc string) []claim {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []claim
	for _, c := range w.claims {
		if c.rec.VPC == vpc {
			out = append(out, claim{rec: c.rec, spec: proto.Clone(c.spec).(*workerv1alpha1.ClaimSpec)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key().String() < out[j].key().String() })
	return out
}

// Reconcile makes the host match the desired state of one VPC scope and
// reports the result on every claim of the scope.
func (w *Worker) Reconcile(ctx context.Context, vpc string) error {
	scope := module.Scope{VPC: vpc}
	claims := w.snapshotScope(vpc)
	if len(claims) == 0 {
		if w.d.Host != nil {
			return w.reconcileHost(ctx, vpc)
		}
		return w.reconcileUnclaimed(ctx, vpc)
	}

	evals, desired, err := w.resolve(ctx, vpc, claims)
	if err != nil {
		return err
	}

	ensure, err := w.planClaimedHost(ctx, vpc)
	if err != nil {
		w.reportFailure(evals, workerv1alpha1.ReasonProgrammingFailed, err)
		return err
	}

	t, err := w.acquire(scope)
	if err != nil {
		reason := workerv1alpha1.ReasonProgrammingFailed
		if errors.Is(err, errOwnedElsewhere) || errors.Is(err, ownership.ErrTransitioning) ||
			errors.Is(err, ownership.ErrNotOwner) {
			reason = workerv1alpha1.ReasonScopeOwnedElsewhere
		}
		w.reportFailure(evals, reason, err)
		return err
	}

	mods, changes, empty, err := w.planModules(ctx, scope, desired)
	if err != nil {
		w.reportFailure(evals, workerv1alpha1.ReasonProgrammingFailed, err)
		return err
	}
	digest, drifts := w.checkDrift(vpc, desired, t.Resync, mods, changes)
	if !empty || ensure || t.Resync {
		mutate := func() error {
			// A snapshot reconciles the complete state, including the host
			// state; Ensure changes nothing already in place.
			if w.d.Host != nil && (ensure || t.Resync) {
				if err := w.d.Host.Ensure(ctx, vpc); err != nil {
					return fmt.Errorf("ensure host state: %w", err)
				}
			}
			return applyModules(ctx, scope, mods, changes)
		}
		// Every change carries the complete desired state of the scope, so
		// a snapshot commit is always correct; an incremental commit is used
		// when the scope does not require one.
		commit := w.d.Fence.Commit
		if t.Resync {
			commit = w.d.Fence.CommitSnapshot
		}
		if _, err := commit(t, mutate); err != nil {
			if !errors.Is(err, ownership.ErrStale) && !errors.Is(err, ownership.ErrTransitioning) &&
				!errors.Is(err, ownership.ErrNotOwner) && !errors.Is(err, ownership.ErrResyncRequired) {
				// The mutation failed part-way: the fence now requires a
				// snapshot, which the retry commits.
				w.mu.Lock()
				w.scope(vpc).repair = true
				w.mu.Unlock()
			}
			w.reportFailure(evals, workerv1alpha1.ReasonProgrammingFailed, err)
			return fmt.Errorf("commit %s: %w", scope.Name(), err)
		}
	}
	w.mu.Lock()
	s := w.scope(vpc)
	s.resyncing, s.repair, s.committed = false, false, digest
	w.mu.Unlock()
	w.noteDrift(vpc, drifts)

	state := map[workerv1alpha1.Mode]module.State{}
	for _, m := range mods {
		st, err := m.Read(ctx, scope)
		if err != nil {
			w.reportFailure(evals, workerv1alpha1.ReasonProgrammingFailed, err)
			return fmt.Errorf("read %s: %w", m.Name(), err)
		}
		state[m.Mode()] = st
	}
	handoffs := map[module.ClaimKey][]module.HandoffInterface{}
	for _, m := range mods {
		if r, ok := m.(module.HandoffReporter); ok {
			for k, ifs := range r.HandoffInterfaces(scope) {
				handoffs[k] = append(handoffs[k], ifs...)
			}
		}
	}
	return w.report(evals, state, handoffs)
}

// planClaimedHost reports whether the canonical host state of vpc, which
// Worker holds claims in, must be ensured. The claims keep the state in use
// whatever else does.
func (w *Worker) planClaimedHost(ctx context.Context, vpc string) (bool, error) {
	if w.d.Host == nil {
		return false, nil
	}
	w.mu.Lock()
	w.scope(vpc).unreferencedSince = time.Time{}
	w.mu.Unlock()
	hp, err := w.d.Host.Plan(ctx, vpc, true)
	if err != nil {
		return false, fmt.Errorf("plan host state: %w", err)
	}
	return hp.Ensure, nil
}

// reconcileHost reconciles a scope Worker holds no claims in. It takes the
// scope, adopting with a snapshot commit that writes nothing whatever host
// state CNI or an earlier writer left, and reclaims the VPC's host state once
// nothing has used it for HostGrace. A scope another writer owns is left
// alone. A scope whose VRF is gone is forgotten.
func (w *Worker) reconcileHost(ctx context.Context, vpc string) error {
	hp, err := w.d.Host.Plan(ctx, vpc, false)
	if err != nil {
		return fmt.Errorf("plan host state of VPC %s: %w", vpc, err)
	}
	if !hp.Present {
		// A transfer an earlier incarnation left open refuses every CNI
		// write, including the ADD that would create the VRF, so it is
		// completed even with nothing on the host.
		if err := w.completeTransfer(vpc); err != nil {
			return err
		}
		w.forgetScope(vpc)
		return nil
	}
	reclaim := w.unusedFor(vpc, hp.Referenced())

	scope := module.Scope{VPC: vpc}
	t, err := w.acquire(scope)
	if errors.Is(err, errOwnedElsewhere) || errors.Is(err, ownership.ErrTransitioning) ||
		errors.Is(err, ownership.ErrNotOwner) {
		w.log.Debug("leaving host state of a VPC another writer owns", "vpc", vpc, "reason", err)
		return nil
	}
	if err != nil {
		return err
	}
	// A module can hold state for a scope with no claims, such as the
	// tenant routes the Fabric module writes for every VPC on the node.
	mods, changes, empty, err := w.planModules(ctx, scope, nil)
	if err != nil {
		return err
	}
	if !reclaim && !t.Resync && empty {
		return nil
	}
	gone := false
	mutate := func() error {
		if err := applyModules(ctx, scope, mods, changes); err != nil {
			return err
		}
		// A claim accepted since the plan keeps the state; its own
		// reconcile follows this one.
		if !reclaim || w.hasClaims(vpc) {
			return nil
		}
		var err error
		gone, err = w.d.Host.Reclaim(ctx, vpc)
		return err
	}
	commit := w.d.Fence.Commit
	if t.Resync {
		commit = w.d.Fence.CommitSnapshot
	}
	if _, err := commit(t, mutate); err != nil {
		return fmt.Errorf("commit host state of %s: %w", module.Scope{VPC: vpc}.Name(), err)
	}
	if gone {
		w.log.Info("reclaimed unused VPC host state", "vpc", vpc)
		w.forgetScope(vpc)
	}
	return nil
}

// reconcileUnclaimed reconciles a scope Worker holds no claims in when it
// manages no host state: it commits whatever the modules hold for the scope
// without claims, and stops tracking a scope that needs nothing.
func (w *Worker) reconcileUnclaimed(ctx context.Context, vpc string) error {
	scope := module.Scope{VPC: vpc}
	mods, changes, empty, err := w.planModules(ctx, scope, nil)
	if err != nil {
		return err
	}
	if empty {
		w.mu.Lock()
		if !w.hasClaimsLocked(vpc) {
			delete(w.scopes, vpc)
		}
		w.mu.Unlock()
		return nil
	}
	t, err := w.acquire(scope)
	if errors.Is(err, errOwnedElsewhere) || errors.Is(err, ownership.ErrTransitioning) ||
		errors.Is(err, ownership.ErrNotOwner) {
		return nil
	}
	if err != nil {
		return err
	}
	commit := w.d.Fence.Commit
	if t.Resync {
		commit = w.d.Fence.CommitSnapshot
	}
	if _, err := commit(t, func() error { return applyModules(ctx, scope, mods, changes) }); err != nil {
		return fmt.Errorf("commit %s: %w", scope.Name(), err)
	}
	return nil
}

// planModules plans every module for scope against desired, by mode, and
// reports whether every change is empty.
func (w *Worker) planModules(ctx context.Context, scope module.Scope,
	desired map[workerv1alpha1.Mode][]module.Claim) ([]module.Module, []module.Change, bool, error) {
	mods := w.d.Modules.Modules()
	changes := make([]module.Change, len(mods))
	empty := true
	for i, m := range mods {
		ch, err := m.Plan(ctx, scope, desired[m.Mode()])
		if err != nil {
			return nil, nil, false, fmt.Errorf("plan %s: %w", m.Name(), err)
		}
		changes[i] = ch
		empty = empty && ch.Empty()
	}
	return mods, changes, empty, nil
}

// applyModules applies every non-empty change. It runs inside a fence commit.
func applyModules(ctx context.Context, scope module.Scope, mods []module.Module, changes []module.Change) error {
	for i, m := range mods {
		if changes[i].Empty() {
			continue
		}
		if err := m.Apply(ctx, scope, changes[i]); err != nil {
			return fmt.Errorf("apply %s: %w", m.Name(), err)
		}
	}
	return nil
}

// completeTransfer takes over vpc's scope when it is transitioning away from
// an earlier Worker incarnation, committing a snapshot that writes nothing.
func (w *Worker) completeTransfer(vpc string) error {
	scope := module.Scope{VPC: vpc}
	rec, err := w.d.Fence.Read(scope.Name())
	if err != nil || !rec.Transitioning || !takeable(rec) {
		return err
	}
	t, err := w.acquire(scope)
	if err != nil {
		return err
	}
	if _, err := w.d.Fence.CommitSnapshot(t, func() error { return nil }); err != nil {
		return fmt.Errorf("commit %s: %w", scope.Name(), err)
	}
	return nil
}

// unusedFor records whether vpc's host state is in use, and reports whether
// it has gone unused for HostGrace. While it waits it queues the scope again
// for when the grace ends.
func (w *Worker) unusedFor(vpc string, referenced bool) bool {
	w.mu.Lock()
	s := w.scope(vpc)
	now := w.d.Now()
	if referenced {
		s.unreferencedSince = time.Time{}
		w.mu.Unlock()
		return false
	}
	if s.unreferencedSince.IsZero() {
		s.unreferencedSince = now
	}
	left := w.cfg.HostGrace - now.Sub(s.unreferencedSince)
	w.mu.Unlock()
	if left > 0 {
		w.queue.AddAfter(vpc, left)
		return false
	}
	return true
}

// hasClaims reports whether Worker holds a claim in vpc.
func (w *Worker) hasClaims(vpc string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hasClaimsLocked(vpc)
}

// hasClaimsLocked is hasClaims with w.mu held.
func (w *Worker) hasClaimsLocked(vpc string) bool {
	for k := range w.claims {
		if k.VPC == vpc {
			return true
		}
	}
	return false
}

// forgetScope stops tracking vpc's scope unless Worker holds claims in it.
func (w *Worker) forgetScope(vpc string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k := range w.claims {
		if k.VPC == vpc {
			return
		}
	}
	delete(w.scopes, vpc)
}

// resolve evaluates every claim of a scope against trusted sources and
// capability status, withdraws claims whose authority was revoked, and
// returns the desired state of each mode.
func (w *Worker) resolve(ctx context.Context, vpc string, claims []claim) (
	[]*claimEval, map[workerv1alpha1.Mode][]module.Claim, error) {
	own, err := w.d.Sources.Locator(ctx, w.cfg.Node)
	if err != nil {
		return nil, nil, fmt.Errorf("read this node's locator: %w", err)
	}
	locators := map[string]netip.Prefix{w.cfg.Node: own}
	locator := func(node string) (netip.Prefix, error) {
		if p, ok := locators[node]; ok {
			return p, nil
		}
		p, err := w.d.Sources.Locator(ctx, node)
		if err != nil {
			return netip.Prefix{}, err
		}
		locators[node] = p
		return p, nil
	}

	desired := map[workerv1alpha1.Mode][]module.Claim{}
	var evals []*claimEval
	for _, c := range claims {
		e := &claimEval{key: c.key(), owner: c.rec.Owner, gen: c.rec.Generation, releasing: c.rec.Releasing}
		evals = append(evals, e)
		if e.releasing {
			continue
		}
		att, ok, err := w.d.Sources.Attachment(ctx, e.key.AttachmentUID)
		if err != nil {
			return nil, nil, fmt.Errorf("read attachment %s: %w", e.key.AttachmentUID, err)
		}
		if !ok || att.VPC != vpc || att.Node != w.cfg.Node || !att.Admitted {
			if err := w.withdraw(e.key, e.gen, store.WithdrawClaim, workerv1alpha1.ReasonAuthorizationRevoked); err != nil {
				return nil, nil, err
			}
			e.releasing = true
			continue
		}
		perMode := map[workerv1alpha1.Mode][]module.Destination{}
		// usable checks a resolved destination's capability, and keeps it
		// for its mode's module when the owner may use it and it runs.
		usable := func(de *destEval, dst module.Destination) {
			capName := module.RequiredCapability(c.spec.GetHandoff(), de.mode)
			if !slices.Contains(c.rec.Capabilities, capName) {
				// The destination resolved to a mode the owner was not
				// allowed when it was admitted, for example once a locator
				// became known.
				de.capReason = workerv1alpha1.ReasonCapabilityNotAllowed
				de.capMsg = c.rec.Owner + " may not use " + capName
			} else if cp := w.d.Modules.Capability(capName); !cp.Available {
				de.capReason, de.capMsg = cp.Reason, cp.Message
				if de.capMsg == "" {
					de.capMsg = capName + " is unavailable"
				}
			} else {
				perMode[de.mode] = append(perMode[de.mode], dst)
			}
		}
		var edgeLink *module.EdgeLink
		if el := c.spec.GetEdgeLink(); el != nil {
			de, dst, link := edgeLinkDestination(e.key, own, att, el)
			if de.resolved && de.capReason == "" {
				usable(&de, dst)
			}
			edgeLink = link
			e.dests = append(e.dests, de)
		}
		for _, d := range c.spec.GetDestinations() {
			de := destEval{ref: d, id: module.DestinationID(d)}
			dst, err := w.resolveDestination(ctx, vpc, own, c.spec.GetMode(), d, locator, &de)
			if err != nil {
				return nil, nil, err
			}
			if de.resolved {
				usable(&de, dst)
			}
			e.dests = append(e.dests, de)
		}
		for mode, dests := range perMode {
			mc := module.Claim{Key: e.key, Owner: e.owner, Generation: e.gen,
				Handoff: c.spec.GetHandoff(), OwnerPod: c.rec.PodUID, Addresses: slices.Clone(att.Addresses),
				Destinations: dests}
			if mode == workerv1alpha1.Mode_MODE_LOCAL {
				mc.EdgeLink = edgeLink
			}
			desired[mode] = append(desired[mode], mc)
		}
	}
	return evals, desired, nil
}

// edgeLinkDestination resolves a connector claim's one destination: its own
// EdgeAttachment, delivered Local through the host link galactic-edge
// created (D37). The link's address is the attachment's, from its trusted
// source; an attachment with none yet programs nothing.
func edgeLinkDestination(k module.ClaimKey, own netip.Prefix, att sources.Attachment,
	el *workerv1alpha1.EdgeLink) (destEval, module.Destination, *module.EdgeLink) {
	ref := &workerv1alpha1.Destination{Target: &workerv1alpha1.Destination_Attachment{
		Attachment: &workerv1alpha1.AttachmentRef{Uid: k.AttachmentUID}}}
	de := destEval{ref: ref, id: module.DestinationID(ref), mode: workerv1alpha1.Mode_MODE_LOCAL, resolved: true}
	if len(att.Addresses) == 0 {
		de.capReason, de.capMsg = workerv1alpha1.ReasonDestinationAddressUnknown,
			"the EdgeAttachment has no address allocated yet"
		return de, module.Destination{}, nil
	}
	link := &module.EdgeLink{Name: el.GetName(), Address: att.Addresses[0]}
	for _, p := range el.GetPrefixes() {
		// validateEdgeLink parsed every prefix when the spec was accepted.
		if pfx, err := netip.ParsePrefix(p); err == nil {
			link.Prefixes = append(link.Prefixes, pfx.Masked())
		}
	}
	dst := module.Destination{ID: de.id, Ref: ref, Mode: de.mode, VPC: att.VPC, Node: att.Node, Locator: own,
		Addresses: slices.Clone(att.Addresses), HostInterface: el.GetName()}
	return de, dst, link
}

// resolveDestination resolves one destination to Local or Fabric. A
// destination on this node's locator is Local; any other is Fabric. Worker
// never falls back from Local to Fabric.
func (w *Worker) resolveDestination(ctx context.Context, vpc string, own netip.Prefix,
	pref workerv1alpha1.Mode, d *workerv1alpha1.Destination,
	locator func(string) (netip.Prefix, error), de *destEval) (module.Destination, error) {
	t, ok := d.GetTarget().(*workerv1alpha1.Destination_Attachment)
	if !ok {
		de.reason = workerv1alpha1.ReasonDestinationKindUnsupported
		de.msg = "shard and backend destinations are resolved by later Tasks (#1437, #1438)"
		return module.Destination{}, nil
	}
	att, found, err := w.d.Sources.Attachment(ctx, t.Attachment.GetUid())
	if err != nil {
		return module.Destination{}, fmt.Errorf("read destination %s: %w", t.Attachment.GetUid(), err)
	}
	switch {
	case !found:
		de.reason, de.msg = workerv1alpha1.ReasonDestinationNotFound, "the destination attachment does not exist"
		return module.Destination{}, nil
	case att.VPC != vpc:
		de.reason, de.msg = workerv1alpha1.ReasonVPCNotAuthorized, "the destination is in another VPC"
		return module.Destination{}, nil
	case !own.IsValid():
		de.reason, de.msg = workerv1alpha1.ReasonLocatorUnknown, "this node has no SRv6 locator yet"
		return module.Destination{}, nil
	}
	loc, err := locator(att.Node)
	if err != nil {
		return module.Destination{}, fmt.Errorf("read locator of %s: %w", att.Node, err)
	}
	if !loc.IsValid() {
		de.reason, de.msg = workerv1alpha1.ReasonLocatorUnknown, "the destination's node has no SRv6 locator yet"
		return module.Destination{}, nil
	}
	mode := workerv1alpha1.Mode_MODE_FABRIC
	if loc == own {
		mode = workerv1alpha1.Mode_MODE_LOCAL
	}
	if (pref == workerv1alpha1.Mode_MODE_LOCAL || pref == workerv1alpha1.Mode_MODE_FABRIC) && pref != mode {
		de.mode = mode
		de.reason, de.msg = workerv1alpha1.ReasonModeUnavailable,
			"the destination resolves to "+modeName(mode)+", not the requested mode"
		return module.Destination{}, nil
	}
	de.mode, de.resolved = mode, true
	return module.Destination{ID: de.id, Ref: d, Mode: mode, VPC: att.VPC, Node: att.Node, Locator: loc,
		Addresses: slices.Clone(att.Addresses), HostInterface: att.HostInterface}, nil
}

func modeName(m workerv1alpha1.Mode) string {
	return strings.ToLower(strings.TrimPrefix(m.String(), "MODE_"))
}

// acquire returns a ticket for this incarnation's next commit to scope:
// Begin for a scope it owns, Claim for an unowned one, and Takeover for one
// an earlier Worker incarnation owned or left transitioning. A scope another
// writer owns, or is moving to, is errOwnedElsewhere or ErrTransitioning.
func (w *Worker) acquire(scope module.Scope) (ownership.Ticket, error) {
	name := scope.Name()
	rec, err := w.d.Fence.Read(name)
	if err != nil {
		return ownership.Ticket{}, err
	}
	switch {
	case !rec.Transitioning && rec.Owner == w.owner:
		return w.d.Fence.Begin(name, w.owner)
	case !rec.Transitioning && rec.Owner == "":
		return w.d.Fence.Claim(name, w.owner)
	case takeable(rec):
		return w.d.Fence.Takeover(name, w.owner, takeable)
	case rec.Transitioning:
		return ownership.Ticket{}, fmt.Errorf("%w: %s is moving to another owner", ownership.ErrTransitioning, name)
	default:
		return ownership.Ticket{}, fmt.Errorf("%w: %q owns %s", errOwnedElsewhere, rec.Owner, name)
	}
}

// takeable accepts a scope no writer owns, one a Worker incarnation owns, or
// one a Worker handback left (internal/worker/handback), as it stands under
// the fence's lock. A Worker installed again after a handback takes back the
// scopes no legacy writer has taken since.
func takeable(r ownership.Record) bool {
	return r.Owner == "" || ownership.WorkerOwned(r.Owner) || ownership.HandedBack(r.Owner)
}

// reportFailure sets Programmed=False with reason on every live claim of
// the pass.
func (w *Worker) reportFailure(evals []*claimEval, reason string, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range evals {
		c := w.claims[e.key]
		if c == nil || c.rec.Generation != e.gen || c.rec.Releasing {
			continue
		}
		before := cloneCondition(readyCondition(c.status))
		setCond(c.status, cond(workerv1alpha1.ConditionProgrammed, condFalse, reason, err.Error()))
		setCond(c.status, cond(workerv1alpha1.ConditionReady, condFalse, reason, ""))
		c.status.ObservedGeneration = e.gen
		w.logReadyChange(c, before)
		w.publish(c)
	}
}

// report turns read-back into status, and deletes released claims whose
// programmed state is gone.
func (w *Worker) report(evals []*claimEval, state map[workerv1alpha1.Mode]module.State,
	handoffs map[module.ClaimKey][]module.HandoffInterface) error {
	present := func(k module.ClaimKey) bool {
		for _, st := range state {
			if len(st[k]) > 0 {
				return true
			}
		}
		return false
	}
	var done []keyGen
	w.mu.Lock()
	for _, e := range evals {
		c := w.claims[e.key]
		if c == nil || c.rec.Generation != e.gen {
			continue
		}
		if c.rec.Releasing {
			if !present(e.key) {
				done = append(done, keyGen{e.key, e.gen})
			}
			continue
		}
		if e.releasing {
			continue
		}
		before := cloneCondition(readyCondition(c.status))
		w.applyStatus(c, e, state)
		w.logReadyChange(c, before)
		c.status.HandoffInterfaces = nil
		for _, h := range handoffs[e.key] {
			c.status.HandoffInterfaces = append(c.status.HandoffInterfaces,
				&workerv1alpha1.HandoffInterface{Role: h.Role, Name: h.Name, Ifindex: h.Ifindex})
		}
		w.publish(c)
	}
	w.mu.Unlock()

	var errs []error
	for _, d := range done {
		if err := w.forget(d.key, d.gen); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// applyStatus computes a live claim's status from its evaluation and the
// read-back. w.mu must be held.
func (w *Worker) applyStatus(c *claim, e *claimEval, state map[workerv1alpha1.Mode]module.State) {
	st := c.status
	st.ObservedGeneration = e.gen
	st.Destinations = nil
	resolved, programmed, ready := true, true, true
	var rReason, rMsg, pReason, pMsg, yReason, yMsg string
	first := func(r, m *string, reason, msg string) {
		if *r == "" {
			*r, *m = reason, msg
		}
	}
	for _, de := range e.dests {
		ds := &workerv1alpha1.DestinationStatus{Destination: de.ref, Mode: de.mode, Resolved: de.resolved}
		switch {
		case !de.resolved:
			ds.Reason, ds.Message = de.reason, de.msg
			resolved = false
			first(&rReason, &rMsg, de.reason, de.id+": "+de.msg)
		case de.capReason != "":
			ds.Reason, ds.Message = de.capReason, de.capMsg
			programmed = false
			first(&pReason, &pMsg, de.capReason, de.id+": "+de.capMsg)
		default:
			got, ok := state[de.mode][e.key][de.id]
			switch {
			case !ok || got.Generation != e.gen:
				ds.Reason, ds.Message = workerv1alpha1.ReasonPending, "not yet programmed"
				if got.Reason != "" {
					ds.Reason, ds.Message = got.Reason, got.Message
				}
				programmed = false
				first(&pReason, &pMsg, ds.Reason, de.id+": "+ds.Message)
			case !got.Programmed:
				ds.Reason, ds.Message = got.Reason, got.Message
				programmed = false
				first(&pReason, &pMsg, got.Reason, de.id+": "+got.Message)
			default:
				ds.Programmed = true
				ds.Ready = got.Ready
				ds.ForwardReady, ds.ReturnReady = got.ForwardReady, got.ReturnReady
				if !got.Ready {
					ds.Reason, ds.Message = got.Reason, got.Message
					ready = false
					first(&yReason, &yMsg, got.Reason, de.id+": "+got.Message)
				}
			}
		}
		st.Destinations = append(st.Destinations, ds)
	}
	set := func(t string, ok bool, reason, msg string) {
		if ok {
			setCond(st, cond(t, condTrue, workerv1alpha1.ReasonAsExpected, ""))
			return
		}
		setCond(st, cond(t, condFalse, reason, msg))
	}
	set(workerv1alpha1.ConditionAdmitted, true, "", "")
	set(workerv1alpha1.ConditionResolved, resolved, rReason, rMsg)
	// Programmed covers every resolved destination; an unresolved one has
	// nothing to program and is reported by Resolved.
	set(workerv1alpha1.ConditionProgrammed, programmed, pReason, pMsg)
	readyOK := resolved && programmed && ready
	switch {
	case !resolved:
		set(workerv1alpha1.ConditionReady, false, rReason, rMsg)
	case !programmed:
		set(workerv1alpha1.ConditionReady, false, pReason, pMsg)
	default:
		set(workerv1alpha1.ConditionReady, readyOK, yReason, yMsg)
	}
	set(workerv1alpha1.ConditionWithdrawing, false, workerv1alpha1.ReasonAsExpected, "")
	st.WithdrawalScope = workerv1alpha1.WithdrawalScope_WITHDRAWAL_SCOPE_UNSPECIFIED
}

// forget deletes a released claim once its programmed state is confirmed
// gone, and sends its last snapshot.
func (w *Worker) forget(k module.ClaimKey, gen uint64) error {
	lock := w.keyLock(k)
	lock.Lock()
	defer lock.Unlock()
	w.mu.Lock()
	c := w.claims[k]
	if c == nil || c.rec.Generation != gen || !c.rec.Releasing {
		w.mu.Unlock()
		return nil
	}
	w.mu.Unlock()
	if err := w.d.Store.Delete(k.Node, k.VPC, k.AttachmentUID); err != nil {
		return fmt.Errorf("delete released claim: %w", err)
	}
	w.mu.Lock()
	delete(w.claims, k)
	for _, t := range []string{workerv1alpha1.ConditionProgrammed, workerv1alpha1.ConditionReady,
		workerv1alpha1.ConditionWithdrawing} {
		setCond(c.status, cond(t, condFalse, workerv1alpha1.ReasonReleased, "programmed state removed"))
	}
	c.status.Released = true
	c.status.ObservedGeneration = gen
	c.status.Destinations = nil
	c.status.HandoffInterfaces = nil
	w.publish(c)
	w.mu.Unlock()
	updateClaimGauge(w)
	w.log.Info("claim released", "owner", c.rec.Owner, "vpc", k.VPC, "attachment", k.AttachmentUID, "generation", gen)
	return nil
}
