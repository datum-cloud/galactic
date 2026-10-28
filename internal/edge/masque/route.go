// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package masque

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/provider"
	edgeroute "go.datum.net/galactic/internal/edge/route"
)

// releaseTimeout bounds releasing a claim when its last request ends.
const releaseTimeout = 5 * time.Second

// route is the EdgeRoute of one connector's /96, claimed while a request of
// the connector holds it.
type route struct {
	name   string
	vpcUID string
	prefix netip.Prefix
	// prep serializes claiming and releasing this route. It is held across
	// API calls and never taken while Adapter.mu is held.
	prep prepLock

	// The fields below are guarded by Adapter.mu.

	refs int
	// active reports that core accepted claim epoch epoch for att, at its
	// generation attGen and UID attUID, under lease.
	active bool
	att    *attachment
	attGen uint64
	attUID types.UID
	epoch  int64
	lease  claim.Lease
	// claimLease is the instance lease the route's current claim was
	// written under, accepted or not; zero until a claim is written.
	claimLease claim.Lease
	// gen increments whenever the route stops being active.
	gen uint64
}

// acquireRoute claims the route of g's /96 for e and waits until core
// accepts the claim under the current lease. It returns a reference the
// caller releases with releaseRoute.
func (a *Adapter) acquireRoute(ctx context.Context, g *Grant, e *attachment) (*route, error) {
	name := provider.RouteName(g.VPCUID, g.Prefix)
	a.mu.Lock()
	r := a.routes[name]
	if r == nil {
		r = &route{name: name, vpcUID: g.VPCUID, prefix: g.Prefix, prep: newPrepLock()}
		a.routes[name] = r
	}
	r.refs++
	a.mu.Unlock()

	if err := a.claim(ctx, g, e, r); err != nil {
		rctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
		defer cancel()
		a.releaseRoute(rctx, r)
		return nil, err
	}
	return r, nil
}

// errRouteRefused is a claim core refuses for a reason no retry changes.
var errRouteRefused = errors.New("core refuses route")

// claim waits until core accepts r's claim for e, and counts a claim that
// fails.
func (a *Adapter) claim(ctx context.Context, g *Grant, e *attachment, r *route) error {
	err := a.claimRoute(ctx, g, e, r)
	switch {
	case errors.Is(err, errRouteRefused):
		routeClaims.WithLabelValues(claimRefused).Inc()
	case err != nil:
		routeClaims.WithLabelValues(claimFailed).Inc()
	}
	return err
}

func (a *Adapter) claimRoute(ctx context.Context, g *Grant, e *attachment, r *route) error {
	if err := r.prep.lock(ctx); err != nil {
		return err
	}
	defer r.prep.unlock()
	for {
		state, err := a.claimOnce(ctx, g, e, r)
		if err != nil || state == "" {
			return err
		}
		if err := a.wait(ctx, state); err != nil {
			return err
		}
	}
}

// claimOnce makes one claim pass. It returns the state it waits on, or ""
// once core accepted the claim. The caller holds r.prep.
func (a *Adapter) claimOnce(ctx context.Context, g *Grant, e *attachment, r *route) (string, error) {
	l, ok := a.heldLease()
	if !ok {
		return "", errors.New("the instance holds no lease")
	}
	a.mu.Lock()
	gen, served, attUID := e.gen, e.backend != nil, e.uid
	if r.active {
		if r.att == e && r.attGen == gen && sameLease(r.lease, l) {
			a.mu.Unlock()
			return "", nil
		}
		// The claim is about to move to another attachment or lease: the
		// requests admitted under the accepted one stop first.
		a.deactivate(r, reasonRouteMoved)
	}
	a.mu.Unlock()
	if !served {
		return "", fmt.Errorf("attachment %s stopped serving", e.name)
	}

	var rt galacticv1alpha1.EdgeRoute
	err := a.cfg.Client.Get(ctx, client.ObjectKey{Namespace: a.cfg.Pod.Namespace, Name: r.name}, &rt)
	switch {
	case apierrors.IsNotFound(err):
		rt = *provider.NewRoute(a.cfg.Pod.Namespace, a.cfg.Provider, g.VPCUID, g.Prefix)
		rt.Spec.Claim = &galacticv1alpha1.EdgeRouteClaim{Attachment: e.name, HolderPodUID: a.cfg.Pod.UID,
			HolderInstance: l.Key, InstanceEpoch: int64(l.Epoch), Epoch: 1}
		err = a.cfg.Client.Create(ctx, &rt)
	case err != nil:
		return "route not read: " + err.Error(), nil
	case rt.Spec.VPCUID != g.VPCUID || rt.Spec.Prefix != g.Prefix.String() ||
		rt.Spec.ProviderRef.Name != a.cfg.Provider:
		return "", fmt.Errorf("EdgeRoute %s is for %s in VPC %s of provider %q", rt.Name, rt.Spec.Prefix,
			rt.Spec.VPCUID, rt.Spec.ProviderRef.Name)
	default:
		err = provider.Claim(ctx, a.cfg.Client, &rt, e.name, a.cfg.Pod.UID, l)
	}
	switch {
	case apierrors.IsConflict(err), apierrors.IsAlreadyExists(err):
		return "route changed concurrently", nil
	case err != nil:
		return "route not claimed: " + err.Error(), nil
	}
	a.mu.Lock()
	r.claimLease = l
	a.mu.Unlock()
	if !acceptedFor(&rt, e.name, attUID, l) {
		if c := meta.FindStatusCondition(rt.Status.Conditions, galacticv1alpha1.EdgeRouteClaimed); c != nil &&
			c.Status == metav1.ConditionFalse && refusals[c.Reason] {
			return "", fmt.Errorf("%w %s: %s: %s", errRouteRefused, rt.Name, c.Reason, c.Message)
		}
		return "waiting for core to accept route " + rt.Name + routeState(&rt), nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !e.serving(gen) {
		return "", fmt.Errorf("attachment %s stopped serving", e.name)
	}
	if cur, ok := a.heldLease(); !ok || !sameLease(cur, l) {
		return "", errors.New("the instance's lease changed while the route was claimed")
	}
	r.active, r.att, r.attGen, r.attUID, r.epoch, r.lease = true, e, gen, attUID, rt.Spec.Claim.Epoch, l
	routeClaims.WithLabelValues(claimAccepted).Inc()
	a.log.Info("route accepted", "route", r.name, "prefix", r.prefix, "epoch", r.epoch, "attachment", e.name)
	return "", nil
}

// refusals are the reasons core refuses a claim that no retry of the same
// grant can change: the service or provider does not grant the route, or
// its prefix is invalid or held in the VPC by another grant. Any other
// refusal, such as waiting for the previous holder to be fenced, is waited
// out.
var refusals = map[string]bool{
	string(admission.ProviderNotGranted):    true,
	string(admission.CapabilityNotGranted):  true,
	string(admission.VPCNotGranted):         true,
	string(admission.PrefixNotGranted):      true,
	string(admission.UnsupportedCapability): true,
	edgeroute.ReasonPrefixConflict:          true,
	edgeroute.ReasonInvalidPrefix:           true,
}

// sameLease reports whether a and b are the same lease: the same instance
// key, holder, incarnation and epoch. Renewals change only its deadline and
// version.
func sameLease(a, b claim.Lease) bool {
	return a.Key == b.Key && a.Holder == b.Holder && a.Incarnation == b.Incarnation && a.Epoch == b.Epoch
}

// acceptedFor reports whether core accepted the route's current claim for
// the attachment with name and uid under lease l, and has neither revoked
// nor closed it.
func acceptedFor(r *galacticv1alpha1.EdgeRoute, attachment string, uid types.UID, l claim.Lease) bool {
	acc, cl := r.Status.Accepted, r.Spec.Claim
	return acc != nil && cl != nil && !cl.Released && acc.Epoch == cl.Epoch && acc.Attachment == attachment &&
		acc.AttachmentUID == string(uid) && acc.InstanceIncarnation == l.Incarnation &&
		cl.Attachment == attachment && acc.Instance == l.Key && acc.InstanceEpoch == int64(l.Epoch) &&
		cl.HolderInstance == l.Key && cl.InstanceEpoch == int64(l.Epoch) && r.Status.ClosedEpoch < cl.Epoch &&
		meta.IsStatusConditionTrue(r.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted)
}

// routeState summarizes why core has not accepted a route.
func routeState(r *galacticv1alpha1.EdgeRoute) string {
	for _, t := range []string{galacticv1alpha1.EdgeRouteClaimed, galacticv1alpha1.EdgeRouteAccepted} {
		if c := meta.FindStatusCondition(r.Status.Conditions, t); c != nil && c.Status != metav1.ConditionTrue {
			return fmt.Sprintf(": %s %s: %s", t, c.Reason, c.Message)
		}
	}
	return ""
}

// releaseRoute drops one reference to r. The last one releases the claim,
// after every request of the connector stopped forwarding, unless another
// request took the route while the release waited for it.
func (a *Adapter) releaseRoute(ctx context.Context, r *route) {
	if a.dropRoute(r) {
		a.releaseUnused(ctx, r)
	}
}

// dropRoute drops one reference to r and reports whether it was the last.
func (a *Adapter) dropRoute(r *route) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	r.refs--
	if r.refs > 0 {
		return false
	}
	a.deactivate(r, reasonRouteReleased)
	return true
}

// releaseUnused releases r's claim and forgets r, unless a request has
// taken r since its last reference was dropped.
func (a *Adapter) releaseUnused(ctx context.Context, r *route) {
	if err := r.prep.lock(ctx); err != nil {
		a.log.Warn("could not release route claim; core revokes it with the lease", "route", r.name, "error", err)
		return
	}
	defer r.prep.unlock()
	a.mu.Lock()
	taken := r.refs > 0
	a.mu.Unlock()
	if taken {
		return
	}
	if err := a.releaseClaim(ctx, r); err != nil {
		a.log.Warn("could not release route claim; core revokes it with the lease", "route", r.name, "error", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.refs == 0 && a.routes[r.name] == r {
		delete(a.routes, r.name)
	}
}

// deactivate ends the requests on r. The caller holds Adapter.mu.
func (a *Adapter) deactivate(r *route, reason string) {
	if r.active {
		r.active = false
		r.gen++
	}
	for _, s := range a.sessions {
		if s.rt == r {
			s.end(reason)
		}
	}
}

// releaseClaim marks r's claim released when it is still the claim this
// adapter wrote. A claim since taken by another holder or lease epoch is
// left alone. The caller holds r.prep.
func (a *Adapter) releaseClaim(ctx context.Context, r *route) error {
	a.mu.Lock()
	l := r.claimLease
	a.mu.Unlock()
	if l.Key == "" {
		return nil
	}
	for range 5 {
		var rt galacticv1alpha1.EdgeRoute
		err := a.cfg.Client.Get(ctx, client.ObjectKey{Namespace: a.cfg.Pod.Namespace, Name: r.name}, &rt)
		if err != nil {
			return client.IgnoreNotFound(err)
		}
		err = provider.Release(ctx, a.cfg.Client, &rt, l)
		switch {
		case errors.Is(err, provider.ErrNotHolder):
			return nil
		case err == nil:
			a.log.Info("route released", "route", r.name)
			return nil
		case !apierrors.IsConflict(err):
			return fmt.Errorf("release route %s: %w", r.name, err)
		}
	}
	return fmt.Errorf("release route %s: it kept changing", r.name)
}

// checkRoute ends the requests on r once core no longer accepts its claim.
func (a *Adapter) checkRoute(ctx context.Context, r *route) {
	a.mu.Lock()
	gen, att, attUID, l, epoch := r.gen, r.att, r.attUID, r.lease, r.epoch
	a.mu.Unlock()
	if att == nil {
		return
	}
	var rt galacticv1alpha1.EdgeRoute
	err := a.cfg.Client.Get(ctx, client.ObjectKey{Namespace: a.cfg.Pod.Namespace, Name: r.name}, &rt)
	if err != nil && !apierrors.IsNotFound(err) {
		return
	}
	if err == nil && acceptedFor(&rt, att.name, attUID, l) && rt.Spec.Claim.Epoch == epoch {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.gen == gen && r.active {
		routeClaims.WithLabelValues(claimRevoked).Inc()
		a.log.Info("route no longer accepted", "route", r.name, "epoch", epoch)
		a.deactivate(r, reasonRouteRevoked)
	}
}
