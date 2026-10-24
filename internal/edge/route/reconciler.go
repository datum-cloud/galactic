// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package route is galactic-controller's half of the Galactic Edge
// forwarding claim: it accepts an EdgeRoute's claim only once the previous
// holder can no longer forward, revokes an accepted holder whose authority
// ended, and keeps each VPC's EdgeRouteIndex, through which acceptance is
// serialized and overlapping routes are refused. It also reaps instances and
// routes no live pod can use. The node half, which opens and closes the
// forwarding gate, is internal/edge/agent.
//
// A provider writes a claim; it grants nothing until accepted. A claim on
// another attachment than the previous holder's is accepted only when that
// holder's node has confirmed its gate closed (closedEpoch), or when the
// leader has seen the previous holder's instance lease unchanged for the
// takeover interval on its own monotonic clock, through reads from the API
// server. The node extends a gate only from renewals of that lease, so an
// unchanged lease means the old gate's deadline has passed. Observations are
// in the leader's memory: a new leader starts every wait again.
package route

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/diag"
	"go.datum.net/galactic/internal/edge/provider"
)

// refusedRetry bounds how long a refused claim waits for an event before it
// is decided again.
const refusedRetry = time.Minute

// maxIndexEntries is EdgeRouteIndex's limit on routes per VPC.
const maxIndexEntries = 1024

// ReasonIndexFull refuses a route once its VPC holds maxIndexEntries.
const ReasonIndexFull = "IndexFull"

// Reconciler accepts and revokes EdgeRoute claims and keeps EdgeRouteIndexes.
type Reconciler struct {
	// Client writes routes, indexes and instances.
	Client client.Client
	// APIReader reads every input from the API server, never a cache.
	APIReader client.Reader
	// Params is the cell's claim timing; every instance and node agent of
	// the cell must use the same.
	Params claim.Params
	// Clock is the leader's monotonic clock, on which takeover waits are
	// measured.
	Clock claim.Clock
	// Now is the wall clock, for grant expiry. Nil means time.Now.
	Now func() time.Time
	// BGPNamespace is where the cell's BGP objects live: the BGPVRFInstance
	// of each VPC on each node, and the BGPAdvertisement published for each
	// accepted route.
	BGPNamespace string
	// Diag records claims refused and accepted holders revoked.
	Diag *diag.Recorder

	mu sync.Mutex
	// observed holds the instance lease versions this leader is waiting on,
	// keyed by what is waited for.
	observed map[string]observation
}

type observation struct {
	version string
	at      time.Duration
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Reconcile implements reconcile.Reconciler for EdgeRoutes: it decides the
// route's claim, then publishes or withdraws its advertisement from the
// result. A route that is gone has every advertisement withdrawn.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var rt galacticv1alpha1.EdgeRoute
	switch err := r.APIReader.Get(ctx, req.NamespacedName, &rt); {
	case apierrors.IsNotFound(err):
		return ctrl.Result{}, r.withdrawGone(ctx, req.NamespacedName)
	case err != nil:
		return ctrl.Result{}, err
	}
	if reaped, err := r.reap(ctx, &rt); reaped || err != nil {
		if err == nil {
			err = r.withdrawGone(ctx, req.NamespacedName)
		}
		return ctrl.Result{}, err
	}
	res, err := r.decide(ctx, &rt)
	if err != nil || res == (ctrl.Result{Requeue: true}) {
		// A pass that lost a write race decides again before publishing.
		return res, err
	}
	if err := r.publish(ctx, &rt); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}
	return res, nil
}

// decide accepts, refuses or revokes the route's claim.
func (r *Reconciler) decide(ctx context.Context, rt *galacticv1alpha1.EdgeRoute) (ctrl.Result, error) {
	acc := rt.Status.Accepted
	if acc != nil && meta.IsStatusConditionTrue(rt.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted) {
		auth, ref, err := CheckAuthority(ctx, r.APIReader, rt, HolderOfAccepted(acc), r.now(), r.Params.MaxSkew)
		if err != nil {
			return ctrl.Result{}, err
		}
		if ref == nil {
			// A subnet, pool or grant created after acceptance revokes the
			// route: workload subnets take precedence over provider routes.
			if ref, err = Conflict(ctx, r.APIReader, auth.Service, auth.Attachment, auth.Prefix); err != nil {
				return ctrl.Result{}, err
			}
		}
		if ref != nil {
			msg := fmt.Sprintf("epoch %d revoked: %s: %s", acc.Epoch, ref.Reason, ref.Message)
			if err := r.setStatus(ctx, rt, func(s *galacticv1alpha1.EdgeRouteStatus) {
				setCondition(s, galacticv1alpha1.EdgeRouteAccepted, metav1.ConditionFalse, ReasonRevoked, msg)
			}); err != nil {
				return ctrl.Result{}, err
			}
			r.Diag.Failure(rt, diag.StageRoute, ref.Reason, msg, diag.ForRoute(rt))
			return ctrl.Result{}, nil
		}
	}

	c := rt.Spec.Claim
	switch {
	case c == nil:
		return ctrl.Result{}, nil
	case acc != nil && c.Epoch <= acc.Epoch:
		// The claim is the accepted one, released or not. A revoked holder
		// must claim a new epoch to be accepted again.
		return ctrl.Result{}, r.setStatus(ctx, rt, func(s *galacticv1alpha1.EdgeRouteStatus) {
			if meta.IsStatusConditionTrue(s.Conditions, galacticv1alpha1.EdgeRouteAccepted) {
				setCondition(s, galacticv1alpha1.EdgeRouteClaimed, metav1.ConditionTrue, ReasonAccepted,
					fmt.Sprintf("epoch %d is the accepted claim", acc.Epoch))
				return
			}
			setCondition(s, galacticv1alpha1.EdgeRouteClaimed, metav1.ConditionFalse, ReasonRevoked,
				fmt.Sprintf("epoch %d was revoked; only a new claim epoch can be accepted", acc.Epoch))
		})
	case c.Released:
		return ctrl.Result{}, nil
	}
	return r.accept(ctx, rt)
}

// accept decides the route's pending claim and, when its previous holder is
// fenced, commits it to the index and then to the route's status.
func (r *Reconciler) accept(ctx context.Context, rt *galacticv1alpha1.EdgeRoute) (ctrl.Result, error) {
	c := rt.Spec.Claim
	pending := func(reason, message string, after time.Duration) (ctrl.Result, error) {
		// Waiting to fence the previous holder is the claim's normal path,
		// not a failure.
		refused := reason != ReasonWaiting && reason != ReasonIndexRebuilt &&
			diag.EnteredFailure(rt.Status.Conditions, galacticv1alpha1.EdgeRouteClaimed, reason)
		err := r.setStatus(ctx, rt, func(s *galacticv1alpha1.EdgeRouteStatus) {
			setCondition(s, galacticv1alpha1.EdgeRouteClaimed, metav1.ConditionFalse, reason, message)
		})
		if err == nil && refused {
			r.Diag.Failure(rt, diag.StageRoute, reason, message, diag.ForRoute(rt))
		}
		return ctrl.Result{RequeueAfter: after}, err
	}
	auth, ref, err := Check(ctx, r.APIReader, rt, HolderOfClaim(c), r.now(), r.Params.MaxSkew)
	if err != nil {
		return ctrl.Result{}, err
	}
	if ref == nil {
		ref, err = Conflict(ctx, r.APIReader, auth.Service, auth.Attachment, auth.Prefix)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	if ref != nil {
		return pending(ref.Reason, ref.Message, refusedRetry)
	}
	idx, err := r.index(ctx, auth.Service.Namespace, rt.Spec.VPCUID)
	if err != nil {
		return ctrl.Result{}, err
	}
	entry := findEntry(idx, string(rt.UID))
	committed := entry != nil && entry.Epoch == c.Epoch && entry.AttachmentUID == string(auth.Attachment.UID)
	if !committed {
		// fencedAt is when the previous holder was last proven fenced by
		// waiting with no lease left to fence; zero when its node confirmed
		// it, its lease was fenced, or none can exist.
		var fencedAt time.Duration
		prev := previous(rt, entry)
		switch {
		case prev == nil && idx.Spec.Rebuilt:
			return pending(ReasonIndexRebuilt, "the VPC's route index was rebuilt; first claims wait the takeover interval",
				r.Params.TakeoverWait()/4)
		case prev == nil, prev.attachmentUID == string(auth.Attachment.UID):
			// A first claim, or the same attachment: no other forwarder can
			// exist.
		case rt.Status.ClosedEpoch >= prev.epoch:
			// The previous holder's node confirmed its gate closed.
		default:
			done, at, after, err := r.waited(ctx, rt, prev)
			if err != nil {
				return ctrl.Result{}, err
			}
			fencedAt = at
			if !done {
				return pending(ReasonWaiting, fmt.Sprintf(
					"waiting for epoch %d's gate on node %s to close or its lease to stay unrenewed",
					prev.epoch, prev.node), after)
			}
		}
		if conflict := overlapping(idx, string(rt.UID), auth.Prefix); conflict != nil {
			return pending(ReasonPrefixConflict, fmt.Sprintf("prefix %s overlaps route %s's %s",
				auth.Prefix, conflict.Route, conflict.Prefix), refusedRetry)
		}
		if entry == nil && len(idx.Spec.Routes) >= maxIndexEntries {
			return pending(ReasonIndexFull, fmt.Sprintf("the VPC's route index holds its limit of %d routes",
				maxIndexEntries), refusedRetry)
		}
		lease := auth.Lease
		e := galacticv1alpha1.EdgeRouteIndexEntry{
			Prefix: auth.Prefix.String(), Route: rt.Namespace + "/" + rt.Name, RouteUID: string(rt.UID),
			Epoch: c.Epoch, AttachmentUID: string(auth.Attachment.UID), Instance: rt.Namespace + "/" + c.HolderInstance,
			InstanceIncarnation: lease.Incarnation, InstanceEpoch: int64(lease.Epoch), Node: auth.Attachment.Status.NodeName,
		}
		setEntry(idx, e)
		// A leader that paused after its final read could commit after the
		// previous holder renewed: proof by waiting holds only as long as
		// the margin the takeover interval leaves.
		if fencedAt != 0 && r.Clock()-fencedAt > r.Params.Margin {
			r.forget(string(rt.UID))
			return ctrl.Result{Requeue: true}, nil
		}
		if err := r.Client.Update(ctx, idx); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, fmt.Errorf("commit route %s to index %s/%s: %w", rt.Name, idx.Namespace, idx.Name, err)
		}
		r.forget(string(rt.UID))
	}
	lease := auth.Lease
	err = r.setStatus(ctx, rt, func(s *galacticv1alpha1.EdgeRouteStatus) {
		s.Accepted = &galacticv1alpha1.EdgeRouteHolder{
			Epoch: c.Epoch, Attachment: auth.Attachment.Name, AttachmentUID: string(auth.Attachment.UID),
			Instance: c.HolderInstance, InstanceIncarnation: lease.Incarnation, InstanceEpoch: int64(lease.Epoch),
			Node: auth.Attachment.Status.NodeName, VPCNamespace: auth.Service.Namespace,
		}
		msg := fmt.Sprintf("epoch %d forwards through %s on node %s", c.Epoch, auth.Attachment.Name,
			auth.Attachment.Status.NodeName)
		setCondition(s, galacticv1alpha1.EdgeRouteAccepted, metav1.ConditionTrue, ReasonAccepted, msg)
		setCondition(s, galacticv1alpha1.EdgeRouteClaimed, metav1.ConditionTrue, ReasonAccepted, msg)
	})
	if apierrors.IsConflict(err) {
		return ctrl.Result{Requeue: true}, nil
	}
	return ctrl.Result{}, err
}

// holder is the previous holder a pending claim must be fenced from.
type holder struct {
	epoch               int64
	attachmentUID       string
	instance            types.NamespacedName
	instanceIncarnation string
	instanceEpoch       int64
	node                string
}

// previous is the route's last accepted holder: the index entry when a
// commit to it was not yet followed by the status write, otherwise the
// status.
func previous(rt *galacticv1alpha1.EdgeRoute, entry *galacticv1alpha1.EdgeRouteIndexEntry) *holder {
	acc := rt.Status.Accepted
	if entry != nil && (acc == nil || entry.Epoch > acc.Epoch) {
		ns, name, _ := strings.Cut(entry.Instance, "/")
		return &holder{epoch: entry.Epoch, attachmentUID: entry.AttachmentUID,
			instance:            types.NamespacedName{Namespace: ns, Name: name},
			instanceIncarnation: entry.InstanceIncarnation, instanceEpoch: entry.InstanceEpoch, node: entry.Node}
	}
	if acc == nil {
		return nil
	}
	return &holder{epoch: acc.Epoch, attachmentUID: acc.AttachmentUID,
		instance:            types.NamespacedName{Namespace: rt.Namespace, Name: acc.Instance},
		instanceIncarnation: acc.InstanceIncarnation, instanceEpoch: acc.InstanceEpoch, node: acc.Node}
}

// waited reports whether this leader has seen prev's lease unchanged, on reads
// from the API server, for the takeover interval, with a final read at the
// end of the wait, and then fenced it; otherwise how long until it may have.
// It also returns when the final read returned, or zero once the lease is
// fenced. A lease that is gone, released, or at another incarnation or epoch
// can never again extend prev's gate, so every later read of it counts as
// unchanged and needs no fence: the wait runs its full interval from the
// first read that found it so, since a gate extended before that still holds
// until its deadline.
func (r *Reconciler) waited(ctx context.Context, rt *galacticv1alpha1.EdgeRoute, prev *holder,
) (bool, time.Duration, time.Duration, error) {
	key := string(rt.UID) + "/" + strconv.FormatInt(prev.epoch, 10)
	version, _, err := r.leaseVersion(ctx, prev)
	if err != nil {
		return false, 0, 0, err
	}
	// Stamped when the read returns: a renewal written while the read was
	// in flight must not start the wait early.
	now := r.Clock()
	wait := r.Params.TakeoverWait()
	r.mu.Lock()
	if r.observed == nil {
		r.observed = map[string]observation{}
	}
	o, ok := r.observed[key]
	if !ok || o.version != version {
		r.observed[key] = observation{version: version, at: now}
		r.mu.Unlock()
		return false, 0, wait, nil
	}
	r.mu.Unlock()
	if elapsed := now - o.at; elapsed < wait {
		return false, 0, wait - elapsed, nil
	}
	final, live, err := r.leaseVersion(ctx, prev)
	if err != nil {
		return false, 0, 0, err
	}
	finalAt := r.Clock()
	if final != version {
		r.mu.Lock()
		r.observed[key] = observation{version: final, at: finalAt}
		r.mu.Unlock()
		return false, 0, wait, nil
	}
	if live == nil {
		return true, finalAt, 0, nil
	}
	// The lease could still be renewed: a renewal sent before the final
	// read may land after it. Fencing it at the version the wait saw makes
	// such a renewal fail, or fails itself because the renewal landed first.
	switch err := provider.Fence(ctx, r.Client, prev.instance.Namespace, *live); {
	case errors.Is(err, claim.ErrConflict):
		r.mu.Lock()
		delete(r.observed, key)
		r.mu.Unlock()
		return false, 0, wait, nil
	case err != nil:
		return false, 0, 0, err
	}
	// Fenced for good: no later renewal can extend the gate, however long
	// this leader takes to commit.
	return true, 0, 0, nil
}

// leaseVersion is the version of prev's instance lease that could still
// extend prev's gate, with that lease, or a fixed value and no lease once
// none can.
func (r *Reconciler) leaseVersion(ctx context.Context, prev *holder) (string, *claim.Record, error) {
	var inst galacticv1alpha1.EdgeInstance
	switch err := r.APIReader.Get(ctx, prev.instance, &inst); {
	case apierrors.IsNotFound(err):
		return "gone", nil, nil
	case err != nil:
		return "", nil, err
	}
	l, found, err := provider.ReadLease(ctx, r.APIReader, &inst)
	switch {
	case err != nil:
		return "", nil, err
	case !found || l.Released || l.Incarnation != prev.instanceIncarnation || int64(l.Epoch) != prev.instanceEpoch:
		return "gone", nil, nil
	}
	return l.Version, &l, nil
}

func (r *Reconciler) forget(routeUID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.observed {
		if strings.HasPrefix(k, routeUID+"/") {
			delete(r.observed, k)
		}
	}
}

// reap deletes a route no live pod can use: its claimed and accepted
// attachments are gone, and its claim is released or its instance is gone.
// The index entry of an accepted holder stays until the holder is fenced.
func (r *Reconciler) reap(ctx context.Context, rt *galacticv1alpha1.EdgeRoute) (bool, error) {
	c := rt.Spec.Claim
	if c == nil {
		return false, nil
	}
	gone := func(obj client.Object, name string) (bool, error) {
		err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: rt.Namespace, Name: name}, obj)
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	names := []string{c.Attachment}
	if acc := rt.Status.Accepted; acc != nil && acc.Attachment != c.Attachment {
		names = append(names, acc.Attachment)
	}
	for _, n := range names {
		if g, err := gone(&galacticv1alpha1.EdgeAttachment{}, n); !g || err != nil {
			return false, err
		}
	}
	if !c.Released {
		if g, err := gone(&galacticv1alpha1.EdgeInstance{}, c.HolderInstance); !g || err != nil {
			return false, err
		}
	}
	uid, rv := rt.UID, rt.ResourceVersion
	err := r.Client.Delete(ctx, rt, client.Preconditions{UID: &uid, ResourceVersion: &rv})
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		return true, nil
	}
	return err == nil, err
}

// index returns the VPC's route index, creating it when it is missing. A
// created index is rebuilt from the accepted holders of every route of the
// VPC and marked Rebuilt: entries of routes deleted while it was missing are
// gone, so no first claim may be accepted until the takeover interval has
// passed.
func (r *Reconciler) index(ctx context.Context, namespace, vpcUID string) (*galacticv1alpha1.EdgeRouteIndex, error) {
	key := client.ObjectKey{Namespace: namespace, Name: vpcUID}
	var idx galacticv1alpha1.EdgeRouteIndex
	err := r.APIReader.Get(ctx, key, &idx)
	if err == nil || !apierrors.IsNotFound(err) {
		return &idx, err
	}
	var routes galacticv1alpha1.EdgeRouteList
	if err := r.APIReader.List(ctx, &routes); err != nil {
		return nil, err
	}
	idx = galacticv1alpha1.EdgeRouteIndex{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: vpcUID},
		Spec:       galacticv1alpha1.EdgeRouteIndexSpec{VPCUID: vpcUID, Rebuilt: true},
	}
	for i := range routes.Items {
		rt := &routes.Items[i]
		acc := rt.Status.Accepted
		if rt.Spec.VPCUID != vpcUID || acc == nil || acc.VPCNamespace != namespace {
			continue
		}
		e := galacticv1alpha1.EdgeRouteIndexEntry{
			Prefix: rt.Spec.Prefix, Route: rt.Namespace + "/" + rt.Name, RouteUID: string(rt.UID), Epoch: acc.Epoch,
			AttachmentUID: acc.AttachmentUID, Instance: rt.Namespace + "/" + acc.Instance,
			InstanceIncarnation: acc.InstanceIncarnation, InstanceEpoch: acc.InstanceEpoch, Node: acc.Node,
		}
		if !meta.IsStatusConditionTrue(rt.Status.Conditions, galacticv1alpha1.EdgeRouteAccepted) {
			e.Removing = ReasonRevoked
		}
		if p, err := netip.ParsePrefix(e.Prefix); err != nil || overlapping(&idx, e.RouteUID, p) != nil {
			// Two accepted routes never overlap; if they do, the later
			// one found waits for the takeover interval like any route.
			continue
		}
		idx.Spec.Routes = append(idx.Spec.Routes, e)
	}
	if err := r.Client.Create(ctx, &idx); err != nil {
		if apierrors.IsAlreadyExists(err) {
			err = r.APIReader.Get(ctx, key, &idx)
			return &idx, err
		}
		return nil, fmt.Errorf("create route index %s: %w", key, err)
	}
	return &idx, nil
}

func findEntry(idx *galacticv1alpha1.EdgeRouteIndex, routeUID string) *galacticv1alpha1.EdgeRouteIndexEntry {
	for i := range idx.Spec.Routes {
		if idx.Spec.Routes[i].RouteUID == routeUID {
			return &idx.Spec.Routes[i]
		}
	}
	return nil
}

// setEntry replaces the route's entry, or adds it.
func setEntry(idx *galacticv1alpha1.EdgeRouteIndex, e galacticv1alpha1.EdgeRouteIndexEntry) {
	for i := range idx.Spec.Routes {
		if idx.Spec.Routes[i].RouteUID == e.RouteUID {
			idx.Spec.Routes[i] = e
			return
		}
	}
	idx.Spec.Routes = append(idx.Spec.Routes, e)
}

// overlapping returns another route's entry whose prefix contains p or is
// contained in it, including one still being removed.
func overlapping(idx *galacticv1alpha1.EdgeRouteIndex, routeUID string, p netip.Prefix,
) *galacticv1alpha1.EdgeRouteIndexEntry {
	for i := range idx.Spec.Routes {
		e := &idx.Spec.Routes[i]
		if e.RouteUID == routeUID {
			continue
		}
		q, err := netip.ParsePrefix(e.Prefix)
		if err != nil || q.Overlaps(p) {
			return e
		}
	}
	return nil
}

// setStatus applies mutate to the route's status and writes it with the
// route's resourceVersion as precondition, unless nothing changed.
func (r *Reconciler) setStatus(ctx context.Context, rt *galacticv1alpha1.EdgeRoute,
	mutate func(*galacticv1alpha1.EdgeRouteStatus)) error {
	before := rt.Status.DeepCopy()
	mutate(&rt.Status)
	if equalStatus(before, &rt.Status) {
		return nil
	}
	if err := r.Client.Status().Update(ctx, rt); err != nil {
		if apierrors.IsConflict(err) {
			return err
		}
		return fmt.Errorf("update route %s/%s status: %w", rt.Namespace, rt.Name, err)
	}
	return nil
}

func equalStatus(a, b *galacticv1alpha1.EdgeRouteStatus) bool {
	if a.ClosedEpoch != b.ClosedEpoch || (a.Accepted == nil) != (b.Accepted == nil) ||
		(a.Accepted != nil && *a.Accepted != *b.Accepted) || len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for _, c := range a.Conditions {
		o := meta.FindStatusCondition(b.Conditions, c.Type)
		if o == nil || o.Status != c.Status || o.Reason != c.Reason || o.Message != c.Message {
			return false
		}
	}
	return true
}

func setCondition(s *galacticv1alpha1.EdgeRouteStatus, typ string, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&s.Conditions, metav1.Condition{Type: typ, Status: status, Reason: reason, Message: msg})
}
