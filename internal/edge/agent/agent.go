// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package agent is the node half of the Galactic Edge attachment lifecycle,
// run by galactic-edge on each edge node: it programs the host state of every
// attachment galactic-controller has admitted and allocated to its node,
// reads it back before reporting it Programmed, and releases it once the
// attachment is deleted, reporting Released so the controller can let the
// object go.
//
// The kernel is reconciled against the API on every pass, so a pass is
// idempotent and recovers whatever an interrupted one left: every link it
// creates carries the attachment's ID (hostattach), a link whose attachment is
// gone or deleted is released, and one whose attachment is live is completed.
// A stamped link is released only under its own ID, so cleanup of an earlier
// attachment never touches a replacement's.
//
// Each VPC on the node is one ownership scope (internal/edge/ownership). A
// process takes over the scopes its predecessors held with Fence and Adopt,
// and writes each scope only inside a snapshot commit of its complete state,
// so a write prepared by an earlier process, or before another writer's
// commit, never lands.
package agent

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/edge/ownership"
)

// Condition reasons the agent sets.
const (
	ReasonProgrammed           = "Programmed"
	ReasonReleased             = "Released"
	ReasonMaintenanceNotFenced = "MaintenanceNotFenced"
	ReasonNamespaceUnavailable = "NamespaceUnavailable"
	ReasonNamespaceReplaced    = "NamespaceReplaced"
	ReasonProvisionFailed      = "ProvisionFailed"
	ReasonReadbackFailed       = "ReadbackFailed"
	ReasonDatapathFailed       = "DatapathFailed"
	ReasonOwnershipUnavailable = "OwnershipUnavailable"
)

// ownerPrefix starts every owner ID galactic-edge uses for a scope, so a new
// process can tell a predecessor's scope from another writer's.
const ownerPrefix = "galactic-edge/"

// Datapath registers attachment host links with the node's uSID datapath.
type Datapath interface {
	// Register registers the host link with ifindex, enslaved to the VRF
	// with routing table vrfTable.
	Register(vrfTable, ifindex uint32, ifname string) error
	// Unregister removes every row Register wrote for ifindex.
	Unregister(ifindex uint32) error
}

// Agent reconciles the host state of the attachments on one node.
type Agent struct {
	// Client reads EdgeAttachments and writes their status.
	Client ctrl.Client
	// NodeName is this node.
	NodeName string
	// Owner is this process's ownership ID, from NewOwner: new for every
	// process start, and ordered by start time.
	Owner string
	// Ownership fences writes to each VPC scope on the node.
	Ownership *ownership.Authority
	// Host is the node's network namespace.
	Host *hostattach.Namespace
	// Namespaces finds provider pods' network namespaces.
	Namespaces NamespaceResolver
	// Datapath registers host links with the uSID datapath.
	Datapath Datapath
	// MTU of every attachment link; at least the fabric's tenant MTU.
	MTU int
	// Program enables creating host state. Until every other writer of the
	// shared state commits through Ownership, the agent only releases and
	// reports MaintenanceNotFenced.
	Program bool

	// tickets holds this process's next ticket for each scope it owns.
	tickets map[string]ownership.Ticket
	// lost holds the scopes another writer took from this process.
	lostMu sync.Mutex
	lost   map[string]bool
}

// outcome is the status the agent reports for one attachment after a pass.
type outcome struct {
	att       *galacticv1alpha1.EdgeAttachment
	condition string
	status    metav1.ConditionStatus
	reason    string
	message   string
	spec      *hostattach.Attachment
}

// Reconcile runs one pass over every attachment on the node and every link
// the kernel holds for one. It is safe to run at any time and any number of
// times.
func (a *Agent) Reconcile(ctx context.Context) error {
	var list galacticv1alpha1.EdgeAttachmentList
	if err := a.Client.List(ctx, &list); err != nil {
		return fmt.Errorf("list EdgeAttachments: %w", err)
	}
	active := map[string][]*galacticv1alpha1.EdgeAttachment{}
	releasing := map[string][]*galacticv1alpha1.EdgeAttachment{}
	pods := map[string]podNS{}
	for i := range list.Items {
		att := &list.Items[i]
		s := att.Status
		if s.NodeName != a.NodeName || s.VPC == "" || s.Address == "" ||
			meta.IsStatusConditionTrue(s.Conditions, galacticv1alpha1.EdgeAttachmentReleased) {
			continue
		}
		if att.DeletionTimestamp.IsZero() {
			active[s.VPC] = append(active[s.VPC], att)
		} else {
			releasing[s.VPC] = append(releasing[s.VPC], att)
		}
		if _, ok := pods[att.Spec.PodUID]; !ok {
			pods[att.Spec.PodUID] = a.resolve(ctx, att.Spec.PodUID)
		}
	}
	// Scopes are found from the links an earlier pass or process left, too;
	// each scope lists its own links again under its lock.
	links, err := hostattach.List(a.Host)
	if err != nil {
		return fmt.Errorf("list attachment links: %w", err)
	}
	scopes := map[string]bool{}
	for _, m := range []map[string][]*galacticv1alpha1.EdgeAttachment{active, releasing} {
		for vpc := range m {
			scopes[vpc] = true
		}
	}
	for _, l := range links {
		if vpc, _, ok := parseID(l.ID); ok {
			scopes[vpc] = true
		}
	}

	var outcomes []outcome
	var errs []error
	for _, vpc := range slices.Sorted(maps.Keys(scopes)) {
		out, err := a.reconcileScope(vpc, active[vpc], releasing[vpc], pods)
		outcomes = append(outcomes, out...)
		if err != nil {
			errs = append(errs, fmt.Errorf("VPC %s: %w", vpc, err))
		}
	}
	for _, o := range outcomes {
		if err := a.report(ctx, o); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// resolveTimeout bounds one CRI lookup. Lookups run before a scope's lock is
// taken, so a stuck runtime delays a pass but never holds the fence.
const resolveTimeout = 5 * time.Second

// podNS is a pod's network namespace path, or why it could not be found.
type podNS struct {
	path string
	err  error
}

func (a *Agent) resolve(ctx context.Context, podUID string) podNS {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	path, err := a.Namespaces.PodNetNS(ctx, podUID)
	return podNS{path: path, err: err}
}

// reconcileScope releases every link of the scope no live attachment wants
// and programs every live attachment, in one snapshot commit.
func (a *Agent) reconcileScope(vpc string, active, releasing []*galacticv1alpha1.EdgeAttachment,
	pods map[string]podNS) ([]outcome, error) {
	scope := "vpc-" + vpc
	t, err := a.ticket(scope)
	if err != nil {
		out := make([]outcome, 0, len(active))
		for _, att := range active {
			out = append(out, outcome{att: att, condition: galacticv1alpha1.EdgeAttachmentProgrammed,
				status: metav1.ConditionFalse, reason: ReasonOwnershipUnavailable, message: err.Error()})
		}
		return out, err
	}
	var out []outcome
	next, err := a.Ownership.CommitSnapshot(t, func() error {
		var err error
		out, err = a.applyScope(vpc, active, releasing, pods)
		return err
	})
	if err != nil {
		delete(a.tickets, scope)
		if !errors.Is(err, ownership.ErrStale) && !errors.Is(err, ownership.ErrNotOwner) &&
			!errors.Is(err, ownership.ErrTransitioning) {
			// The snapshot ran but did not complete: report what it did,
			// and the next pass, a snapshot again, finishes the rest.
			return out, fmt.Errorf("commit: %w", err)
		}
		// Another writer took the scope over; this process never takes it
		// back.
		a.markLost(scope)
		return nil, fmt.Errorf("commit: %w", err)
	}
	a.tickets[scope] = next
	return out, nil
}

// ticket returns this process's ticket for scope, taking the scope over the
// first time: an unowned scope is claimed, and a scope an older galactic-edge
// process owns, or was handing over, is fenced and adopted. A scope another
// writer owns or is handing over, or one a newer process took from this
// one, is refused.
func (a *Agent) ticket(scope string) (ownership.Ticket, error) {
	if a.tickets == nil {
		a.tickets = map[string]ownership.Ticket{}
	}
	if t, ok := a.tickets[scope]; ok {
		return t, nil
	}
	if a.isLost(scope) {
		return ownership.Ticket{}, fmt.Errorf("%w: scope %s was taken over by another writer", ownership.ErrNotOwner, scope)
	}
	rec, err := a.Ownership.Read(scope)
	if err != nil {
		return ownership.Ticket{}, err
	}
	var t ownership.Ticket
	switch {
	case rec.Owner == a.Owner && !rec.Transitioning:
		t, err = a.Ownership.Begin(scope, a.Owner)
	case rec.Owner == a.Owner:
		a.markLost(scope)
		err = fmt.Errorf("%w: scope %s is being handed over", ownership.ErrTransitioning, scope)
	case rec.Owner == "" && !rec.Transitioning:
		t, err = a.Ownership.Claim(scope, a.Owner)
	case olderIncarnation(rec.Owner, a.Owner):
		var gen uint64
		if gen, err = a.Ownership.Fence(scope); err == nil {
			t, err = a.Ownership.Adopt(scope, a.Owner, gen)
		}
	case rec.Transitioning:
		err = fmt.Errorf("%w: scope %s", ownership.ErrTransitioning, scope)
	default:
		err = fmt.Errorf("%w: scope %s is owned by %q", ownership.ErrNotOwner, scope, rec.Owner)
	}
	if err != nil {
		return ownership.Ticket{}, err
	}
	a.tickets[scope] = t
	return t, nil
}

func (a *Agent) markLost(scope string) {
	a.lostMu.Lock()
	defer a.lostMu.Unlock()
	if a.lost == nil {
		a.lost = map[string]bool{}
	}
	a.lost[scope] = true
}

func (a *Agent) isLost(scope string) bool {
	a.lostMu.Lock()
	defer a.lostMu.Unlock()
	return a.lost[scope]
}

// Healthy fails once another writer has taken a scope from this process,
// which then neither programs nor releases there: a restart starts a new
// process that takes the scope over again if its holder was an older
// galactic-edge, and reports why it cannot otherwise.
func (a *Agent) Healthy(*http.Request) error {
	a.lostMu.Lock()
	defer a.lostMu.Unlock()
	if len(a.lost) > 0 {
		return fmt.Errorf("lost ownership of %d scopes to another writer", len(a.lost))
	}
	return nil
}

// applyScope is the scope's snapshot: it runs with the scope's lock held. It
// lists the scope's links itself, under the lock, so no link a predecessor
// created after the pass started is missed. An error leaves the scope
// requiring another snapshot.
func (a *Agent) applyScope(vpc string, active, releasing []*galacticv1alpha1.EdgeAttachment,
	pods map[string]podNS) ([]outcome, error) {
	all, err := hostattach.List(a.Host)
	if err != nil {
		return nil, err
	}
	links := map[string]hostattach.ObservedAttachment{}
	for _, l := range all {
		if v, _, ok := parseID(l.ID); ok && v == vpc {
			links[l.ID] = l
		}
	}
	var out []outcome
	var errs []error
	for _, att := range releasing {
		id := attachmentID(att.Status.VPC, string(att.UID))
		err := a.release(att, links[id], pods[att.Spec.PodUID])
		delete(links, id)
		if err != nil {
			errs = append(errs, fmt.Errorf("release %s/%s: %w", att.Namespace, att.Name, err))
			continue
		}
		out = append(out, released(att))
	}
	for _, att := range active {
		delete(links, attachmentID(att.Status.VPC, string(att.UID)))
	}
	// What is left carries the scope's stamp but no attachment wants it:
	// its attachment is gone altogether.
	for id, l := range links {
		if err := a.release(nil, l, podNS{}); err != nil {
			errs = append(errs, fmt.Errorf("release orphaned link %s: %w", id, err))
		}
	}
	for _, att := range active {
		out = append(out, a.program(att, pods[att.Spec.PodUID]))
	}
	return out, errors.Join(errs...)
}

func released(att *galacticv1alpha1.EdgeAttachment) outcome {
	return outcome{att: att, condition: galacticv1alpha1.EdgeAttachmentReleased, status: metav1.ConditionTrue,
		reason: ReasonReleased, message: "host state released"}
}

// release removes a link's datapath rows, then the link and the pod's
// device. att is the deleted attachment the link belongs to, or nil when
// none is left; link is zero when the kernel holds no link for att. A pod
// whose namespace lookup failed for any reason but its absence is retried,
// not released without it.
func (a *Agent) release(att *galacticv1alpha1.EdgeAttachment, link hostattach.ObservedAttachment, pod podNS) error {
	spec := hostattach.Attachment{ID: link.ID, HostLink: link.HostLink}
	if att != nil {
		var err error
		if spec, err = desired(att, a.MTU); err != nil {
			return err
		}
	}
	if pod.err != nil && !errors.Is(pod.err, ErrNamespaceUnavailable) {
		return pod.err
	}
	if link.HostIndex != 0 {
		// The link still carries this ID, so its ifindex is still its own.
		if err := a.Datapath.Unregister(uint32(link.HostIndex)); err != nil {
			return err
		}
	}
	var podH *hostattach.Namespace
	if att != nil && pod.err == nil {
		if h, err := hostattach.OpenNamespace(pod.path); err == nil {
			podH = h
			defer func() { _ = h.Close() }()
		}
	}
	return hostattach.Release(a.Host, podH, spec)
}

// releaseLink releases the attachment's own host link, and its datapath
// rows, without touching its pod.
func (a *Agent) releaseLink(spec hostattach.Attachment) error {
	links, err := hostattach.List(a.Host)
	if err != nil {
		return err
	}
	for _, l := range links {
		if l.ID == spec.ID {
			if err := a.Datapath.Unregister(uint32(l.HostIndex)); err != nil {
				return err
			}
		}
	}
	return hostattach.Release(a.Host, nil, spec)
}

// program provisions one live attachment, reads it back and registers its
// host link with the datapath.
func (a *Agent) program(att *galacticv1alpha1.EdgeAttachment, ns podNS) outcome {
	fail := func(reason string, err error) outcome {
		return outcome{att: att, condition: galacticv1alpha1.EdgeAttachmentProgrammed,
			status: metav1.ConditionFalse, reason: reason, message: err.Error()}
	}
	if !a.Program {
		return fail(ReasonMaintenanceNotFenced, errors.New("programming is disabled until every writer of the "+
			"node's shared datapath state commits through the ownership fence"))
	}
	spec, err := desired(att, a.MTU)
	if err != nil {
		return fail(ReasonProvisionFailed, err)
	}
	if ns.err != nil {
		return fail(ReasonNamespaceUnavailable, ns.err)
	}
	pod, err := hostattach.OpenNamespace(ns.path)
	if err != nil {
		return fail(ReasonNamespaceUnavailable, err)
	}
	defer func() { _ = pod.Close() }()
	res, err := hostattach.Provision(a.Host, pod, spec)
	if errors.Is(err, hostattach.ErrStalePeer) {
		// The pod's sandbox was replaced: the link to the old one is this
		// attachment's own, so it is released and provisioned again.
		if err = a.releaseLink(spec); err == nil {
			res, err = hostattach.Provision(a.Host, pod, spec)
		}
	}
	switch {
	case errors.Is(err, hostattach.ErrNamespaceReplaced):
		return fail(ReasonNamespaceReplaced, err)
	case err != nil:
		return fail(ReasonProvisionFailed, err)
	}
	if err := hostattach.Readback(a.Host, pod, spec); err != nil {
		return fail(ReasonReadbackFailed, err)
	}
	if err := a.Datapath.Register(res.HostTable, uint32(res.HostIndex), spec.HostLink); err != nil {
		return fail(ReasonDatapathFailed, err)
	}
	return outcome{att: att, condition: galacticv1alpha1.EdgeAttachmentProgrammed, status: metav1.ConditionTrue,
		reason: ReasonProgrammed, message: fmt.Sprintf("host link %s in %s", spec.HostLink, spec.HostVRF), spec: &spec}
}

// report writes one outcome, with the attachment's resourceVersion as
// precondition. A conflict is retried by the next pass.
func (a *Agent) report(ctx context.Context, o outcome) error {
	att := o.att
	before := att.DeepCopy()
	meta.SetStatusCondition(&att.Status.Conditions, metav1.Condition{
		Type: o.condition, Status: o.status, Reason: o.reason, Message: o.message,
	})
	if o.spec != nil {
		att.Status.HostLink, att.Status.PodVRF = o.spec.HostLink, o.spec.PodVRF
		if o.spec.TUN != nil {
			att.Status.PacketDevice = o.spec.TUN.Name
		}
	}
	if c := meta.FindStatusCondition(before.Status.Conditions, o.condition); c != nil &&
		c.Status == o.status && c.Reason == o.reason && c.Message == o.message &&
		before.Status.HostLink == att.Status.HostLink && before.Status.PodVRF == att.Status.PodVRF &&
		before.Status.PacketDevice == att.Status.PacketDevice {
		return nil
	}
	err := a.Client.Status().Patch(ctx, att, ctrl.MergeFromWithOptions(before, ctrl.MergeFromWithOptimisticLock{}))
	if err != nil {
		key := types.NamespacedName{Namespace: att.Namespace, Name: att.Name}
		return fmt.Errorf("report %s on %s: %w", o.condition, key, err)
	}
	return nil
}

// Resync is how often the agent reconciles without an event, to repair host
// state that drifted under it.
const Resync = time.Minute
