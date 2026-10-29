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
// and writes each scope only inside a commit, so a write prepared by an
// earlier process, or before another writer's commit, never lands.
//
// The agent also keeps each host link's forwarding gate (Gate): which
// prefixes beyond the attachment's own address the link carries, and until
// when. A link's host routes carry exactly its open gates' prefixes.
package agent

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/claim"
	"go.datum.net/galactic/internal/edge/diag"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/edge/ownership"
	"go.datum.net/galactic/internal/edge/timing"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// Condition reasons the agent sets.
const (
	ReasonProgrammed           = "Programmed"
	ReasonReleased             = "Released"
	ReasonNamespaceUnavailable = "NamespaceUnavailable"
	ReasonNamespaceReplaced    = "NamespaceReplaced"
	ReasonProvisionFailed      = "ProvisionFailed"
	ReasonReadbackFailed       = "ReadbackFailed"
	ReasonDatapathFailed       = "DatapathFailed"
	ReasonOwnershipUnavailable = "OwnershipUnavailable"
	ReasonMTUExceedsUnderlay   = "MTUExceedsUnderlay"
)

// ownerPrefix starts every owner ID galactic-edge uses for a scope, so a new
// process can tell a predecessor's scope from another writer's.
const ownerPrefix = "galactic-edge/"

// Datapath registers attachment host links with the node's uSID datapath.
type Datapath interface {
	// Register registers the host link with ifindex, enslaved to the VRF
	// with routing table vrfTable, as an edge link whose own address is
	// addr: it carries nothing else until a gate opens for it, and nothing
	// its traffic policy does not allow. The link is gated before any
	// program that forwards its traffic is attached. It is called while a
	// new link is still down.
	Register(vrfTable, ifindex uint32, ifname string, addr netip.Addr) error
	// Unregister closes ifindex's gates and removes every row Register
	// wrote for it except the gate's link row, so the link carries nothing
	// beyond its own address until it is gone.
	Unregister(ifindex uint32) error
	// Forget removes ifindex's gate link row, once the link is deleted.
	Forget(ifindex uint32) error
	// SyncRoutes makes the destinations the workloads of the VRF with
	// routing table vrfTable reach on this node's edge links exactly want,
	// so the VRF's default route to the egress shards never takes them.
	SyncRoutes(vrfTable uint32, want []netip.Prefix) error
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
	// EncapMTU reads the largest packet the datapath encapsulates
	// (encap_mtu_table): the fabric underlay's MTU less the outer header,
	// or zero when galactic-cni has set no limit. An attachment is not
	// programmed while MTU exceeds it, since usid_egress drops a larger
	// packet from an edge link with no error sent. Nil checks nothing.
	EncapMTU func() (int, error)

	// APIReader reads every input of a gate decision from the API server.
	APIReader ctrl.Reader
	// Gates is the node's forwarding gate. Nil opens no gate, so no link
	// carries more than its own address.
	Gates GateTable
	// Params is the cell's claim timing; it must be every provider's and
	// galactic-controller's.
	Params claim.Params
	// BootID is the node's current boot ID. Instances of another boot are
	// never applied: their renewal starts are on another clock.
	BootID string
	// BootClock reads CLOCK_BOOTTIME, the gates' clock. Nil means
	// timing.BootClock.
	BootClock claim.Clock
	// Now is the wall clock, for grant expiry. Nil means time.Now.
	Now func() time.Time
	// Diag records programming failures, closed gates and failed cleanup.
	Diag *diag.Recorder

	// mu serializes passes: they share tickets.
	mu sync.Mutex
	// tickets holds this process's next ticket for each scope it owns.
	tickets map[string]ownership.Ticket
	// lost holds the scopes another writer took from this process.
	lostMu sync.Mutex
	lost   map[string]bool
	// held is, for the pass under way, each attachment's prefixes from
	// routes still accepted on this node, by attachment UID.
	held map[string][]netip.Prefix
	// local is, by VPC, each attachment's prefixes beyond its own address
	// that the last sync of the VPC's local routes kept, by attachment UID.
	local map[string]map[string]map[netip.Prefix]bool
}

// outcome is the status the agent reports for one attachment after a pass.
type outcome struct {
	att       *galacticv1alpha1.EdgeAttachment
	condition string
	status    metav1.ConditionStatus
	reason    string
	message   string
	spec      *hostattach.Attachment
	// conflict reports a failure on host state another attachment still
	// holds, such as a prefix route a previous holder has not yet pruned.
	conflict bool
}

// Reconcile runs one pass over every attachment on the node and every link
// the kernel holds for one. It is safe to run at any time and any number of
// times.
func (a *Agent) Reconcile(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var list galacticv1alpha1.EdgeAttachmentList
	if err := a.Client.List(ctx, &list); err != nil {
		return fmt.Errorf("list EdgeAttachments: %w", err)
	}
	held, err := a.heldPrefixes(ctx)
	if err != nil {
		return err
	}
	a.held = held
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
		if vpc, _, ok := hostattach.ParseLinkID(l.ID); ok {
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
	scope := ownership.VPCScope(vpc)
	unavailable := func(err error) ([]outcome, error) {
		out := make([]outcome, 0, len(active))
		for _, att := range active {
			out = append(out, outcome{att: att, condition: galacticv1alpha1.EdgeAttachmentProgrammed,
				status: metav1.ConditionFalse, reason: ReasonOwnershipUnavailable, message: err.Error()})
		}
		return out, err
	}
	t, err := a.ticket(scope)
	if err != nil {
		return unavailable(err)
	}
	var out []outcome
	snapshot := func(t ownership.Ticket) (ownership.Ticket, error) {
		return a.Ownership.CommitSnapshot(t, func() error {
			var err error
			out, err = a.applyScope(vpc, active, releasing, pods)
			return err
		})
	}
	next, err := snapshot(t)
	if errors.Is(err, ownership.ErrStale) {
		// A writer that does not own the scope, such as garbage collection,
		// wrote it since this process's last commit. The scope is still this
		// process's, and the refused snapshot never ran, so it runs again
		// from a fresh ticket.
		delete(a.tickets, scope)
		if t, err = a.ticket(scope); err != nil {
			return unavailable(err)
		}
		next, err = snapshot(t)
	}
	if err != nil {
		delete(a.tickets, scope)
		if errors.Is(err, ownership.ErrStale) {
			return nil, fmt.Errorf("commit: %w", err)
		}
		if !errors.Is(err, ownership.ErrNotOwner) && !errors.Is(err, ownership.ErrTransitioning) {
			// The snapshot ran but did not complete, so nothing it did is
			// confirmed: report only its failures, and the next pass, a
			// snapshot again, settles the rest.
			return slices.DeleteFunc(out, func(o outcome) bool {
				return o.status == metav1.ConditionTrue
			}), fmt.Errorf("commit: %w", err)
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
		if v, _, ok := hostattach.ParseLinkID(l.ID); ok && v == vpc {
			links[l.ID] = l
		}
	}
	var out []outcome
	var errs []error
	for _, att := range releasing {
		id := hostattach.LinkID(att.Status.VPC, string(att.UID))
		err := a.release(att, links[id], pods[att.Spec.PodUID])
		delete(links, id)
		if err != nil {
			errs = append(errs, fmt.Errorf("release %s/%s: %w", att.Namespace, att.Name, err))
			a.Diag.CleanupFailed()
			continue
		}
		out = append(out, released(att))
	}
	current := map[string]hostattach.ObservedAttachment{}
	for _, att := range active {
		id := hostattach.LinkID(att.Status.VPC, string(att.UID))
		current[id] = links[id]
		delete(links, id)
	}
	// What is left carries the scope's stamp but no attachment wants it:
	// its attachment is gone altogether.
	for id, l := range links {
		if err := a.release(nil, l, podNS{}); err != nil {
			errs = append(errs, fmt.Errorf("release orphaned link %s: %w", id, err))
			a.Diag.CleanupFailed()
		}
	}
	// An attachment whose route another one still holds, such as a prefix
	// moving between two attachments of the VPC, is programmed again once
	// every other attachment has pruned what its gates no longer carry.
	var retry []int
	for _, att := range active {
		o := a.program(att, pods[att.Spec.PodUID], current[hostattach.LinkID(att.Status.VPC, string(att.UID))])
		if o.conflict {
			retry = append(retry, len(out))
		}
		out = append(out, o)
	}
	for _, i := range retry {
		att := out[i].att
		out[i] = a.program(att, pods[att.Spec.PodUID], current[hostattach.LinkID(att.Status.VPC, string(att.UID))])
	}
	if err := a.syncRoutes(vpc); err != nil {
		errs = append(errs, fmt.Errorf("sync local routes: %w", err))
	}
	return out, errors.Join(errs...)
}

// heldPrefixes returns, by attachment UID, the prefix of every route
// accepted on this node whose holder has not released it at the accepted
// epoch, whether or not its gate is open.
func (a *Agent) heldPrefixes(ctx context.Context) (map[string][]netip.Prefix, error) {
	if a.Gates == nil {
		return nil, nil
	}
	var routes galacticv1alpha1.EdgeRouteList
	if err := a.Client.List(ctx, &routes); err != nil {
		return nil, fmt.Errorf("list EdgeRoutes: %w", err)
	}
	held := map[string][]netip.Prefix{}
	for i := range routes.Items {
		rt := &routes.Items[i]
		p, err := netip.ParsePrefix(rt.Spec.Prefix)
		if err != nil || !holds(rt, a.NodeName) {
			continue
		}
		held[rt.Status.Accepted.AttachmentUID] = append(held[rt.Status.Accepted.AttachmentUID], p.Masked())
	}
	return held, nil
}

// holds reports whether rt is accepted on node and its holder has not
// released it at the accepted epoch. A revoked route still holds: its
// accepted holder stays until another is accepted or the route is deleted.
func holds(rt *galacticv1alpha1.EdgeRoute, node string) bool {
	acc := rt.Status.Accepted
	if acc == nil || acc.Node != node {
		return false
	}
	c := rt.Spec.Claim
	return c == nil || c.Epoch != acc.Epoch || !c.Released
}

// syncRoutes routes the VPC's workloads on this node to its edge links: each
// registered link's own address, the prefixes whose gates are open on it, and
// every other prefix of a route its attachment holds. A held prefix whose gate
// is closed has no host route, so the kernel finds the VRF's unreachable
// default for it and drops it, rather than usid_egress sending it to the
// VPC's ::/0 shard route as public egress. A VPC whose VRF is gone has no
// workload here to route, and no table ID to sync against. Its rows cannot
// outlive the VRF: maintenance's Guard.Reclaim refuses to delete the VRF while
// an attachment is not Released, and the agent reports Released only after a
// snapshot pass that ran this with an empty want while the VRF still existed.
func (a *Agent) syncRoutes(vpc string) error {
	table, ok, err := hostattach.VRFTable(a.Host, intf.GenerateInterfaceNameVRF(vpc))
	if err != nil || !ok {
		return err
	}
	links, err := hostattach.List(a.Host)
	if err != nil {
		return err
	}
	var want []netip.Prefix
	local := map[string]map[netip.Prefix]bool{}
	for _, l := range links {
		v, uid, ok := hostattach.ParseLinkID(l.ID)
		if !ok || v != vpc || l.HostIndex == 0 || a.Gates == nil {
			continue
		}
		addr, registered, err := a.Gates.Link(uint32(l.HostIndex))
		if err != nil {
			return err
		}
		if !registered {
			continue
		}
		own := netip.PrefixFrom(addr, addr.BitLen())
		want = append(want, own)
		local[uid] = map[netip.Prefix]bool{}
		for _, p := range append(a.openPrefixes(l, addr.String()), a.held[uid]...) {
			if p != own && !local[uid][p] {
				local[uid][p] = true
				want = append(want, p)
			}
		}
	}
	if err := a.Datapath.SyncRoutes(table, want); err != nil {
		return err
	}
	if a.local == nil {
		a.local = map[string]map[string]map[netip.Prefix]bool{}
	}
	a.local[vpc] = local
	return nil
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
	if err := hostattach.Release(a.Host, podH, spec); err != nil {
		return err
	}
	return a.forget(link)
}

// forget removes a released link's gate link row.
func (a *Agent) forget(link hostattach.ObservedAttachment) error {
	if link.HostIndex == 0 {
		return nil
	}
	return a.Datapath.Forget(uint32(link.HostIndex))
}

// releaseLink releases the attachment's own host link, and its datapath
// rows, without touching its pod.
func (a *Agent) releaseLink(spec hostattach.Attachment) error {
	links, err := hostattach.List(a.Host)
	if err != nil {
		return err
	}
	var own hostattach.ObservedAttachment
	for _, l := range links {
		if l.ID == spec.ID {
			own = l
			if err := a.Datapath.Unregister(uint32(l.HostIndex)); err != nil {
				return err
			}
		}
	}
	if err := hostattach.Release(a.Host, nil, spec); err != nil {
		return err
	}
	return a.forget(own)
}

// program provisions one live attachment, registering its host link with the
// datapath before the link comes up, and reads it back. The host routes carry
// the prefixes whose gates are open on the link as it was found, so a prefix
// is routed to the link only once the link is registered and gated; a link
// created now carries none until the next pass.
func (a *Agent) program(att *galacticv1alpha1.EdgeAttachment, ns podNS, link hostattach.ObservedAttachment) outcome {
	fail := func(reason string, err error) outcome {
		return outcome{att: att, condition: galacticv1alpha1.EdgeAttachmentProgrammed,
			status: metav1.ConditionFalse, reason: reason, message: err.Error()}
	}
	spec, err := desired(att, a.MTU)
	if err != nil {
		return fail(ReasonProvisionFailed, err)
	}
	if reason, err := a.checkUnderlay(); err != nil {
		return fail(reason, err)
	}
	if link.ID == spec.ID {
		spec.Prefixes = a.openPrefixes(link, att.Status.Address)
	}
	if ns.err != nil {
		return fail(ReasonNamespaceUnavailable, ns.err)
	}
	pod, err := hostattach.OpenNamespace(ns.path)
	if err != nil {
		return fail(ReasonNamespaceUnavailable, err)
	}
	defer func() { _ = pod.Close() }()
	fresh := link.ID != spec.ID
	var datapathErr error
	register := func(res hostattach.Result) error {
		// A link created now may reuse the ifindex of a link a pod's
		// deletion took with it, whose rows, gates included, nothing has
		// removed yet: they are cleared before the new link is registered,
		// so it never carries another attachment's prefixes or policy.
		if fresh || res.HostIndex != link.HostIndex {
			datapathErr = a.Datapath.Unregister(uint32(res.HostIndex))
		}
		if datapathErr == nil {
			datapathErr = a.Datapath.Register(res.HostTable, uint32(res.HostIndex), spec.HostLink, spec.Address)
		}
		return datapathErr
	}
	_, err = hostattach.ProvisionRegistered(a.Host, pod, spec, register)
	if errors.Is(err, hostattach.ErrStalePeer) {
		// The pod's sandbox was replaced: the link to the old one is this
		// attachment's own, so it is released and provisioned again, with
		// no gates until the new link is registered.
		spec.Prefixes = nil
		fresh = true
		if err = a.releaseLink(spec); err == nil {
			_, err = hostattach.ProvisionRegistered(a.Host, pod, spec, register)
		}
	}
	switch {
	case datapathErr != nil:
		return fail(ReasonDatapathFailed, err)
	case errors.Is(err, hostattach.ErrNamespaceReplaced):
		return fail(ReasonNamespaceReplaced, err)
	case err != nil:
		o := fail(ReasonProvisionFailed, err)
		o.conflict = errors.Is(err, hostattach.ErrNotOwned)
		return o
	}
	if err := hostattach.Readback(a.Host, pod, spec); err != nil {
		return fail(ReasonReadbackFailed, err)
	}
	return outcome{att: att, condition: galacticv1alpha1.EdgeAttachmentProgrammed, status: metav1.ConditionTrue,
		reason: ReasonProgrammed, message: fmt.Sprintf("host link %s in %s", spec.HostLink, spec.HostVRF), spec: &spec}
}

// checkUnderlay refuses a.MTU when it exceeds the largest packet the fabric
// underlay carries once encapsulated. An edge host link has no gateway for
// usid_egress to send Packet Too Big from, so such a packet would be dropped
// silently. A limit that cannot be read refuses too: nothing is provisioned
// past a check that did not run. A link an earlier pass programmed is left as
// it is, neither reprogrammed nor released, and reported not programmed.
func (a *Agent) checkUnderlay() (string, error) {
	if a.EncapMTU == nil {
		return "", nil
	}
	limit, err := a.EncapMTU()
	switch {
	case err != nil:
		return ReasonDatapathFailed, fmt.Errorf("read the fabric's encapsulation MTU: %w", err)
	case limit != 0 && a.MTU > limit:
		return ReasonMTUExceedsUnderlay, fmt.Errorf(
			"attachment MTU %d exceeds %d, the largest packet the fabric underlay carries once encapsulated",
			a.MTU, limit)
	}
	return "", nil
}

// report writes one outcome, with the attachment's resourceVersion as
// precondition. A conflict is retried by the next pass.
func (a *Agent) report(ctx context.Context, o outcome) error {
	att := o.att
	before := att.DeepCopy()
	entered := o.status == metav1.ConditionFalse &&
		diag.EnteredFailure(before.Status.Conditions, o.condition, o.reason)
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
	if entered {
		a.Diag.Failure(att, diag.StageProgramming, o.reason, o.message, diag.ForAttachment(att))
	}
	return nil
}

// Resync is how often the agent reconciles without an event, to repair host
// state that drifted under it.
const Resync = time.Minute

func (a *Agent) bootClock() time.Duration {
	if a.BootClock != nil {
		return a.BootClock()
	}
	return timing.BootClock()
}

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}
