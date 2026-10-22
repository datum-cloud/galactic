// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package node is galactic-router's traffic policy reconciler: for every
// VPCAttachment on this node, it compiles the policy each direction of its
// interface is bound to and publishes it into the uSID datapath, keeps
// each rule's counter row across updates, reports what it applied in the
// binding's per-node status, and exports the counters.
package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/trafficpolicy"
	"go.datum.net/galactic/internal/trafficpolicy/cell"
)

// resync bounds how long a missed event can leave an interface stale.
const resync = 5 * time.Minute

// pendingRetry is how soon an interface whose datapath state is not ready
// yet is looked at again.
const pendingRetry = 5 * time.Second

// policyRefIndex indexes bindings by every policy name they reference.
const policyRefIndex = "galactic.datumapis.com/node-policy-refs"

var directions = [2]struct {
	dir  uint32
	name galacticv1alpha1.Direction
	ref  func(*galacticv1alpha1.TrafficPolicyBindingSpec) *galacticv1alpha1.LocalPolicyReference
}{
	{tpmap.DirIngress, galacticv1alpha1.DirectionIngress,
		func(s *galacticv1alpha1.TrafficPolicyBindingSpec) *galacticv1alpha1.LocalPolicyReference {
			return s.IngressPolicyRef
		}},
	{tpmap.DirEgress, galacticv1alpha1.DirectionEgress,
		func(s *galacticv1alpha1.TrafficPolicyBindingSpec) *galacticv1alpha1.LocalPolicyReference {
			return s.EgressPolicyRef
		}},
}

// ruleKey identifies a rule's counter interval within one interface
// lifetime, direction and policy: renaming the rule or changing its action
// starts a new one.
type ruleKey struct {
	name  string
	allow bool
}

// applied is what is installed for one interface direction.
type applied struct {
	attachment types.NamespacedName
	labels     interfaceLabels
	token      uint64
	policy     galacticv1alpha1.PolicyIdentity
	rules      []ruleKey
	rows       []uint32 // rows[i] is rules[i]'s counter row
}

type interfaceLabels struct {
	namespace, vpc, attachment, iface, ifaceUID string
}

// iface is an attachment's interface on this node, as last reconciled.
type iface struct {
	ifindex uint32
	token   uint64
	labels  interfaceLabels
}

type bindingKey struct {
	ifindex uint32
	dir     uint32
}

// Reconciler is galactic-router's traffic policy reconciler. Each request
// names a VPCAttachment.
type Reconciler struct {
	Client   client.Client
	NodeName string
	PinDir   string

	mu       sync.Mutex
	maps     *tpmap.Maps
	alloc    *tpmap.CounterAllocator
	state    map[bindingKey]*applied
	adopted  map[bindingKey]tpmap.Snapshot // bound before a restart, not yet reconciled
	ifaces   map[types.NamespacedName]iface
	openedAt time.Time
	sweptAt  time.Time // the last snapshot pin sweep

	// openMaps opens the datapath's maps, and counterRows sizes the row
	// allocator, zero meaning the whole of tp_rule_counters; tests set both.
	openMaps    func(pinDir string) (*tpmap.Maps, error)
	counterRows uint32
}

// SetupWithManager registers the reconciler and its collector.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &galacticv1alpha1.TrafficPolicyBinding{},
		policyRefIndex, func(o client.Object) []string {
			b := o.(*galacticv1alpha1.TrafficPolicyBinding)
			var refs []string
			for _, d := range directions {
				if ref := d.ref(&b.Spec); ref != nil {
					refs = append(refs, ref.Name)
				}
			}
			return refs
		}); err != nil {
		return fmt.Errorf("index bindings by policy: %w", err)
	}
	sameName := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		return []reconcile.Request{{NamespacedName: client.ObjectKeyFromObject(o)}}
	})
	byPolicy := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		var bindings galacticv1alpha1.TrafficPolicyBindingList
		if err := mgr.GetClient().List(ctx, &bindings, client.InNamespace(o.GetNamespace()),
			client.MatchingFields{policyRefIndex: o.GetName()}); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "list bindings referencing policy", "policy", o.GetName())
			return nil
		}
		out := make([]reconcile.Request, 0, len(bindings.Items))
		for i := range bindings.Items {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&bindings.Items[i])})
		}
		return out
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("traffic-policy-node").
		For(&cloudv1alpha1.VPCAttachment{}).
		Watches(&galacticv1alpha1.TrafficPolicyBinding{}, sameName).
		Watches(&galacticv1alpha1.TrafficPolicy{}, byPolicy).
		Complete(r)
}

// Reconcile implements reconcile.Reconciler. It changes the datapath under
// the lock and writes status after releasing it, so a scrape never waits on
// the API server.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	update, res, err := r.reconcile(ctx, req)
	if update != nil {
		if serr := r.writeStatus(ctx, req.NamespacedName, update.results); serr != nil {
			err = errors.Join(err, serr)
		}
	}
	return res, err
}

// statusUpdate is this node's entry for a binding: both directions, or, when
// results is nil, no entry.
type statusUpdate struct {
	results *[2]galacticv1alpha1.AppliedPolicy
}

var removeStatus = &statusUpdate{}

func pendingStatus(msg string) *statusUpdate {
	p := galacticv1alpha1.AppliedPolicy{State: galacticv1alpha1.StatePending, Message: msg}
	return &statusUpdate{results: &[2]galacticv1alpha1.AppliedPolicy{p, p}}
}

func (r *Reconciler) reconcile(ctx context.Context, req ctrl.Request) (*statusUpdate, ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.open(ctx); err != nil {
		// The datapath pins its maps when galactic-cni loads it, which may be
		// after this process starts.
		log.Info("traffic policy maps are not available yet", "error", err.Error())
		return nil, ctrl.Result{RequeueAfter: pendingRetry}, nil
	}
	r.sweepAdopted(ctx)
	r.sweepPins(ctx)

	var att cloudv1alpha1.VPCAttachment
	if err := r.Client.Get(ctx, req.NamespacedName, &att); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, ctrl.Result{}, err
		}
		r.forget(ctx, req.NamespacedName)
		return removeStatus, ctrl.Result{}, nil
	}
	if att.Status.Node != r.NodeName || att.Status.HostInterface == "" {
		r.forget(ctx, req.NamespacedName)
		return removeStatus, ctrl.Result{}, nil
	}
	link, err := netlink.LinkByName(att.Status.HostInterface)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			// Keep what is installed through a transient failure.
			return nil, ctrl.Result{}, fmt.Errorf("find host interface %q: %w", att.Status.HostInterface, err)
		}
		r.forget(ctx, req.NamespacedName)
		return pendingStatus("the interface is not on this node yet"), ctrl.Result{RequeueAfter: pendingRetry}, nil
	}
	ifindex := uint32(link.Attrs().Index) //nolint:gosec // a kernel ifindex
	var row prog.UsidTpIfaceValue
	if err := r.maps.Interfaces.Lookup(ifindex, &row); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, ctrl.Result{}, fmt.Errorf("read tp_iface_table[%d]: %w", ifindex, err)
		}
		// CNI ADD has not written the row yet; the interface denies as
		// policy_unavailable meanwhile.
		return pendingStatus("the interface's datapath state is not ready"), ctrl.Result{RequeueAfter: pendingRetry}, nil
	}
	if prev, ok := r.ifaces[req.NamespacedName]; ok && prev.ifindex != ifindex {
		r.drop(ctx, prev.ifindex, req.NamespacedName)
	}

	var binding galacticv1alpha1.TrafficPolicyBinding
	bindingFound := true
	if err := r.Client.Get(ctx, req.NamespacedName, &binding); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, ctrl.Result{}, err
		}
		bindingFound = false
	}
	labels := interfaceLabels{
		namespace: att.Namespace, vpc: att.Spec.VPC.Name, attachment: att.Name,
		iface: att.Spec.Interface.Name, ifaceUID: string(att.UID),
	}
	r.ifaces[req.NamespacedName] = iface{ifindex: ifindex, token: row.PolicyToken, labels: labels}

	var results [2]galacticv1alpha1.AppliedPolicy
	var errs []error
	for i, d := range directions {
		var ref *galacticv1alpha1.LocalPolicyReference
		if bindingFound {
			ref = d.ref(&binding.Spec)
		}
		res, err := r.reconcileDirection(ctx, bindingKey{ifindex, d.dir}, req.NamespacedName, labels,
			row.PolicyToken, att.Namespace, ref)
		res.ObservedGeneration = binding.Generation
		results[i] = res
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d.name, err))
		}
	}
	var update *statusUpdate
	if bindingFound {
		update = &statusUpdate{results: &results}
	}
	return update, ctrl.Result{RequeueAfter: resync}, errors.Join(errs...)
}

// reconcileDirection resolves, compiles and publishes one direction, and
// returns what the node now applies there.
func (r *Reconciler) reconcileDirection(ctx context.Context, key bindingKey, att types.NamespacedName,
	labels interfaceLabels, token uint64, ns string, ref *galacticv1alpha1.LocalPolicyReference,
) (galacticv1alpha1.AppliedPolicy, error) {
	identity, model, unresolved, invalid, err := r.resolve(ctx, ns, ref)
	if err != nil {
		// An API outage keeps what is installed.
		return failed(r.state[key], err.Error()), err
	}
	prev := r.state[key]
	sameLifetime := prev != nil && prev.policy.UID == identity.UID && prev.token == token
	if unresolved != "" {
		// A missing or reserved-conflict reference never keeps old grants.
		if err := r.invalidate(key); err != nil {
			return failed(prev, err.Error()), err
		}
		return galacticv1alpha1.AppliedPolicy{State: galacticv1alpha1.StatePending, Message: unresolved}, nil
	}
	if invalid != "" {
		// The same policy keeps its last good snapshot; any other identity,
		// including one adopted across a restart, is invalidated.
		if sameLifetime {
			return failed(prev, invalid), nil
		}
		if err := r.invalidate(key); err != nil {
			return failed(nil, err.Error()), err
		}
		return failed(nil, invalid), nil
	}
	if prev == nil && r.adopt(key, att, labels, token, identity, model) {
		return appliedState(r.state[key]), nil // bound before a restart, and still current
	}
	if prev != nil && prev.policy == identity && prev.token == token {
		return appliedState(prev), nil // nothing changed
	}
	if err := r.publish(key, att, labels, token, identity, model); err != nil {
		if sameLifetime {
			return failed(prev, err.Error()), err // an update of the same policy keeps its last snapshot
		}
		// A rebind that cannot be installed must not leave the old grants.
		if ierr := r.invalidate(key); ierr != nil {
			return failed(prev, err.Error()), errors.Join(err, ierr)
		}
		return failed(nil, err.Error()), err
	}
	return appliedState(r.state[key]), nil
}

// resolve reads what a reference names. unresolved explains a reference that
// resolves to nothing; invalid explains a policy that does not compile.
func (r *Reconciler) resolve(ctx context.Context, ns string, ref *galacticv1alpha1.LocalPolicyReference) (
	identity galacticv1alpha1.PolicyIdentity, model trafficpolicy.Policy, unresolved, invalid string, err error,
) {
	if ref == nil {
		builtin := galacticv1alpha1.PolicyIdentity{
			Name: galacticv1alpha1.DefaultPolicyName, UID: galacticv1alpha1.DefaultPolicyUID,
		}
		return builtin, trafficpolicy.Default(), "", "", nil
	}
	var p galacticv1alpha1.TrafficPolicy
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref.Name}, &p); err != nil {
		if apierrors.IsNotFound(err) {
			return identity, model, "TrafficPolicy " + ref.Name + " does not exist", "", nil
		}
		return identity, model, "", "", err
	}
	if cell.IsReservedConflict(&p) {
		return identity, model, "TrafficPolicy " + ref.Name + " holds the reserved default name without being " +
			"the controller's default policy", "", nil
	}
	identity = galacticv1alpha1.PolicyIdentity{Name: p.Name, UID: string(p.UID), Generation: p.Generation}
	model, errs := trafficpolicy.FromAPI(p.Spec, field.NewPath("spec"))
	if len(errs) > 0 {
		return identity, model, "", "TrafficPolicy " + ref.Name + " is invalid: " + errs.ToAggregate().Error(), nil
	}
	return identity, model, "", "", nil
}

// publish installs model for key, reusing the counter row of every rule whose
// name and action are unchanged within the same policy and interface
// lifetime, and freeing the rows the replaced snapshot alone used once the
// kernel has stopped every program that could still count into them. On
// failure nothing it allocated stays allocated and the bound snapshot is
// unchanged.
func (r *Reconciler) publish(key bindingKey, att types.NamespacedName, labels interfaceLabels, token uint64,
	identity galacticv1alpha1.PolicyIdentity, model trafficpolicy.Policy,
) error {
	prev := r.state[key]
	reuse := map[ruleKey]uint32{}
	if prev != nil && prev.policy.UID == identity.UID && prev.token == token {
		for i, k := range prev.rules {
			reuse[k] = prev.rows[i]
		}
	}
	entries, err := trafficpolicy.Compile(model)
	if err != nil {
		return err
	}
	next := &applied{attachment: att, labels: labels, token: token, policy: identity}
	var fresh []uint32
	rollback := func() {
		for _, row := range fresh {
			r.alloc.Free(row)
		}
	}
	for _, rule := range model.Rules {
		k := ruleKey{rule.Name, rule.Allow}
		row, ok := reuse[k]
		if !ok {
			var err error
			if row, err = r.alloc.Allocate(1); err != nil {
				rollback()
				return err
			}
			fresh = append(fresh, row)
			if err := r.maps.ZeroCounters(row, 1); err != nil {
				rollback()
				return err
			}
		}
		delete(reuse, k)
		next.rules = append(next.rules, k)
		next.rows = append(next.rows, row)
	}
	for i := range entries {
		entries[i].Rule = uint16(next.rows[entries[i].Rule]) //nolint:gosec // rows < RuleCounterRows
	}
	snap := tpmap.Snapshot{
		Token: token, Generation: identity.Generation, PolicyUID: PolicyUIDBytes(identity.UID), Entries: entries,
	}
	if err := r.maps.PublishSnapshot(key.ifindex, key.dir, snap); err != nil {
		rollback()
		return err
	}
	// Publish returned, so no program can still be counting into a row only
	// the replaced snapshot named.
	if prev != nil {
		if prev.policy.UID == identity.UID && prev.token == token {
			for _, row := range reuse {
				r.alloc.Free(row)
			}
		} else {
			for _, row := range prev.rows {
				r.alloc.Free(row)
			}
		}
	}
	r.state[key] = next
	r.freeAdopted(key)
	return nil
}

// invalidate unbinds key, which denies as policy_unavailable, then frees the
// rows its snapshot used.
func (r *Reconciler) invalidate(key bindingKey) error {
	if err := r.maps.Invalidate(key.ifindex, key.dir); err != nil {
		return err
	}
	if prev := r.state[key]; prev != nil {
		for _, row := range prev.rows {
			r.alloc.Free(row)
		}
	}
	delete(r.state, key)
	r.freeAdopted(key)
	return nil
}

// forget drops what this node installed for an attachment that left it.
// CNI DEL removes the interface's datapath state.
func (r *Reconciler) forget(ctx context.Context, att types.NamespacedName) {
	if i, ok := r.ifaces[att]; ok {
		r.drop(ctx, i.ifindex, att)
		delete(r.ifaces, att)
	}
}

// drop unbinds att's directions on ifindex so their rows can be freed. A
// direction another attachment now holds, after the ifindex was reused, is
// left alone. A direction that cannot be unbound keeps its rows, and Collect
// stops exporting it because att no longer owns the ifindex.
func (r *Reconciler) drop(ctx context.Context, ifindex uint32, att types.NamespacedName) {
	for _, d := range directions {
		key := bindingKey{ifindex, d.dir}
		if a := r.state[key]; a != nil && a.attachment != att {
			continue
		}
		if err := r.invalidate(key); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "unbind traffic policy", "ifindex", ifindex, "direction", d.name)
		}
	}
}

// open loads the pinned maps and reserves the rows of every snapshot already
// bound, adopting them, on the first reconcile; it retries until the
// datapath has pinned its maps. Nothing is kept unless every bound snapshot
// was read, since a row left unreserved could be handed to another rule
// while a bound snapshot still counts into it. The one exception is a
// snapshot this process cannot read at all (tpmap.ErrSnapshotUnreadable), such
// as one bound before snapshots were pinned: it is adopted as empty, so it
// stays bound until its attachment's reconcile replaces it or the sweep
// unbinds it, and its rows may count another rule's packets until then.
func (r *Reconciler) open(ctx context.Context) error {
	if r.maps != nil {
		return nil
	}
	openMaps := r.openMaps
	if openMaps == nil {
		openMaps = tpmap.OpenPinned
	}
	maps, err := openMaps(r.PinDir)
	if err != nil {
		return fmt.Errorf("open traffic policy maps: %w", err)
	}
	rows := r.counterRows
	if rows == 0 {
		rows = tpmap.RuleCounterRows
	}
	alloc := tpmap.NewCounterAllocator(rows)
	adopted := map[bindingKey]tpmap.Snapshot{}
	if err := readBound(ctx, maps, alloc, adopted); err != nil {
		if r.openMaps == nil {
			maps.Close()
		}
		return err
	}
	r.maps, r.alloc, r.adopted = maps, alloc, adopted
	r.state = map[bindingKey]*applied{}
	r.ifaces = map[types.NamespacedName]iface{}
	r.openedAt = time.Now()
	return nil
}

func readBound(ctx context.Context, maps *tpmap.Maps, alloc *tpmap.CounterAllocator,
	adopted map[bindingKey]tpmap.Snapshot,
) error {
	keys, err := maps.BoundKeys()
	if err != nil {
		return err
	}
	for _, k := range keys {
		snap, ok, err := maps.ReadSnapshot(k.Ifindex, k.Direction)
		if errors.Is(err, tpmap.ErrSnapshotUnreadable) {
			ctrl.LoggerFrom(ctx).Info("adopting an unreadable traffic policy snapshot as empty until it is republished",
				"ifindex", k.Ifindex, "direction", k.Direction, "error", err.Error())
			adopted[bindingKey{k.Ifindex, k.Direction}] = tpmap.Snapshot{}
			continue
		}
		if err != nil {
			return err
		}
		if !ok {
			continue // unbound since it was listed
		}
		for _, row := range snapshotRows(snap) {
			if err := alloc.Reserve(row, 1); err != nil {
				return fmt.Errorf("reserve row %d of ifindex %d direction %d: %w", row, k.Ifindex, k.Direction, err)
			}
		}
		adopted[bindingKey{k.Ifindex, k.Direction}] = snap
	}
	return nil
}

// freeAdopted releases the rows of a snapshot bound before a restart, once
// it has been replaced or unbound, except those the current state reuses.
func (r *Reconciler) freeAdopted(key bindingKey) {
	snap, ok := r.adopted[key]
	if !ok {
		return
	}
	keep := map[uint32]bool{}
	if cur := r.state[key]; cur != nil {
		for _, row := range cur.rows {
			keep[row] = true
		}
	}
	for _, row := range snapshotRows(snap) {
		if !keep[row] {
			r.alloc.Free(row)
		}
	}
	delete(r.adopted, key)
}

// sweepPins removes snapshot pins left holding no bound snapshot, on the
// first reconcile and once a resync after: those a publish left behind when
// galactic-router stopped during it, or when an interface's DEL unbound the
// snapshot while it was being pinned. It runs under r.mu, so never during one
// of this reconciler's publishes.
func (r *Reconciler) sweepPins(ctx context.Context) {
	if time.Since(r.sweptAt) < resync {
		return
	}
	r.sweptAt = time.Now()
	if err := r.maps.SweepPins(); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "remove stale traffic policy snapshot pins")
	}
}

// sweepAdopted unbinds the snapshots bound before a restart that no
// attachment has claimed within a full resync, such as one whose
// VPCAttachment was deleted while galactic-router was down, so their rows
// are not held forever. Their interfaces deny as policy_unavailable. An
// interface this node has reconciled is never swept: a direction whose
// reconcile keeps failing keeps what it had.
func (r *Reconciler) sweepAdopted(ctx context.Context) {
	if len(r.adopted) == 0 || time.Since(r.openedAt) < resync+pendingRetry {
		return
	}
	known := map[uint32]bool{}
	for _, i := range r.ifaces {
		known[i.ifindex] = true
	}
	for key := range r.adopted {
		if known[key.ifindex] {
			continue
		}
		if err := r.invalidate(key); err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "unbind unclaimed traffic policy", "ifindex", key.ifindex)
		}
	}
}

// snapshotRows is every counter row a snapshot's entries name.
func snapshotRows(s tpmap.Snapshot) []uint32 {
	var rows []uint32
	seen := map[uint32]bool{}
	for _, e := range s.Entries {
		row := s.CounterBase + uint32(e.Rule)
		if !seen[row] {
			seen[row] = true
			rows = append(rows, row)
		}
	}
	return rows
}

// NoRow marks a rule that compiles to no entries, and so names no row in a
// snapshot.
const NoRow = ^uint32(0)

// RuleRows maps each of a policy's rules to the counter row a bound snapshot
// gives it, from entries, what the policy compiles to with rule indexes. It
// reports false unless the snapshot holds exactly those entries, so a
// snapshot an older compiler produced, or one of another policy, never
// matches.
func RuleRows(entries []trafficpolicy.Entry, snap tpmap.Snapshot, rules int) ([]uint32, bool) {
	if len(entries) != len(snap.Raw) {
		return nil, false
	}
	rows := make([]uint32, rules)
	for i := range rows {
		rows[i] = NoRow
	}
	owner := map[uint32]uint16{}
	for i, e := range entries {
		got := snap.Raw[i]
		want := tpmap.EncodeEntry(e)
		row := snap.CounterBase + uint32(got.Rule)
		got.Rule, want.Rule = 0, 0
		if got != want || int(e.Rule) >= rules {
			return nil, false
		}
		if prev, ok := owner[row]; ok && prev != e.Rule {
			return nil, false // two rules share a row
		}
		if rows[e.Rule] != NoRow && rows[e.Rule] != row {
			return nil, false // one rule names two rows
		}
		owner[row] = e.Rule
		rows[e.Rule] = row
	}
	return rows, true
}

// adopt takes over a snapshot bound before a restart when it holds exactly
// what the policy now desired compiles to, so its counters continue. A rule
// that compiles to no entries counts nothing and gets a fresh row.
func (r *Reconciler) adopt(key bindingKey, att types.NamespacedName, labels interfaceLabels, token uint64,
	identity galacticv1alpha1.PolicyIdentity, model trafficpolicy.Policy,
) bool {
	snap, ok := r.adopted[key]
	if !ok || snap.Token != token || snap.Generation != identity.Generation ||
		snap.PolicyUID != PolicyUIDBytes(identity.UID) {
		return false
	}
	entries, err := trafficpolicy.Compile(model)
	if err != nil {
		return false
	}
	rows, ok := RuleRows(entries, snap, len(model.Rules))
	if !ok {
		return false
	}
	var fresh []uint32
	for i, row := range rows {
		if row != NoRow {
			continue
		}
		row, err := r.alloc.Allocate(1)
		if err == nil {
			err = r.maps.ZeroCounters(row, 1)
			fresh = append(fresh, row)
		}
		if err != nil {
			for _, f := range fresh {
				r.alloc.Free(f)
			}
			return false
		}
		rows[i] = row
	}
	a := &applied{attachment: att, labels: labels, token: token, policy: identity, rows: rows}
	for _, rule := range model.Rules {
		a.rules = append(a.rules, ruleKey{rule.Name, rule.Allow})
	}
	r.state[key] = a
	delete(r.adopted, key)
	return true
}

// PolicyUIDBytes is the 16-byte policy identity a snapshot header records: a
// Kubernetes UID's own bytes, or a digest of the synthetic built-in identity.
func PolicyUIDBytes(uid string) [16]byte {
	if u, err := uuid.Parse(uid); err == nil {
		return u
	}
	sum := sha256.Sum256([]byte(uid))
	var b [16]byte
	copy(b[:], sum[:])
	return b
}

func appliedState(a *applied) galacticv1alpha1.AppliedPolicy {
	p := a.policy
	return galacticv1alpha1.AppliedPolicy{Policy: &p, State: galacticv1alpha1.StateApplied}
}

func failed(last *applied, msg string) galacticv1alpha1.AppliedPolicy {
	out := galacticv1alpha1.AppliedPolicy{State: galacticv1alpha1.StateFailed, Message: truncate(msg)}
	if last != nil {
		p := last.policy
		out.Policy = &p
	}
	return out
}

func truncate(s string) string {
	if len(s) > 1024 {
		return s[:1021] + "..."
	}
	return s
}

// fieldOwner is this node's server-side apply field manager, within the
// 128-byte limit for any node name.
func fieldOwner(node string) string {
	owner := "galactic-router/" + node
	if len(owner) <= 128 {
		return owner
	}
	sum := sha256.Sum256([]byte(node))
	return "galactic-router/" + node[:64] + "-" + hex.EncodeToString(sum[:8])
}

// writeStatus applies this node's entry in the binding's status.nodes, or,
// when results is nil, removes it. It writes only when the entry would
// change, so resyncs, pending retries and attachments on other nodes cost no
// API writes.
func (r *Reconciler) writeStatus(ctx context.Context, binding types.NamespacedName,
	results *[2]galacticv1alpha1.AppliedPolicy,
) error {
	var cur galacticv1alpha1.TrafficPolicyBinding
	if err := r.Client.Get(ctx, binding, &cur); err != nil {
		if apierrors.IsNotFound(err) {
			return nil // no binding: both directions use the built-in default
		}
		return err
	}
	var existing *galacticv1alpha1.NodeBindingStatus
	for i := range cur.Status.Nodes {
		if cur.Status.Nodes[i].Node == r.NodeName {
			existing = &cur.Status.Nodes[i]
		}
	}
	nodes := []galacticv1alpha1.NodeBindingStatus{}
	if results == nil {
		if existing == nil {
			return nil
		}
	} else {
		in, eg := results[0], results[1]
		now := metav1.Now()
		for _, a := range []*galacticv1alpha1.AppliedPolicy{&in, &eg} {
			if a.ObservedGeneration == 0 {
				a.ObservedGeneration = cur.Generation
			}
		}
		if existing != nil {
			keepTransitionTimes(&[2]*galacticv1alpha1.AppliedPolicy{&in, &eg}, *existing)
		}
		for _, a := range []*galacticv1alpha1.AppliedPolicy{&in, &eg} {
			if a.LastTransitionTime == nil {
				a.LastTransitionTime = &now
			}
		}
		entry := galacticv1alpha1.NodeBindingStatus{Node: r.NodeName, Ingress: &in, Egress: &eg}
		if existing != nil && equality.Semantic.DeepEqual(*existing, entry) {
			return nil
		}
		nodes = append(nodes, entry)
	}
	body, err := json.Marshal(map[string]any{
		"apiVersion": galacticv1alpha1.GroupVersion.String(),
		"kind":       "TrafficPolicyBinding",
		"metadata":   metav1.ObjectMeta{Name: binding.Name, Namespace: binding.Namespace},
		"status":     map[string]any{"nodes": nodes},
	})
	if err != nil {
		return err
	}
	obj := &galacticv1alpha1.TrafficPolicyBinding{}
	obj.Name, obj.Namespace = binding.Name, binding.Namespace
	err = r.Client.Status().Patch(ctx, obj, client.RawPatch(types.ApplyPatchType, body),
		client.FieldOwner(fieldOwner(r.NodeName)), client.ForceOwnership)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("apply node status: %w", err)
	}
	return nil
}

// keepTransitionTimes carries over lastTransitionTime for each direction
// whose state and policy are unchanged from this node's existing entry.
func keepTransitionTimes(results *[2]*galacticv1alpha1.AppliedPolicy, existing galacticv1alpha1.NodeBindingStatus) {
	for i, old := range []*galacticv1alpha1.AppliedPolicy{existing.Ingress, existing.Egress} {
		cur := results[i]
		if old == nil || old.State != cur.State || !samePolicy(old.Policy, cur.Policy) {
			continue
		}
		cur.LastTransitionTime = old.LastTransitionTime
	}
}

func samePolicy(a, b *galacticv1alpha1.PolicyIdentity) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
