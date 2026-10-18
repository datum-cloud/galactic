// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package topology

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// maxListed bounds how many conflicts or missing endpoints a condition
// message names.
const maxListed = 5

// Reconciler generates one FabricTopology's BGPPeers.
type Reconciler struct {
	client.Client
	// APIReader reads around the cache, so a deleted topology releases
	// every peer it controls, including one the cache has not seen yet.
	APIReader client.Reader
}

// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=fabrictopologies;fabricendpoints,verbs=get;list;watch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=fabrictopologies,verbs=patch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=fabrictopologies/status;fabricendpoints/status,verbs=patch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=fabrictopologies/finalizers,verbs=update
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=bgppeers,verbs=create;update;delete

// snapshot is the namespace state one pass reads.
type snapshot struct {
	topology    *networkv1alpha1.FabricTopology
	endpoints   map[string]*EndpointState
	routers     map[string]*networkv1alpha1.BGPRouter
	profiles    map[string]*networkv1alpha1.BGPPeerProfile
	policies    map[string]bool
	deployments map[string]*networkv1alpha1.FabricRouterDeployment
	peers       []networkv1alpha1.BGPPeer
	nodeLabels  map[string]map[string]string
}

// Reconcile generates one topology's peers and reports what it did.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	topo := &networkv1alpha1.FabricTopology{}
	if err := r.Get(ctx, req.NamespacedName, topo); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !topo.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.releaseAll(ctx, topo)
	}
	if !controllerutil.ContainsFinalizer(topo, networkv1alpha1.FabricTopologyFinalizer) {
		// Without the finalizer, deleting the topology would leave its
		// peers to the garbage collector.
		patch := client.MergeFromWithOptions(topo.DeepCopy(), client.MergeFromWithOptimisticLock{})
		controllerutil.AddFinalizer(topo, networkv1alpha1.FabricTopologyFinalizer)
		if err := r.Patch(ctx, topo, patch); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
	}
	snap, err := r.read(ctx, topo)
	if err != nil {
		return ctrl.Result{}, err
	}
	st := &status{}
	plan, err := Generate(Input{Topology: topo, Endpoints: snap.endpoints, Routers: snap.routers,
		Profiles: snap.profiles, NodeLabels: snap.nodeLabels})
	if err != nil {
		st.notAccepted(networkv1alpha1.FabricTopologyReasonInvalidSelector, err.Error())
		return ctrl.Result{}, r.writeStatus(ctx, topo, st)
	}
	st.members = int32(len(plan.Members))
	st.missing = plan.MissingEndpoints
	if len(plan.OverLimit) > 0 {
		st.notAccepted(networkv1alpha1.FabricTopologyReasonTooManySessions,
			fmt.Sprintf("more than %d sessions on %s; nothing was changed", topo.Spec.MaxSessionsPerRouter,
				listed(plan.OverLimit)))
		return ctrl.Result{}, r.writeStatus(ctx, topo, st)
	}
	if missing := snap.unresolved(plan); len(missing) > 0 {
		st.unresolved = missing
		return ctrl.Result{}, r.writeStatus(ctx, topo, st)
	}
	if err := r.apply(ctx, snap, plan, st); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.writeStatus(ctx, topo, st)
}

// read gathers the namespace state the topology depends on.
func (r *Reconciler) read(ctx context.Context, topo *networkv1alpha1.FabricTopology) (*snapshot, error) {
	ns := client.InNamespace(topo.Namespace)
	snap := &snapshot{topology: topo, routers: map[string]*networkv1alpha1.BGPRouter{},
		profiles: map[string]*networkv1alpha1.BGPPeerProfile{}, policies: map[string]bool{},
		deployments: map[string]*networkv1alpha1.FabricRouterDeployment{}, nodeLabels: map[string]map[string]string{}}

	routers := &networkv1alpha1.BGPRouterList{}
	if err := r.List(ctx, routers, ns); err != nil {
		return nil, err
	}
	for i := range routers.Items {
		snap.routers[routers.Items[i].Name] = &routers.Items[i]
	}
	cells, err := localCells(ctx, r.Client, topo.Namespace)
	if err != nil {
		return nil, err
	}
	endpoints := &networkv1alpha1.FabricEndpointList{}
	if err := r.List(ctx, endpoints, ns); err != nil {
		return nil, err
	}
	snap.endpoints = Analyze(endpoints.Items, cells, snap.routers)

	profiles := &networkv1alpha1.BGPPeerProfileList{}
	if err := r.List(ctx, profiles, ns); err != nil {
		return nil, err
	}
	for i := range profiles.Items {
		snap.profiles[profiles.Items[i].Name] = &profiles.Items[i]
	}
	policies := &networkv1alpha1.BGPPolicyList{}
	if err := r.List(ctx, policies, ns); err != nil {
		return nil, err
	}
	for i := range policies.Items {
		snap.policies[policies.Items[i].Name] = true
	}
	deps := &networkv1alpha1.FabricRouterDeploymentList{}
	if err := r.List(ctx, deps, ns); err != nil {
		return nil, err
	}
	for i := range deps.Items {
		snap.deployments[deps.Items[i].Name] = &deps.Items[i]
	}
	peers := &networkv1alpha1.BGPPeerList{}
	if err := r.List(ctx, peers, ns); err != nil {
		return nil, err
	}
	snap.peers = peers.Items

	for _, router := range snap.routers {
		node := router.Spec.TargetRef.Name
		if _, seen := snap.nodeLabels[node]; seen || topo.Spec.FailureDomainLabel == "" {
			continue
		}
		obj := &metav1.PartialObjectMetadata{}
		obj.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Node"))
		err := r.Get(ctx, types.NamespacedName{Name: node}, obj)
		if client.IgnoreNotFound(err) != nil {
			return nil, err
		}
		snap.nodeLabels[node] = obj.Labels
	}
	return snap, nil
}

// localCells are the cells the namespace's topologies generate for.
func localCells(ctx context.Context, c client.Reader, namespace string) (map[string]bool, error) {
	topos := &networkv1alpha1.FabricTopologyList{}
	if err := c.List(ctx, topos, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, t := range topos.Items {
		if t.DeletionTimestamp.IsZero() {
			out[t.Spec.Cell] = true
		}
	}
	return out, nil
}

// unresolved names every profile and policy the relationships reference
// that does not exist.
func (s *snapshot) unresolved(plan Plan) []string {
	var out []string
	for _, p := range plan.Profiles {
		if s.profiles[p] == nil {
			out = append(out, "BGPPeerProfile "+p)
		}
	}
	for _, p := range plan.Policies {
		if !s.policies[p] {
			out = append(out, "BGPPolicy "+p)
		}
	}
	return out
}

// owned reports whether the topology generated peer: it controls it and
// labelled it. Anything else is never changed or deleted.
func owned(topo *networkv1alpha1.FabricTopology, peer *networkv1alpha1.BGPPeer) bool {
	ref := metav1.GetControllerOf(peer)
	return ref != nil && ref.UID == topo.UID &&
		peer.Labels[networkv1alpha1.LabelManagedBy] == networkv1alpha1.ManagedByFabricTopology &&
		peer.Labels[networkv1alpha1.LabelFabricTopology] == topo.Name
}

// apply writes the plan's peers, keeps or deletes the generated peers it no
// longer holds, and records the outcome in st.
func (r *Reconciler) apply(ctx context.Context, snap *snapshot, plan Plan, st *status) error {
	topo := snap.topology
	byName := map[string]*networkv1alpha1.BGPPeer{}
	holders := map[key]*networkv1alpha1.BGPPeer{}
	for i := range snap.peers {
		p := &snap.peers[i]
		byName[p.Name] = p
		if p.Spec.RouterRef == nil {
			continue
		}
		if a, err := netip.ParseAddr(p.Spec.Address); err == nil {
			holders[key{p.Spec.RouterRef.Name, a}] = p
		}
	}
	for _, o := range plan.Overlaps {
		st.conflict(fmt.Sprintf("%s and %s both peer router %s with %s", o.Kept, o.Dropped, o.Router, o.Address))
	}

	held := map[string]bool{}
	for _, s := range plan.Sessions {
		want := s.Peer
		held[want.Name] = true
		addr, _ := netip.ParseAddr(want.Spec.Address)
		holder := holders[key{want.Spec.RouterRef.Name, addr}]
		existing := byName[want.Name]
		switch {
		case holder != nil && holder.Name != want.Name:
			kind := "hand-authored"
			if owned(topo, holder) {
				kind = "retained"
			}
			st.conflict(fmt.Sprintf("%s BGPPeer %s already peers router %s with %s", kind, holder.Name,
				want.Spec.RouterRef.Name, want.Spec.Address))
		case existing != nil && !owned(topo, existing):
			st.conflict(fmt.Sprintf("BGPPeer %s exists and was not generated by this topology", want.Name))
		case existing != nil:
			if err := r.update(ctx, existing, want); err != nil {
				return err
			}
			st.generated++
		default:
			if err := controllerutil.SetControllerReference(topo, want, r.Scheme()); err != nil {
				return err
			}
			if err := r.Create(ctx, want); err != nil && !apierrors.IsAlreadyExists(err) {
				return fmt.Errorf("create BGPPeer %s: %w", want.Name, err)
			}
			st.generated++
		}
	}

	for i := range snap.peers {
		p := &snap.peers[i]
		if held[p.Name] || !owned(topo, p) || !p.DeletionTimestamp.IsZero() {
			continue
		}
		if why := snap.released(p); why != "" {
			log.FromContext(ctx).Info("releasing generated peer", "peer", p.Name, "reason", why)
			if err := r.Delete(ctx, p, client.Preconditions{UID: &p.UID}); client.IgnoreNotFound(err) != nil {
				return fmt.Errorf("delete BGPPeer %s: %w", p.Name, err)
			}
			continue
		}
		st.retained++
	}
	return nil
}

// releaseAll hands every peer the deleting topology controls to manual
// control, then lets the topology go. A released peer keeps its spec, so the
// router keeps compiling the same sessions; it loses the controller
// reference and generated labels, so neither the garbage collector nor a
// topology created again acts on it.
func (r *Reconciler) releaseAll(ctx context.Context, topo *networkv1alpha1.FabricTopology) error {
	if !controllerutil.ContainsFinalizer(topo, networkv1alpha1.FabricTopologyFinalizer) {
		return nil
	}
	peers := &networkv1alpha1.BGPPeerList{}
	if err := r.APIReader.List(ctx, peers, client.InNamespace(topo.Namespace)); err != nil {
		return err
	}
	for i := range peers.Items {
		p := &peers.Items[i]
		if !owned(topo, p) {
			continue
		}
		refs := p.OwnerReferences[:0]
		for _, ref := range p.OwnerReferences {
			if ref.UID != topo.UID {
				refs = append(refs, ref)
			}
		}
		p.OwnerReferences = refs
		delete(p.Labels, networkv1alpha1.LabelManagedBy)
		delete(p.Labels, networkv1alpha1.LabelFabricTopology)
		if p.Annotations == nil {
			p.Annotations = map[string]string{}
		}
		p.Annotations[networkv1alpha1.AnnotationReleasedFromTopology] = topo.Name
		if err := r.Update(ctx, p); err != nil {
			return fmt.Errorf("release BGPPeer %s: %w", p.Name, err)
		}
		log.FromContext(ctx).Info("handed generated peer to manual control", "peer", p.Name)
	}
	patch := client.MergeFromWithOptions(topo.DeepCopy(), client.MergeFromWithOptimisticLock{})
	controllerutil.RemoveFinalizer(topo, networkv1alpha1.FabricTopologyFinalizer)
	return client.IgnoreNotFound(r.Patch(ctx, topo, patch))
}

// update makes existing match want's spec, labels and annotations, writing
// only when something differs.
func (r *Reconciler) update(ctx context.Context, existing, want *networkv1alpha1.BGPPeer) error {
	next := existing.DeepCopy()
	next.Spec = want.Spec
	next.Labels = merged(existing.Labels, want.Labels, generatedLabels)
	next.Annotations = merged(existing.Annotations, want.Annotations, generatedAnnotations)
	if equality.Semantic.DeepEqual(existing.Spec, next.Spec) &&
		equality.Semantic.DeepEqual(existing.Labels, next.Labels) &&
		equality.Semantic.DeepEqual(existing.Annotations, next.Annotations) {
		return nil
	}
	if err := r.Update(ctx, next); err != nil {
		return fmt.Errorf("update BGPPeer %s: %w", existing.Name, err)
	}
	return nil
}

var (
	generatedLabels = []string{networkv1alpha1.LabelManagedBy, networkv1alpha1.LabelFabricTopology,
		networkv1alpha1.LabelPeerFailureDomain, networkv1alpha1.LabelPeerCell}
	generatedAnnotations = []string{networkv1alpha1.AnnotationRelationship, networkv1alpha1.AnnotationLocalEndpoint,
		networkv1alpha1.AnnotationRemoteEndpoint, networkv1alpha1.AnnotationRemoteEndpointUID,
		networkv1alpha1.AnnotationRemoteRouter}
)

// merged is have with every key in keys set as in want: keys want lacks are
// removed, and keys outside keys are left as they are.
func merged(have, want map[string]string, keys []string) map[string]string {
	out := map[string]string{}
	for k, v := range have {
		out[k] = v
	}
	for _, k := range keys {
		if v, ok := want[k]; ok {
			out[k] = v
		} else {
			delete(out, k)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// released says why a generated peer the topology no longer holds may be
// deleted, or returns empty when it must be kept. A session is released only
// on evidence that one of its ends is out of service:
//   - the local router is gone, retired (its deployment committed a
//     retiring promotion), or drained;
//   - an endpoint it uses is drained;
//   - for an external session, the topology no longer lists the peer;
//   - for a session toward this cell, the remote router is gone, retired or
//     drained;
//   - for a session toward another cell, its endpoint record was deleted,
//     which is visible here because the peer exists only because the record
//     did.
//
// A record that still exists but no longer matches, a member that left the
// selector, or an endpoint of this cell deleted while its router still runs,
// keeps the session until one of those holds.
func (s *snapshot) released(p *networkv1alpha1.BGPPeer) string {
	topo := s.topology
	local := p.Spec.RouterRef.Name
	if why := s.routerOut(local); why != "" {
		return "local router " + local + " " + why
	}
	for _, ann := range []string{networkv1alpha1.AnnotationLocalEndpoint, networkv1alpha1.AnnotationRemoteEndpoint} {
		if ep := p.Annotations[ann]; ep != "" && s.drainedEndpoint(ep) {
			return "endpoint " + ep + " is drained"
		}
	}
	kind, name, _ := strings.Cut(p.Annotations[networkv1alpha1.AnnotationRelationship], "/")
	if kind == KindExternal {
		if !externalListed(topo, name, p.Spec.Address) {
			return "external peer " + p.Spec.Address + " is no longer in relationship " + name
		}
		return ""
	}
	remoteEP := p.Annotations[networkv1alpha1.AnnotationRemoteEndpoint]
	if p.Labels[networkv1alpha1.LabelPeerCell] == topo.Spec.Cell {
		remote := p.Annotations[networkv1alpha1.AnnotationRemoteRouter]
		if why := s.routerOut(remote); why != "" {
			return "remote router " + remote + " " + why
		}
		return ""
	}
	ep := s.endpoints[remoteEP]
	if ep == nil || string(ep.Endpoint.UID) != p.Annotations[networkv1alpha1.AnnotationRemoteEndpointUID] {
		return "endpoint record " + remoteEP + " was deleted"
	}
	return ""
}

// routerOut says how a router of this cell is out of service, or returns
// empty while it may still be running.
func (s *snapshot) routerOut(name string) string {
	if d := s.topology.Spec.Drain; d != nil {
		for _, r := range d.Routers {
			if r.Name == name {
				return "is drained"
			}
		}
	}
	router := s.routers[name]
	if router == nil {
		return "is deleted"
	}
	dep := s.deployments[name]
	if dep != nil && dep.Spec.RouterRef.UID == string(router.UID) && retired(dep) {
		return "is retired"
	}
	return ""
}

// retired reports whether the deployment's router committed the promotion
// that retired it: no revision runs after it and nothing restores an
// earlier one.
func retired(dep *networkv1alpha1.FabricRouterDeployment) bool {
	return dep.Spec.Recovery != nil && dep.Spec.Recovery.Retired && dep.Spec.ActivationEpoch > 0 &&
		dep.Status.AppliedEpoch >= dep.Spec.ActivationEpoch
}

func (s *snapshot) drainedEndpoint(name string) bool {
	if d := s.topology.Spec.Drain; d != nil {
		for _, e := range d.Endpoints {
			if e.Name == name {
				return true
			}
		}
	}
	return false
}

func externalListed(topo *networkv1alpha1.FabricTopology, rel, address string) bool {
	want, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}
	for _, e := range topo.Spec.External {
		if e.Name != rel {
			continue
		}
		for _, p := range e.Peers {
			if a, err := netip.ParseAddr(p.Address); err == nil && a == want {
				return true
			}
		}
	}
	return false
}

// status accumulates one pass's outcome.
type status struct {
	acceptReason, acceptMessage string
	unresolved                  []string
	conflicts                   []string
	missing                     []string
	members, generated          int32
	retained                    int32
}

func (st *status) notAccepted(reason, message string) {
	st.acceptReason, st.acceptMessage = reason, message
}

func (st *status) conflict(msg string) { st.conflicts = append(st.conflicts, msg) }

// listed names up to maxListed items and counts the rest.
func listed(items []string) string {
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	if len(sorted) <= maxListed {
		return strings.Join(sorted, "; ")
	}
	return fmt.Sprintf("%s; and %d more", strings.Join(sorted[:maxListed], "; "), len(sorted)-maxListed)
}

// writeStatus records st on the topology, writing only when it changed.
func (r *Reconciler) writeStatus(ctx context.Context, topo *networkv1alpha1.FabricTopology, st *status) error {
	before := topo.DeepCopy()
	gen := topo.Generation
	set := func(t string, ok bool, reason, msg string) {
		s := metav1.ConditionFalse
		if ok {
			s = metav1.ConditionTrue
		}
		if len(msg) > 1024 {
			msg = msg[:1021] + "..."
		}
		meta.SetStatusCondition(&topo.Status.Conditions, metav1.Condition{
			Type: t, Status: s, Reason: reason, Message: msg, ObservedGeneration: gen,
		})
	}
	accepted := st.acceptReason == ""
	if accepted {
		set(networkv1alpha1.ConditionTypeAccepted, true, networkv1alpha1.FabricTopologyReasonAccepted,
			"the relationships are valid")
	} else {
		set(networkv1alpha1.ConditionTypeAccepted, false, st.acceptReason, st.acceptMessage)
	}
	resolved := len(st.unresolved) == 0
	if resolved {
		set(networkv1alpha1.FabricTopologyConditionResolvedRefs, true, networkv1alpha1.FabricTopologyReasonResolved,
			"every referenced profile and policy exists")
	} else {
		set(networkv1alpha1.FabricTopologyConditionResolvedRefs, false, networkv1alpha1.FabricTopologyReasonUnresolvedRef,
			"missing "+listed(st.unresolved)+"; nothing was changed")
	}
	if len(st.conflicts) == 0 {
		set(networkv1alpha1.FabricTopologyConditionConflicts, false, networkv1alpha1.FabricTopologyReasonNoConflicts,
			"no session is blocked")
	} else {
		set(networkv1alpha1.FabricTopologyConditionConflicts, true, networkv1alpha1.FabricTopologyReasonPeerConflict,
			listed(st.conflicts))
	}
	switch {
	case !accepted:
		set(networkv1alpha1.ConditionTypeReady, false, networkv1alpha1.FabricTopologyReasonNotAccepted, st.acceptMessage)
	case !resolved:
		set(networkv1alpha1.ConditionTypeReady, false, networkv1alpha1.FabricTopologyReasonUnresolvedRef,
			"missing "+listed(st.unresolved))
	case len(st.conflicts) > 0:
		set(networkv1alpha1.ConditionTypeReady, false, networkv1alpha1.FabricTopologyReasonConflictsBlocking,
			fmt.Sprintf("%d sessions are blocked", len(st.conflicts)))
	case len(st.missing) > 0:
		set(networkv1alpha1.ConditionTypeReady, false, networkv1alpha1.FabricTopologyReasonMissingEndpoints,
			"no usable endpoint: "+listed(st.missing))
	default:
		set(networkv1alpha1.ConditionTypeReady, true, networkv1alpha1.FabricTopologyReasonGenerated,
			fmt.Sprintf("%d sessions generated, %d retained until an end is out of service", st.generated, st.retained))
	}
	topo.Status.ObservedGeneration = gen
	if accepted && resolved {
		topo.Status.Members = st.members
		topo.Status.Generated = st.generated
		topo.Status.Conflicting = int32(len(st.conflicts))
		topo.Status.Retained = st.retained
	}
	topo.Status.MissingEndpoints = int32(len(st.missing))
	if equality.Semantic.DeepEqual(before.Status, topo.Status) {
		return nil
	}
	return r.Status().Patch(ctx, topo, client.MergeFrom(before))
}

// SetupWithManager reconciles a namespace's topologies when the topology,
// a peer it controls, or anything it reads changes: endpoints, routers,
// peers (a hand-authored one may conflict), profiles, policies,
// deployments (retirement), and the failure-domain labels of Nodes.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	namespaceTopologies := handler.EnqueueRequestsFromMapFunc(
		func(ctx context.Context, o client.Object) []reconcile.Request {
			return topologies(ctx, r.Client, client.InNamespace(o.GetNamespace()))
		})
	allTopologies := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
		return topologies(ctx, r.Client)
	})
	labelsChanged := predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool { return true },
		DeleteFunc: func(event.DeleteEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			return !equality.Semantic.DeepEqual(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels())
		},
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("fabric-topology").
		For(&networkv1alpha1.FabricTopology{}).
		Owns(&networkv1alpha1.BGPPeer{}).
		Watches(&networkv1alpha1.FabricTopology{}, namespaceTopologies).
		Watches(&networkv1alpha1.FabricEndpoint{}, namespaceTopologies).
		Watches(&networkv1alpha1.BGPRouter{}, namespaceTopologies).
		Watches(&networkv1alpha1.BGPPeer{}, namespaceTopologies).
		Watches(&networkv1alpha1.BGPPeerProfile{}, namespaceTopologies).
		Watches(&networkv1alpha1.BGPPolicy{}, namespaceTopologies).
		Watches(&networkv1alpha1.FabricRouterDeployment{}, namespaceTopologies).
		WatchesMetadata(&corev1.Node{}, allTopologies, builder.WithPredicates(labelsChanged)).
		Complete(r)
}

func topologies(ctx context.Context, c client.Reader, opts ...client.ListOption) []reconcile.Request {
	list := &networkv1alpha1.FabricTopologyList{}
	if err := c.List(ctx, list, opts...); err != nil {
		log.FromContext(ctx).Error(err, "list FabricTopologies to requeue")
		return nil
	}
	out := make([]reconcile.Request, 0, len(list.Items))
	for _, t := range list.Items {
		out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&t)})
	}
	return out
}
