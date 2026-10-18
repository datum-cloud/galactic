// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package topology

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

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

const (
	// maxListed bounds how many conflicts or missing endpoints a condition
	// message names.
	maxListed = 5

	// minHeldReleases is the number of pending releases on absence below
	// which the release guard never holds.
	minHeldReleases = 2

	// DefaultReleaseSettle is how long a router or record must stay gone
	// before the sessions toward it are released.
	DefaultReleaseSettle = time.Minute
)

// Reconciler generates one FabricTopology's BGPPeers.
type Reconciler struct {
	client.Client
	// APIReader reads around the cache: absence that would release a
	// session, and the peers of a deleted topology, are confirmed with it.
	APIReader client.Reader
	// Namespace is the only namespace whose topologies are served; empty
	// serves every namespace.
	Namespace string
	// ReleaseSettle is how long an absence must last before it releases a
	// session; zero is DefaultReleaseSettle. Absences that pile up within it
	// are weighed together by the release guard.
	ReleaseSettle time.Duration
}

// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=fabrictopologies;fabricendpoints,verbs=get;list;watch
// +kubebuilder:rbac:groups=galactic.datumapis.com,namespace=galactic-system,resources=fabrictopologies,verbs=patch
// +kubebuilder:rbac:groups=galactic.datumapis.com,namespace=galactic-system,resources=fabrictopologies/status;fabricendpoints/status,verbs=patch
// +kubebuilder:rbac:groups=galactic.datumapis.com,namespace=galactic-system,resources=bgppeers,verbs=create;update;delete

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
	// reader confirms an absence seen in the cache; nil trusts the cache.
	reader client.Reader
}

// Reconcile generates one topology's peers and reports what it did.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if r.Namespace != "" && req.Namespace != r.Namespace {
		// RBAC grants writes in the served namespace only.
		return ctrl.Result{}, nil
	}
	topo := &networkv1alpha1.FabricTopology{}
	if err := r.Get(ctx, req.NamespacedName, topo); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !topo.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.releaseAll(ctx, topo)
	}
	if !controllerutil.ContainsFinalizer(topo, networkv1alpha1.FabricTopologyFinalizer) {
		// The finalizer holds the topology until its peers are handed to
		// manual control.
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
	st.recordsDigest, st.relationshipsDigest = plan.RecordsDigest, plan.RelationshipsDigest
	for _, c := range plan.NameClashes {
		st.conflict("two sessions named " + c)
	}
	if over := snap.overLimit(plan); len(over) > 0 {
		st.notAccepted(networkv1alpha1.FabricTopologyReasonTooManySessions,
			fmt.Sprintf("more than %d sessions, counting retained ones, on %s; nothing was changed",
				topo.Spec.MaxSessionsPerRouter, listed(over)))
		return ctrl.Result{}, r.writeStatus(ctx, topo, st)
	}
	if missing := snap.unresolved(plan); len(missing) > 0 {
		st.unresolved = missing
		return ctrl.Result{}, r.writeStatus(ctx, topo, st)
	}
	if err := r.apply(ctx, snap, plan, st); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: st.requeue}, r.writeStatus(ctx, topo, st)
}

// read gathers the namespace state the topology depends on.
func (r *Reconciler) read(ctx context.Context, topo *networkv1alpha1.FabricTopology) (*snapshot, error) {
	ns := client.InNamespace(topo.Namespace)
	snap := &snapshot{topology: topo, routers: map[string]*networkv1alpha1.BGPRouter{},
		profiles: map[string]*networkv1alpha1.BGPPeerProfile{}, policies: map[string]bool{},
		deployments: map[string]*networkv1alpha1.FabricRouterDeployment{}, nodeLabels: map[string]map[string]string{},
		reader: r.APIReader}

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
	sort.Slice(snap.peers, func(i, j int) bool { return snap.peers[i].Name < snap.peers[j].Name })

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

// overLimit names the members that would hold more than the topology's
// session limit: the sessions the plan wants plus the generated peers it
// retains.
func (s *snapshot) overLimit(plan Plan) []string {
	limit := s.topology.Spec.MaxSessionsPerRouter
	if limit <= 0 {
		return nil
	}
	wanted := map[key]bool{}
	count := map[string]int32{}
	for _, sess := range plan.Sessions {
		k, _ := peerKey(sess.Peer)
		wanted[k] = true
		count[k.router]++
	}
	for i := range s.peers {
		p := &s.peers[i]
		if k, ok := peerKey(p); ok && owned(s.topology, p) && !wanted[k] {
			wanted[k] = true
			count[k.router]++
		}
	}
	var out []string
	for router, n := range count {
		if n > limit {
			out = append(out, router)
		}
	}
	return out
}

// peerKey is the session a peer configures: its router and remote address.
func peerKey(p *networkv1alpha1.BGPPeer) (key, bool) {
	if p.Spec.RouterRef == nil {
		return key{}, false
	}
	a, err := netip.ParseAddr(p.Spec.Address)
	if err != nil {
		return key{}, false
	}
	return key{p.Spec.RouterRef.Name, a}, true
}

// owned reports whether the topology generated peer: it carries the
// generated labels and the topology's UID. A peer of an earlier version of
// the controller carries a controller reference to the topology instead of
// the UID annotation, and is owned too until it is migrated. Anything else
// is never changed or deleted.
func owned(topo *networkv1alpha1.FabricTopology, peer *networkv1alpha1.BGPPeer) bool {
	if peer.Labels[networkv1alpha1.LabelManagedBy] != networkv1alpha1.ManagedByFabricTopology ||
		peer.Labels[networkv1alpha1.LabelFabricTopology] != topo.Name {
		return false
	}
	if uid, ok := peer.Annotations[networkv1alpha1.AnnotationFabricTopologyUID]; ok {
		return uid == string(topo.UID)
	}
	ref := metav1.GetControllerOf(peer)
	return ref != nil && ref.UID == topo.UID
}

// withoutOwner is refs without any reference to uid.
func withoutOwner(refs []metav1.OwnerReference, uid types.UID) []metav1.OwnerReference {
	var out []metav1.OwnerReference
	for _, ref := range refs {
		if ref.UID != uid {
			out = append(out, ref)
		}
	}
	return out
}

// releaseAll hands every peer the deleting topology generated to manual
// control, then lets the topology go. A released peer keeps its spec, so
// the router keeps compiling the same sessions; it loses the generated
// labels, UID and any owner reference, so neither the garbage collector
// nor a topology created again acts on it.
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
		p.OwnerReferences = withoutOwner(p.OwnerReferences, topo.UID)
		delete(p.Labels, networkv1alpha1.LabelManagedBy)
		delete(p.Labels, networkv1alpha1.LabelFabricTopology)
		if p.Annotations == nil {
			p.Annotations = map[string]string{}
		}
		delete(p.Annotations, networkv1alpha1.AnnotationFabricTopologyUID)
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

// release is a generated peer the topology no longer wants, and why it may
// go.
type release struct {
	peer *networkv1alpha1.BGPPeer
	why  string
	// absent is a release because a router or record is gone, which the
	// release guard bounds.
	absent bool
}

// apply writes the plan's sessions, keeps or releases the generated peers
// it no longer wants, and records the outcome in st.
//
// A session is its router and remote address. A wanted session already
// held by one of the topology's peers is updated in that peer, whatever the
// peer's name, so renaming the relationship or record that produces it
// never deletes the peer. Only a session no peer holds gets a new peer.
func (r *Reconciler) apply(ctx context.Context, snap *snapshot, plan Plan, st *status) error {
	topo := snap.topology
	byName := map[string]*networkv1alpha1.BGPPeer{}
	mine := map[key]*networkv1alpha1.BGPPeer{}
	foreign := map[key]*networkv1alpha1.BGPPeer{}
	for i := range snap.peers {
		p := &snap.peers[i]
		byName[p.Name] = p
		k, ok := peerKey(p)
		switch {
		case !ok:
		case !owned(topo, p):
			foreign[k] = p
		case mine[k] == nil && p.DeletionTimestamp.IsZero():
			mine[k] = p
		}
	}
	for _, o := range plan.Overlaps {
		st.conflict(fmt.Sprintf("%s and %s both peer router %s with %s", o.Kept, o.Dropped, o.Router, o.Address))
	}

	held, err := r.applySessions(ctx, plan, mine, foreign, byName, st)
	if err != nil {
		return err
	}
	return r.releaseUnwanted(ctx, snap, held, st)
}

// applySessions writes the plan's sessions: each is updated in the peer of
// the topology holding it, or created, unless a peer the topology did not
// generate is in its way. It returns the names of the peers holding wanted
// sessions.
func (r *Reconciler) applySessions(
	ctx context.Context, plan Plan, mine, foreign map[key]*networkv1alpha1.BGPPeer,
	byName map[string]*networkv1alpha1.BGPPeer, st *status,
) (map[string]bool, error) {
	held := map[string]bool{}
	for _, s := range plan.Sessions {
		want := s.Peer
		k, _ := peerKey(want)
		existing := mine[k]
		if existing != nil {
			// Even blocked, the session stays where it is.
			held[existing.Name] = true
		}
		switch other := foreign[k]; {
		case other != nil:
			st.conflict(fmt.Sprintf("BGPPeer %s, not generated by this topology, already peers router %s with %s",
				other.Name, want.Spec.RouterRef.Name, want.Spec.Address))
		case existing != nil:
			if err := r.update(ctx, existing, want); err != nil {
				return nil, err
			}
			st.generated++
		case byName[want.Name] != nil:
			st.conflict(fmt.Sprintf("BGPPeer %s exists for another session", want.Name))
		default:
			if err := r.Create(ctx, want); err != nil && !apierrors.IsAlreadyExists(err) {
				return nil, fmt.Errorf("create BGPPeer %s: %w", want.Name, err)
			}
			st.generated++
		}
	}
	return held, nil
}

// releaseUnwanted keeps or releases the topology's peers that hold no
// wanted session. A release because something is gone waits out the settle
// period, and none happens while the release guard holds.
func (r *Reconciler) releaseUnwanted(ctx context.Context, snap *snapshot, held map[string]bool, st *status) error {
	topo := snap.topology
	var releases []release
	owners := 0
	for i := range snap.peers {
		p := &snap.peers[i]
		if !owned(topo, p) || !p.DeletionTimestamp.IsZero() {
			continue
		}
		owners++
		if held[p.Name] {
			continue
		}
		why, absent, err := snap.released(ctx, p)
		if err != nil {
			return err
		}
		if why == "" {
			if err := r.migrate(ctx, topo, p); err != nil {
				return err
			}
			st.retained++
			continue
		}
		releases = append(releases, release{p, why, absent})
	}

	absent := 0
	for _, rel := range releases {
		if rel.absent {
			absent++
		}
	}
	// Absences are weighed together: every one still pending counts, so a
	// mass deletion arriving as a stream of events is held as a whole.
	hold := absent > minHeldReleases && 2*absent > owners
	settle := r.ReleaseSettle
	if settle <= 0 {
		settle = DefaultReleaseSettle
	}
	now := time.Now()
	for _, rel := range releases {
		if rel.absent {
			since, err := r.pendingSince(ctx, topo, rel.peer, now)
			if err != nil {
				return err
			}
			if wait := settle - now.Sub(since); hold || wait > 0 {
				if !hold && (st.requeue == 0 || wait < st.requeue) {
					st.requeue = wait
				}
				st.retained++
				continue
			}
		}
		log.FromContext(ctx).Info("releasing generated peer", "peer", rel.peer.Name, "reason", rel.why)
		uid := rel.peer.UID
		if err := r.Delete(ctx, rel.peer, client.Preconditions{UID: &uid}); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("delete BGPPeer %s: %w", rel.peer.Name, err)
		}
	}
	if hold {
		st.held = fmt.Sprintf("%d of the topology's %d peers would be released because their router or record "+
			"is gone; drain them explicitly to release them", absent, owners)
	}
	return nil
}

// pendingSince is when the peer's release on absence was first found,
// recording now on the peer, and migrating it, when it was not.
func (r *Reconciler) pendingSince(
	ctx context.Context, topo *networkv1alpha1.FabricTopology, p *networkv1alpha1.BGPPeer, now time.Time,
) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, p.Annotations[networkv1alpha1.AnnotationReleasePendingSince]); err == nil {
		return t, nil
	}
	next := p.DeepCopy()
	next.OwnerReferences = withoutOwner(p.OwnerReferences, topo.UID)
	if next.Annotations == nil {
		next.Annotations = map[string]string{}
	}
	next.Annotations[networkv1alpha1.AnnotationFabricTopologyUID] = string(topo.UID)
	next.Annotations[networkv1alpha1.AnnotationReleasePendingSince] = now.UTC().Format(time.RFC3339)
	if err := r.Update(ctx, next); err != nil {
		return now, fmt.Errorf("mark BGPPeer %s pending release: %w", p.Name, err)
	}
	return now, nil
}

// update makes existing match want's spec, labels and annotations, drops
// any owner reference to the topology, and writes only when something
// differs. The peer keeps its name.
func (r *Reconciler) update(ctx context.Context, existing, want *networkv1alpha1.BGPPeer) error {
	next := existing.DeepCopy()
	next.Spec = want.Spec
	next.Labels = merged(existing.Labels, want.Labels, generatedLabels)
	next.Annotations = merged(existing.Annotations, want.Annotations, generatedAnnotations)
	if uid := want.Annotations[networkv1alpha1.AnnotationFabricTopologyUID]; uid != "" {
		next.OwnerReferences = withoutOwner(existing.OwnerReferences, types.UID(uid))
	}
	if equality.Semantic.DeepEqual(existing.Spec, next.Spec) &&
		equality.Semantic.DeepEqual(existing.Labels, next.Labels) &&
		equality.Semantic.DeepEqual(existing.Annotations, next.Annotations) &&
		equality.Semantic.DeepEqual(existing.OwnerReferences, next.OwnerReferences) {
		return nil
	}
	if err := r.Update(ctx, next); err != nil {
		return fmt.Errorf("update BGPPeer %s: %w", existing.Name, err)
	}
	return nil
}

// migrate moves a retained peer of an earlier controller version from a
// controller reference to the UID annotation, and clears a pending release
// whose absence ended, leaving its spec alone.
func (r *Reconciler) migrate(
	ctx context.Context, topo *networkv1alpha1.FabricTopology, p *networkv1alpha1.BGPPeer,
) error {
	next := p.DeepCopy()
	next.OwnerReferences = withoutOwner(p.OwnerReferences, topo.UID)
	if next.Annotations == nil {
		next.Annotations = map[string]string{}
	}
	next.Annotations[networkv1alpha1.AnnotationFabricTopologyUID] = string(topo.UID)
	delete(next.Annotations, networkv1alpha1.AnnotationReleasePendingSince)
	if equality.Semantic.DeepEqual(p.OwnerReferences, next.OwnerReferences) &&
		equality.Semantic.DeepEqual(p.Annotations, next.Annotations) {
		return nil
	}
	if err := r.Update(ctx, next); err != nil {
		return fmt.Errorf("migrate BGPPeer %s: %w", p.Name, err)
	}
	return nil
}

var (
	generatedLabels = []string{networkv1alpha1.LabelManagedBy, networkv1alpha1.LabelFabricTopology,
		networkv1alpha1.LabelPeerFailureDomain, networkv1alpha1.LabelPeerCell}
	generatedAnnotations = []string{networkv1alpha1.AnnotationRelationship, networkv1alpha1.AnnotationLocalEndpoint,
		networkv1alpha1.AnnotationRemoteEndpoint, networkv1alpha1.AnnotationRemoteEndpointUID,
		networkv1alpha1.AnnotationRemoteRouter, networkv1alpha1.AnnotationFabricTopologyUID,
		networkv1alpha1.AnnotationReleasePendingSince}
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

// released says why a generated peer the topology no longer wants may be
// deleted, or returns empty when it must be kept, and whether the reason is
// that something is gone. A session is released only on evidence that one
// of its ends is out of service:
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
// An absence seen in the cache is confirmed with the API server first. A
// record that still exists but no longer matches, a member that left the
// selector, or an endpoint of this cell deleted while its router still runs,
// keeps the session until one of those holds.
func (s *snapshot) released(ctx context.Context, p *networkv1alpha1.BGPPeer) (string, bool, error) {
	if p.Spec.RouterRef == nil {
		return "", false, nil
	}
	topo := s.topology
	local := p.Spec.RouterRef.Name
	if why, absent, err := s.routerOut(ctx, local); why != "" || err != nil {
		return "local router " + local + " " + why, absent, err
	}
	for _, ann := range []string{networkv1alpha1.AnnotationLocalEndpoint, networkv1alpha1.AnnotationRemoteEndpoint} {
		if ep := p.Annotations[ann]; ep != "" && s.drainedEndpoint(ep) {
			return "endpoint " + ep + " is drained", false, nil
		}
	}
	kind, name, _ := strings.Cut(p.Annotations[networkv1alpha1.AnnotationRelationship], "/")
	if kind == KindExternal {
		if !externalListed(topo, name, p.Spec.Address) {
			return "external peer " + p.Spec.Address + " is no longer in relationship " + name, false, nil
		}
		return "", false, nil
	}
	remoteEP := p.Annotations[networkv1alpha1.AnnotationRemoteEndpoint]
	if p.Labels[networkv1alpha1.LabelPeerCell] == topo.Spec.Cell {
		remote := p.Annotations[networkv1alpha1.AnnotationRemoteRouter]
		why, absent, err := s.routerOut(ctx, remote)
		if why != "" {
			why = "remote router " + remote + " " + why
		}
		return why, absent, err
	}
	uid := p.Annotations[networkv1alpha1.AnnotationRemoteEndpointUID]
	if ep := s.endpoints[remoteEP]; ep != nil && string(ep.Endpoint.UID) == uid {
		return "", false, nil
	}
	gone, err := s.confirmGone(ctx, &networkv1alpha1.FabricEndpoint{}, remoteEP, uid)
	if err != nil || !gone {
		return "", false, err
	}
	return "endpoint record " + remoteEP + " was deleted", true, nil
}

// routerOut says how a router of this cell is out of service, or returns
// empty while it may still be running, and whether the reason is that it
// is gone.
func (s *snapshot) routerOut(ctx context.Context, name string) (string, bool, error) {
	if d := s.topology.Spec.Drain; d != nil {
		for _, r := range d.Routers {
			if r.Name == name {
				return "is drained", false, nil
			}
		}
	}
	router := s.routers[name]
	if router == nil {
		gone, err := s.confirmGone(ctx, &networkv1alpha1.BGPRouter{}, name, "")
		if err != nil || !gone {
			return "", false, err
		}
		return "is deleted", true, nil
	}
	dep := s.deployments[name]
	if dep != nil && dep.Spec.RouterRef.UID == string(router.UID) && retired(dep) {
		return "is retired", false, nil
	}
	return "", false, nil
}

// confirmGone reads the named object from the API server, around the
// cache: it is gone when it does not exist, or exists with another UID
// than uid when uid is set. Without a reader the cache's absence stands.
func (s *snapshot) confirmGone(ctx context.Context, obj client.Object, name, uid string) (bool, error) {
	if s.reader == nil {
		return true, nil
	}
	err := s.reader.Get(ctx, types.NamespacedName{Namespace: s.topology.Namespace, Name: name}, obj)
	switch {
	case apierrors.IsNotFound(err):
		return true, nil
	case err != nil:
		return false, err
	}
	return uid != "" && string(obj.GetUID()) != uid, nil
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
	acceptReason, acceptMessage        string
	unresolved                         []string
	conflicts                          []string
	missing                            []string
	held                               string
	requeue                            time.Duration
	members, generated                 int32
	retained                           int32
	recordsDigest, relationshipsDigest string
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
	if st.held == "" {
		set(networkv1alpha1.FabricTopologyConditionReleaseHeld, false, networkv1alpha1.FabricTopologyReasonNothingHeld,
			"no release is held")
	} else {
		set(networkv1alpha1.FabricTopologyConditionReleaseHeld, true, networkv1alpha1.FabricTopologyReasonReleaseHeld,
			st.held)
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
	case st.held != "":
		set(networkv1alpha1.ConditionTypeReady, false, networkv1alpha1.FabricTopologyReasonReleaseHeld, st.held)
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
	if st.recordsDigest != "" {
		topo.Status.RecordsDigest, topo.Status.RelationshipsDigest = st.recordsDigest, st.relationshipsDigest
	}
	if equality.Semantic.DeepEqual(before.Status, topo.Status) {
		return nil
	}
	return r.Status().Patch(ctx, topo, client.MergeFrom(before))
}

// SetupWithManager reconciles a namespace's topologies when the topology,
// or anything it reads, changes: endpoints, routers, peers (its own, or a
// hand-authored one that may conflict), profiles, policies, deployments
// (retirement), and the failure-domain labels of Nodes.
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
