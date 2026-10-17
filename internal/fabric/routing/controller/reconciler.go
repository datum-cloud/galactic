// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package controller compiles every fabric-class BGPRouter into immutable
// FabricRouterRevisions. For each router it resolves the objects the
// configuration depends on, checks their generations did not move while it
// read them, creates the revision for the result if it does not exist, and
// reports the outcome on the router's status. It never writes FRR: the node
// agent activates revisions.
package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
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
	"go.datum.net/galactic/internal/fabric/routing/compile"
	"go.datum.net/galactic/internal/fabric/routing/revision"
)

const (
	// RouterLabel names the router on each of its revisions.
	RouterLabel = "galactic.datumapis.com/router"

	// KeepRevisions is how many revisions per router are kept.
	KeepRevisions = 10

	// ConditionResolvedRefs reports whether every referenced object exists.
	ConditionResolvedRefs = "ResolvedRefs"

	reasonCompiled         = "Compiled"
	reasonResolved         = "Resolved"
	reasonRevisionTooLarge = "RevisionTooLarge"
	reasonDuplicateID      = "DuplicateRouterID"
	reasonTargetNotFound   = "TargetNotFound"
	reasonRevisionInvalid  = "RevisionInvalid"

	// SequenceAnnotation records each revision's creation order, finer
	// than its one-second creation timestamp.
	SequenceAnnotation = "galactic.datumapis.com/revision-sequence"
)

// Reconciler compiles fabric routers into revisions.
type Reconciler struct {
	client.Client
	// APIReader reads around the cache, for the generation re-check.
	APIReader client.Reader
}

// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=bgprouters,verbs=get;list;watch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=bgprouters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=bgprouterclasses;frrrouterparameters,verbs=get;list;watch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=bgppeers;bgppeerprofiles;bgppolicies;bgpprefixlists;bgpcommunitysets;bgpadvertisements;bgpstaticroutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=fabricrouterrevisions,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=fabricrouterdeployments,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile compiles one router.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	router := &networkv1alpha1.BGPRouter{}
	if err := r.Get(ctx, req.NamespacedName, router); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	class, mine, err := r.class(ctx, router)
	if err != nil || !mine {
		return ctrl.Result{}, err
	}

	in, err := r.resolve(ctx, router, class)
	if err != nil {
		return ctrl.Result{}, err
	}
	nodeUID, err := r.nodeUID(ctx, router.Spec.TargetRef.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	if nodeUID == "" {
		// A revision binds to the Node's UID; one for a missing Node would
		// be replaced the moment the Node appears.
		return ctrl.Result{}, r.refuse(ctx, router, reasonTargetNotFound,
			"Node "+router.Spec.TargetRef.Name+" does not exist", false)
	}
	rev, _, err := revision.Build(in, nodeUID)
	var refusal compile.RefusalError
	switch {
	case errors.As(err, &refusal):
		return ctrl.Result{}, r.refuseCompile(ctx, router, refusal)
	case errors.Is(err, revision.ErrTooLarge):
		return ctrl.Result{}, r.refuse(ctx, router, reasonRevisionTooLarge, err.Error(), true)
	case err != nil:
		return ctrl.Result{}, err
	}
	if holder, err := r.routerIDHolder(ctx, router); err != nil {
		return ctrl.Result{}, err
	} else if holder != "" {
		return ctrl.Result{}, r.refuse(ctx, router, reasonDuplicateID,
			fmt.Sprintf("router ID %s is already BGPRouter %s's", router.Spec.RouterID, holder), true)
	}

	// Inputs read from the cache may lag; the revision only stands if every
	// input still has the generation it was compiled from. An object that
	// becomes an input during the compile (a new peer, a re-pointed
	// reference) arrives as its own watch event and compiles again.
	if moved, err := r.inputsMoved(ctx, router.Namespace, rev.Spec.Inputs); err != nil {
		return ctrl.Result{}, err
	} else if moved != "" {
		log.FromContext(ctx).V(1).Info("input changed during compile, retrying", "input", moved)
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	if err := r.ensureRevision(ctx, router, rev); err != nil {
		var invalid *revisionInvalidError
		if errors.As(err, &invalid) {
			return ctrl.Result{}, r.refuse(ctx, router, reasonRevisionInvalid, invalid.Error(), true)
		}
		return ctrl.Result{}, err
	}
	if err := r.accept(ctx, router, rev); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.prune(ctx, router, rev.Name)
}

// class returns the router's class and whether this controller owns it.
func (r *Reconciler) class(
	ctx context.Context, router *networkv1alpha1.BGPRouter,
) (*networkv1alpha1.BGPRouterClass, bool, error) {
	if router.Spec.RouterClassName == nil {
		return nil, false, nil
	}
	class := &networkv1alpha1.BGPRouterClass{}
	err := r.Get(ctx, types.NamespacedName{Name: *router.Spec.RouterClassName}, class)
	if apierrors.IsNotFound(err) {
		// A router naming no existing class is owned by nobody.
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return class, class.Spec.ControllerName == networkv1alpha1.FabricRouterControllerName, nil
}

// resolve gathers everything the router's configuration can depend on.
func (r *Reconciler) resolve(
	ctx context.Context, router *networkv1alpha1.BGPRouter, class *networkv1alpha1.BGPRouterClass,
) (compile.Input, error) {
	in := compile.Input{Router: router, Class: class}
	if ref := class.Spec.ParametersRef; ref != nil && ref.Kind == networkv1alpha1.FRRRouterParametersKind &&
		ref.Group == networkv1alpha1.GroupVersion.Group {
		params := &networkv1alpha1.FRRRouterParameters{}
		if err := r.Get(ctx, types.NamespacedName{Name: ref.Name}, params); err == nil {
			in.Parameters = params
		} else if !apierrors.IsNotFound(err) {
			return in, err
		}
	}
	ns := client.InNamespace(router.Namespace)

	peers := &networkv1alpha1.BGPPeerList{}
	if err := r.List(ctx, peers, ns); err != nil {
		return in, err
	}
	for _, p := range peers.Items {
		if p.Spec.RouterRef != nil && p.Spec.RouterRef.Name == router.Name {
			in.Peers = append(in.Peers, p)
		}
	}
	advs := &networkv1alpha1.BGPAdvertisementList{}
	if err := r.List(ctx, advs, ns); err != nil {
		return in, err
	}
	for _, a := range advs.Items {
		if a.Spec.RouterRef.Name == router.Name {
			in.Advertisements = append(in.Advertisements, a)
		}
	}
	statics := &networkv1alpha1.BGPStaticRouteList{}
	if err := r.List(ctx, statics, ns); err != nil {
		return in, err
	}
	for _, s := range statics.Items {
		if s.Spec.RouterRef.Name == router.Name {
			in.StaticRoutes = append(in.StaticRoutes, s)
		}
	}

	var err error
	if in.Profiles, err = listByName(ctx, r.Client, ns, &networkv1alpha1.BGPPeerProfileList{},
		func(l *networkv1alpha1.BGPPeerProfileList) []networkv1alpha1.BGPPeerProfile { return l.Items }); err != nil {
		return in, err
	}
	if in.Policies, err = listByName(ctx, r.Client, ns, &networkv1alpha1.BGPPolicyList{},
		func(l *networkv1alpha1.BGPPolicyList) []networkv1alpha1.BGPPolicy { return l.Items }); err != nil {
		return in, err
	}
	if in.PrefixLists, err = listByName(ctx, r.Client, ns, &networkv1alpha1.BGPPrefixListList{},
		func(l *networkv1alpha1.BGPPrefixListList) []networkv1alpha1.BGPPrefixList { return l.Items }); err != nil {
		return in, err
	}
	in.CommunitySets, err = listByName(ctx, r.Client, ns, &networkv1alpha1.BGPCommunitySetList{},
		func(l *networkv1alpha1.BGPCommunitySetList) []networkv1alpha1.BGPCommunitySet { return l.Items })
	return in, err
}

func listByName[L client.ObjectList, T any, PT interface {
	*T
	client.Object
}](ctx context.Context, c client.Reader, ns client.ListOption, list L, items func(L) []T) (map[string]PT, error) {
	if err := c.List(ctx, list, ns); err != nil {
		return nil, err
	}
	all := items(list)
	out := make(map[string]PT, len(all))
	for i := range all {
		o := PT(&all[i])
		out[o.GetName()] = o
	}
	return out, nil
}

// routerIDHolder names another router of the same class in the namespace
// that holds this router's ID, if there is one. A router holds an ID when
// its latest revision runs with it; between two routers that both or
// neither run it, the older one holds it. A newcomer, or a router edited to
// take a running router's ID, therefore never takes that router offline.
func (r *Reconciler) routerIDHolder(ctx context.Context, router *networkv1alpha1.BGPRouter) (string, error) {
	routers := &networkv1alpha1.BGPRouterList{}
	if err := r.List(ctx, routers, client.InNamespace(router.Namespace)); err != nil {
		return "", err
	}
	id := router.Spec.RouterID
	mine, err := r.runningID(ctx, router)
	if err != nil {
		return "", err
	}
	for i := range routers.Items {
		other := &routers.Items[i]
		if other.Name == router.Name || other.Spec.RouterClassName == nil ||
			*other.Spec.RouterClassName != *router.Spec.RouterClassName {
			continue
		}
		theirs, err := r.runningID(ctx, other)
		if err != nil {
			return "", err
		}
		otherRuns, iRun := theirs == id, mine == id
		switch {
		case otherRuns && !iRun:
			return other.Name, nil
		case other.Spec.RouterID != id && !otherRuns:
			// No conflict: the other router neither wants nor runs the ID.
		case otherRuns == iRun && older(other, router):
			return other.Name, nil
		}
	}
	return "", nil
}

// runningID is the router ID of the router's latest revision, or empty when
// it has none.
func (r *Reconciler) runningID(ctx context.Context, router *networkv1alpha1.BGPRouter) (string, error) {
	if router.Status.Fabric == nil || router.Status.Fabric.LatestRevision == "" {
		return "", nil
	}
	rev := &networkv1alpha1.FabricRouterRevision{}
	err := r.Get(ctx, types.NamespacedName{Namespace: router.Namespace, Name: router.Status.Fabric.LatestRevision}, rev)
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return rev.Spec.Configuration.Router.RouterID, nil
}

func older(a, b *networkv1alpha1.BGPRouter) bool {
	if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
		return a.CreationTimestamp.Before(&b.CreationTimestamp)
	}
	return a.Name < b.Name
}

// nodeUID reads the Node from the API server, since its UID is part of the
// revision's identity. It is empty when the Node does not exist.
func (r *Reconciler) nodeUID(ctx context.Context, name string) (string, error) {
	node := &metav1.PartialObjectMetadata{}
	node.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Node"))
	err := r.APIReader.Get(ctx, types.NamespacedName{Name: name}, node)
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	return string(node.UID), err
}

// inputsMoved re-reads each input from the API server and names the first
// whose generation differs from the one compiled.
func (r *Reconciler) inputsMoved(
	ctx context.Context, namespace string, inputs []networkv1alpha1.FabricRevisionInput,
) (string, error) {
	for _, in := range inputs {
		obj, clusterScoped := newObject(in.Kind)
		if obj == nil {
			return "", fmt.Errorf("unknown input kind %s", in.Kind)
		}
		key := types.NamespacedName{Namespace: namespace, Name: in.Name}
		if clusterScoped {
			key.Namespace = ""
		}
		err := r.APIReader.Get(ctx, key, obj)
		switch {
		case apierrors.IsNotFound(err):
			return in.Kind + "/" + in.Name, nil
		case err != nil:
			return "", err
		case obj.GetGeneration() != in.Generation || string(obj.GetUID()) != in.UID:
			return in.Kind + "/" + in.Name, nil
		}
	}
	return "", nil
}

func newObject(kind string) (client.Object, bool) {
	switch kind {
	case "BGPRouter":
		return &networkv1alpha1.BGPRouter{}, false
	case "BGPRouterClass":
		return &networkv1alpha1.BGPRouterClass{}, true
	case networkv1alpha1.FRRRouterParametersKind:
		return &networkv1alpha1.FRRRouterParameters{}, true
	case "BGPPeer":
		return &networkv1alpha1.BGPPeer{}, false
	case "BGPPeerProfile":
		return &networkv1alpha1.BGPPeerProfile{}, false
	case "BGPPolicy":
		return &networkv1alpha1.BGPPolicy{}, false
	case "BGPPrefixList":
		return &networkv1alpha1.BGPPrefixList{}, false
	case "BGPCommunitySet":
		return &networkv1alpha1.BGPCommunitySet{}, false
	case "BGPAdvertisement":
		return &networkv1alpha1.BGPAdvertisement{}, false
	case "BGPStaticRoute":
		return &networkv1alpha1.BGPStaticRoute{}, false
	}
	return nil, false
}

// revisionInvalidError is a revision the API server refused as written,
// which retrying cannot fix.
type revisionInvalidError struct{ err error }

func (e *revisionInvalidError) Error() string {
	return "the API server refused the revision: " + e.err.Error()
}
func (e *revisionInvalidError) Unwrap() error { return e.err }

// ensureRevision creates rev if it does not exist. An existing revision of
// the same name must carry the same three digests. It cannot differ unless
// the compiler's output changed without a semantics version bump, which the
// golden digest test exists to prevent; the router then reports
// RevisionInvalid until the stale revision is deleted.
func (r *Reconciler) ensureRevision(
	ctx context.Context, router *networkv1alpha1.BGPRouter, rev *networkv1alpha1.FabricRouterRevision,
) error {
	existing := &networkv1alpha1.FabricRouterRevision{}
	err := r.Get(ctx, client.ObjectKeyFromObject(rev), existing)
	if err == nil {
		e, w := existing.Spec, rev.Spec
		if e.ActivationDependencyDigest != w.ActivationDependencyDigest || e.SemanticsDigest != w.SemanticsDigest ||
			e.RenderedDigest != w.RenderedDigest {
			return &revisionInvalidError{fmt.Errorf("revision %s exists with other digests", rev.Name)}
		}
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	rev.Labels = map[string]string{RouterLabel: router.Name}
	rev.Annotations = map[string]string{SequenceAnnotation: strconv.FormatInt(time.Now().UnixNano(), 10)}
	if err := controllerutil.SetControllerReference(router, rev, r.Scheme()); err != nil {
		return err
	}
	err = r.Create(ctx, rev)
	switch {
	case apierrors.IsInvalid(err):
		return &revisionInvalidError{err}
	case err != nil && !apierrors.IsAlreadyExists(err):
		return err
	}
	return nil
}

// prune deletes all but the newest KeepRevisions revisions this router
// controls, never the latest, ordered by the creation sequence the
// controller records.
//
// A revision a FabricRouterDeployment names as its active, candidate or
// recovery target is always kept, so a node can resume or recover to it.
func (r *Reconciler) prune(ctx context.Context, router *networkv1alpha1.BGPRouter, latest string) error {
	revs := &networkv1alpha1.FabricRouterRevisionList{}
	if err := r.List(ctx, revs, client.InNamespace(router.Namespace),
		client.MatchingLabels{RouterLabel: router.Name}); err != nil {
		return err
	}
	var items []networkv1alpha1.FabricRouterRevision
	for _, rev := range revs.Items {
		if metav1.IsControlledBy(&rev, router) {
			items = append(items, rev)
		}
	}
	inUse, err := r.deployed(ctx, router)
	if err != nil {
		return err
	}
	sort.SliceStable(items, func(i, j int) bool { return sequence(&items[i]) > sequence(&items[j]) })
	kept := 0
	for i := range items {
		if items[i].Name == latest || inUse[items[i].Name] {
			continue
		}
		if kept < KeepRevisions-1 {
			kept++
			continue
		}
		if err := r.Delete(ctx, &items[i]); client.IgnoreNotFound(err) != nil {
			return err
		}
	}
	return nil
}

// deployed names the revisions the router's deployments refer to.
func (r *Reconciler) deployed(ctx context.Context, router *networkv1alpha1.BGPRouter) (map[string]bool, error) {
	deps := &networkv1alpha1.FabricRouterDeploymentList{}
	if err := r.List(ctx, deps, client.InNamespace(router.Namespace)); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, d := range deps.Items {
		if d.Spec.RouterRef.Name != router.Name {
			continue
		}
		for _, ref := range []*networkv1alpha1.LocalObjectRef{d.Spec.ActiveRevisionRef, d.Spec.CandidateRevisionRef} {
			if ref != nil {
				out[ref.Name] = true
			}
		}
		if rec := d.Spec.Recovery; rec != nil && rec.TargetRevisionRef != nil {
			out[rec.TargetRevisionRef.Name] = true
		}
	}
	return out, nil
}

// sequence is a revision's creation order: the controller's annotation, or
// its creation time when the annotation is missing.
func sequence(rev *networkv1alpha1.FabricRouterRevision) int64 {
	if n, err := strconv.ParseInt(rev.Annotations[SequenceAnnotation], 10, 64); err == nil {
		return n
	}
	return rev.CreationTimestamp.UnixNano()
}

func (r *Reconciler) accept(
	ctx context.Context, router *networkv1alpha1.BGPRouter, rev *networkv1alpha1.FabricRouterRevision,
) error {
	before := router.DeepCopy()
	gen := router.Generation
	meta.SetStatusCondition(&router.Status.Conditions, metav1.Condition{
		Type: networkv1alpha1.ConditionTypeAccepted, Status: metav1.ConditionTrue, ObservedGeneration: gen,
		Reason: reasonCompiled, Message: "compiled; status.fabric names the revision",
	})
	meta.SetStatusCondition(&router.Status.Conditions, metav1.Condition{
		Type: ConditionResolvedRefs, Status: metav1.ConditionTrue, ObservedGeneration: gen,
		Reason: reasonResolved, Message: "every referenced object exists",
	})
	router.Status.ObservedGeneration = gen
	router.Status.Fabric = &networkv1alpha1.BGPRouterFabricStatus{
		LatestRevision:             rev.Name,
		ActivationDependencyDigest: rev.Spec.ActivationDependencyDigest,
		RenderedDigest:             rev.Spec.RenderedDigest,
	}
	return r.patchStatus(ctx, before, router)
}

// refuseCompile reports a compile refusal. An unresolved reference is a
// ResolvedRefs problem; anything else means the router is not accepted.
func (r *Reconciler) refuseCompile(
	ctx context.Context, router *networkv1alpha1.BGPRouter, refusal compile.RefusalError,
) error {
	// The problems are sorted; the first names the reason, unless any
	// reference is unresolved, which outranks the rest.
	reason, unresolved := string(refusal[0].Reason), refusal.Has(compile.ReasonUnresolvedRef)
	msg := refusal.Error()
	if len(msg) > 1024 {
		msg = msg[:1021] + "..."
	}
	if unresolved {
		return r.refuse(ctx, router, string(compile.ReasonUnresolvedRef), msg, false)
	}
	return r.refuse(ctx, router, reason, msg, true)
}

// refuse records why the router has no new revision: Accepted is false
// with reason and message, and ResolvedRefs is false too when resolved is
// false. The last accepted revision stays in status, since the router keeps
// running it.
func (r *Reconciler) refuse(
	ctx context.Context, router *networkv1alpha1.BGPRouter, reason, message string, resolved bool,
) error {
	before := router.DeepCopy()
	gen := router.Generation
	meta.SetStatusCondition(&router.Status.Conditions, metav1.Condition{
		Type: networkv1alpha1.ConditionTypeAccepted, Status: metav1.ConditionFalse, ObservedGeneration: gen,
		Reason: reason, Message: message,
	})
	refs := metav1.Condition{
		Type: ConditionResolvedRefs, Status: metav1.ConditionTrue, ObservedGeneration: gen,
		Reason: reasonResolved, Message: "every referenced object exists",
	}
	if !resolved {
		refs.Status, refs.Reason, refs.Message = metav1.ConditionFalse, reason, message
	}
	meta.SetStatusCondition(&router.Status.Conditions, refs)
	router.Status.ObservedGeneration = gen
	return r.patchStatus(ctx, before, router)
}

// patchStatus writes the router's status when it changed. Conditions keep
// their transition time when their status is unchanged, so a reconcile that
// finds nothing new writes nothing.
func (r *Reconciler) patchStatus(ctx context.Context, before, router *networkv1alpha1.BGPRouter) error {
	if equality.Semantic.DeepEqual(before.Status, router.Status) {
		return nil
	}
	return r.Status().Patch(ctx, router, client.MergeFrom(before))
}

// SetupWithManager watches fabric routers, the revisions they control, and
// every kind their configuration reads. A change to a shared definition, or
// to any router (whose router ID another router may share), requeues the
// classed routers of its namespace; a class or parameter change requeues
// every classed router; a Node appearing or going requeues the routers on it.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	namespaceRouters := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		return r.classedRouters(ctx, func(*networkv1alpha1.BGPRouter) bool { return true },
			client.InNamespace(o.GetNamespace()))
	})
	allRouters := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
		return r.classedRouters(ctx, func(*networkv1alpha1.BGPRouter) bool { return true })
	})
	nodeRouters := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		return r.classedRouters(ctx, func(rt *networkv1alpha1.BGPRouter) bool {
			return rt.Spec.TargetRef.Name == o.GetName()
		})
	})
	nodeLifecycle := predicate.Funcs{
		CreateFunc:  func(event.CreateEvent) bool { return true },
		DeleteFunc:  func(event.DeleteEvent) bool { return true },
		UpdateFunc:  func(e event.UpdateEvent) bool { return e.ObjectOld.GetUID() != e.ObjectNew.GetUID() },
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("fabric-router-revisions").
		For(&networkv1alpha1.BGPRouter{}).
		Owns(&networkv1alpha1.FabricRouterRevision{}).
		Watches(&networkv1alpha1.BGPRouter{}, namespaceRouters).
		Watches(&networkv1alpha1.BGPPeer{}, namespaceRouters).
		Watches(&networkv1alpha1.BGPPeerProfile{}, namespaceRouters).
		Watches(&networkv1alpha1.BGPPolicy{}, namespaceRouters).
		Watches(&networkv1alpha1.BGPPrefixList{}, namespaceRouters).
		Watches(&networkv1alpha1.BGPCommunitySet{}, namespaceRouters).
		Watches(&networkv1alpha1.BGPAdvertisement{}, namespaceRouters).
		Watches(&networkv1alpha1.BGPStaticRoute{}, namespaceRouters).
		Watches(&networkv1alpha1.BGPRouterClass{}, allRouters,
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&networkv1alpha1.FRRRouterParameters{}, allRouters,
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WatchesMetadata(&corev1.Node{}, nodeRouters, builder.WithPredicates(nodeLifecycle)).
		Complete(r)
}

func (r *Reconciler) classedRouters(
	ctx context.Context, match func(*networkv1alpha1.BGPRouter) bool, opts ...client.ListOption,
) []reconcile.Request {
	routers := &networkv1alpha1.BGPRouterList{}
	if err := r.List(ctx, routers, opts...); err != nil {
		log.FromContext(ctx).Error(err, "list BGPRouters to requeue")
		return nil
	}
	var out []reconcile.Request
	for _, router := range routers.Items {
		if router.Spec.RouterClassName != nil && match(&router) {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&router)})
		}
	}
	return out
}
