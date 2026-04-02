package controller

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bgpv1alpha1 "go.miloapis.com/bgp/api/v1alpha1"
)

// PeeringPolicyReconciler reconciles BGPPeeringPolicy resources by selecting
// BGPEndpoint objects and creating BGPSession resources for every pair (mesh mode).
// It also watches BGPEndpoint events to re-reconcile policies when endpoints change.
//
// Because the operator runs as a DaemonSet, multiple pods reconcile the same
// BGPPeeringPolicy resources concurrently. This is safe because:
//   - Session creation uses errors.IsAlreadyExists to handle concurrent creates.
//   - Session GC only deletes sessions whose names are not in the computed desired
//     set, and all pods compute identical desired sets from the same policy spec.
//   - Status patches may conflict; conflicts cause a requeue and eventual convergence.
type PeeringPolicyReconciler struct {
	client.Client
}

// Reconcile handles BGPPeeringPolicy events.
// For "mesh" mode, it creates a BGPSession for every unique pair of matching endpoints
// and removes sessions that no longer correspond to a valid pair.
func (r *PeeringPolicyReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	log.Printf("bgp/policy: Reconcile %s", req.Name)

	var policy bgpv1alpha1.BGPPeeringPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		// Policy deleted — owned sessions are garbage collected via owner references.
		return ctrl.Result{}, nil
	}

	if policy.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}

	// Select matching endpoints.
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("invalid selector: %w", err)
	}

	var endpointList bgpv1alpha1.BGPEndpointList
	if err := r.List(ctx, &endpointList, &client.ListOptions{LabelSelector: selector}); err != nil {
		return ctrl.Result{}, fmt.Errorf("list BGPEndpoints: %w", err)
	}

	endpoints := endpointList.Items
	desiredSessions, configErr := r.computeDesiredSessions(&policy, endpoints)

	// Surface configuration errors as a status condition.
	if configErr != nil {
		statusPatch := client.MergeFrom(policy.DeepCopy())
		apimeta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               bgpv1alpha1.BGPPeeringPolicyInvalidConfig,
			Status:             metav1.ConditionTrue,
			Reason:             "InvalidConfig",
			Message:            configErr.Error(),
			ObservedGeneration: policy.Generation,
		})
		if err := r.Status().Patch(ctx, &policy, statusPatch); err != nil {
			return ctrl.Result{}, fmt.Errorf("patch policy status (InvalidConfig): %w", err)
		}
		return ctrl.Result{}, configErr
	}

	// Clear any pre-existing InvalidConfig condition on success.
	if apimeta.FindStatusCondition(policy.Status.Conditions, bgpv1alpha1.BGPPeeringPolicyInvalidConfig) != nil {
		statusPatch := client.MergeFrom(policy.DeepCopy())
		apimeta.RemoveStatusCondition(&policy.Status.Conditions, bgpv1alpha1.BGPPeeringPolicyInvalidConfig)
		if err := r.Status().Patch(ctx, &policy, statusPatch); err != nil {
			return ctrl.Result{}, fmt.Errorf("patch policy status (clear InvalidConfig): %w", err)
		}
	}

	// Reconcile desired sessions: create any that are missing.
	created := 0
	for _, desired := range desiredSessions {
		var existing bgpv1alpha1.BGPSession
		err := r.Get(ctx, types.NamespacedName{Name: desired.Name}, &existing)
		if err != nil {
			if !errors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("get BGPSession %s: %w", desired.Name, err)
			}
			// Create the session.
			if createErr := r.Create(ctx, desired); createErr != nil && !errors.IsAlreadyExists(createErr) {
				return ctrl.Result{}, fmt.Errorf("create BGPSession %s: %w", desired.Name, createErr)
			}
			log.Printf("bgp/policy: created BGPSession %s (policy=%s)", desired.Name, policy.Name)
			created++
		}
		// Sessions owned by this policy are left as-is if they already exist —
		// the session reconciler manages GoBGP state.
	}

	// Garbage-collect sessions owned by this policy that no longer correspond to a valid pair.
	desiredNames := make(map[string]struct{}, len(desiredSessions))
	for _, s := range desiredSessions {
		desiredNames[s.Name] = struct{}{}
	}

	var ownedList bgpv1alpha1.BGPSessionList
	if err := r.List(ctx, &ownedList); err != nil {
		return ctrl.Result{}, fmt.Errorf("list BGPSessions: %w", err)
	}

	deleted := 0
	for i := range ownedList.Items {
		sess := &ownedList.Items[i]
		if !isOwnedByPolicy(sess, &policy) {
			continue
		}
		if _, wanted := desiredNames[sess.Name]; !wanted {
			if err := r.Delete(ctx, sess); err != nil && !errors.IsNotFound(err) {
				log.Printf("bgp/policy: delete stale BGPSession %s: %v", sess.Name, err)
			} else {
				log.Printf("bgp/policy: deleted stale BGPSession %s (policy=%s)", sess.Name, policy.Name)
				deleted++
			}
		}
	}

	// Update status.
	activeSessions := int32(len(desiredSessions))
	matchedEndpoints := int32(len(endpoints))
	if policy.Status.MatchedEndpoints != matchedEndpoints || policy.Status.ActiveSessions != activeSessions {
		statusPatch := client.MergeFrom(policy.DeepCopy())
		policy.Status.MatchedEndpoints = matchedEndpoints
		policy.Status.ActiveSessions = activeSessions
		if err := r.Status().Patch(ctx, &policy, statusPatch); err != nil {
			return ctrl.Result{}, fmt.Errorf("patch policy status: %w", err)
		}
	}

	if created > 0 || deleted > 0 {
		log.Printf("bgp/policy: reconciled %s: %d endpoints, %d sessions (+%d/-%d)",
			policy.Name, len(endpoints), activeSessions, created, deleted)
	}

	// If no endpoints matched, requeue quickly in case the informer cache had stale label
	// data at reconcile time (endpoint label updates that predated this policy's creation
	// cannot be retriggered via the endpoint watch). A short requeue ensures we catch up.
	if matchedEndpoints == 0 {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// Periodic requeue to pick up any missed endpoint label changes.
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

// computeDesiredSessions returns the set of BGPSession objects that should exist
// for the given policy and matched endpoints. Returns a non-nil error when the
// policy spec is invalid (e.g. route-reflector mode with no RR found).
func (r *PeeringPolicyReconciler) computeDesiredSessions(
	policy *bgpv1alpha1.BGPPeeringPolicy,
	endpoints []bgpv1alpha1.BGPEndpoint,
) ([]*bgpv1alpha1.BGPSession, error) {
	// Sort endpoints by name for deterministic pair ordering.
	sorted := make([]bgpv1alpha1.BGPEndpoint, len(endpoints))
	copy(sorted, endpoints)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	switch policy.Spec.Mode {
	case "route-reflector":
		return r.computeRRSessions(policy, sorted)
	default: // "mesh" and unset
		return r.computeMeshSessions(policy, sorted), nil
	}
}

// computeMeshSessions creates one BGPSession per unique (i, j) ordered pair.
func (r *PeeringPolicyReconciler) computeMeshSessions(
	policy *bgpv1alpha1.BGPPeeringPolicy,
	sorted []bgpv1alpha1.BGPEndpoint,
) []*bgpv1alpha1.BGPSession {
	var sessions []*bgpv1alpha1.BGPSession

	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			a := sorted[i].Name
			b := sorted[j].Name
			sessionName := "session-" + a + "-" + b

			sess := r.buildSession(policy, sessionName, a, b, nil)
			sessions = append(sessions, sess)
		}
	}

	return sessions
}

// computeRRSessions creates sessions only between the route reflector and each client.
// Returns an error if RouteReflectorConfig is nil, no RR is found, or multiple RRs match.
func (r *PeeringPolicyReconciler) computeRRSessions(
	policy *bgpv1alpha1.BGPPeeringPolicy,
	sorted []bgpv1alpha1.BGPEndpoint,
) ([]*bgpv1alpha1.BGPSession, error) {
	rrCfg := policy.Spec.RouteReflectorConfig
	if rrCfg == nil {
		return nil, fmt.Errorf("mode is route-reflector but routeReflectorConfig is not set")
	}

	reflectorSelector, err := metav1.LabelSelectorAsSelector(&rrCfg.ReflectorSelector)
	if err != nil {
		return nil, fmt.Errorf("invalid reflectorSelector: %w", err)
	}

	// Partition endpoints into RR and clients.
	var rrEndpoints []bgpv1alpha1.BGPEndpoint
	var clients []bgpv1alpha1.BGPEndpoint
	for _, ep := range sorted {
		if reflectorSelector.Matches(labels.Set(ep.Labels)) {
			rrEndpoints = append(rrEndpoints, ep)
		} else {
			clients = append(clients, ep)
		}
	}

	if len(rrEndpoints) == 0 {
		return nil, fmt.Errorf("route-reflector mode: reflectorSelector matched no BGPEndpoints")
	}
	if len(rrEndpoints) > 1 {
		names := make([]string, len(rrEndpoints))
		for i, ep := range rrEndpoints {
			names[i] = ep.Name
		}
		return nil, fmt.Errorf("route-reflector mode: reflectorSelector matched %d endpoints (%v); exactly one is required",
			len(rrEndpoints), names)
	}

	rr := rrEndpoints[0]
	rrConfig := &bgpv1alpha1.RouteReflectorConfig{ClusterID: rrCfg.ClusterID}

	sessions := make([]*bgpv1alpha1.BGPSession, 0, len(clients))
	for _, ep := range clients {
		// Ensure deterministic name: sort rr and client names alphabetically.
		a, b := rr.Name, ep.Name
		if a > b {
			a, b = b, a
		}
		sessionName := "session-" + a + "-" + b

		sess := r.buildSession(policy, sessionName, rr.Name, ep.Name, rrConfig)
		sessions = append(sessions, sess)
	}

	return sessions, nil
}

// buildSession constructs a BGPSession owned by the policy.
// rrConfig, when non-nil, is set on the session spec to mark the remote as an RR client.
func (r *PeeringPolicyReconciler) buildSession(
	policy *bgpv1alpha1.BGPPeeringPolicy,
	sessionName, local, remote string,
	rrConfig *bgpv1alpha1.RouteReflectorConfig,
) *bgpv1alpha1.BGPSession {
	sess := &bgpv1alpha1.BGPSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: sessionName,
			Labels: map[string]string{
				"bgp.miloapis.com/policy": policy.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(policy, bgpv1alpha1.GroupVersion.WithKind("BGPPeeringPolicy")),
			},
		},
		Spec: bgpv1alpha1.BGPSessionSpec{
			LocalEndpoint:  local,
			RemoteEndpoint: remote,
			RouteReflector: rrConfig,
		},
	}

	// Apply session template overrides if present.
	if t := policy.Spec.SessionTemplate; t != nil {
		if t.HoldTime > 0 {
			sess.Spec.HoldTime = t.HoldTime
		}
		if t.KeepaliveTime > 0 {
			sess.Spec.KeepaliveTime = t.KeepaliveTime
		}
	}

	return sess
}

// isOwnedByPolicy returns true when the session has an owner reference pointing
// to the given BGPPeeringPolicy.
func isOwnedByPolicy(session *bgpv1alpha1.BGPSession, policy *bgpv1alpha1.BGPPeeringPolicy) bool {
	for _, ref := range session.OwnerReferences {
		if ref.Kind == "BGPPeeringPolicy" && ref.Name == policy.Name && ref.UID == policy.UID {
			return true
		}
	}
	return false
}


// mapEndpointToPolicies returns reconcile requests for all BGPPeeringPolicies whose
// selector matches the given BGPEndpoint. Used to re-reconcile policies when endpoints change.
func (r *PeeringPolicyReconciler) mapEndpointToPolicies(ctx context.Context, obj client.Object) []reconcile.Request {
	endpoint, ok := obj.(*bgpv1alpha1.BGPEndpoint)
	if !ok {
		return nil
	}

	var policyList bgpv1alpha1.BGPPeeringPolicyList
	if err := r.List(ctx, &policyList); err != nil {
		log.Printf("bgp/policy: list BGPPeeringPolicies for endpoint %s: %v", endpoint.Name, err)
		return nil
	}

	var requests []reconcile.Request
	for _, policy := range policyList.Items {
		sel, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
		if err != nil {
			continue
		}
		if sel.Matches(labels.Set(endpoint.Labels)) {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: policy.Name},
			})
		}
	}
	return requests
}

// mapSessionToPolicies returns reconcile requests for the BGPPeeringPolicy that owns
// the given BGPSession. Used to re-reconcile the policy when a session is deleted so
// that the reconciler can immediately recreate it rather than waiting for the next
// RequeueAfter interval.
func (r *PeeringPolicyReconciler) mapSessionToPolicies(_ context.Context, obj client.Object) []reconcile.Request {
	session, ok := obj.(*bgpv1alpha1.BGPSession)
	if !ok {
		return nil
	}
	for _, ref := range session.OwnerReferences {
		if ref.Kind == "BGPPeeringPolicy" {
			return []reconcile.Request{
				{NamespacedName: types.NamespacedName{Name: ref.Name}},
			}
		}
	}
	return nil
}

// SetupWithManager registers the PeeringPolicyReconciler with the controller-runtime manager.
// It watches BGPPeeringPolicy, BGPEndpoint, and BGPSession resources.
func (r *PeeringPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.BGPPeeringPolicy{}).
		Watches(
			&bgpv1alpha1.BGPEndpoint{},
			handler.EnqueueRequestsFromMapFunc(r.mapEndpointToPolicies),
		).
		Watches(
			&bgpv1alpha1.BGPSession{},
			handler.EnqueueRequestsFromMapFunc(r.mapSessionToPolicies),
		).
		Complete(r)
}
