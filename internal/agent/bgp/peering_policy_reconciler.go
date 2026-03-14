package bgp

import (
	"context"
	"fmt"
	"log"
	"sort"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bgpv1alpha1 "go.datum.net/galactic/pkg/apis/bgp/v1alpha1"
)

// PeeringPolicyReconciler reconciles BGPPeeringPolicy resources by selecting
// BGPEndpoint objects and creating BGPSession resources for every pair (mesh mode).
// It also watches BGPEndpoint events to re-reconcile policies when endpoints change.
type PeeringPolicyReconciler struct {
	client.Client
}

// Reconcile handles BGPPeeringPolicy events.
// For "mesh" mode, it creates a BGPSession for every unique pair of matching endpoints
// and removes sessions that no longer correspond to a valid pair.
func (r *PeeringPolicyReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
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
	desiredSessions := r.computeDesiredSessions(&policy, endpoints)

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
	statusPatch := client.MergeFrom(policy.DeepCopy())
	policy.Status.MatchedEndpoints = int32(len(endpoints))
	policy.Status.ActiveSessions = activeSessions
	if err := r.Status().Patch(ctx, &policy, statusPatch); err != nil {
		log.Printf("bgp/policy: patch status: %v", err)
	}

	if created > 0 || deleted > 0 {
		log.Printf("bgp/policy: reconciled %s: %d endpoints, %d sessions (+%d/-%d)",
			policy.Name, len(endpoints), activeSessions, created, deleted)
	}

	return ctrl.Result{}, nil
}

// computeDesiredSessions returns the set of BGPSession objects that should exist
// for the given policy and matched endpoints. In mesh mode, one session per unique
// ordered pair (alphabetical) of distinct endpoints is created.
func (r *PeeringPolicyReconciler) computeDesiredSessions(
	policy *bgpv1alpha1.BGPPeeringPolicy,
	endpoints []bgpv1alpha1.BGPEndpoint,
) []*bgpv1alpha1.BGPSession {
	// Sort endpoints by name for deterministic pair ordering.
	sorted := make([]bgpv1alpha1.BGPEndpoint, len(endpoints))
	copy(sorted, endpoints)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	var sessions []*bgpv1alpha1.BGPSession

	// mesh: create one session per unique (i, j) pair where i < j.
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			a := sorted[i].Name
			b := sorted[j].Name
			// Names are already sorted (a < b), so the session name is deterministic.
			sessionName := "session-" + a + "-" + b

			sess := &bgpv1alpha1.BGPSession{
				ObjectMeta: metav1.ObjectMeta{
					Name: sessionName,
					Labels: map[string]string{
						"bgp.galactic.datumapis.com/policy": policy.Name,
					},
					OwnerReferences: []metav1.OwnerReference{
						*metav1.NewControllerRef(policy, bgpv1alpha1.GroupVersion.WithKind("BGPPeeringPolicy")),
					},
				},
				Spec: bgpv1alpha1.BGPSessionSpec{
					LocalEndpoint:  a,
					RemoteEndpoint: b,
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

			sessions = append(sessions, sess)
		}
	}

	return sessions
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

// SetupWithManager registers the PeeringPolicyReconciler with the controller-runtime manager.
// It watches both BGPPeeringPolicy and BGPEndpoint resources.
func (r *PeeringPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.BGPPeeringPolicy{}).
		Watches(
			&bgpv1alpha1.BGPEndpoint{},
			handler.EnqueueRequestsFromMapFunc(r.mapEndpointToPolicies),
		).
		Complete(r)
}
