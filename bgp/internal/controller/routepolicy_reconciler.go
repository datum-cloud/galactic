package controller

import (
	"context"
	"fmt"
	"log"

	gobgpapi "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bgpv1alpha1 "go.miloapis.com/bgp/api/v1alpha1"
)

const (
	// RoutePolicyFinalizer ensures GoBGP policy cleanup before CRD deletion.
	RoutePolicyFinalizer = "bgp.miloapis.com/routepolicy-cleanup"

	// BGPRoutePolicyApplied is the condition type indicating policy application state.
	BGPRoutePolicyApplied = "Applied"
)

// RoutePolicyReconciler reconciles BGPRoutePolicy resources into GoBGP policy calls.
// It maps the CRD's three-layer model (PrefixSets → Policies → PolicyAssignments)
// onto GoBGP's equivalent gRPC API.
type RoutePolicyReconciler struct {
	client.Client
	GoBGP *GoBGPClient
}

// Reconcile handles BGPRoutePolicy events.
func (r *RoutePolicyReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var policy bgpv1alpha1.BGPRoutePolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	c := r.GoBGP.Client()
	if c == nil {
		return ctrl.Result{}, fmt.Errorf("GoBGP not connected")
	}

	// Handle deletion.
	if !policy.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.handleDelete(ctx, c, &policy)
	}

	// Ensure finalizer.
	if !controllerutil.ContainsFinalizer(&policy, RoutePolicyFinalizer) {
		patch := client.MergeFrom(policy.DeepCopy())
		controllerutil.AddFinalizer(&policy, RoutePolicyFinalizer)
		if err := r.Patch(ctx, &policy, patch); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
		if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}

	// Step 1: Upsert DefinedSets (one PrefixSet per statement with prefixSet).
	if err := r.upsertDefinedSets(ctx, c, &policy); err != nil {
		return r.setAppliedFalse(ctx, &policy, fmt.Sprintf("upsert defined sets: %v", err))
	}

	// Step 2: Upsert the Policy.
	if err := r.upsertPolicy(ctx, c, &policy); err != nil {
		return r.setAppliedFalse(ctx, &policy, fmt.Sprintf("upsert policy: %v", err))
	}

	// Step 3: Resolve peer addresses if peerSelector is set.
	peerAddresses, err := r.resolvePeerAddresses(ctx, &policy)
	if err != nil {
		return r.setAppliedFalse(ctx, &policy, fmt.Sprintf("resolve peer addresses: %v", err))
	}

	// Step 4: Upsert PolicyAssignments.
	if err := r.upsertPolicyAssignments(ctx, c, &policy, peerAddresses); err != nil {
		return r.setAppliedFalse(ctx, &policy, fmt.Sprintf("upsert assignments: %v", err))
	}

	// Update status.
	statusPatch := client.MergeFrom(policy.DeepCopy())
	apimeta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               BGPRoutePolicyApplied,
		Status:             metav1.ConditionTrue,
		Reason:             "Applied",
		Message:            fmt.Sprintf("policy %s applied to GoBGP", gobgpPolicyName(policy.Name)),
		ObservedGeneration: policy.Generation,
	})
	if err := r.Status().Patch(ctx, &policy, statusPatch); err != nil {
		log.Printf("bgp/routepolicy: patch status: %v", err)
	}

	RecordRoutePolicyApplied(policy.Name, true)
	log.Printf("bgp/routepolicy: reconciled %s", policy.Name)
	return ctrl.Result{}, nil
}

// handleDelete removes all policy assignments, the policy, and its defined sets from GoBGP.
func (r *RoutePolicyReconciler) handleDelete(ctx context.Context, c gobgpapi.GobgpApiClient, policy *bgpv1alpha1.BGPRoutePolicy) error {
	if !controllerutil.ContainsFinalizer(policy, RoutePolicyFinalizer) {
		return nil
	}

	policyName := gobgpPolicyName(policy.Name)

	// Step 1: Delete all policy assignments for this policy.
	r.deleteAllAssignments(ctx, c, policy)

	// Step 2: Delete the policy.
	if _, err := c.DeletePolicy(ctx, &gobgpapi.DeletePolicyRequest{
		Policy:             &gobgpapi.Policy{Name: policyName},
		PreserveStatements: false,
		All:                false,
	}); err != nil && !isGoBGPNotFound(err) {
		log.Printf("bgp/routepolicy: delete policy %s: %v", policyName, err)
	}

	// Step 3: Delete each defined set.
	for i, stmt := range policy.Spec.Statements {
		if len(stmt.PrefixSet) == 0 {
			continue
		}
		setName := gobgpDefinedSetName(policy.Name, i)
		if _, err := c.DeleteDefinedSet(ctx, &gobgpapi.DeleteDefinedSetRequest{
			DefinedSet: &gobgpapi.DefinedSet{
				DefinedType: gobgpapi.DefinedType_PREFIX,
				Name:        setName,
			},
			All: false,
		}); err != nil && !isGoBGPNotFound(err) {
			log.Printf("bgp/routepolicy: delete defined set %s: %v", setName, err)
		}
	}

	RecordRoutePolicyApplied(policy.Name, false)

	patch := client.MergeFrom(policy.DeepCopy())
	controllerutil.RemoveFinalizer(policy, RoutePolicyFinalizer)
	return r.Patch(ctx, policy, patch)
}

// upsertDefinedSets creates or replaces the GoBGP PrefixSets for each statement.
func (r *RoutePolicyReconciler) upsertDefinedSets(ctx context.Context, c gobgpapi.GobgpApiClient, policy *bgpv1alpha1.BGPRoutePolicy) error {
	for i, stmt := range policy.Spec.Statements {
		if len(stmt.PrefixSet) == 0 {
			continue
		}

		setName := gobgpDefinedSetName(policy.Name, i)
		prefixes := make([]*gobgpapi.Prefix, 0, len(stmt.PrefixSet))
		for _, pm := range stmt.PrefixSet {
			gp := &gobgpapi.Prefix{IpPrefix: pm.CIDR}
			if pm.MaskLengthMin != nil {
				gp.MaskLengthMin = *pm.MaskLengthMin
			}
			if pm.MaskLengthMax != nil {
				gp.MaskLengthMax = *pm.MaskLengthMax
			}
			prefixes = append(prefixes, gp)
		}

		ds := &gobgpapi.DefinedSet{
			DefinedType: gobgpapi.DefinedType_PREFIX,
			Name:        setName,
			Prefixes:    prefixes,
		}

		// Try AddDefinedSet; if already exists, replace it.
		if _, err := c.AddDefinedSet(ctx, &gobgpapi.AddDefinedSetRequest{
			DefinedSet: ds,
			Replace:    true,
		}); err != nil {
			return fmt.Errorf("add/replace defined set %s: %w", setName, err)
		}
	}
	return nil
}

// upsertPolicy creates or replaces the GoBGP Policy.
// Per D2: an implicit Accept statement is always appended as the last statement.
func (r *RoutePolicyReconciler) upsertPolicy(ctx context.Context, c gobgpapi.GobgpApiClient, policy *bgpv1alpha1.BGPRoutePolicy) error {
	policyName := gobgpPolicyName(policy.Name)

	// +1 for the implicit final Accept statement (Decision D2).
	statements := make([]*gobgpapi.Statement, 0, len(policy.Spec.Statements)+1)
	for i, stmt := range policy.Spec.Statements {
		gStmt := &gobgpapi.Statement{}

		// Add prefix set condition if present.
		if len(stmt.PrefixSet) > 0 {
			setName := gobgpDefinedSetName(policy.Name, i)
			gStmt.Conditions = &gobgpapi.Conditions{
				PrefixSet: &gobgpapi.MatchSet{
					Name: setName,
					Type: gobgpapi.MatchSet_ANY,
				},
			}
		}

		// Set action.
		gStmt.Actions = &gobgpapi.Actions{}
		switch stmt.Action {
		case "Reject":
			gStmt.Actions.RouteAction = gobgpapi.RouteAction_REJECT
		default: // "Accept"
			gStmt.Actions.RouteAction = gobgpapi.RouteAction_ACCEPT
		}

		statements = append(statements, gStmt)
	}

	// D2: append implicit final Accept statement.
	statements = append(statements, &gobgpapi.Statement{
		Actions: &gobgpapi.Actions{
			RouteAction: gobgpapi.RouteAction_ACCEPT,
		},
	})

	gobgpPolicy := &gobgpapi.Policy{
		Name:       policyName,
		Statements: statements,
	}

	// Delete the existing policy first (if any) to allow clean replacement.
	if _, err := c.AddPolicy(ctx, &gobgpapi.AddPolicyRequest{
		Policy:                  gobgpPolicy,
		ReferExistingStatements: false,
	}); err != nil {
		// On already-exists: delete and re-add.
		if isGoBGPAlreadyExists(err) {
			if _, delErr := c.DeletePolicy(ctx, &gobgpapi.DeletePolicyRequest{
				Policy:             &gobgpapi.Policy{Name: policyName},
				PreserveStatements: false,
				All:                false,
			}); delErr != nil && !isGoBGPNotFound(delErr) {
				return fmt.Errorf("delete policy %s for re-add: %w", policyName, delErr)
			}
			if _, addErr := c.AddPolicy(ctx, &gobgpapi.AddPolicyRequest{
				Policy:                  gobgpPolicy,
				ReferExistingStatements: false,
			}); addErr != nil {
				return fmt.Errorf("re-add policy %s: %w", policyName, addErr)
			}
			return nil
		}
		return fmt.Errorf("add policy %s: %w", policyName, err)
	}
	return nil
}

// resolvePeerAddresses returns the remote endpoint addresses for sessions matching
// the policy's peerSelector. Returns nil when peerSelector is nil (global assignment).
func (r *RoutePolicyReconciler) resolvePeerAddresses(ctx context.Context, policy *bgpv1alpha1.BGPRoutePolicy) ([]string, error) {
	if policy.Spec.PeerSelector == nil {
		return nil, nil
	}

	sel, err := metav1.LabelSelectorAsSelector(policy.Spec.PeerSelector)
	if err != nil {
		return nil, fmt.Errorf("invalid peerSelector: %w", err)
	}

	var sessionList bgpv1alpha1.BGPSessionList
	if err := r.List(ctx, &sessionList); err != nil {
		return nil, fmt.Errorf("list BGPSessions: %w", err)
	}

	addresses := make([]string, 0, len(sessionList.Items))
	for _, sess := range sessionList.Items {
		if !sel.Matches(labels.Set(sess.Labels)) {
			continue
		}

		// Resolve the remote endpoint address.
		var remoteEP bgpv1alpha1.BGPEndpoint
		if err := r.Get(ctx, types.NamespacedName{Name: sess.Spec.RemoteEndpoint}, &remoteEP); err != nil {
			log.Printf("bgp/routepolicy: get remote endpoint %s for session %s: %v", sess.Spec.RemoteEndpoint, sess.Name, err)
			continue
		}
		addresses = append(addresses, remoteEP.Spec.Address)
	}

	return addresses, nil
}

// upsertPolicyAssignments reconciles the GoBGP PolicyAssignment set for this policy.
// When peerAddresses is nil (global policy), a single global assignment is created.
// When peerAddresses is non-nil (scoped policy), per-peer assignments are created.
func (r *RoutePolicyReconciler) upsertPolicyAssignments(ctx context.Context, c gobgpapi.GobgpApiClient, policy *bgpv1alpha1.BGPRoutePolicy, peerAddresses []string) error {
	policyName := gobgpPolicyName(policy.Name)
	direction := policyDirection(policy.Spec.Type)

	if peerAddresses == nil {
		// Global assignment.
		return r.addPolicyAssignment(ctx, c, policyName, direction, "")
	}

	// Per-peer assignments.
	for _, addr := range peerAddresses {
		if err := r.addPolicyAssignment(ctx, c, policyName, direction, addr); err != nil {
			log.Printf("bgp/routepolicy: assign policy %s to peer %s: %v", policyName, addr, err)
		}
	}
	return nil
}

// addPolicyAssignment calls GoBGP AddPolicyAssignment for either a global (peerAddr="")
// or per-peer assignment.
func (r *RoutePolicyReconciler) addPolicyAssignment(ctx context.Context, c gobgpapi.GobgpApiClient, policyName string, direction gobgpapi.PolicyDirection, peerAddr string) error {
	assignment := &gobgpapi.PolicyAssignment{
		Direction:     direction,
		DefaultAction: gobgpapi.RouteAction_ACCEPT,
		Policies:      []*gobgpapi.Policy{{Name: policyName}},
	}
	if peerAddr != "" {
		assignment.Name = peerAddr
	}

	if _, err := c.AddPolicyAssignment(ctx, &gobgpapi.AddPolicyAssignmentRequest{
		Assignment: assignment,
	}); err != nil && !isGoBGPAlreadyExists(err) {
		return fmt.Errorf("add policy assignment (peer=%q): %w", peerAddr, err)
	}
	return nil
}

// deleteAllAssignments removes all GoBGP PolicyAssignments for this policy.
// It lists existing assignments and deletes those referencing our policy name.
func (r *RoutePolicyReconciler) deleteAllAssignments(ctx context.Context, c gobgpapi.GobgpApiClient, policy *bgpv1alpha1.BGPRoutePolicy) {
	policyName := gobgpPolicyName(policy.Name)
	direction := policyDirection(policy.Spec.Type)

	// List all assignments in this direction via the streaming RPC.
	var assignments []*gobgpapi.PolicyAssignment
	stream, err := c.ListPolicyAssignment(ctx, &gobgpapi.ListPolicyAssignmentRequest{
		Direction: direction,
	})
	if err != nil {
		log.Printf("bgp/routepolicy: list policy assignments for %s: %v", policyName, err)
	} else {
		for {
			resp, err := stream.Recv()
			if err != nil {
				break
			}
			if resp.Assignment == nil {
				continue
			}
			for _, p := range resp.Assignment.Policies {
				if p.Name == policyName {
					assignments = append(assignments, resp.Assignment)
					break
				}
			}
		}
	}

	for _, a := range assignments {
		if _, err := c.DeletePolicyAssignment(ctx, &gobgpapi.DeletePolicyAssignmentRequest{
			Assignment: a,
			All:        false,
		}); err != nil && !isGoBGPNotFound(err) {
			log.Printf("bgp/routepolicy: delete assignment for %s: %v", policyName, err)
		}
	}
}

// setAppliedFalse sets the Applied condition to False and requeues.
func (r *RoutePolicyReconciler) setAppliedFalse(ctx context.Context, policy *bgpv1alpha1.BGPRoutePolicy, msg string) (reconcile.Result, error) {
	patch := client.MergeFrom(policy.DeepCopy())
	apimeta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               BGPRoutePolicyApplied,
		Status:             metav1.ConditionFalse,
		Reason:             "Error",
		Message:            msg,
		ObservedGeneration: policy.Generation,
	})
	if err := r.Status().Patch(ctx, policy, patch); err != nil {
		log.Printf("bgp/routepolicy: patch status: %v", err)
	}
	RecordRoutePolicyApplied(policy.Name, false)
	return ctrl.Result{}, fmt.Errorf("%s", msg)
}

// mapSessionToPolicies returns reconcile requests for BGPRoutePolicies with
// a non-nil peerSelector when a BGPSession changes.
func (r *RoutePolicyReconciler) mapSessionToPolicies(ctx context.Context, obj client.Object) []reconcile.Request {
	var policyList bgpv1alpha1.BGPRoutePolicyList
	if err := r.List(ctx, &policyList); err != nil {
		log.Printf("bgp/routepolicy: list BGPRoutePolicies for session change: %v", err)
		return nil
	}

	var requests []reconcile.Request
	for _, p := range policyList.Items {
		if p.Spec.PeerSelector != nil {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: p.Name},
			})
		}
	}
	return requests
}

// SetupWithManager registers the RoutePolicyReconciler with the controller-runtime manager.
func (r *RoutePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.BGPRoutePolicy{}).
		Watches(
			&bgpv1alpha1.BGPSession{},
			handler.EnqueueRequestsFromMapFunc(r.mapSessionToPolicies),
		).
		Complete(r)
}

// gobgpPolicyName returns the deterministic GoBGP policy name for a BGPRoutePolicy.
func gobgpPolicyName(policyName string) string {
	return "bgprp-" + policyName
}

// gobgpDefinedSetName returns the deterministic GoBGP DefinedSet name for a statement.
func gobgpDefinedSetName(policyName string, statementIndex int) string {
	return fmt.Sprintf("bgprp-%s-stmt%d", policyName, statementIndex)
}

// policyDirection maps the BGPRoutePolicy type string to a GoBGP PolicyDirection.
func policyDirection(policyType string) gobgpapi.PolicyDirection {
	switch policyType {
	case "Import":
		return gobgpapi.PolicyDirection_IMPORT
	default: // "Export"
		return gobgpapi.PolicyDirection_EXPORT
	}
}

// isGoBGPNotFound returns true for GoBGP "not found" errors.
func isGoBGPNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}

// isGoBGPAlreadyExists returns true for GoBGP "already exists" errors.
func isGoBGPAlreadyExists(err error) bool {
	return status.Code(err) == codes.AlreadyExists
}
