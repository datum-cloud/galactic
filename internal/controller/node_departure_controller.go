// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// defaultNodeDepartureInterval is how often NodeDepartureReconciler sweeps
// when Interval is unset.
const defaultNodeDepartureInterval = 5 * time.Minute

// nodeDepartureRequest is the single key every NodeDepartureReconciler event
// maps to, so concurrent Node events collapse into one sweep.
var nodeDepartureRequest = ctrl.Request{NamespacedName: types.NamespacedName{Name: "node-departure"}}

// NodeDepartureReconciler cleans up after nodes whose Node object no longer
// exists. Only a node's own galactic-router clears its "<node>/BackendsBound"
// conditions, deletes its generated ServiceVIPBindings and removes the
// teardown finalizer from bindings targeting it, so a decommissioned node
// would otherwise leave all three behind for good, and a deleted rule's
// bindings would stay Terminating. Its kernel state died with the node, so
// there is nothing left to tear down.
//
// It runs on every router and every pass is idempotent: each sweep removes
// the departed nodes' BackendsBound conditions from every NetworkRule,
// deletes their generated bindings and removes the teardown finalizer from
// every binding targeting them, hand-written ones included. Writes retry on
// conflict and treat NotFound as done, so routers sweeping at once converge.
//
// A sweep runs at startup, on every Node deletion and every Interval, so a
// router that was down when a Node was deleted still cleans up after it.
type NodeDepartureReconciler struct {
	client.Client

	// APIReader reads from the API server, bypassing the informer cache. A
	// node is treated as departed only once it confirms the Node is gone.
	APIReader client.Reader

	// Interval is the time between periodic sweeps; zero means
	// defaultNodeDepartureInterval.
	Interval time.Duration
}

// Reconcile sweeps every NetworkRule and ServiceVIPBinding for state left by
// departed nodes. It returns the joined errors of any cleanup that failed, so
// the sweep is retried, and otherwise requeues after Interval.
func (r *NodeDepartureReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	interval := r.Interval
	if interval == 0 {
		interval = defaultNodeDepartureInterval
	}

	rules := &bgpv1alpha1.NetworkRuleList{}
	if err := r.List(ctx, rules); err != nil {
		return ctrl.Result{}, fmt.Errorf("list NetworkRules: %w", err)
	}
	bindings := &bgpv1alpha1.ServiceVIPBindingList{}
	if err := r.List(ctx, bindings); err != nil {
		return ctrl.Result{}, fmt.Errorf("list ServiceVIPBindings: %w", err)
	}

	departed, err := r.departedNodes(ctx, rules.Items, bindings.Items)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(departed) == 0 {
		return ctrl.Result{RequeueAfter: interval}, nil
	}
	log.FromContext(ctx).Info("cleaning up ServiceVIPBinding state of departed nodes", "nodes", sortedKeys(departed))

	var errs []error
	for i := range rules.Items {
		if err := r.clearRuleConditions(ctx, &rules.Items[i], departed); err != nil {
			errs = append(errs, err)
		}
	}
	for i := range bindings.Items {
		binding := &bindings.Items[i]
		if !departed[binding.Spec.TargetRef.Name] {
			continue
		}
		if err := r.releaseBinding(ctx, binding); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

// departedNodes returns the nodes named by a BackendsBound condition on any of
// rules or by the targetRef of any of bindings whose Node does not exist. A
// node missing from the cached Node list counts only once APIReader reports
// it NotFound.
func (r *NodeDepartureReconciler) departedNodes(
	ctx context.Context, rules []bgpv1alpha1.NetworkRule, bindings []bgpv1alpha1.ServiceVIPBinding,
) (map[string]bool, error) {
	nodes := &corev1.NodeList{}
	if err := r.List(ctx, nodes); err != nil {
		return nil, fmt.Errorf("list Nodes: %w", err)
	}
	live := make(map[string]bool, len(nodes.Items))
	for i := range nodes.Items {
		live[nodes.Items[i].Name] = true
	}

	candidates := map[string]bool{}
	for i := range rules {
		for _, c := range rules[i].Status.Conditions {
			if node, ok := backendsBoundConditionNode(c.Type); ok && !live[node] {
				candidates[node] = true
			}
		}
	}
	for i := range bindings {
		if node := bindings[i].Spec.TargetRef.Name; node != "" && !live[node] {
			candidates[node] = true
		}
	}

	departed := make(map[string]bool, len(candidates))
	for node := range candidates {
		err := r.APIReader.Get(ctx, client.ObjectKey{Name: node}, &corev1.Node{})
		switch {
		case apierrors.IsNotFound(err):
			departed[node] = true
		case err != nil:
			return nil, fmt.Errorf("get Node %s: %w", node, err)
		}
	}
	return departed, nil
}

// clearRuleConditions removes every departed node's BackendsBound condition
// from rule, writing its status only if one was present. A rule deleted in
// the meantime counts as done.
func (r *NodeDepartureReconciler) clearRuleConditions(
	ctx context.Context, rule *bgpv1alpha1.NetworkRule, departed map[string]bool,
) error {
	if !hasDepartedCondition(rule.Status.Conditions, departed) {
		return nil
	}
	key := client.ObjectKeyFromObject(rule)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &bgpv1alpha1.NetworkRule{}
		if err := r.Get(ctx, key, current); err != nil {
			return err
		}
		changed := false
		for node := range departed {
			if meta.RemoveStatusCondition(&current.Status.Conditions, backendsBoundConditionType(node)) {
				changed = true
			}
		}
		if !changed {
			return nil
		}
		return r.Status().Update(ctx, current)
	})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("clear departed nodes' %s conditions on NetworkRule %s: %w",
			conditionTypeBackendsBound, key, err)
	}
	return nil
}

// releaseBinding deletes binding if NetworkRuleBindingReconciler generated it,
// then removes its teardown finalizer, which only the departed node it targets
// would otherwise remove. A binding already gone counts as done.
func (r *NodeDepartureReconciler) releaseBinding(ctx context.Context, binding *bgpv1alpha1.ServiceVIPBinding) error {
	key := client.ObjectKeyFromObject(binding)
	if binding.Labels[bindingManagedByLabel] == bindingManagedByValue && binding.DeletionTimestamp.IsZero() {
		if err := r.Delete(ctx, binding); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete ServiceVIPBinding %s of departed node %s: %w",
				key, binding.Spec.TargetRef.Name, err)
		}
	}

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &bgpv1alpha1.ServiceVIPBinding{}
		if err := r.Get(ctx, key, current); err != nil {
			return err
		}
		if !controllerutil.ContainsFinalizer(current, serviceVIPBindingFinalizer) {
			return nil
		}
		base := current.DeepCopy()
		controllerutil.RemoveFinalizer(current, serviceVIPBindingFinalizer)
		return r.Patch(ctx, current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("remove finalizer from ServiceVIPBinding %s of departed node %s: %w",
			key, binding.Spec.TargetRef.Name, err)
	}
	return nil
}

// hasDepartedCondition reports whether conds holds a BackendsBound condition
// of any node in departed.
func hasDepartedCondition(conds []metav1.Condition, departed map[string]bool) bool {
	for _, c := range conds {
		if node, ok := backendsBoundConditionNode(c.Type); ok && departed[node] {
			return true
		}
	}
	return false
}

// backendsBoundConditionNode returns the node a backendsBoundConditionType
// names, and false for any other condition type.
func backendsBoundConditionNode(condType string) (string, bool) {
	node, ok := strings.CutSuffix(condType, "/"+conditionTypeBackendsBound)
	if !ok || node == "" {
		return "", false
	}
	return node, true
}

// sortedKeys returns the keys of set in order.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SetupWithManager registers the NodeDepartureReconciler with the manager.
// Every Node create and delete maps to nodeDepartureRequest: the creates of
// the initial list give the startup sweep, and a delete sweeps at once.
func (r *NodeDepartureReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(
			func(context.Context, client.Object) []ctrlreconcile.Request {
				return []ctrlreconcile.Request{nodeDepartureRequest}
			}),
			builder.WithPredicates(predicate.Funcs{
				UpdateFunc:  func(event.UpdateEvent) bool { return false },
				GenericFunc: func(event.GenericEvent) bool { return false },
			}),
		).
		Named("node-departure").
		Complete(r)
}
