// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const (
	testDepartedNode    = "departed-node"
	testDepartureSweep  = 7 * time.Minute
	testHandWrittenName = "hand-written"
)

func newDepartureTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := newRuleTestScheme(t)
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme core: %v", err)
	}
	return scheme
}

func newDepartureTestNode(name string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

// newDepartureTestBinding returns a binding targeting node with the teardown
// finalizer, labelled as generated when generated is set.
func newDepartureTestBinding(name, node string, generated bool) *bgpv1alpha1.ServiceVIPBinding {
	b := &bgpv1alpha1.ServiceVIPBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  testNamespace,
			Name:       name,
			Finalizers: []string{serviceVIPBindingFinalizer},
		},
		Spec: bgpv1alpha1.ServiceVIPBindingSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: testTargetRefKind, Name: node},
		},
	}
	if generated {
		b.Labels = map[string]string{
			networkRuleLabel:      testRuleName,
			bindingNodeLabel:      gatewayNodeLabelValue(node),
			bindingManagedByLabel: bindingManagedByValue,
		}
	}
	return b
}

// newDepartureTestRule returns testRuleName with a BackendsBound condition
// for each of nodes.
func newDepartureTestRule(nodes ...string) *bgpv1alpha1.NetworkRule {
	rule := newBindingTestRule()
	for _, node := range nodes {
		meta.SetStatusCondition(&rule.Status.Conditions, metav1.Condition{
			Type:   backendsBoundConditionType(node),
			Status: metav1.ConditionTrue,
			Reason: reasonBindingsBound,
		})
	}
	return rule
}

func newDepartureReconciler(t *testing.T, objs ...client.Object) (*NodeDepartureReconciler, client.Client) {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(newDepartureTestScheme(t)).
		WithStatusSubresource(&bgpv1alpha1.NetworkRule{}, &bgpv1alpha1.ServiceVIPBinding{}).
		WithObjects(objs...).
		Build()
	return &NodeDepartureReconciler{Client: c, APIReader: c, Interval: testDepartureSweep}, c
}

func sweepDepartedNodes(t *testing.T, r *NodeDepartureReconciler) {
	t.Helper()
	res, err := r.Reconcile(context.Background(), nodeDepartureRequest)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != testDepartureSweep {
		t.Errorf("RequeueAfter = %v, want %v", res.RequeueAfter, testDepartureSweep)
	}
}

// getDepartureTestBinding returns the named binding, or nil if it is gone.
func getDepartureTestBinding(t *testing.T, c client.Client, name string) *bgpv1alpha1.ServiceVIPBinding {
	t.Helper()
	b := &bgpv1alpha1.ServiceVIPBinding{}
	err := c.Get(context.Background(), client.ObjectKey{Namespace: testNamespace, Name: name}, b)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("get ServiceVIPBinding %s: %v", name, err)
	}
	return b
}

// TestNodeDepartureReconciler_CleansUpDepartedNode covers a node whose Node
// object is gone: its BackendsBound condition is removed, its generated
// binding deleted, and a hand-written binding targeting it released from the
// teardown finalizer but kept, while a live node's state stays as it was.
func TestNodeDepartureReconciler_CleansUpDepartedNode(t *testing.T) {
	r, c := newDepartureReconciler(t,
		newDepartureTestNode(testComputeNodeName),
		newDepartureTestRule(testComputeNodeName, testDepartedNode),
		newDepartureTestBinding("departed-generated", testDepartedNode, true),
		newDepartureTestBinding(testHandWrittenName, testDepartedNode, false),
		newDepartureTestBinding("live-generated", testComputeNodeName, true),
		newDepartureTestBinding("live-hand-written", testComputeNodeName, false),
	)

	// A second sweep finds nothing left to do and must not fail on it.
	sweepDepartedNodes(t, r)
	sweepDepartedNodes(t, r)

	conds := getBindingRule(t, c).Status.Conditions
	if meta.FindStatusCondition(conds, backendsBoundConditionType(testDepartedNode)) != nil {
		t.Errorf("departed node's %s condition still on the rule", conditionTypeBackendsBound)
	}
	if meta.FindStatusCondition(conds, backendsBoundConditionType(testComputeNodeName)) == nil {
		t.Errorf("live node's %s condition removed", conditionTypeBackendsBound)
	}
	if meta.FindStatusCondition(conds, bgpv1alpha1.ConditionTypeAccepted) == nil {
		t.Errorf("Accepted condition removed")
	}

	tests := []struct {
		name          string
		binding       string
		wantExists    bool
		wantFinalizer bool
	}{
		{"DepartedGeneratedDeleted", "departed-generated", false, false},
		{"DepartedHandWrittenReleased", testHandWrittenName, true, false},
		{"LiveGeneratedUntouched", "live-generated", true, true},
		{"LiveHandWrittenUntouched", "live-hand-written", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := getDepartureTestBinding(t, c, tt.binding)
			if (b != nil) != tt.wantExists {
				t.Fatalf("binding exists = %v, want %v", b != nil, tt.wantExists)
			}
			if b == nil {
				return
			}
			if got := controllerutil.ContainsFinalizer(b, serviceVIPBindingFinalizer); got != tt.wantFinalizer {
				t.Errorf("has teardown finalizer = %v, want %v", got, tt.wantFinalizer)
			}
			if !b.DeletionTimestamp.IsZero() {
				t.Errorf("binding is being deleted, want it left alone")
			}
		})
	}
}

// TestNodeDepartureReconciler_ReleasesTerminatingBinding covers a binding of
// a departed node already being deleted, as when its rule was deleted: it
// would stay Terminating until the finalizer is removed.
func TestNodeDepartureReconciler_ReleasesTerminatingBinding(t *testing.T) {
	tests := []struct {
		name      string
		generated bool
	}{
		{"Generated", true},
		{"HandWritten", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding := newDepartureTestBinding("terminating", testDepartedNode, tt.generated)
			now := metav1.Now()
			binding.DeletionTimestamp = &now
			r, c := newDepartureReconciler(t, binding)

			sweepDepartedNodes(t, r)

			if b := getDepartureTestBinding(t, c, "terminating"); b != nil {
				t.Errorf("binding still present with finalizers %v, want it gone", b.Finalizers)
			}
		})
	}
}

// TestNodeDepartureReconciler_KeepsNodeMissingOnlyFromCache covers a Node the
// cache has not seen yet: the API server still has it, so its state stays.
func TestNodeDepartureReconciler_KeepsNodeMissingOnlyFromCache(t *testing.T) {
	r, c := newDepartureReconciler(t,
		newDepartureTestRule(testDepartedNode),
		newDepartureTestBinding("generated", testDepartedNode, true),
	)
	r.APIReader = fake.NewClientBuilder().
		WithScheme(newDepartureTestScheme(t)).
		WithObjects(newDepartureTestNode(testDepartedNode)).
		Build()

	sweepDepartedNodes(t, r)

	if meta.FindStatusCondition(getBindingRule(t, c).Status.Conditions,
		backendsBoundConditionType(testDepartedNode)) == nil {
		t.Errorf("%s condition removed for a node the API server still has", conditionTypeBackendsBound)
	}
	b := getDepartureTestBinding(t, c, "generated")
	if b == nil || !controllerutil.ContainsFinalizer(b, serviceVIPBindingFinalizer) {
		t.Errorf("binding = %+v, want it kept with its finalizer", b)
	}
}

func TestBackendsBoundConditionNode(t *testing.T) {
	tests := []struct {
		name     string
		condType string
		wantNode string
		wantOK   bool
	}{
		{"NodeCondition", backendsBoundConditionType(testComputeNodeName), testComputeNodeName, true},
		{"ProgrammedCondition", programmedConditionType(testComputeNodeName), "", false},
		{"Accepted", bgpv1alpha1.ConditionTypeAccepted, "", false},
		{"EmptyNode", "/" + conditionTypeBackendsBound, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, ok := backendsBoundConditionNode(tt.condType)
			if node != tt.wantNode || ok != tt.wantOK {
				t.Errorf("backendsBoundConditionNode(%q) = %q, %v, want %q, %v",
					tt.condType, node, ok, tt.wantNode, tt.wantOK)
			}
		})
	}
}
