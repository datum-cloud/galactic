// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/serviceroute"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// ServiceRoutePolicyReconciler resolves service policies against local Cloud
// API attachments and programs the resulting stateful eBPF forwarding policy
// directly on this node. It intentionally does not create child Kubernetes
// resources or Linux routes.
type ServiceRoutePolicyReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	NodeName   string
	Programmer serviceroute.RouteProgrammer

	mu      sync.Mutex
	Applied map[types.NamespacedName]map[types.NamespacedName]serviceroute.RouteIntent
}

// Reconcile resolves one policy and replaces the local routes previously
// programmed for that policy.
func (r *ServiceRoutePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	policy := &networkv1alpha1.ServiceRoutePolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, r.removePolicy(req.NamespacedName)
		}
		return ctrl.Result{}, err
	}
	endpoint := &networkv1alpha1.ServiceEndpoint{}
	endpointKey := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Spec.ServiceRef.Name}
	if err := r.Get(ctx, endpointKey, endpoint); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, errors.Join(
				r.replacePolicy(req.NamespacedName, nil),
				r.setAccepted(ctx, policy, metav1.ConditionFalse, "EndpointNotFound", "referenced ServiceEndpoint does not exist"),
			)
		}
		return ctrl.Result{}, fmt.Errorf("get ServiceEndpoint %s/%s: %w", policy.Namespace, policy.Spec.ServiceRef.Name, err)
	}
	attachments := &cloudv1alpha1.VPCAttachmentList{}
	if err := r.List(ctx, attachments); err != nil {
		return ctrl.Result{}, fmt.Errorf("list VPCAttachments: %w", err)
	}
	local := make([]*cloudv1alpha1.VPCAttachment, 0, len(attachments.Items))
	for i := range attachments.Items {
		if attachments.Items[i].Status.Node == r.NodeName {
			local = append(local, &attachments.Items[i])
		}
	}
	intents, err := serviceroute.Compile(policy, endpoint, local, r.NodeName)
	if err != nil {
		return ctrl.Result{}, errors.Join(
			err,
			r.removePolicy(req.NamespacedName),
			r.setAccepted(ctx, policy, metav1.ConditionFalse, "Invalid", err.Error()),
		)
	}
	if err := r.replacePolicy(req.NamespacedName, intents); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, r.setAccepted(ctx, policy, metav1.ConditionTrue, "Accepted", "policy is valid")
}

func (r *ServiceRoutePolicyReconciler) setAccepted(
	ctx context.Context,
	policy *networkv1alpha1.ServiceRoutePolicy,
	status metav1.ConditionStatus,
	reason, message string,
) error {
	before := policy.Status.DeepCopy()
	policy.Status.ObservedGeneration = policy.Generation
	meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               networkv1alpha1.ConditionTypeServiceRouteAccepted,
		Status:             status,
		ObservedGeneration: policy.Generation,
		Reason:             reason,
		Message:            message,
	})
	if reflect.DeepEqual(before, &policy.Status) {
		return nil
	}
	if err := r.Status().Update(ctx, policy); err != nil {
		return fmt.Errorf("update ServiceRoutePolicy status: %w", err)
	}
	return nil
}

// SetupWithManager watches policies, endpoints, and attachments. Events from
// either backing API requeue matching policies so status.node moves and service
// endpoint changes converge without child resources.
func (r *ServiceRoutePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkv1alpha1.ServiceRoutePolicy{}).
		Watches(&networkv1alpha1.ServiceEndpoint{}, handler.EnqueueRequestsFromMapFunc(r.endpointPolicies)).
		Watches(&cloudv1alpha1.VPCAttachment{}, handler.EnqueueRequestsFromMapFunc(r.attachmentPolicies)).
		Complete(r)
}

func (r *ServiceRoutePolicyReconciler) endpointPolicies(ctx context.Context, obj client.Object) []ctrl.Request {
	return r.policiesForEndpoint(ctx, obj.GetNamespace(), obj.GetName())
}

func (r *ServiceRoutePolicyReconciler) attachmentPolicies(ctx context.Context, _ client.Object) []ctrl.Request {
	return r.allPolicies(ctx)
}

func (r *ServiceRoutePolicyReconciler) policiesForEndpoint(ctx context.Context, namespace, name string) []ctrl.Request {
	list := &networkv1alpha1.ServiceRoutePolicyList{}
	if err := r.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0)
	for _, policy := range list.Items {
		if policy.Spec.ServiceRef.Name == name {
			requests = append(requests, ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: policy.Namespace,
				Name:      policy.Name,
			}})
		}
	}
	return requests
}

func (r *ServiceRoutePolicyReconciler) allPolicies(ctx context.Context) []ctrl.Request {
	list := &networkv1alpha1.ServiceRoutePolicyList{}
	if err := r.List(ctx, list); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0, len(list.Items))
	for _, policy := range list.Items {
		requests = append(requests, ctrl.Request{NamespacedName: types.NamespacedName{
			Namespace: policy.Namespace,
			Name:      policy.Name,
		}})
	}
	return requests
}

func (r *ServiceRoutePolicyReconciler) replacePolicy(
	key types.NamespacedName,
	intents []serviceroute.RouteIntent,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Applied == nil {
		r.Applied = make(map[types.NamespacedName]map[types.NamespacedName]serviceroute.RouteIntent)
	}
	current := r.Applied[key]
	if current == nil {
		current = make(map[types.NamespacedName]serviceroute.RouteIntent)
		r.Applied[key] = current
	}
	desired := make(map[types.NamespacedName]serviceroute.RouteIntent, len(intents))
	for _, intent := range intents {
		desired[intent.Attachment] = intent
	}

	// Revoke obsolete or changed intents first. Each successful operation is
	// reflected in Applied immediately, so a later failure leaves an accurate,
	// retryable snapshot rather than leaking untracked kernel state.
	for attachment, existing := range current {
		next, ok := desired[attachment]
		if ok && reflect.DeepEqual(existing, next) {
			continue
		}
		if err := r.Programmer.Remove(existing); err != nil {
			return err
		}
		delete(current, attachment)
	}
	for attachment, intent := range desired {
		if existing, ok := current[attachment]; ok && reflect.DeepEqual(existing, intent) {
			continue
		}
		if err := r.Programmer.Apply(intent); err != nil {
			return err
		}
		current[attachment] = intent
	}
	if len(current) == 0 {
		delete(r.Applied, key)
	}
	return nil
}

func (r *ServiceRoutePolicyReconciler) removePolicy(key types.NamespacedName) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.Applied[key]
	for attachment, intent := range current {
		if err := r.Programmer.Remove(intent); err != nil {
			return err
		}
		delete(current, attachment)
	}
	delete(r.Applied, key)
	return nil
}
