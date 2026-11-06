// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// requestQueue is the controller's work queue.
type requestQueue = workqueue.TypedRateLimitingInterface[reconcile.Request]

// The service route controller has one worker, and every reconcile reads every
// attachment. Requeueing every policy for each attachment, endpoint or VPC
// event in the cell keeps its queue full, so a new consumer waits a whole
// pass over every policy before its route is installed. These mappers requeue
// only the policies an event can change.

// attachmentEventPolicies requeues, for a VPCAttachment event, the policies
// that select the attachment as it was or as it is: as a consumer, or as a
// producer of their endpoint. An attachment leaving a selector requeues the
// policy it left, so that policy withdraws its route. Policies that conflict
// over a consumer both select it, so both are requeued for a consumer's
// event; a conflict that a producer, endpoint or VPC event creates or clears
// requeues the other policies through noteConflicts.
func (r *ServiceRoutePolicyReconciler) attachmentEventPolicies() handler.EventHandler {
	enqueue := func(ctx context.Context, q requestQueue, objs ...client.Object) {
		attachments := make([]*cloudv1alpha1.VPCAttachment, 0, len(objs))
		for _, obj := range objs {
			if a, ok := obj.(*cloudv1alpha1.VPCAttachment); ok && a != nil {
				attachments = append(attachments, a)
			}
		}
		for _, req := range r.attachmentPolicies(ctx, attachments...) {
			q.Add(req)
		}
	}
	return handler.Funcs{
		CreateFunc: func(ctx context.Context, e event.CreateEvent, q requestQueue) {
			enqueue(ctx, q, e.Object)
		},
		UpdateFunc: func(ctx context.Context, e event.UpdateEvent, q requestQueue) {
			enqueue(ctx, q, e.ObjectOld, e.ObjectNew)
		},
		DeleteFunc: func(ctx context.Context, e event.DeleteEvent, q requestQueue) {
			enqueue(ctx, q, e.Object)
		},
		GenericFunc: func(ctx context.Context, e event.GenericEvent, q requestQueue) {
			enqueue(ctx, q, e.Object)
		},
	}
}

// attachmentPolicies returns the policies that select any of attachments as
// a consumer or as a producer of their endpoint. A policy whose selector does
// not parse, or whose endpoint is not in the cache, is returned too: its
// reconcile reports the problem, and requeueing it costs one reconcile.
func (r *ServiceRoutePolicyReconciler) attachmentPolicies(ctx context.Context,
	attachments ...*cloudv1alpha1.VPCAttachment,
) []ctrl.Request {
	if len(attachments) == 0 {
		return nil
	}
	policies := &networkv1alpha1.ServiceRoutePolicyList{}
	if err := r.List(ctx, policies); err != nil {
		log.FromContext(ctx).Error(err, "list service route policies for an attachment event")
		return nil
	}
	endpoints := map[types.NamespacedName]*networkv1alpha1.ServiceEndpoint{}
	endpointFor := func(policy *networkv1alpha1.ServiceRoutePolicy) (*networkv1alpha1.ServiceEndpoint, bool) {
		key := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Spec.ServiceRef.Name}
		if endpoint, ok := endpoints[key]; ok {
			return endpoint, endpoint != nil
		}
		endpoint := &networkv1alpha1.ServiceEndpoint{}
		if err := r.Get(ctx, key, endpoint); err != nil {
			endpoints[key] = nil
			return nil, false
		}
		endpoints[key] = endpoint
		return endpoint, true
	}
	var requests []ctrl.Request
	for i := range policies.Items {
		policy := &policies.Items[i]
		endpoint, found := endpointFor(policy)
		if !found || policySelectsAny(policy, endpoint, attachments) {
			requests = append(requests, policyRequest(policy))
		}
	}
	return requests
}

// policySelectsAny reports whether policy selects any of attachments as a
// consumer, or endpoint selects any of them as a producer. It errs toward
// true: a selector that does not parse matches.
func policySelectsAny(policy *networkv1alpha1.ServiceRoutePolicy, endpoint *networkv1alpha1.ServiceEndpoint,
	attachments []*cloudv1alpha1.VPCAttachment,
) bool {
	consumers, consumerErr := metav1.LabelSelectorAsSelector(&policy.Spec.AttachmentSelector)
	var producers labels.Selector
	var producerErr error
	if endpoint.Spec.AttachmentSelector != nil {
		producers, producerErr = metav1.LabelSelectorAsSelector(endpoint.Spec.AttachmentSelector)
	}
	if consumerErr != nil || producerErr != nil {
		return true
	}
	for _, a := range attachments {
		set := labels.Set(a.Labels)
		if consumers.Matches(set) && consumerInPolicyVPC(policy, a) {
			return true
		}
		if ref := endpoint.Spec.AttachmentRef; ref != nil && ref.Namespace == a.Namespace && ref.Name == a.Name {
			return true
		}
		if producers != nil && producers.Matches(set) {
			return true
		}
	}
	return false
}

// consumerInPolicyVPC reports whether a can be one of policy's consumers by
// its consumer VPC reference. The VPC identity in a's status is not compared:
// an attachment whose identity changes still requeues the policy that served
// it.
func consumerInPolicyVPC(policy *networkv1alpha1.ServiceRoutePolicy, a *cloudv1alpha1.VPCAttachment) bool {
	ref := policy.Spec.ConsumerVPCRef
	return ref == nil || (a.Namespace == policy.Namespace && a.Spec.VPC.Name == ref.Name)
}

// endpointPolicies requeues the policies that route to the ServiceEndpoint
// obj, or to the endpoint whose producers the ServiceEndpointProducerReport
// obj describes.
func (r *ServiceRoutePolicyReconciler) endpointPolicies(ctx context.Context, obj client.Object) []ctrl.Request {
	name := obj.GetName()
	if report, ok := obj.(*networkv1alpha1.ServiceEndpointProducerReport); ok {
		name = report.Spec.EndpointName
	}
	policies := &networkv1alpha1.ServiceRoutePolicyList{}
	if err := r.List(ctx, policies, client.InNamespace(obj.GetNamespace())); err != nil {
		log.FromContext(ctx).Error(err, "list service route policies for an endpoint event")
		return nil
	}
	var requests []ctrl.Request
	for i := range policies.Items {
		if policies.Items[i].Spec.ServiceRef.Name == name {
			requests = append(requests, policyRequest(&policies.Items[i]))
		}
	}
	return requests
}

// vpcPolicies requeues the policies whose consumer VPC reference names the
// VPC obj, the only policies that read a VPC.
func (r *ServiceRoutePolicyReconciler) vpcPolicies(ctx context.Context, obj client.Object) []ctrl.Request {
	policies := &networkv1alpha1.ServiceRoutePolicyList{}
	if err := r.List(ctx, policies, client.InNamespace(obj.GetNamespace())); err != nil {
		log.FromContext(ctx).Error(err, "list service route policies for a VPC event")
		return nil
	}
	var requests []ctrl.Request
	for i := range policies.Items {
		if ref := policies.Items[i].Spec.ConsumerVPCRef; ref != nil && ref.Name == obj.GetName() {
			requests = append(requests, policyRequest(&policies.Items[i]))
		}
	}
	return requests
}

// policyEventPolicies requeues every policy for a policy's create, delete or
// spec change: whether two policies conflict over a consumer is decided across
// all of them.
func (r *ServiceRoutePolicyReconciler) policyEventPolicies(ctx context.Context, _ client.Object) []ctrl.Request {
	return r.allPolicies(ctx)
}

func policyRequest(policy *networkv1alpha1.ServiceRoutePolicy) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}}
}

// noteConflicts requeues, apart from self, every policy that entered or left
// the conflict set since the last reconcile. A conflict can start or end
// through an event that requeues only one of the policies involved, such as
// its producer becoming ready, and the reconcile that sees it withdraws or
// would restore the others' routes. The caller holds r.mu.
func (r *ServiceRoutePolicyReconciler) noteConflicts(self types.NamespacedName,
	conflicts map[types.NamespacedName]bool,
) {
	previous := r.conflicted
	r.conflicted = make(map[types.NamespacedName]bool, len(conflicts))
	for key, conflicted := range conflicts {
		if conflicted {
			r.conflicted[key] = true
		}
	}
	changed := func(key types.NamespacedName) {
		if key == self || r.requeue == nil {
			return
		}
		select {
		case r.requeue <- event.GenericEvent{Object: &networkv1alpha1.ServiceRoutePolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
		}}:
		default:
			// Full: the policy's own periodic requeue still reaches it.
		}
	}
	for key := range r.conflicted {
		if !previous[key] {
			changed(key)
		}
	}
	for key := range previous {
		if !r.conflicted[key] {
			changed(key)
		}
	}
}
