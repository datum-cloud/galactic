/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package controller

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

// upstreamGenerationAnnotation names the generation of the project's subnet
// that the copy propagated here was taken from. The operator that owns the
// subnet stamps it on the copy, and reads a report back only for the
// generation it stamped. The key is the operator's; it is spelled out here
// because the operator version this module pins does not export it yet.
const upstreamGenerationAnnotation = "networking.datumapis.com/upstream-generation"

// SubnetReconciler reports whether a location's address range is in place on
// this cell: the VPC built for the subnet's network context carries the range
// and is ready. It closes the Programmed condition the networking operator
// leaves for the data plane, on the copy of the Subnet propagated to this cell,
// and the federation carries the report back to the project.
//
// The range is in place when traffic can be routed in it. A VPC carries the
// range the moment it is built, because its address space is fixed at
// creation; what it waits for is the identity the fabric routes it by.
type SubnetReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=networking.datumapis.com,resources=subnets,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.datumapis.com,resources=subnets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=vpcs,verbs=get;list;watch

func (r *SubnetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var subnet networkingv1alpha.Subnet
	if err := r.Get(ctx, req.NamespacedName, &subnet); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !subnet.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	var vpc *cloudv1alpha1.VPC
	if subnet.Spec.NetworkContext.Name != "" {
		vpc = &cloudv1alpha1.VPC{}
		key := client.ObjectKey{Namespace: subnet.Namespace, Name: subnet.Spec.NetworkContext.Name}
		if err := r.Get(ctx, key, vpc); err != nil {
			if !apierrors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("read the VPC for subnet %s: %w", req.NamespacedName, err)
			}
			vpc = nil
		}
	}

	condition := subnetProgrammedCondition(&subnet, vpc)
	condition.ObservedGeneration = reportedGeneration(&subnet)
	if !meta.SetStatusCondition(&subnet.Status.Conditions, condition) {
		return ctrl.Result{}, nil
	}
	if err := r.Status().Update(ctx, &subnet); err != nil {
		return ctrl.Result{}, fmt.Errorf("update subnet %s status: %w", req.NamespacedName, err)
	}
	return ctrl.Result{}, nil
}

// subnetProgrammedCondition says whether the subnet's range is in place on this
// cell, given the VPC built for its network context, or nil for none yet.
func subnetProgrammedCondition(subnet *networkingv1alpha.Subnet, vpc *cloudv1alpha1.VPC) metav1.Condition {
	condition := metav1.Condition{
		Type:   networkingv1alpha.SubnetProgrammed,
		Status: metav1.ConditionFalse,
	}

	start, prefixLength, ok := subnetRange(subnet)
	if !ok {
		condition.Reason = networkingv1alpha.SubnetProgrammedReasonNotProgrammed
		condition.Message = "the subnet states no range to put in place"
		return condition
	}
	network := cloudv1alpha1.Network(fmt.Sprintf("%s/%d", start, prefixLength))

	if vpc == nil {
		condition.Reason = networkingv1alpha.SubnetProgrammedReasonProgrammingInProgress
		condition.Message = fmt.Sprintf("waiting for the VPC for network context %q to be built", subnet.Spec.NetworkContext.Name)
		return condition
	}

	// The address space is fixed when the VPC is built. A range that was not
	// there then is not routed by it now, and no amount of waiting changes that.
	if !slices.Contains(vpc.Spec.Networks, network) {
		condition.Reason = networkingv1alpha.SubnetProgrammedReasonNotProgrammed
		condition.Message = fmt.Sprintf("VPC %q was built without %s; its address space is fixed at creation", vpc.Name, network)
		return condition
	}

	ready := meta.FindStatusCondition(vpc.Status.Conditions, cloudv1alpha1.ConditionTypeReady)
	if ready == nil || ready.Status != metav1.ConditionTrue || vpc.Status.VPC == "" {
		condition.Reason = networkingv1alpha.SubnetProgrammedReasonProgrammingInProgress
		condition.Message = fmt.Sprintf("VPC %q carries %s but is not ready yet", vpc.Name, network)
		if ready != nil && ready.Message != "" {
			condition.Message += ": " + ready.Message
		}
		return condition
	}

	condition.Status = metav1.ConditionTrue
	condition.Reason = networkingv1alpha.SubnetProgrammedReasonProgrammed
	condition.Message = fmt.Sprintf("%s is routed by VPC %s", network, vpc.Status.VPC)
	return condition
}

// reportedGeneration is the generation the report is about. Each API server
// counts generation on its own, so the copy's own generation says nothing to
// the project; the report is made against the upstream generation stamped on
// the copy, and falls back to the copy's generation for one that carries none.
func reportedGeneration(subnet *networkingv1alpha.Subnet) int64 {
	if generation, err := strconv.ParseInt(subnet.Annotations[upstreamGenerationAnnotation], 10, 64); err == nil {
		return generation
	}
	return subnet.Generation
}

// SetupWithManager registers the reconciler with the manager.
func (r *SubnetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1alpha.Subnet{}).
		Watches(&cloudv1alpha1.VPC{}, handler.EnqueueRequestsFromMapFunc(r.subnetsForVPC)).
		Named("subnet").
		Complete(r)
}

// subnetsForVPC names the subnets a VPC was built for, so its becoming ready
// is reported on each of them.
func (r *SubnetReconciler) subnetsForVPC(ctx context.Context, obj client.Object) []ctrl.Request {
	vpc, ok := obj.(*cloudv1alpha1.VPC)
	if !ok {
		return nil
	}
	var subnets networkingv1alpha.SubnetList
	if err := r.List(ctx, &subnets, client.InNamespace(vpc.Namespace)); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0, len(subnets.Items))
	for i := range subnets.Items {
		if subnets.Items[i].Spec.NetworkContext.Name != vpc.Name {
			continue
		}
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&subnets.Items[i])})
	}
	return requests
}
