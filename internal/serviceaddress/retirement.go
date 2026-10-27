// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package serviceaddress coordinates terminal allocations that never reached a gateway.
package serviceaddress

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	api "go.datum.net/galactic/api/network/v1alpha1"
)

const withdrawalFinalizer = "galactic.datum.net/address-withdrawal"
const addressLabel = "galactic.datum.net/service-address"
const addressNamespaceLabel = "galactic.datum.net/service-address-namespace"

// RetirementReconciler acknowledges terminal-at-creation allocations without serving gateways.
type RetirementReconciler struct {
	client.Client
	APIReader client.Reader
}

func (r *RetirementReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	address := &api.NetworkServiceAddress{}
	if err := reader.Get(ctx, req.NamespacedName, address); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !address.Spec.Retired || address.Generation != 1 || address.Spec.VPCRef != "" ||
		len(address.Spec.Group.Listeners) != 0 ||
		!address.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	if !controllerutil.ContainsFinalizer(address, withdrawalFinalizer) {
		base := address.DeepCopy()
		controllerutil.AddFinalizer(address, withdrawalFinalizer)
		if err := r.Patch(ctx, address, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
			return ctrl.Result{}, err
		}
	}
	if c := meta.FindStatusCondition(address.Status.Conditions, api.ConditionTypeAddressRetired); c != nil &&
		c.Status == metav1.ConditionTrue &&
		c.ObservedGeneration == address.Generation {
		return ctrl.Result{}, nil
	}
	pending, err := r.pendingResources(ctx, reader, address)
	if err != nil || pending {
		return ctrl.Result{RequeueAfter: time.Second}, err
	}
	meta.SetStatusCondition(&address.Status.Conditions, metav1.Condition{Type: api.ConditionTypeAddressRetired,
		Status: metav1.ConditionTrue, ObservedGeneration: address.Generation, Reason: "NeverActivated",
		Message: "Allocation was permanently retired at creation and has no forwarding resources"})
	address.Status.ObservedGeneration = address.Generation
	return ctrl.Result{}, r.Status().Update(ctx, address)
}

func (r *RetirementReconciler) pendingResources(
	ctx context.Context,
	reader client.Reader,
	address *api.NetworkServiceAddress,
) (bool, error) {
	gateways := &api.NetworkGatewayList{}
	if err := reader.List(ctx, gateways); err != nil {
		return true, err
	}
	if len(gateways.Items) > 0 {
		return true, nil
	}
	services := &api.NetworkServiceList{}
	if err := reader.List(ctx, services); err != nil {
		return true, err
	}
	for _, service := range services.Items {
		if service.Spec.AddressGroup != nil && service.Spec.AddressGroup.UID == address.Spec.Group.UID {
			return true, nil
		}
	}
	ads := &api.BGPAdvertisementList{}
	if err := reader.List(ctx, ads); err != nil {
		return true, err
	}
	for _, ad := range ads.Items {
		if (ad.Labels[addressLabel] == address.Name || ad.Annotations[addressLabel] == address.Name) &&
			(ad.Labels[addressNamespaceLabel] == address.Namespace || ad.Namespace == address.Namespace) {
			return true, nil
		}
		for _, owner := range ad.OwnerReferences {
			if owner.UID == address.UID {
				return true, nil
			}
		}
	}
	bindings := &api.ServiceVIPBindingList{}
	if err := reader.List(ctx, bindings); err != nil {
		return true, err
	}
	for _, binding := range bindings.Items {
		if binding.Spec.SourceRef != nil && binding.Spec.SourceRef.AllocationUID == address.Spec.Group.UID {
			return true, nil
		}
	}
	return false, nil
}

// SetupWithManager registers the retirement controller on the cell control plane.
func (r *RetirementReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.APIReader = mgr.GetAPIReader()
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.NetworkServiceAddress{}).
		Named("networkserviceaddress-retirement").
		Complete(r)
}
