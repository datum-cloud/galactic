// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package serviceaddress coordinates terminal allocations that never reached a gateway.
package serviceaddress

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
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

const (
	reasonAwaitingGateway  = "AwaitingGatewayAcknowledgement"
	reasonForwardingState  = "ForwardingStatePresent"
	minRetirementBackoff   = time.Second
	maxRetirementBackoff   = 5 * time.Minute
	maxReportedGatewayRefs = 3
)

// RetirementReconciler acknowledges terminal-at-creation allocations without serving gateways.
type RetirementReconciler struct {
	client.Client
	APIReader client.Reader
}

type pendingRetirement struct {
	reason  string
	message string
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
	pending, err := r.pendingResources(ctx, r.Client, address)
	if err == nil && pending == nil {
		pending, err = r.pendingResources(ctx, reader, address)
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	if pending != nil {
		return r.awaitRetirement(ctx, address, pending)
	}
	meta.SetStatusCondition(&address.Status.Conditions, metav1.Condition{Type: api.ConditionTypeAddressRetired,
		Status: metav1.ConditionTrue, ObservedGeneration: address.Generation, Reason: "NeverActivated",
		Message: "Allocation was permanently retired at creation and has no forwarding resources"})
	address.Status.ObservedGeneration = address.Generation
	return ctrl.Result{}, r.Status().Update(ctx, address)
}

func (r *RetirementReconciler) awaitRetirement(
	ctx context.Context,
	address *api.NetworkServiceAddress,
	pending *pendingRetirement,
) (ctrl.Result, error) {
	changed := meta.SetStatusCondition(&address.Status.Conditions, metav1.Condition{
		Type: api.ConditionTypeAddressRetired, Status: metav1.ConditionFalse,
		ObservedGeneration: address.Generation, Reason: pending.reason, Message: pending.message,
	})
	if changed {
		address.Status.ObservedGeneration = address.Generation
		if err := r.Status().Update(ctx, address); err != nil {
			return ctrl.Result{}, err
		}
	}
	condition := meta.FindStatusCondition(address.Status.Conditions, api.ConditionTypeAddressRetired)
	return ctrl.Result{RequeueAfter: retirementBackoff(time.Since(condition.LastTransitionTime.Time))}, nil
}

func retirementBackoff(waited time.Duration) time.Duration {
	return min(max(waited, minRetirementBackoff), maxRetirementBackoff)
}

func (r *RetirementReconciler) pendingResources(
	ctx context.Context,
	reader client.Reader,
	address *api.NetworkServiceAddress,
) (*pendingRetirement, error) {
	gateways := &api.NetworkGatewayList{}
	if err := reader.List(ctx, gateways); err != nil {
		return nil, err
	}
	if len(gateways.Items) > 0 {
		return &pendingRetirement{reason: reasonAwaitingGateway, message: gatewayWaitMessage(gateways.Items)}, nil
	}
	services := &api.NetworkServiceList{}
	if err := reader.List(ctx, services); err != nil {
		return nil, err
	}
	var referrer referrer
	for _, service := range services.Items {
		if service.Spec.AddressGroup != nil && service.Spec.AddressGroup.UID == address.Spec.Group.UID {
			referrer.offer(service.Namespace, service.Name)
		}
	}
	if pending := referrer.pending("NetworkService"); pending != nil {
		return pending, nil
	}
	ads := &api.BGPAdvertisementList{}
	if err := reader.List(ctx, ads); err != nil {
		return nil, err
	}
	for _, ad := range ads.Items {
		if ((ad.Labels[addressLabel] == address.Name || ad.Annotations[addressLabel] == address.Name) &&
			(ad.Labels[addressNamespaceLabel] == address.Namespace || ad.Namespace == address.Namespace)) ||
			slices.ContainsFunc(ad.OwnerReferences, func(o metav1.OwnerReference) bool { return o.UID == address.UID }) {
			referrer.offer(ad.Namespace, ad.Name)
		}
	}
	if pending := referrer.pending("BGPAdvertisement"); pending != nil {
		return pending, nil
	}
	bindings := &api.ServiceVIPBindingList{}
	if err := reader.List(ctx, bindings); err != nil {
		return nil, err
	}
	for _, binding := range bindings.Items {
		if binding.Spec.SourceRef != nil && binding.Spec.SourceRef.AllocationUID == address.Spec.Group.UID {
			referrer.offer(binding.Namespace, binding.Name)
		}
	}
	return referrer.pending("ServiceVIPBinding"), nil
}

type referrer struct {
	found           bool
	namespace, name string
}

func (r *referrer) offer(namespace, name string) {
	if !r.found || cmp.Or(cmp.Compare(namespace, r.namespace), cmp.Compare(name, r.name)) < 0 {
		*r = referrer{found: true, namespace: namespace, name: name}
	}
}

func (r *referrer) pending(kind string) *pendingRetirement {
	if !r.found {
		return nil
	}
	return &pendingRetirement{
		reason:  reasonForwardingState,
		message: fmt.Sprintf("Waiting for %s %s/%s to stop referring to this allocation", kind, r.namespace, r.name),
	}
}

func gatewayWaitMessage(gateways []api.NetworkGateway) string {
	slices.SortFunc(gateways, func(a, b api.NetworkGateway) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	refs := make([]string, 0, maxReportedGatewayRefs)
	for _, gw := range gateways[:min(len(gateways), maxReportedGatewayRefs)] {
		refs = append(refs, fmt.Sprintf("%s/%s (node %s)", gw.Namespace, gw.Name, gw.Spec.TargetRef.Name))
	}
	message := "Waiting for galactic-gateway to acknowledge withdrawal; NetworkGateways: " + strings.Join(refs, ", ")
	if extra := len(gateways) - len(refs); extra > 0 {
		message += fmt.Sprintf(" and %d more", extra)
	}
	return message
}

// SetupWithManager registers the retirement controller on the cell control plane.
func (r *RetirementReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.APIReader = mgr.GetAPIReader()
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.NetworkServiceAddress{}).
		Named("networkserviceaddress-retirement").
		Complete(r)
}
