// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"
	"maps"
	"net/netip"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// ipv4Bindings holds the generated ServiceVIPBindings of IPv4 VIPs in one
// namespace, by name. The gateway reads them to decide which IPv4 backends a
// rule's IPv4 VIP may be balanced over and whether it may be advertised.
type ipv4Bindings map[string]*bgpv1alpha1.ServiceVIPBinding

// listIPv4Bindings returns the generated ServiceVIPBindings of IPv4 VIPs in
// namespace. Bindings for IPv6 VIPs, and bindings galactic-router did not
// write, are left out.
func listIPv4Bindings(ctx context.Context, c client.Client, namespace string) (ipv4Bindings, error) {
	list := &bgpv1alpha1.ServiceVIPBindingList{}
	if err := c.List(ctx, list,
		client.InNamespace(namespace),
		client.MatchingLabels{bindingManagedByLabel: bindingManagedByValue},
	); err != nil {
		return nil, fmt.Errorf("list ServiceVIPBindings in %s: %w", namespace, err)
	}
	out := make(ipv4Bindings, len(list.Items))
	for i := range list.Items {
		if bindingIsIPv4(&list.Items[i]) {
			out[list.Items[i].Name] = &list.Items[i]
		}
	}
	return out, nil
}

// unbound returns why backend b of rule has no Bound binding for the IPv4 VIP
// vip, or "" when it has one. A binding counts only when it is the one
// b's node writes for rule today (generatedBinding): same name, rule label and
// spec, so a binding left from an earlier spec, or not yet updated to the
// current one, does not open the gate. A binding being deleted does not count
// either.
func (idx ipv4Bindings) unbound(rule *bgpv1alpha1.NetworkService, vip netip.Addr, b ruleBackend) string {
	want := generatedBinding(rule, b.node, vip, b)
	got, ok := idx[want.Name]
	switch {
	case !ok:
		return "ServiceVIPBinding not created yet"
	case !got.DeletionTimestamp.IsZero():
		// Its finalizer is removing its rows, so the backend is about to
		// stop answering on the VIP whatever its Bound condition says.
		return "ServiceVIPBinding being deleted"
	case got.Labels[networkRuleLabel] != rule.Name || got.Spec != want.Spec:
		return "ServiceVIPBinding not updated to the rule yet"
	}
	if reason := bindingUnboundReason(got); reason != "" {
		return "ServiceVIPBinding " + reason
	}
	return ""
}

// ipv4BindingReadinessChanged passes ServiceVIPBinding events that can change
// whether a gateway may balance over or advertise an IPv4 VIP: a create or
// delete of a generated IPv4 binding, and an update that changes its spec,
// whether it is Bound, or whether it is being deleted. Bindings of IPv6 VIPs are dropped, since the gateway
// reads only IPv4 ones.
func ipv4BindingReadinessChanged() predicate.Predicate {
	relevant := func(obj client.Object) bool {
		binding, ok := obj.(*bgpv1alpha1.ServiceVIPBinding)
		return ok && binding.Labels[bindingManagedByLabel] == bindingManagedByValue && bindingIsIPv4(binding)
	}
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return relevant(e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return relevant(e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return relevant(e.Object) },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldBinding, okOld := e.ObjectOld.(*bgpv1alpha1.ServiceVIPBinding)
			newBinding, okNew := e.ObjectNew.(*bgpv1alpha1.ServiceVIPBinding)
			if !okOld || !okNew || (!relevant(oldBinding) && !relevant(newBinding)) {
				return false
			}
			return oldBinding.Generation != newBinding.Generation ||
				oldBinding.DeletionTimestamp.IsZero() != newBinding.DeletionTimestamp.IsZero() ||
				!maps.Equal(oldBinding.Labels, newBinding.Labels) ||
				(bindingUnboundReason(oldBinding) == "") != (bindingUnboundReason(newBinding) == "")
		},
	}
}
