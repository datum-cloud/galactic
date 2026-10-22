// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"
	"net/netip"
	"sort"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// Per-node Programmed reasons for a loaded rule with a healthCheck. Each is
// reported with status True: the rule serves.
const (
	// reasonBackendsUnhealthy: the rule is loaded without the backends their
	// nodes report Unhealthy.
	reasonBackendsUnhealthy = "BackendsUnhealthy"

	// reasonNoHealthyBackends: every backend of a VIP family is reported
	// Unhealthy, so all of them are kept.
	reasonNoHealthyBackends = "NoHealthyBackends"

	// reasonHealthChecksNotApplied: some gateway node in the namespace does
	// not apply backend health, so none of them does.
	reasonHealthChecksNotApplied = "HealthChecksNotApplied"
)

// healthGate is whether one pass applies backend health, and why not.
//
// Health changes a rule's Maglev table, so a gateway applies it only while
// every NetworkGateway in its namespace reports BackendHealthFiltering: every
// gateway then reads the same decisions, and a gateway that does not apply
// health, an older one included, turns it off for all of them instead of
// building a different table.
type healthGate struct {
	// apply is set when this pass applies health.
	apply bool

	// why says why health is not applied, for a rule with a healthCheck.
	why string
}

// passHealthGate returns this pass's healthGate for namespace.
func (r *NetworkGatewayReconciler) passHealthGate(ctx context.Context, namespace string) (healthGate, error) {
	if !r.BackendHealth {
		return healthGate{why: "backend health is off on gateway node " + r.NodeName}, nil
	}
	list := &bgpv1alpha1.NetworkGatewayList{}
	if err := r.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return healthGate{}, fmt.Errorf("list NetworkGateways in %s: %w", namespace, err)
	}
	var missing []string
	for i := range list.Items {
		if !list.Items[i].Status.BackendHealthFiltering {
			missing = append(missing, list.Items[i].Spec.TargetRef.Name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return healthGate{why: "backend health is not applied by gateway nodes " + cappedList(missing)}, nil
	}
	return healthGate{apply: true}, nil
}

// unhealthy reports whether b's node reports b Unhealthy for rule's VIP vip:
// the binding b's node writes for rule today (generatedBinding), not being
// deleted, carries a status.health of Unhealthy for b's attachment and rule's
// health check port. Any other decision, or none, keeps b.
func (idx serviceBindings) unhealthy(rule *bgpv1alpha1.NetworkService, vip netip.Addr, b ruleBackend) bool {
	want := generatedBinding(rule, b.node, vip, b)
	got, ok := idx[want.Name]
	if !ok || !got.DeletionTimestamp.IsZero() || got.Labels[networkRuleLabel] != rule.Name || got.Spec != want.Spec {
		return false
	}
	h := got.Status.Health
	return h != nil && h.State == bgpv1alpha1.BackendHealthUnhealthy &&
		h.AttachmentUID == b.uid && h.Port == ruleHealthCheckPort(rule)
}

// ruleHealth is what health did to one rule's backends in a pass.
type ruleHealth struct {
	// unhealthy lists the backends left out, or kept with noneHealthy, as
	// "address:port", sorted, once per VIP family.
	unhealthy []string

	// noneHealthy is set when every backend of some VIP family was reported
	// Unhealthy, so all of them were kept.
	noneHealthy bool

	// notApplied says why the rule's healthCheck was not applied, or "".
	notApplied string
}

// gatewayHealthFilteringChanged passes NetworkGateway events that can change
// whether every gateway in a namespace applies health: a create or delete, and
// an update of BackendHealthFiltering.
func gatewayHealthFilteringChanged() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldGW, okOld := e.ObjectOld.(*bgpv1alpha1.NetworkGateway)
			newGW, okNew := e.ObjectNew.(*bgpv1alpha1.NetworkGateway)
			return !okOld || !okNew || oldGW.Status.BackendHealthFiltering != newGW.Status.BackendHealthFiltering
		},
	}
}
