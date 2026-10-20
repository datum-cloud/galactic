// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cell holds galactic-controller's cell-role reconcilers for traffic
// policy: TrafficPolicy acceptance, the reserved default policy in every
// tenant namespace, and TrafficPolicyBinding reference resolution. None of
// them touch a node; the per-node datapath state is galactic-router's.
package cell

import (
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/trafficpolicy"
	"go.datum.net/galactic/internal/trafficpolicy/webhook"
)

// ManagedByLabel marks the default policy galactic-controller provisions.
// A default-deny-all without it, or with a different spec, is a conflict the
// controller reports and never adopts.
const (
	ManagedByLabel = webhook.ManagedByLabel
	ManagedByValue = webhook.ManagedByValue
)

// Condition types and reasons.
const (
	ConditionAccepted = "Accepted"
	ConditionResolved = "Resolved"

	ReasonAccepted       = "Accepted"
	ReasonInvalid        = "Invalid"
	ReasonReservedName   = "ReservedNameConflict"
	ReasonDefault        = "Default"
	ReasonResolved       = "Resolved"
	ReasonNotFound       = "NotFound"
	ReasonPolicyInvalid  = "PolicyInvalid"
	ReasonPolicyConflict = "PolicyReservedNameConflict"
)

// IsReservedConflict reports whether p holds the reserved default name
// without being the controller's own default policy.
func IsReservedConflict(p *galacticv1alpha1.TrafficPolicy) bool {
	if p.Name != galacticv1alpha1.DefaultPolicyName {
		return false
	}
	return p.Labels[ManagedByLabel] != ManagedByValue || !equality.Semantic.DeepEqual(p.Spec, webhook.DefaultSpec())
}

// Resolve is what one direction's reference resolves to. ref nil selects the
// built-in default; policy nil means the referenced policy authoritatively
// does not exist. The result's Policy is set whenever the node side has an
// identity to act on: the built-in default, a valid policy, or an invalid
// one, whose last good snapshot a node keeps for the same UID.
func Resolve(ref *galacticv1alpha1.LocalPolicyReference, policy *galacticv1alpha1.TrafficPolicy,
	generation int64,
) galacticv1alpha1.DirectionStatus {
	cond := metav1.Condition{Type: ConditionResolved, ObservedGeneration: generation}
	var st galacticv1alpha1.DirectionStatus
	switch {
	case ref == nil:
		st.Policy = &galacticv1alpha1.PolicyIdentity{
			Name: galacticv1alpha1.DefaultPolicyName, UID: galacticv1alpha1.DefaultPolicyUID,
		}
		cond.Status, cond.Reason = metav1.ConditionTrue, ReasonDefault
		cond.Message = "no reference: the built-in default denies everything in this direction"
	case policy == nil:
		cond.Status, cond.Reason = metav1.ConditionFalse, ReasonNotFound
		cond.Message = "TrafficPolicy " + ref.Name + " does not exist; this direction denies everything"
	case IsReservedConflict(policy):
		cond.Status, cond.Reason = metav1.ConditionFalse, ReasonPolicyConflict
		cond.Message = "TrafficPolicy " + ref.Name + " holds the reserved default name but is not the " +
			"controller's default policy; this direction denies everything"
	default:
		st.Policy = &galacticv1alpha1.PolicyIdentity{
			Name: policy.Name, UID: string(policy.UID), Generation: policy.Generation,
		}
		if _, errs := trafficpolicy.FromAPI(policy.Spec, field.NewPath("spec")); len(errs) > 0 {
			cond.Status, cond.Reason = metav1.ConditionFalse, ReasonPolicyInvalid
			cond.Message = "TrafficPolicy " + ref.Name + " is invalid: " + errs.ToAggregate().Error() +
				"; nodes keep its last valid version, or deny if they have none"
		} else {
			cond.Status, cond.Reason = metav1.ConditionTrue, ReasonResolved
			cond.Message = "resolved to TrafficPolicy " + ref.Name
		}
	}
	meta.SetStatusCondition(&st.Conditions, cond)
	return st
}
