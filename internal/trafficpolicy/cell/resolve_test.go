// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cell

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

func TestResolve(t *testing.T) {
	const uid = "u-1"
	ref := &galacticv1alpha1.LocalPolicyReference{Name: "web"}
	valid := &galacticv1alpha1.TrafficPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "web", UID: uid, Generation: 3},
		Spec: galacticv1alpha1.TrafficPolicySpec{Rules: []galacticv1alpha1.TrafficRule{{
			Name: "a", Action: galacticv1alpha1.ActionAllow,
		}}},
	}
	// Admitted before a stricter validator, or written past admission: its
	// identity still reaches the nodes, which keep the last valid version.
	invalid := valid.DeepCopy()
	invalid.Spec.Rules = append(invalid.Spec.Rules, galacticv1alpha1.TrafficRule{
		Name: "a", Action: galacticv1alpha1.ActionDeny,
	})
	ownDefault := DefaultPolicy("tenant-a")
	ownDefault.UID = "u-default"
	conflict := ownDefault.DeepCopy()
	conflict.Labels = nil

	tests := []struct {
		name       string
		ref        *galacticv1alpha1.LocalPolicyReference
		policy     *galacticv1alpha1.TrafficPolicy
		status     metav1.ConditionStatus
		reason     string
		identityOf string // the expected Policy.UID, empty for none
	}{
		{"omitted", nil, nil, metav1.ConditionTrue, ReasonDefault, galacticv1alpha1.DefaultPolicyUID},
		{"missing", ref, nil, metav1.ConditionFalse, ReasonNotFound, ""},
		{"valid", ref, valid, metav1.ConditionTrue, ReasonResolved, uid},
		{"invalid", ref, invalid, metav1.ConditionFalse, ReasonPolicyInvalid, uid},
		{"explicit default", &galacticv1alpha1.LocalPolicyReference{Name: galacticv1alpha1.DefaultPolicyName},
			ownDefault, metav1.ConditionTrue, ReasonResolved, "u-default"},
		{"conflicting default", &galacticv1alpha1.LocalPolicyReference{Name: galacticv1alpha1.DefaultPolicyName},
			conflict, metav1.ConditionFalse, ReasonPolicyConflict, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := Resolve(tt.ref, tt.policy, 7)
			c := meta.FindStatusCondition(st.Conditions, ConditionResolved)
			if c == nil || c.Status != tt.status || c.Reason != tt.reason || c.ObservedGeneration != 7 {
				t.Fatalf("condition = %+v, want %s/%s at generation 7", c, tt.status, tt.reason)
			}
			switch {
			case tt.identityOf == "" && st.Policy != nil:
				t.Errorf("policy = %+v, want none", st.Policy)
			case tt.identityOf != "" && (st.Policy == nil || st.Policy.UID != tt.identityOf):
				t.Errorf("policy = %+v, want UID %s", st.Policy, tt.identityOf)
			}
		})
	}
}
