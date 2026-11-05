// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// Service route policies are requeued for a BGPRouter or BGPVRFInstance only
// when it can change an attachment's SID, not for the status and annotation
// writes that nearly every BGPRouter reconcile makes.
func TestRoutingDependencyChangedPassesOnlySIDInputs(t *testing.T) {
	router := &networkv1alpha1.BGPRouter{ObjectMeta: metav1.ObjectMeta{Name: "watch-router", Generation: 3}}
	statusOnly := router.DeepCopy()
	now := metav1.Now()
	statusOnly.Status.LastSuccessfulReconcileTime = &now
	statusOnly.Annotations = map[string]string{annotationConfigHash: "next"}
	specChange := router.DeepCopy()
	specChange.Generation++
	vrf := &networkv1alpha1.BGPVRFInstance{ObjectMeta: metav1.ObjectMeta{Name: "7-watch-router", Generation: 1}}
	vrfStatus := vrf.DeepCopy()
	vrfStatus.Status.Conditions = []metav1.Condition{{Type: ConditionReady, Status: metav1.ConditionTrue}}

	if routingDependencyChanged.Update(event.UpdateEvent{ObjectOld: router, ObjectNew: statusOnly}) {
		t.Error("a BGPRouter status and annotation write requeued every policy")
	}
	if routingDependencyChanged.Update(event.UpdateEvent{ObjectOld: vrf, ObjectNew: vrfStatus}) {
		t.Error("a BGPVRFInstance status write requeued every policy")
	}
	if !routingDependencyChanged.Update(event.UpdateEvent{ObjectOld: router, ObjectNew: specChange}) {
		t.Error("a BGPRouter spec change did not requeue the policies")
	}
	if !routingDependencyChanged.Create(event.CreateEvent{Object: vrf}) ||
		!routingDependencyChanged.Delete(event.DeleteEvent{Object: vrf}) {
		t.Error("a BGPVRFInstance arriving or leaving did not requeue the policies")
	}
}
