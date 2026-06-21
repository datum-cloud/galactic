// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	bgpv1alpha1 "go.miloapis.com/cosmos/api/bgp/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Condition types used across BGP resources.
const (
	// BGPRouter conditions.
	ConditionReady         = "Ready"
	ConditionConfigApplied = "ConfigApplied"

	// BGPPeer FSM conditions (set by setPeerSessionState).
	ConditionSessionIdle     = "SessionIdle"
	ConditionSessionConnect  = "SessionConnect"
	ConditionSessionActive   = "SessionActive"
	ConditionSessionOpenSent = "SessionOpenSent"
	ConditionSessionOpenCfm  = "SessionOpenConfirm"
	ConditionSessionEstab    = "SessionEstablished"

	// BGPAdvertisement conditions.
	ConditionAdvertised = "Advertised"

	// BGPPolicy conditions.
	ConditionPolicyApplied = "PolicyApplied"
)

// fsmConditions is the ordered set of FSM session condition type names.
var fsmConditions = []string{
	ConditionSessionIdle,
	ConditionSessionConnect,
	ConditionSessionActive,
	ConditionSessionOpenSent,
	ConditionSessionOpenCfm,
	ConditionSessionEstab,
}

// fsmStateToCondition maps a BGPPeerState to its corresponding condition name.
var fsmStateToCondition = map[bgpv1alpha1.BGPPeerState]string{
	bgpv1alpha1.BGPPeerStateIdle:        ConditionSessionIdle,
	bgpv1alpha1.BGPPeerStateConnect:     ConditionSessionConnect,
	bgpv1alpha1.BGPPeerStateActive:      ConditionSessionActive,
	bgpv1alpha1.BGPPeerStateOpenSent:    ConditionSessionOpenSent,
	bgpv1alpha1.BGPPeerStateOpenConfirm: ConditionSessionOpenCfm,
	bgpv1alpha1.BGPPeerStateEstablished: ConditionSessionEstab,
}

// setRouterPhase sets the BGPRouter phase in status.
func setRouterPhase(router *bgpv1alpha1.BGPRouter, phase bgpv1alpha1.BGPRouterPhase) {
	router.Status.Phase = phase
	router.Status.ObservedGeneration = router.Generation
}

// setRouterCondition sets or updates a condition on BGPRouter.
func setRouterCondition(router *bgpv1alpha1.BGPRouter, condition metav1.Condition) {
	condition.ObservedGeneration = router.Generation
	meta.SetStatusCondition(&router.Status.Conditions, condition)
}

// setPeerSessionState updates the BGPPeer session state and sets exactly one
// FSM condition to True, all others to False.
func setPeerSessionState(peer *bgpv1alpha1.BGPPeer, state bgpv1alpha1.BGPPeerState) {
	peer.Status.SessionState = state
	peer.Status.ObservedGeneration = peer.Generation

	activeCondition := fsmStateToCondition[state]
	for _, condType := range fsmConditions {
		status := metav1.ConditionFalse
		reason := "NotInState"
		if condType == activeCondition {
			status = metav1.ConditionTrue
			reason = string(state)
		}
		meta.SetStatusCondition(&peer.Status.Conditions, metav1.Condition{
			Type:               condType,
			Status:             status,
			ObservedGeneration: peer.Generation,
			Reason:             reason,
		})
	}
}

// setPeerCondition sets or updates a condition on BGPPeer.
func setPeerCondition(peer *bgpv1alpha1.BGPPeer, condition metav1.Condition) {
	condition.ObservedGeneration = peer.Generation
	meta.SetStatusCondition(&peer.Status.Conditions, condition)
}

// setAdvertisementCondition sets or updates a condition on BGPAdvertisement.
func setAdvertisementCondition(adv *bgpv1alpha1.BGPAdvertisement, condition metav1.Condition) {
	condition.ObservedGeneration = adv.Generation
	meta.SetStatusCondition(&adv.Status.Conditions, condition)
}

// setPolicyCondition sets or updates a condition on BGPPolicy.
func setPolicyCondition(policy *bgpv1alpha1.BGPPolicy, condition metav1.Condition) {
	condition.ObservedGeneration = policy.Generation
	meta.SetStatusCondition(&policy.Status.Conditions, condition)
}
