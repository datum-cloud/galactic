// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// Condition types used across BGP resources.
const (
	// BGPRouter conditions.
	ConditionReady         = "Ready"
	ConditionConfigApplied = "ConfigApplied"

	// BGPAdvertisement conditions.
	ConditionAdvertised = "Advertised"

	// BGPPolicy conditions.
	ConditionPolicyApplied = "PolicyApplied"
)

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

// setPeerReadyCondition updates the Ready condition from the current FSM state.
// Ready is true only when the session is Established, and false otherwise with
// the reason set to the FSM state; for Idle, idleReason is used instead.
func setPeerReadyCondition(peer *bgpv1alpha1.BGPPeer, state bgpv1alpha1.BGPPeerState, idleReason string) {
	peer.Status.SessionState = state
	peer.Status.ObservedGeneration = peer.Generation

	cond := metav1.Condition{
		Type:               bgpv1alpha1.ConditionTypeReady,
		ObservedGeneration: peer.Generation,
	}

	switch state {
	case bgpv1alpha1.BGPPeerStateEstablished:
		cond.Status = metav1.ConditionTrue
		cond.Reason = "Established"
		cond.Message = "BGP session is Established; address families negotiated."
	case bgpv1alpha1.BGPPeerStateOpenConfirm:
		cond.Status = metav1.ConditionFalse
		cond.Reason = "OpenConfirm"
		cond.Message = "BGP session in OpenConfirm state, awaiting KEEPALIVE."
	case bgpv1alpha1.BGPPeerStateOpenSent:
		cond.Status = metav1.ConditionFalse
		cond.Reason = "OpenSent"
		cond.Message = "BGP OPEN message sent, awaiting peer OPEN."
	case bgpv1alpha1.BGPPeerStateActive:
		cond.Status = metav1.ConditionFalse
		cond.Reason = "Active"
		cond.Message = "BGP session Active, attempting to establish TCP connection."
	case bgpv1alpha1.BGPPeerStateConnect:
		cond.Status = metav1.ConditionFalse
		cond.Reason = "Connect"
		cond.Message = "BGP session in Connect state, waiting for TCP connection."
	case bgpv1alpha1.BGPPeerStateIdle:
		cond.Status = metav1.ConditionFalse
		cond.Reason = idleReason
		cond.Message = "BGP session is Idle."
	default:
		cond.Status = metav1.ConditionFalse
		cond.Reason = "Unknown"
		cond.Message = "BGP session is in unknown state " + string(state) + "."
	}

	meta.SetStatusCondition(&peer.Status.Conditions, cond)
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

// setVRFInstanceCondition sets or updates a condition on BGPVRFInstance.
func setVRFInstanceCondition(vrf *bgpv1alpha1.BGPVRFInstance, condition metav1.Condition) {
	condition.ObservedGeneration = vrf.Generation
	meta.SetStatusCondition(&vrf.Status.Conditions, condition)
}

// ConditionNPTv6Configured reports whether a BGPVRFInstance's NPTv6 field, when
// set, parses into a valid mapping. It is defined here rather than in the API
// module this workstream does not own, generic conditions being exactly the
// extension point the status already exposes.
//
// It reflects config validity only, never live datapath state: the process that
// registers those map entries runs in a different container with no access back
// to this CRD's status.
const ConditionNPTv6Configured = "NPTv6Configured"

// setGatewayCondition sets or updates a condition on a NetworkGateway. Ready is
// the only type it currently uses.
func setGatewayCondition(gw *bgpv1alpha1.NetworkGateway, condition metav1.Condition) {
	condition.ObservedGeneration = gw.Generation
	meta.SetStatusCondition(&gw.Status.Conditions, condition)
}

// setBindingCondition sets or updates a condition on a ServiceVIPBinding. Bound
// is the only type it uses.
func setBindingCondition(binding *bgpv1alpha1.ServiceVIPBinding, condition metav1.Condition) {
	condition.ObservedGeneration = binding.Generation
	meta.SetStatusCondition(&binding.Status.Conditions, condition)
}

// setRuleCondition sets or updates a condition on a NetworkRule. It uses two
// types: Accepted, from the admission ownership check, and Ready, from the
// engine's convergence result for that rule.
func setRuleCondition(rule *bgpv1alpha1.NetworkRule, condition metav1.Condition) {
	condition.ObservedGeneration = rule.Generation
	meta.SetStatusCondition(&rule.Status.Conditions, condition)
}

// setEgressShardCondition sets or updates a condition on an EgressShard. Ready is
// the only type it currently uses.
func setEgressShardCondition(shard *bgpv1alpha1.EgressShard, condition metav1.Condition) {
	condition.ObservedGeneration = shard.Generation
	meta.SetStatusCondition(&shard.Status.Conditions, condition)
}
