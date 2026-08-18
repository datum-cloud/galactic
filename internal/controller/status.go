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

// setPeerReadyCondition updates the Ready condition based on the current BGP
// FSM state, following the same semantics as the reference implementation in
// the BGP API (BGPPeerStatus.updatePeerConditions). Ready is True only when
// sessionState == Established; False otherwise with Reason set to the FSM
// state (for Idle, the idleReason argument is used).
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

// ConditionNPTv6Configured reports whether a BGPVRFInstance's own
// Spec.NPTv6 field (when set) parses into a valid RFC 6296 mapping —
// locally defined here (rather than added to the network module's own
// vrf_types.go, which this workstream does not own) since generic
// Conditions is exactly the extension point BGPVRFInstanceStatus already
// exposes for this. It reflects config validity only, not live eBPF
// datapath state: the process that actually registers/reconciles
// nptv6_table entries (gc.SweepEBPFNPTv6Table, run from
// internal/installer.Run inside the CNI "run" container) has no access
// back to this CRD's status from there — see that function's own doc
// comment for why eBPF map access is confined to that container.
const ConditionNPTv6Configured = "NPTv6Configured"

// setGatewayCondition sets or updates a condition on NetworkGateway.
// ConditionTypeReady (reused from peer_types.go, not redeclared) is the
// only condition type NetworkGateway currently uses.
func setGatewayCondition(gw *bgpv1alpha1.NetworkGateway, condition metav1.Condition) {
	condition.ObservedGeneration = gw.Generation
	meta.SetStatusCondition(&gw.Status.Conditions, condition)
}

// setBindingCondition sets or updates a condition on ServiceVIPBinding.
// bgpv1alpha1.ConditionTypeBound (vipbinding_types.go) is the only
// condition type ServiceVIPBinding uses.
func setBindingCondition(binding *bgpv1alpha1.ServiceVIPBinding, condition metav1.Condition) {
	condition.ObservedGeneration = binding.Generation
	meta.SetStatusCondition(&binding.Status.Conditions, condition)
}

// setRuleCondition sets or updates a condition on NetworkRule.
// ConditionTypeReady and ConditionTypeAccepted (both reused from
// peer_types.go) are the condition types NetworkRule uses — Accepted per
// the admission-webhook ownership check (internal/webhook), Ready per the
// engine's own convergence result for that rule.
func setRuleCondition(rule *bgpv1alpha1.NetworkRule, condition metav1.Condition) {
	condition.ObservedGeneration = rule.Generation
	meta.SetStatusCondition(&rule.Status.Conditions, condition)
}

// setNAT66ShardCondition sets or updates a condition on NAT66Shard.
// ConditionTypeReady (reused from peer_types.go, not redeclared) is the
// only condition type NAT66Shard currently uses — mirrors
// setGatewayCondition's identical shape for NetworkGateway.
func setNAT66ShardCondition(shard *bgpv1alpha1.NAT66Shard, condition metav1.Condition) {
	condition.ObservedGeneration = shard.Generation
	meta.SetStatusCondition(&shard.Status.Conditions, condition)
}
