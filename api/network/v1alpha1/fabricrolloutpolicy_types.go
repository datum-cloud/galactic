// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// FabricRolloutPolicy sets how the rollout manager promotes and observes
// the routers that reference it.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=frpolicy
type FabricRolloutPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec FabricRolloutPolicySpec `json:"spec"`
}

// FabricRolloutPolicySpec are the rollout settings. The rollout manager
// copies the ones the agent needs into each promotion's activation
// settings.
//
// +kubebuilder:validation:XValidation:rule="!has(self.optionalPeers) || !has(self.maintenancePeers) || self.optionalPeers.all(o, !self.maintenancePeers.exists(m, m.name == o.name))",message="a peer is optional or in maintenance, not both"
type FabricRolloutPolicySpec struct {
	// MaxUnavailable is how many routers of one failure domain, within one
	// cell, may be activating at once.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	MaxUnavailable int32 `json:"maxUnavailable,omitempty"`

	// FailureDomainLabel is the Node label that groups routers.
	// +kubebuilder:default="topology.kubernetes.io/zone"
	// +kubebuilder:validation:MaxLength=317
	// +kubebuilder:validation:Pattern=`^([a-z0-9]([-a-z0-9.]*[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`
	FailureDomainLabel string `json:"failureDomainLabel,omitempty"`

	// StabilizationSeconds is how long an applied revision must stay
	// healthy before the agent commits it.
	// +kubebuilder:default=60
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	StabilizationSeconds int32 `json:"stabilizationSeconds,omitempty"`

	// ApplyTimeoutSeconds bounds one reload.
	// +kubebuilder:default=60
	// +kubebuilder:validation:Minimum=5
	// +kubebuilder:validation:Maximum=900
	ApplyTimeoutSeconds int32 `json:"applyTimeoutSeconds,omitempty"`

	// HeartbeatTimeoutSeconds is how long an agent's silence leaves its
	// router healthy before readiness becomes Unknown.
	// +kubebuilder:default=60
	// +kubebuilder:validation:Minimum=10
	// +kubebuilder:validation:Maximum=3600
	HeartbeatTimeoutSeconds int32 `json:"heartbeatTimeoutSeconds,omitempty"`

	// OfflineBootSeconds is how long a committed checkpoint may be applied
	// at boot without the API.
	// +kubebuilder:default=604800
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=7776000
	OfflineBootSeconds int64 `json:"offlineBootSeconds,omitempty"`

	// OptionalPeers names BGPPeers, in the policy's namespace, that need not
	// reach Established for a router to be healthy.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=256
	OptionalPeers []LocalObjectRef `json:"optionalPeers,omitempty"`

	// MaintenancePeers names BGPPeers, in the policy's namespace, that are
	// administratively down and excluded from health.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=256
	MaintenancePeers []LocalObjectRef `json:"maintenancePeers,omitempty"`

	// MinWitnesses is how many other routers must see a router's
	// originations before a promotion counts as healthy.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	MinWitnesses int32 `json:"minWitnesses,omitempty"`
}

// FabricRolloutPolicyList is a list of FabricRolloutPolicy resources.
// +kubebuilder:object:root=true
type FabricRolloutPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricRolloutPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FabricRolloutPolicy{}, &FabricRolloutPolicyList{})
}
