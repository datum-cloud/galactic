/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BGPRoutePolicySpec declares import/export filtering rules.
type BGPRoutePolicySpec struct {
	// Type is "Import" or "Export".
	// +kubebuilder:validation:Enum=Import;Export
	// +required
	Type string `json:"type"`

	// PeerSelector selects which BGPPeer resources this policy applies to.
	// If empty, the policy applies to all peers.
	// +optional
	PeerSelector *metav1.LabelSelector `json:"peerSelector,omitempty"`

	// Statements is an ordered list of policy statements.
	// Statements are evaluated in order; first match wins.
	// +kubebuilder:validation:MinItems=1
	// +required
	Statements []PolicyStatement `json:"statements"`
}

// PolicyStatement is a single policy rule.
type PolicyStatement struct {
	// PrefixSet is the set of prefixes to match against.
	// +optional
	PrefixSet []PrefixMatch `json:"prefixSet,omitempty"`

	// Action is "Accept" or "Reject".
	// +kubebuilder:validation:Enum=Accept;Reject
	// +required
	Action string `json:"action"`
}

// PrefixMatch matches a prefix and an optional length range.
// Primary Phase 2 use: reject individual /48s when an aggregate /40 covers them.
type PrefixMatch struct {
	// CIDR is the prefix to match (e.g. "2001:db8:ff00::/40").
	// +required
	CIDR string `json:"cidr"`

	// MaskLengthMin constrains the match to prefixes with mask >= this length.
	// +optional
	MaskLengthMin *uint32 `json:"maskLengthMin,omitempty"`

	// MaskLengthMax constrains the match to prefixes with mask <= this length.
	// +optional
	MaskLengthMax *uint32 `json:"maskLengthMax,omitempty"`
}

// BGPRoutePolicyStatus reflects the observed policy state.
type BGPRoutePolicyStatus struct {
	// Conditions describe the current state of the policy.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,shortName=bgprp
// Phase 2 resource — defined here for schema completeness.

// BGPRoutePolicy declares import/export filtering rules applied to BGP sessions.
type BGPRoutePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec BGPRoutePolicySpec `json:"spec"`
	// +optional
	Status BGPRoutePolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BGPRoutePolicyList contains a list of BGPRoutePolicy.
type BGPRoutePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPRoutePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPRoutePolicy{}, &BGPRoutePolicyList{})
}
