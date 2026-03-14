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

// BGPPeeringPolicySpec defines the desired peering automation behavior.
type BGPPeeringPolicySpec struct {
	// Selector selects BGPEndpoint resources to include in this policy.
	// +required
	Selector metav1.LabelSelector `json:"selector"`

	// Mode defines how selected endpoints are peered.
	// "mesh" creates a BGPSession between every pair of matching endpoints.
	// +kubebuilder:validation:Enum=mesh
	// +kubebuilder:default=mesh
	// +optional
	Mode string `json:"mode,omitempty"`

	// SessionTemplate provides defaults for created BGPSession resources.
	// +optional
	SessionTemplate *BGPSessionTemplate `json:"sessionTemplate,omitempty"`
}

// BGPSessionTemplate provides default values for BGPSession resources created
// by a BGPPeeringPolicy.
type BGPSessionTemplate struct {
	// HoldTime is the BGP hold time in seconds.
	// +optional
	HoldTime int32 `json:"holdTime,omitempty"`

	// KeepaliveTime is the BGP keepalive interval in seconds.
	// +optional
	KeepaliveTime int32 `json:"keepaliveTime,omitempty"`
}

// BGPPeeringPolicyStatus reflects the observed state of a BGPPeeringPolicy.
type BGPPeeringPolicyStatus struct {
	// Conditions describe the current state of the policy.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// MatchedEndpoints is the number of BGPEndpoint resources matching the selector.
	// +optional
	MatchedEndpoints int32 `json:"matchedEndpoints,omitempty"`

	// ActiveSessions is the number of BGPSession resources created by this policy.
	// +optional
	ActiveSessions int32 `json:"activeSessions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,shortName=bgppp
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Endpoints",type=integer,JSONPath=`.status.matchedEndpoints`
// +kubebuilder:printcolumn:name="Sessions",type=integer,JSONPath=`.status.activeSessions`

// BGPPeeringPolicy automates BGPSession creation by selecting BGPEndpoint resources
// via label selectors and creating sessions based on the chosen mode.
// In "mesh" mode, a BGPSession is created for every pair of matching endpoints.
type BGPPeeringPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec BGPPeeringPolicySpec `json:"spec"`
	// +optional
	Status BGPPeeringPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BGPPeeringPolicyList contains a list of BGPPeeringPolicy.
type BGPPeeringPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPPeeringPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPPeeringPolicy{}, &BGPPeeringPolicyList{})
}
