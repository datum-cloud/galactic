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

// PeeringPolicyRRConfig specifies how to identify the route reflector endpoint.
type PeeringPolicyRRConfig struct {
	// ReflectorSelector selects exactly one BGPEndpoint to act as the route reflector.
	// If the selector matches more than one endpoint, an error condition is set and
	// no sessions are created.
	// +required
	ReflectorSelector metav1.LabelSelector `json:"reflectorSelector"`

	// ClusterID is the BGP route reflector cluster ID assigned to all client sessions.
	// Must be a valid dotted-decimal IPv4 string (BGP convention).
	// +required
	ClusterID string `json:"clusterID"`
}

// BGPPeeringPolicySpec defines the desired peering automation behavior.
type BGPPeeringPolicySpec struct {
	// Selector selects BGPEndpoint resources to include in this policy.
	// +required
	Selector metav1.LabelSelector `json:"selector"`

	// Mode defines how selected endpoints are peered.
	// "mesh" creates a BGPSession between every pair of matching endpoints.
	// "route-reflector" creates sessions between the route reflector and each client endpoint.
	// +kubebuilder:validation:Enum=mesh;route-reflector
	// +kubebuilder:default=mesh
	// +optional
	Mode string `json:"mode,omitempty"`

	// SessionTemplate provides defaults for created BGPSession resources.
	// +optional
	SessionTemplate *BGPSessionTemplate `json:"sessionTemplate,omitempty"`

	// RouteReflectorConfig holds route-reflector topology parameters.
	// Required when mode is "route-reflector".
	// +optional
	RouteReflectorConfig *PeeringPolicyRRConfig `json:"routeReflectorConfig,omitempty"`
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

// Condition type constants for BGPPeeringPolicy.
const (
	// BGPPeeringPolicyInvalidConfig indicates the policy spec is invalid (e.g.
	// route-reflector mode with missing or ambiguous ReflectorSelector).
	BGPPeeringPolicyInvalidConfig = "InvalidConfig"
)

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
