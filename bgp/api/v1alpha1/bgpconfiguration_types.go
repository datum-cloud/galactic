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

// BGPConfigurationSpec declares the local BGP speaker identity.
// There should be exactly one BGPConfiguration per cluster.
type BGPConfigurationSpec struct {
	// ASNumber is the local AS number for this BGP speaker.
	// For single-cluster iBGP, all nodes share the same AS number.
	// For multi-cluster eBGP, each cluster has a unique AS number.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	// +required
	ASNumber uint32 `json:"asNumber"`

	// ListenPort is the TCP port GoBGP listens on for BGP sessions.
	// Defaults to 1790 (Galactic convention, non-privileged).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=1790
	// +optional
	ListenPort int32 `json:"listenPort,omitempty"`

	// RouterIDSource controls how the router ID is determined.
	// "NodeIP" uses the node's IPv6 InternalIP (default).
	// "Manual" requires routerID to be set explicitly.
	// +kubebuilder:validation:Enum=NodeIP;Manual
	// +kubebuilder:default=NodeIP
	// +optional
	RouterIDSource string `json:"routerIDSource,omitempty"`

	// RouterID is the BGP router ID. Required when routerIDSource is "Manual".
	// Must be a valid IPv4 address in dotted-decimal notation (BGP convention).
	// +optional
	RouterID string `json:"routerID,omitempty"`

	// AddressFamilies lists the address families the speaker should activate.
	// Defaults to IPv6 unicast only.
	// +optional
	AddressFamilies []AddressFamily `json:"addressFamilies,omitempty"`
}

// AddressFamily identifies a BGP address family.
type AddressFamily struct {
	// AFI is the Address Family Indicator.
	// +kubebuilder:validation:Enum=IPv4;IPv6
	// +required
	AFI string `json:"afi"`

	// SAFI is the Subsequent Address Family Indicator.
	// +kubebuilder:validation:Enum=Unicast;Multicast
	// +kubebuilder:default=Unicast
	// +optional
	SAFI string `json:"safi,omitempty"`
}

// BGPConfigurationStatus reflects the observed state of the BGP speaker.
type BGPConfigurationStatus struct {
	// Conditions describe the current state of the BGP configuration.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedASNumber is the AS number currently configured in GoBGP.
	// +optional
	ObservedASNumber uint32 `json:"observedASNumber,omitempty"`

	// ObservedRouterID is the router ID currently configured in GoBGP.
	// +optional
	ObservedRouterID string `json:"observedRouterID,omitempty"`
}

// Condition types for BGPConfiguration.
const (
	// BGPSpeakerReady indicates GoBGP is running and configured with this spec.
	BGPSpeakerReady = "SpeakerReady"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,shortName=bgpconfig
// +kubebuilder:printcolumn:name="AS",type=integer,JSONPath=`.spec.asNumber`
// +kubebuilder:printcolumn:name="Port",type=integer,JSONPath=`.spec.listenPort`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="SpeakerReady")].status`

// BGPConfiguration declares the local BGP speaker identity for the cluster.
// There should be exactly one BGPConfiguration per cluster.
type BGPConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec BGPConfigurationSpec `json:"spec"`
	// +optional
	Status BGPConfigurationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BGPConfigurationList contains a list of BGPConfiguration.
type BGPConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPConfiguration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPConfiguration{}, &BGPConfigurationList{})
}
