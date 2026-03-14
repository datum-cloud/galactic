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

// BGPEndpointSpec declares the identity of a BGP speaker endpoint.
// An endpoint is a self-advertisement: "I exist at this address, with this AS."
type BGPEndpointSpec struct {
	// Address is the IPv6 address of this BGP speaker.
	// +kubebuilder:validation:Format=ipv6
	// +required
	Address string `json:"address"`

	// ASNumber is the AS number this endpoint belongs to.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	// +required
	ASNumber uint32 `json:"asNumber"`

	// AddressFamilies lists the address families this endpoint supports.
	// Defaults to IPv6 unicast.
	// +optional
	AddressFamilies []AddressFamily `json:"addressFamilies,omitempty"`
}

// BGPEndpointStatus reflects the observed state of a BGPEndpoint.
type BGPEndpointStatus struct {
	// Conditions describe the current state of the endpoint.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,shortName=bgpep
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.spec.address`
// +kubebuilder:printcolumn:name="ASN",type=integer,JSONPath=`.spec.asNumber`

// BGPEndpoint declares a BGP speaker endpoint — an address and AS number that
// other speakers can peer with. Endpoints are produced by the node auto-peer
// operator (one per node) or created manually by platform operators.
// BGPPeeringPolicy resources reference endpoints via label selectors to
// automate session creation.
type BGPEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec BGPEndpointSpec `json:"spec"`
	// +optional
	Status BGPEndpointStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BGPEndpointList contains a list of BGPEndpoint.
type BGPEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPEndpoint `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPEndpoint{}, &BGPEndpointList{})
}
