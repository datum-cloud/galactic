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

// BGPAdvertisementSpec declares one or more prefixes to advertise into BGP.
type BGPAdvertisementSpec struct {
	// Prefixes is the list of IPv6 CIDR prefixes to advertise.
	// +kubebuilder:validation:MinItems=1
	// +required
	Prefixes []string `json:"prefixes"`

	// PeerSelector selects which BGPPeer resources this advertisement targets.
	// If empty, the prefixes are advertised to all peers.
	// +optional
	PeerSelector *metav1.LabelSelector `json:"peerSelector,omitempty"`

	// Communities is a list of BGP community values to attach to the advertised routes.
	// Format: "AS:value" (e.g. "65001:100"). Phase 2+ extensibility placeholder.
	// +optional
	Communities []string `json:"communities,omitempty"`

	// LocalPref sets the LOCAL_PREF attribute. Only meaningful for iBGP.
	// Phase 2+ extensibility placeholder.
	// +kubebuilder:validation:Minimum=0
	// +optional
	LocalPref *uint32 `json:"localPref,omitempty"`
}

// BGPAdvertisementStatus reflects the observed advertising state.
type BGPAdvertisementStatus struct {
	// Conditions describe the current state of the advertisement.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// AdvertisedPrefixCount is how many prefixes are currently in the GoBGP RIB.
	// +optional
	AdvertisedPrefixCount int32 `json:"advertisedPrefixCount,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,shortName=bgpadvert
// Phase 2 resource — defined here for schema completeness.

// BGPAdvertisement declares what IPv6 prefixes the local speaker should advertise.
type BGPAdvertisement struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec BGPAdvertisementSpec `json:"spec"`
	// +optional
	Status BGPAdvertisementStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BGPAdvertisementList contains a list of BGPAdvertisement.
type BGPAdvertisementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPAdvertisement `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPAdvertisement{}, &BGPAdvertisementList{})
}
