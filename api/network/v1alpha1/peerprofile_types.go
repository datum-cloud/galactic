// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// BGPPeerProfile is a reusable set of session settings that BGPPeers
// reference with spec.peerProfileRef. The FRR implementation renders a
// profile as one peer group and each referencing peer as a member. There
// is no profile inheritance: a peer's own transport and family settings
// override the profile field by field.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=bgppp
// +kubebuilder:printcolumn:name="PEER-ASN",type="integer",JSONPath=".spec.peerASN"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type BGPPeerProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec   BGPPeerProfileSpec   `json:"spec"`
	Status BGPPeerProfileStatus `json:"status,omitempty"`
}

// BGPPeerProfileSpec defines a peer profile's settings.
type BGPPeerProfileSpec struct {
	// FRR holds FRR rendering settings.
	// +optional
	FRR *BGPPeerProfileFRR `json:"frr,omitempty"`

	// PeerASN, when set, is the remote ASN of every member. A member whose
	// own peerASN differs is rejected.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	PeerASN *int64 `json:"peerASN,omitempty"`

	// Transport holds session transport settings.
	// +optional
	Transport *BGPPeerTransport `json:"transport,omitempty"`

	// AddressFamilies lists the families a member activates, with their
	// settings.
	// +optional
	// +listType=map
	// +listMapKey=afi
	// +listMapKey=safi
	// +kubebuilder:validation:MaxItems=8
	AddressFamilies []BGPPeerFamilySettings `json:"addressFamilies,omitempty"`
}

// BGPPeerProfileFRR holds FRR rendering settings for a peer profile.
type BGPPeerProfileFRR struct {
	// PeerGroupName is the FRR peer group name. When unset the profile's
	// metadata.name is used.
	// +optional
	PeerGroupName *FRRObjectName `json:"peerGroupName,omitempty"`
}

// BGPPeerProfileStatus defines the observed state of BGPPeerProfile.
type BGPPeerProfileStatus struct {
	// ObservedGeneration is the .metadata.generation this status was computed from.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions contains the standard conditions for this resource.
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// BGPPeerProfileList is a list of BGPPeerProfile resources.
// +kubebuilder:object:root=true
type BGPPeerProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPPeerProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPPeerProfile{}, &BGPPeerProfileList{})
}
