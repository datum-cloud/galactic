// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const VPCAttachmentAnnotation = "k8s.v1alpha.galactic.datumapis.com/vpc-attachment"

// VPCAttachmentSpec defines the desired state of VPCAttachment
type VPCAttachmentSpec struct {
	// VPC this attachment belongs to.
	// +required
	VPC corev1.ObjectReference `json:"vpc"`

	// Interface defines the network interface configuration.
	// +required
	Interface VPCAttachmentInterface `json:"interface"`
}

// VPCAttachmentInterface defines the network interface details.
type VPCAttachmentInterface struct {
	// Name of the interface (e.g., eth0).
	// +required
	// +default:value="galactic0"
	Name string `json:"name"`

	// A list of IPv4 or IPv6 addresses associated with the interface.
	// +kubebuilder:validation:MinItems=1
	// +required
	Addresses []string `json:"addresses"`
}

// VPCAttachmentStatus defines the observed state of VPCAttachment.
type VPCAttachmentStatus struct {
	// Indicates whether the VPCAttachment is ready for use
	// +required
	// +default:value=false
	Ready bool `json:"ready,omitempty"`

	// A unique 16-bit hex identifier (4 lowercase hex characters) assigned
	// to this VPCAttachment, scoped to its parent VPC.
	// +optional
	Identifier string `json:"identifier,omitempty"`

	// The full IPv6 SRv6 service SID for this VPCAttachment, computed as
	// <pop-locator>:<vpc-id-32>:<attachment-id-16>:<zero-16>. Agents
	// install END.DT46 decap for this SID locally and advertise it as the
	// SRv6 service SID for VPN BGP UPDATEs originating pods on this
	// attachment.
	// +optional
	ServiceSID string `json:"serviceSID,omitempty"`

	// The BGP route target for this VPCAttachment's parent VPC, formatted
	// as <asn>:<vpc-id-32>. Encoded on the wire as a transitive 4-octet
	// AS-specific extended community (RFC 5668, type 0x0202). All
	// VPCAttachments belonging to the same VPC share the same route
	// target.
	// +optional
	RouteTarget string `json:"routeTarget,omitempty"`

	// The BGP route distinguisher for this VPCAttachment's parent VPC,
	// formatted as <asn>:<vpc-id-32>. Encoded on the wire as RD type 2
	// (4-byte ASN administrator + 4-byte assigned). Same value across all
	// attachments in the VPC.
	// +optional
	RouteDistinguisher string `json:"routeDistinguisher,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// VPCAttachment is the Schema for the vpcattachments API
type VPCAttachment struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of VPCAttachment
	// +required
	Spec VPCAttachmentSpec `json:"spec"`

	// status defines the observed state of VPCAttachment
	// +optional
	Status VPCAttachmentStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// VPCAttachmentList contains a list of VPCAttachments
type VPCAttachmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPCAttachment `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VPCAttachment{}, &VPCAttachmentList{})
}
