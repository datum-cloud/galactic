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

	// Routes defines additional routing entries for the VPCAttachment.
	// +optional
	Routes []VPCAttachmentRoute `json:"routes,omitempty"`
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

// VPCAttachmentRoute defines a routing entry for the VPCAttachment.
type VPCAttachmentRoute struct {
	// IPv4 or IPv6 destination network in CIDR notation.
	// +required
	Destination string `json:"destination"`

	// Via is the next hop address.
	// +optional
	Via string `json:"via"`
}

// VPCAttachmentStatus defines the observed state of VPCAttachment.
type VPCAttachmentStatus struct {
	// Indicates whether the VPCAttachment is ready for use
	// +required
	// +default:value=false
	Ready bool `json:"ready,omitempty"`

	// A unique identifier assigned to this VPCAttachment
	// +optional
	Identifier string `json:"identifier,omitempty"`
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
