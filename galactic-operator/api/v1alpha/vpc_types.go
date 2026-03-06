package v1alpha

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VPCSpec defines the desired state of a VPC
type VPCSpec struct {
	// A list of networks in IPv4 or IPv6 CIDR notation associated with the VPC
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:Items=string
	Networks []string `json:"networks"`
}

// VPCStatus defines the observed state of a VPC
type VPCStatus struct {
	// Indicates whether the VPC is ready for use
	// +required
	// +default:value=false
	Ready bool `json:"ready,omitempty"`

	// A unique identifier assigned to this VPC
	// +optional
	Identifier string `json:"identifier,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// VPC is the Schema for the vpcs API
type VPC struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of a VPC
	// +required
	Spec VPCSpec `json:"spec"`

	// status defines the observed state of a VPC
	// +optional
	Status VPCStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// VPCList contains a list of VPCs
type VPCList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPC `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VPC{}, &VPCList{})
}
