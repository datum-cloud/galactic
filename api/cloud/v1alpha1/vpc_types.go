/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VPCFinalizer is the finalizer applied to VPCs to ensure graceful cleanup.
const VPCFinalizer = "galactic.datumapis.com/finalizer"

// Network is an IPv4 or IPv6 CIDR block (e.g., "10.0.0.0/24").
// +kubebuilder:validation:MaxLength=64
type Network string

// VPCSpec defines the desired state of a VPC. It specifies the CIDR address space.
//
// +kubebuilder:validation:XValidation:rule="self.networks.all(n, isCIDR(n))",message="each network must be a valid IPv4 or IPv6 CIDR"
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable"
type VPCSpec struct {
	// CIDR blocks that form the VPC address space.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	Networks []Network `json:"networks"`
}

// VPCStatus defines the observed state of a VPC, populated by the controller.
type VPCStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Base62-encoded VPC identifier.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=16
	VPC string `json:"vpc"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="VPC",type="string",JSONPath=".status.vpc",description="Base62 VPC identifier"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description="Ready status"

// VPC represents a virtual private cloud — an isolated Layer 2 domain backed
// by one or more CIDR blocks.
type VPC struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Desired CIDR address space.
	// +required
	Spec VPCSpec `json:"spec"`

	// Controller-observed state.
	// +optional
	Status VPCStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VPCList is a list of VPC resources.
type VPCList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPC `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VPC{}, &VPCList{})
}
