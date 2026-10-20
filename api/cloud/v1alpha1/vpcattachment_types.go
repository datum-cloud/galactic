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

const VPCAttachmentAnnotation = "k8s.v1alpha1.galactic.datumapis.com/vpc-attachment"

const (
	// ConditionTypeReady reports that identifiers are allocated and the
	// NetworkAttachmentDefinition is written.
	ConditionTypeReady = "Ready"

	// ConditionTypeProgrammed reports that the data plane realized the attachment.
	ConditionTypeProgrammed = "Programmed"
)

// VPCAttachmentSpec defines the desired state of VPCAttachment
type VPCAttachmentSpec struct {
	// VPC this attachment belongs to.
	// +required
	VPC VPCRef `json:"vpc"`

	// NetworkInterface this attachment realizes.
	// +optional
	InterfaceRef *NetworkInterfaceRef `json:"interfaceRef,omitempty"`

	// Interface defines the network interface configuration.
	// +required
	Interface VPCAttachmentInterface `json:"interface"`
}

// VPCRef references a VPC by name within the same namespace.
type VPCRef struct {
	// Name is the name of the VPC.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// NetworkInterfaceRef references a networking.datumapis.com NetworkInterface in
// the same namespace.
type NetworkInterfaceRef struct {
	// Name of the NetworkInterface.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`
}

// IPAddress is an IPv4 or IPv6 address with CIDR notation.
// +kubebuilder:validation:MaxLength=64
type IPAddress string

// VPCAttachmentInterfaceMode is how the workload consumes the interface. It
// describes the guest, not the data plane, so a change of implementation on the
// data plane side does not move this API.
// +kubebuilder:validation:Enum=Netns;Hypervisor;HypervisorDeclared
type VPCAttachmentInterfaceMode string

const (
	// VPCAttachmentInterfaceModeNetns moves the interface into the workload's
	// network namespace, which is what a container consumes.
	VPCAttachmentInterfaceModeNetns VPCAttachmentInterfaceMode = "Netns"

	// VPCAttachmentInterfaceModeHypervisor hands the interface to a hypervisor as
	// a device, which is what a virtual machine guest consumes.
	VPCAttachmentInterfaceModeHypervisor VPCAttachmentInterfaceMode = "Hypervisor"

	// VPCAttachmentInterfaceModeHypervisorDeclared also hands the interface to a
	// hypervisor as a device. It differs from Hypervisor in who tells the
	// hypervisor that the device exists. Under Hypervisor the hypervisor finds
	// the device from what the node publishes. Under HypervisorDeclared the data
	// plane states the device, its addresses, and its MTU to the hypervisor
	// directly, which is what a guest whose hypervisor reads no node state
	// needs.
	VPCAttachmentInterfaceModeHypervisorDeclared VPCAttachmentInterfaceMode = "HypervisorDeclared"
)

// VPCAttachmentInterface defines the network interface details.
//
// +kubebuilder:validation:XValidation:rule="!has(self.addresses) || self.addresses.all(a, isCIDR(a))",message="each address must be a valid IPv4 or IPv6 CIDR"
type VPCAttachmentInterface struct {
	// Name of the interface (e.g., eth0).
	// +required
	// +default:value="eth0"
	Name string `json:"name"`

	// Mode is how the workload consumes the interface, resolved and written by
	// the attachment controller rather than by whoever runs the workload.
	// +kubebuilder:default=Netns
	// +optional
	Mode VPCAttachmentInterfaceMode `json:"mode,omitempty"`

	// A list of IPv4 or IPv6 addresses associated with the interface. Empty when
	// the guest manages its own addressing.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Addresses []IPAddress `json:"addresses,omitempty"`
}

// VPCAttachmentStatus defines the observed state of VPCAttachment.
//
// Every field but Conditions is optional: an identifier is recorded before a pod
// attaches, and a guest managing its own addressing never reports a subnet.
type VPCAttachmentStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Base62-encoded VPC identifier.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=16
	// +optional
	VPC string `json:"vpc,omitempty"`

	// Base62-encoded VPCAttachment identifier.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=16
	// +optional
	VPCAttachment string `json:"vpcAttachment,omitempty"`

	// Kubernetes node name where the attachment lives.
	// +kubebuilder:validation:MinLength=1
	// +optional
	Node string `json:"node,omitempty"`

	// Full container ID (46 hex characters).
	// +kubebuilder:validation:MinLength=46
	// +kubebuilder:validation:MaxLength=46
	// +optional
	ContainerID string `json:"containerID,omitempty"`

	// Pod name.
	// +kubebuilder:validation:MinLength=1
	// +optional
	PodName string `json:"podName,omitempty"`

	// Host-side veth or tap device name (e.g., "G000000010013H").
	// +kubebuilder:validation:MinLength=1
	// +optional
	HostInterface string `json:"hostInterface,omitempty"`

	// VRF device name, which is per-VPC (e.g., "G000000010V").
	// +kubebuilder:validation:MinLength=1
	// +optional
	VRFInterface string `json:"vrfInterface,omitempty"`

	// Guest-side veth device name (e.g., "G000000010013G").
	// +kubebuilder:validation:MinLength=1
	// +optional
	GuestInterface string `json:"guestInterface,omitempty"`

	// Allocated subnet in CIDR notation (e.g., "fd00:10:ff01:0:1::/80").
	// +kubebuilder:validation:MinLength=1
	// +optional
	//
	// +kubebuilder:validation:XValidation:rule="isCIDR(self)",message="podSubnet must be a valid IPv6 CIDR"
	PodSubnet string `json:"podSubnet,omitempty"`

	// NetworkAttachmentDefinition rendered for this attachment.
	// +kubebuilder:validation:MinLength=1
	// +optional
	NetworkAttachmentDefinition string `json:"networkAttachmentDefinition,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// VPCAttachment is the Schema for the vpcattachments API
type VPCAttachment struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of VPCAttachment
	// +required
	Spec VPCAttachmentSpec `json:"spec"`

	// status defines the observed state of VPCAttachment
	// +optional
	Status VPCAttachmentStatus `json:"status,omitempty"`
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
