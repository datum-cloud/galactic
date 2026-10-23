// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EdgeServiceReference names an EdgeService by namespace, name and UID. The
// UID pins the attachment to one grant object, so a service deleted and
// recreated under the same name does not inherit it.
type EdgeServiceReference struct {
	// Namespace is the EdgeService's namespace, its VPC's namespace.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`

	// Name is the EdgeService's name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// UID is the EdgeService's metadata.uid.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	UID string `json:"uid"`
}

// EdgeInstanceReference names an EdgeInstance in the attachment's namespace.
type EdgeInstanceReference struct {
	// Name is the EdgeInstance's name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// EdgePacketDevice is the owner of a PacketAccess attachment's TUN device,
// the user and group the provider opens it as without CAP_NET_ADMIN.
type EdgePacketDevice struct {
	// Owner is the user ID allowed to open the device.
	// +required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967294
	Owner int64 `json:"owner"`

	// Group is the group ID allowed to open the device.
	// +required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967294
	Group int64 `json:"group"`
}

// EdgeAttachmentSpec is an instance's request for one isolated connection to
// its service's VPC. The instance writes it at create; a
// ValidatingAdmissionPolicy requires podUID to be the pod its token was
// issued for.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable"
// +kubebuilder:validation:XValidation:rule="self.capabilities.exists(c, c.name == 'PacketAccess') == has(self.packetDevice)",message="packetDevice is required with PacketAccess and allowed only with it"
type EdgeAttachmentSpec struct {
	// ProviderRef is the provider the requesting instance runs. It must be
	// the service's and the instance's provider. The provider's admission
	// binding checks the writer against it.
	// +required
	ProviderRef EdgeProviderReference `json:"providerRef"`

	// ServiceRef is the EdgeService granting the VPC.
	// +required
	ServiceRef EdgeServiceReference `json:"serviceRef"`

	// InstanceRef is the requesting EdgeInstance.
	// +required
	InstanceRef EdgeInstanceReference `json:"instanceRef"`

	// PodUID is the requesting pod's metadata.uid. It must equal the
	// instance's.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	PodUID string `json:"podUID"`

	// ContractVersion is the provider contract version the request is
	// written to.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=16
	ContractVersion string `json:"contractVersion"`

	// Capabilities are the capability versions the attachment uses:
	// SocketAccess, PacketAccess or both.
	// +required
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=2
	// +kubebuilder:validation:XValidation:rule="self.all(c, c.name in ['SocketAccess', 'PacketAccess'])",message="an attachment uses only SocketAccess and PacketAccess"
	Capabilities []EdgeCapability `json:"capabilities"`

	// PacketDevice owns the TUN device. Required with PacketAccess.
	// +optional
	PacketDevice *EdgePacketDevice `json:"packetDevice,omitempty"`
}

// Condition types of an EdgeAttachment. Core (galactic-controller) sets
// Admitted, Allocated and Draining; the node agent (galactic-edge) sets
// Programmed and Released; the provider sets only Ready.
const (
	EdgeAttachmentAdmitted   = "Admitted"
	EdgeAttachmentAllocated  = "Allocated"
	EdgeAttachmentDraining   = "Draining"
	EdgeAttachmentProgrammed = "Programmed"
	EdgeAttachmentReleased   = "Released"
	EdgeAttachmentReady      = "Ready"
)

// EdgeAttachmentFinalizer holds an attachment until its node confirms its
// host state is released.
const EdgeAttachmentFinalizer = "galactic.datumapis.com/edge-attachment"

// EdgeAttachmentStatus is the attachment's lifecycle. A field is written only
// by the writer named on it.
type EdgeAttachmentStatus struct {
	// Conditions are Admitted, Allocated, Draining (core), Programmed,
	// Released (node) and Ready (provider).
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// NodeName is the node that programs the attachment, from its instance.
	// Set by core at admission.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	NodeName string `json:"nodeName,omitempty"`

	// VPC is the base62 identifier of the service's VPC. Set by core at
	// admission.
	// +optional
	// +kubebuilder:validation:MaxLength=16
	VPC string `json:"vpc,omitempty"`

	// Address is the attachment's IPv6 address in the VPC, from the
	// service's client pool. Set by core at allocation.
	// +optional
	// +kubebuilder:validation:MaxLength=39
	Address string `json:"address,omitempty"`

	// DrainDeadline is when core deletes an attachment it is draining.
	// +optional
	DrainDeadline *metav1.Time `json:"drainDeadline,omitempty"`

	// HostLink is the host end of the attachment's link. Set by the node.
	// +optional
	// +kubebuilder:validation:MaxLength=15
	HostLink string `json:"hostLink,omitempty"`

	// PodVRF is the VRF in the provider pod that the provider binds its
	// sockets to. Set by the node.
	// +optional
	// +kubebuilder:validation:MaxLength=15
	PodVRF string `json:"podVRF,omitempty"`

	// PacketDevice is the TUN device in the provider pod. Set by the node
	// for a PacketAccess attachment.
	// +optional
	// +kubebuilder:validation:MaxLength=15
	PacketDevice string `json:"packetDevice,omitempty"`
}

// EdgeAttachment is one provider instance's isolated connection to the VPC
// its EdgeService grants: an address from the service's client pool, a link
// from the pod into the VPC's host VRF on the pod's node and, with
// PacketAccess, a TUN device. It lives in the provider's namespace. Its name
// is derived from the service and pod UIDs, so a retried create lands on the
// same object.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=galactic
// +kubebuilder:printcolumn:name="Service",type=string,JSONPath=`.spec.serviceRef.name`
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.status.nodeName`
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.status.address`
// +kubebuilder:printcolumn:name="Programmed",type=string,JSONPath=`.status.conditions[?(@.type=="Programmed")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EdgeAttachment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec EdgeAttachmentSpec `json:"spec"`

	// +optional
	Status EdgeAttachmentStatus `json:"status,omitempty"`
}

// EdgeAttachmentList is a list of EdgeAttachment.
// +kubebuilder:object:root=true
type EdgeAttachmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EdgeAttachment `json:"items"`
}
