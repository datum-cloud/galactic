// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EdgeProviderReference names an EdgeProvider.
type EdgeProviderReference struct {
	// Name is the EdgeProvider's name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// EdgeVPCReference names a VPC in the service's own namespace. UID pins the
// grant to one VPC object, so a VPC deleted and recreated under the same name
// is not granted.
type EdgeVPCReference struct {
	// Name is the VPC's name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// UID is the VPC's metadata.uid.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=36
	UID string `json:"uid"`
}

// EdgeServiceSpec is a tenant's grant to one provider in one VPC.
// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef",message="providerRef is immutable"
// +kubebuilder:validation:XValidation:rule="self.vpcRef.uid == oldSelf.vpcRef.uid",message="vpcRef.uid is immutable"
// +kubebuilder:validation:XValidation:rule="self.capabilities == oldSelf.capabilities",message="capabilities are immutable"
// +kubebuilder:validation:XValidation:rule="has(self.clientPool) == has(oldSelf.clientPool) && (!has(self.clientPool) || self.clientPool == oldSelf.clientPool)",message="clientPool is immutable"
type EdgeServiceSpec struct {
	// ProviderRef is the only provider the grant authorizes.
	// +required
	ProviderRef EdgeProviderReference `json:"providerRef"`

	// VPCRef is the only VPC the grant authorizes.
	// +required
	VPCRef EdgeVPCReference `json:"vpcRef"`

	// Capabilities are the capability names the provider may use in the VPC.
	// +required
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=3
	// +kubebuilder:validation:items:Enum=SocketAccess;PacketAccess;PrefixReachability
	Capabilities []string `json:"capabilities"`

	// Prefixes bound the prefixes the provider may request in the VPC. Each
	// is a masked CIDR.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=43
	// +kubebuilder:validation:XValidation:rule="self.all(p, isCIDR(p) && cidr(p) == cidr(p).masked())",message="each prefix must be a masked CIDR"
	Prefixes []string `json:"prefixes,omitempty"`

	// ValidUntil, when set, is the wall-clock time after which the grant
	// authorizes nothing. Admission refuses it, and revokes what it issued,
	// once fewer than the cell's maximum clock skew remain.
	// +optional
	ValidUntil *metav1.Time `json:"validUntil,omitempty"`

	// ClientPool is the IPv6 range, inside the VPC, that attachments take
	// their addresses from: a masked CIDR from /64 to /120. Pools of services
	// granting the same VPC must not overlap. Without one, the service
	// admits no attachment.
	// +optional
	// +kubebuilder:validation:MaxLength=43
	// +kubebuilder:validation:XValidation:rule="isCIDR(self) && cidr(self).ip().family() == 6 && cidr(self) == cidr(self).masked() && cidr(self).prefixLength() >= 64 && cidr(self).prefixLength() <= 120",message="clientPool must be a masked IPv6 CIDR from /64 to /120"
	ClientPool string `json:"clientPool,omitempty"`

	// DrainSeconds is how long an attachment the foundation revokes keeps
	// its resources before they are released. Unset means 30.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=300
	DrainSeconds *int32 `json:"drainSeconds,omitempty"`
}

// EdgeAllocation is one client pool address and the attachment holding it.
type EdgeAllocation struct {
	// Address is the allocated IPv6 address.
	// +required
	// +kubebuilder:validation:MaxLength=39
	Address string `json:"address"`

	// Attachment is the holding EdgeAttachment's namespace and name.
	// +required
	// +kubebuilder:validation:MaxLength=317
	Attachment string `json:"attachment"`

	// AttachmentUID is the holding EdgeAttachment's metadata.uid.
	// +required
	// +kubebuilder:validation:MaxLength=36
	AttachmentUID string `json:"attachmentUID"`
}

// EdgeServiceStatus reports the grant's admission state.
type EdgeServiceStatus struct {
	// ObservedGeneration is the generation Conditions describe.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions include Admitted.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Allocations are the client pool addresses held by attachments. Core
	// writes them with a resourceVersion precondition, so two writers never
	// hand out one address, and removes one only after the attachment's node
	// has released it.
	// +optional
	// +listType=map
	// +listMapKey=address
	// +kubebuilder:validation:MaxItems=1024
	Allocations []EdgeAllocation `json:"allocations,omitempty"`
}

// EdgeService grants one Galactic Edge provider the use of one VPC: the
// capabilities it may use there and the prefixes it may request. It lives in
// the VPC's namespace and is written by the platform authority, never by the
// provider. Changing the spec revokes every authorization issued under the
// previous generation; deleting it revokes them all.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=galactic
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.providerRef.name`
// +kubebuilder:printcolumn:name="VPC",type=string,JSONPath=`.spec.vpcRef.name`
// +kubebuilder:printcolumn:name="Valid Until",type=date,JSONPath=`.spec.validUntil`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EdgeService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec EdgeServiceSpec `json:"spec"`

	// +optional
	Status EdgeServiceStatus `json:"status,omitempty"`
}

// EdgeServiceList is a list of EdgeService.
// +kubebuilder:object:root=true
type EdgeServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EdgeService `json:"items"`
}
