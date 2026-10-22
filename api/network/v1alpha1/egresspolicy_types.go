package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkEgressPolicy enables internet egress for a single tenant
// VPC/VPCAttachment, served by the sharded, stateful galactic-nat tier
// (see EgressShard). Unlike NetworkService, it carries no VIP/backend/port:
// egress is on or off for a (vpcRef, vpcAttachmentRef) pair,
// existence-implies-enabled, not a per-flow rule — because the destination
// of an egress flow is an arbitrary internet address, not a pre-configured
// backend list.
//
// It is namespaced (deployed to galactic-system), and RBAC on the namespace
// decides who may write it. Like NetworkService's vpcRef, vpcRef and
// vpcAttachmentRef are opaque string identifiers because this kind carries
// identifiers from the VPC API in api/cloud/v1alpha1 without a Kubernetes
// object reference. Galactic does not check that the writer is authorized for
// them, and nothing in this repository sets the Accepted condition.
//
// Presence of a NetworkEgressPolicy resolves only *enablement*
// (should this tenant's VRF get an egress route toward the shared
// translation tier at all) — unlike this type's original design (superseded), there is
// no single "assigned gateway node" to compute or pin: any EgressShard may
// serve any tenant's flow, chosen by the shard-placement consistent-hash
// ring (internal/maglev, keyed on (tenant VRFID, backend, destination) —
// see EgressShard's doc comment), not by a per-tenant node assignment stored
// here. *Isolation* (preventing two tenants with colliding ULA source
// addresses from colliding in the egress connection table) is a separate,
// datapath-level concern resolved by tagging each flow with the VRFID
// carried in the tenant's own SRv6 Argument, not by anything in this spec.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=netegress
// +kubebuilder:printcolumn:name="VPC",type="string",JSONPath=".spec.vpcRef"
// +kubebuilder:printcolumn:name="VPC-ATTACHMENT",type="string",JSONPath=".spec.vpcAttachmentRef"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type NetworkEgressPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkEgressPolicySpec   `json:"spec,omitempty"`
	Status NetworkEgressPolicyStatus `json:"status,omitempty"`
}

// NetworkEgressPolicySpec defines the desired egress-enablement state for a
// tenant VPC/VPCAttachment.
type NetworkEgressPolicySpec struct {
	// VPCRef is the opaque identifier of the target VPC this policy applies
	// to. This repo does not own the VPC API and does not validate the
	// identifier beyond non-emptiness, or check that the writer is
	// authorized for this VPC.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	VPCRef string `json:"vpcRef"`

	// VPCAttachmentRef is the opaque identifier of the target
	// VPCAttachment this policy applies to. Like VPCRef, this is an opaque
	// string reference that this API checks only for non-emptiness.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	VPCAttachmentRef string `json:"vpcAttachmentRef"`
}

// NetworkEgressPolicyStatus defines the observed state of a
// NetworkEgressPolicy.
type NetworkEgressPolicyStatus struct {
	// ObservedGeneration is the .metadata.generation this status was computed from.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions contains the standard conditions for this resource. Nothing
	// in this repository sets them. Accepted, when set, uses the ownership
	// reasons shared with NetworkService (see AcceptedReasonOwnershipVerified).
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// NetworkEgressPolicyList is a list of NetworkEgressPolicy resources.
// +kubebuilder:object:root=true
type NetworkEgressPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkEgressPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkEgressPolicy{}, &NetworkEgressPolicyList{})
}
