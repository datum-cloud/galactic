package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ServiceVIPBinding drives one worker node's backend-side half of the
// DSR/Maglev load-balancer datapath: it tells the node which service VIP a
// specific local backend must be reachable on, so the backend can reply to
// clients directly (the "Direct Server Return" this design depends on —
// see NetworkGateway's doc comment). Generated, never written by users:
// galactic-router on each worker node writes one object per (service, VIP,
// backend) for every backend a NetworkService's BackendSelector places on that
// node, owned by the service, and the same process's per-node reconciler
// consumes it.
//
// EgressKind decides which of two backend mechanisms this object drives,
// mirroring the same veth/tap fork the SRv6 uSID decap datapath already
// has (internal/plumbing/ebpf/usidmap's egress_kind field). Both mechanisms
// now converge on the same VIP-boundary substitution
// (BackendAddress:BackendPort for VIPAddress:Port at the SRv6 uSID TC-BPF
// boundary, usid_ingress's inbound half / usid_egress's outbound half) —
// required for both, not just tap, since a decapsulated ingress packet is
// delivered into the owning tenant's own VRF routing table, which has no
// route to an address bound outside that VRF (found live: see galactic's
// ServiceVIPBindingReconciler doc comment):
//
//   - veth (container backend): the node ALSO binds VIPAddress on its own
//     galactic-vip0 dummy interface (internal/plumbing/vip's
//     Bind/Unbind/Verify in galactic) — this alone does not deliver
//     anything to the backend pod (galactic-vip0 lives in the node's root
//     namespace, not the tenant's VRF), but still lets the node itself
//     verifiably answer on the VIP.
//   - tap (VM backend): there is no guest-side configuration capability in
//     this repo by design (internal/cnitap's own doc comment), so the
//     substitution above is this kind's *only* delivery mechanism — the
//     guest OS never needs to know the VIP exists at all.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=svcvip
// +kubebuilder:printcolumn:name="NODE",type="string",JSONPath=".spec.targetRef.name"
// +kubebuilder:printcolumn:name="VIP",type="string",JSONPath=".spec.vipAddress"
// +kubebuilder:printcolumn:name="BACKEND",type="string",JSONPath=".spec.backendAddress"
// +kubebuilder:printcolumn:name="KIND",type="string",JSONPath=".spec.egressKind"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type ServiceVIPBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ServiceVIPBindingSpec   `json:"spec,omitempty"`
	Status ServiceVIPBindingStatus `json:"status,omitempty"`
}

// ConditionTypeBound indicates whether the backend is actually confirmed
// reachable on the VIP -- see ServiceVIPBindingStatus's doc comment.
const ConditionTypeBound string = "Bound"

// ServiceVIPBindingEgressKind mirrors usidmap's EgressKindVeth/EgressKindTap
// constants at the API layer — see ServiceVIPBinding's doc comment.
//
// +kubebuilder:validation:Enum=veth;tap
type ServiceVIPBindingEgressKind string

const (
	// ServiceVIPBindingEgressKindVeth selects the netns-bind mechanism.
	ServiceVIPBindingEgressKindVeth ServiceVIPBindingEgressKind = "veth"

	// ServiceVIPBindingEgressKindTap selects the transparent tap-boundary
	// translation mechanism.
	ServiceVIPBindingEgressKindTap ServiceVIPBindingEgressKind = "tap"
)

// ServiceVIPBindingSpec defines the desired VIP binding/translation state.
type ServiceVIPBindingSpec struct {
	// TargetRef identifies the Node this binding applies to.
	// +kubebuilder:validation:Required
	TargetRef TargetRef `json:"targetRef"`

	// VPCRef is the opaque identifier of the VPC the backend belongs to,
	// copied from the owning NetworkService. It names the tenant VRF the
	// binding's translation rows are written for, so two tenants using the
	// same backend address on one node never share a row.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	VPCRef string `json:"vpcRef"`

	// VIPAddress is the service VIP the backend must be reachable on.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="isIP(self)",message="vipAddress must be a valid IP address"
	VIPAddress string `json:"vipAddress"`

	// Port is the VIP-facing port traffic arrives on.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// Protocol is the transport protocol this binding applies to.
	// +kubebuilder:validation:Required
	Protocol NetworkServiceProtocol `json:"protocol"`

	// BackendAddress is the backend's own real address (its pod-netns
	// address for a veth backend, or its actual guest-facing address for a
	// tap backend) — the VIP-boundary substitution target for both kinds
	// now (see EgressKind's own doc comment for why veth needs this too,
	// not just tap). +optional at the API level for the same reason
	// EgressKind itself carries no matching CEL requirement; the
	// reconciler validates it's set for either kind before doing anything.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == '' || isIP(self)",message="backendAddress must be a valid IP address"
	BackendAddress string `json:"backendAddress,omitempty"`

	// BackendPort is the backend's own real port, paired with
	// BackendAddress — required for both kinds, see that field's doc
	// comment.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	BackendPort int32 `json:"backendPort,omitempty"`

	// EgressKind selects which backend mechanism this binding drives.
	// +kubebuilder:validation:Required
	EgressKind ServiceVIPBindingEgressKind `json:"egressKind"`
}

// ServiceVIPBindingStatus defines the observed state of a ServiceVIPBinding.
type ServiceVIPBindingStatus struct {
	// ObservedGeneration is the .metadata.generation this status was computed from.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions contains the standard conditions for this resource,
	// including Bound (set True once internal/plumbing/vip.Verify or the
	// equivalent tap-translation-table check confirms the backend is
	// actually reachable on VIPAddress, not merely that the bind/table-write
	// call itself returned nil).
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ServiceVIPBindingList is a list of ServiceVIPBinding resources.
// +kubebuilder:object:root=true
type ServiceVIPBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceVIPBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ServiceVIPBinding{}, &ServiceVIPBindingList{})
}
