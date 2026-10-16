package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkServiceProtocol is the transport protocol matched by a NetworkService's
// ingress VIP.
//
// +kubebuilder:validation:Enum=tcp;udp
type NetworkServiceProtocol string

const (
	// NetworkServiceProtocolTCP matches TCP traffic.
	NetworkServiceProtocolTCP NetworkServiceProtocol = "tcp"

	// NetworkServiceProtocolUDP matches UDP traffic.
	NetworkServiceProtocolUDP NetworkServiceProtocol = "udp"
)

// Accepted reasons — used as Accepted.Reason on NetworkService (and reused by
// NetworkEgressPolicy), set by the admission webhook that verifies the
// requester is authorized for the VPC resources the object references.
const (
	// AcceptedReasonOwnershipVerified indicates admission verified the
	// requester is authorized for the VPC resources the object references.
	AcceptedReasonOwnershipVerified string = "OwnershipVerified"

	// AcceptedReasonOwnershipDenied indicates admission rejected the object
	// because the requester is not authorized for the VPC resources it
	// references.
	AcceptedReasonOwnershipDenied string = "OwnershipDenied"
)

// NetworkService defines ingress load-balancing for a single tenant VPC, served
// by every NetworkGateway node identically (anycast Direct Server Return —
// see NetworkGateway's doc comment). It is namespaced (deployed to
// galactic-system) and tenant-writable; vpcRef is an opaque string identifier
// because this kind carries identifiers from the VPC API in
// api/cloud/v1alpha1 without a Kubernetes object reference. An admission webhook (implemented by the consuming controller) must
// verify the requester is authorized for vpcRef before a service is accepted —
// see the Accepted condition.
//
// Unlike the earlier Full-NAT design this type originally described, there
// is no primary/secondary gateway node for a service: every NetworkGateway
// advertises every accepted service's vipAddresses at equal BGP preference,
// consistent-hashes the same backend list to the same backend for the same
// flow (internal/maglev), and forwards without rewriting anything —
// backend selection never needs a single "owning" node the way Full-NAT's
// SNAT-source model did.
//
// Backends are not listed. BackendSelector picks the VPCAttachments that
// serve the service, so the backend set follows attachments as they are
// created, deleted or moved to another node, and galactic-router on each
// node generates the ServiceVIPBinding its backends need from the same
// selection.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=netsvc
// +kubebuilder:printcolumn:name="VPC",type="string",JSONPath=".spec.vpcRef"
// +kubebuilder:printcolumn:name="PROTOCOL",type="string",JSONPath=".spec.protocol"
// +kubebuilder:printcolumn:name="PORT",type="integer",JSONPath=".spec.port"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type NetworkService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkServiceSpec   `json:"spec,omitempty"`
	Status NetworkServiceStatus `json:"status,omitempty"`
}

// NetworkServiceSpec defines the desired ingress load-balancing state for a
// tenant VPC.
type NetworkServiceSpec struct {
	// VPCRef is the opaque identifier of the target VPC this service applies
	// to. This repo does not own the VPC API and does not validate the
	// identifier beyond non-emptiness; the admission webhook of the
	// consuming controller is responsible for verifying the requester is
	// authorized for this VPC before the service is accepted.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	VPCRef string `json:"vpcRef"`

	// VIPAddresses is the list of ingress VIP addresses this service provisions
	// on the assigned gateway node(s).
	//
	// Only IPv6 addresses are admitted until the gateway datapath serves IPv4
	// VIPs (datum-cloud/galactic#705). A service created with an IPv4 VIP before
	// this restriction keeps it while the list is unchanged, since the API
	// server ratchets validation of an unchanged field on Kubernetes 1.30 and
	// later; any edit to the list must drop it, and on an older API server any
	// update to such a service is refused. The gateways do not load or advertise
	// an IPv4 VIP.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=45
	// +kubebuilder:validation:XValidation:rule="self.all(v, isIP(v))",message="vipAddresses must all be valid IPv4 or IPv6 addresses"
	// +kubebuilder:validation:XValidation:rule="self.all(v, !isIP(v) || ip(v).family() == 6)",message="vipAddresses must be IPv6: IPv4 VIPs are not served yet (datum-cloud/galactic#705)"
	// +listType=set
	VIPAddresses []string `json:"vipAddresses"`

	// Protocol is the transport protocol matched by VIPAddresses/Port.
	// +kubebuilder:validation:Required
	Protocol NetworkServiceProtocol `json:"protocol"`

	// Port is the ingress port on VIPAddresses that this service load-balances.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// BackendSelector selects the VPCAttachments (galactic.datumapis.com/v1alpha1,
	// in any namespace) that serve this service, matched against each
	// VPCAttachment object's own labels. Only attachments whose status.vpc
	// equals VPCRef are candidates, whatever their labels, so a selector cannot
	// reach into another tenant's VPC. Each selected attachment contributes the
	// IPv6 addresses in its spec.interface.addresses as backends, on
	// BackendPort; the DSR datapath carries IPv6 backends only. An attachment
	// with no status.node or no IPv6 address is not a backend until it has
	// both. An empty selector is rejected rather than read as "every attachment
	// in the VPC".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="(has(self.matchLabels) && size(self.matchLabels) > 0) || (has(self.matchExpressions) && size(self.matchExpressions) > 0)",message="backendSelector must not be empty"
	BackendSelector metav1.LabelSelector `json:"backendSelector"`

	// BackendPort is the destination port on every selected backend.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	BackendPort int32 `json:"backendPort"`
}

// NetworkServiceStatus defines the observed state of a NetworkService.
type NetworkServiceStatus struct {
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

// NetworkServiceList is a list of NetworkService resources.
// +kubebuilder:object:root=true
type NetworkServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkService `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkService{}, &NetworkServiceList{})
}
