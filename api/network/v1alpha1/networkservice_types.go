package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkServiceProtocol is the IP protocol a VIP or endpoint matches.
//
// The set of values is open-ended. A client reading an object that carries
// this type must accept a value it does not recognise, preserve it when it
// writes the object back, and treat it as a protocol it cannot act on, never
// as tcp or udp. Each field of this type admits only the values it lists, and
// the API server refuses any other.
type NetworkServiceProtocol string

const (
	// NetworkServiceProtocolTCP matches TCP traffic.
	NetworkServiceProtocolTCP NetworkServiceProtocol = "tcp"

	// NetworkServiceProtocolUDP matches UDP traffic.
	NetworkServiceProtocolUDP NetworkServiceProtocol = "udp"

	// NetworkServiceProtocolSCTP matches SCTP traffic (IP protocol 132), which
	// has ports. It is declared but not served yet.
	NetworkServiceProtocolSCTP NetworkServiceProtocol = "sctp"

	// NetworkServiceProtocolESP matches IPsec Encapsulating Security Payload
	// traffic (IP protocol 50), which has no ports. It is declared but not
	// served yet.
	NetworkServiceProtocolESP NetworkServiceProtocol = "esp"

	// NetworkServiceProtocolGRE matches Generic Routing Encapsulation traffic
	// (IP protocol 47), which has no ports. It is declared but not served yet.
	NetworkServiceProtocolGRE NetworkServiceProtocol = "gre"

	// NetworkServiceProtocolICMP matches ICMP traffic: ICMPv6 (IP protocol 58)
	// on an IPv6 VIP and ICMP (IP protocol 1) on an IPv4 VIP. It has no ports.
	// It is declared but not served yet.
	NetworkServiceProtocolICMP NetworkServiceProtocol = "icmp"
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
// BackendSelector and optional BackendAddresses select VPCAttachments in the
// service's observed VPC. Address-only selection does not require a label.
// galactic-router generates ServiceVIPBindings from the same selection.
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
//
// +kubebuilder:validation:XValidation:rule="!(self.protocol in ['tcp', 'udp', 'sctp']) || has(self.port)",message="port is required for tcp, udp and sctp"
// +kubebuilder:validation:XValidation:rule="!(self.protocol in ['tcp', 'udp', 'sctp']) || has(self.backendPort)",message="backendPort is required for tcp, udp and sctp"
// +kubebuilder:validation:XValidation:rule="!(self.protocol in ['esp', 'gre', 'icmp']) || !has(self.port)",message="port must not be set for esp, gre and icmp, which have no ports"
// +kubebuilder:validation:XValidation:rule="!(self.protocol in ['esp', 'gre', 'icmp']) || !has(self.backendPort)",message="backendPort must not be set for esp, gre and icmp, which have no ports"
// +kubebuilder:validation:XValidation:rule="has(self.backendAddresses) || (has(self.backendSelector) && ((has(self.backendSelector.matchLabels) && size(self.backendSelector.matchLabels) > 0) || (has(self.backendSelector.matchExpressions) && size(self.backendSelector.matchExpressions) > 0)))",message="a nonempty backendSelector or backendAddresses is required"
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
	// on the gateway nodes: at most one IPv6 and at most one IPv4 address.
	//
	// A backend node rewrites a reply's source from the backend's address, port
	// and protocol back to a single VIP of the client's family, so a backend
	// cannot answer for a second VIP of one family. Another VIP of a family
	// needs its own service whose backends listen on a different BackendPort.
	// An IPv4 VIP is written in dotted form; the IPv4-mapped IPv6 form is
	// refused.
	//
	// Workloads are IPv6 only, so both VIPs are served by the selected
	// attachments' IPv6 addresses. A backend node translates the IPv4 VIP's
	// flows statelessly: the backend sees an IPv4 client a.b.c.d as
	// 64:ff9b::a.b.c.d (RFC 6052) and replies to that address, and its node
	// sends the reply back to the client as IPv4 from the VIP. A gateway node
	// serves the IPv4 VIP only while it has IPv4 VIPs turned on, and
	// load-balances it only over the backends whose ServiceVIPBinding for it
	// reports Bound. It advertises the IPv4 VIP while at least one such
	// backend exists, and reports the outcome in its "<node>/IPv4Served"
	// condition. The IPv6 VIP is served independently of the IPv4 one.
	//
	// An existing service whose list breaks these limits keeps validating while
	// the list is unchanged, since the API server ratchets validation of an
	// unchanged field on Kubernetes 1.30 and later; any edit to the list must
	// bring it within them, and an older API server refuses any update to such
	// a service.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=45
	// +kubebuilder:validation:XValidation:rule="self.all(v, isIP(v))",message="vipAddresses must all be valid IPv4 or IPv6 addresses, an IPv4 address in dotted form rather than IPv4-mapped (::ffff:a.b.c.d)"
	// +kubebuilder:validation:XValidation:rule="self.filter(v, isIP(v) && ip(v).family() == 6).size() <= 1",message="vipAddresses may hold at most one IPv6 address: a backend answers for only one VIP of each family, so serve another IPv6 VIP from its own NetworkService with a different backendPort"
	// +kubebuilder:validation:XValidation:rule="self.filter(v, isIP(v) && ip(v).family() == 4).size() <= 1",message="vipAddresses may hold at most one IPv4 address: a backend answers for only one VIP of each family, so serve another IPv4 VIP from its own NetworkService with a different backendPort"
	// +listType=set
	VIPAddresses []string `json:"vipAddresses"`

	// Protocol is the IP protocol this service load-balances on VIPAddresses.
	//
	// The API admits tcp, udp, sctp, esp, gre and icmp, and the gateway
	// datapath serves tcp and udp. A service with any other admitted value is
	// refused with a message saying its protocol is not served yet. sctp has
	// ports and needs Port and BackendPort. esp, gre and icmp have no ports
	// and must set neither; a backend for them is chosen from the client and
	// VIP addresses alone. The set of values is open-ended, so a client must
	// accept and preserve a value it does not recognise, as
	// NetworkServiceProtocol describes.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=tcp;udp;sctp;esp;gre;icmp
	// +kubebuilder:validation:XValidation:rule="self in ['tcp', 'udp']",message="protocol is not served yet: the gateway datapath serves tcp and udp only"
	Protocol NetworkServiceProtocol `json:"protocol"`

	// Port is the ingress port on VIPAddresses that this service load-balances,
	// 1-65535. It is required for a protocol with ports (tcp, udp and sctp)
	// and must be unset for one without (esp, gre and icmp). Zero means unset
	// and is omitted when encoding, and an explicit 0 is refused.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// BackendSelector selects the VPCAttachments (galactic.datumapis.com/v1alpha1,
	// in any namespace) that serve this service, matched against each
	// VPCAttachment object's own labels. Only attachments whose status.vpc
	// equals VPCRef are candidates, whatever their labels, so a selector cannot
	// reach into another tenant's VPC. Each selected attachment contributes the
	// IPv6 addresses in its spec.interface.addresses as backends, on
	// BackendPort, for both VIPs: its node translates the IPv4 VIP's flows to
	// and from IPv6, and its IPv4 addresses are never backends. An attachment
	// with no status.node, or no IPv6 address, is not a backend until it has
	// both. An empty selector is accepted only with BackendAddresses and then
	// matches all attachments in this service's observed VPC.
	// +optional
	BackendSelector metav1.LabelSelector `json:"backendSelector,omitempty"`

	// BackendAddresses restricts selected attachments to these IPv6 backend
	// addresses. When set without a selector, it matches attachments by address
	// only, still requiring status.vpc to equal VPCRef. An explicit empty list
	// withdraws all backends and their bindings without broadening selection.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:XValidation:rule="self.all(a, isIP(a) && ip(a).family() == 6)",message="backendAddresses must contain IPv6 addresses"
	// +listType=set
	BackendAddresses *[]string `json:"backendAddresses,omitempty"`

	// BackendPort is the destination port on every selected backend, 1-65535.
	// Like Port, it is required for tcp, udp and sctp and must be unset for
	// esp, gre and icmp. Zero means unset and is omitted when encoding, and an
	// explicit 0 is refused.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	BackendPort int32 `json:"backendPort,omitempty"`
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
