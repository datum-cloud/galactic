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

// NetworkServiceSessionAffinity selects which parts of a flow a gateway hashes
// to pick its backend. Every gateway node hashes a service the same way, so a
// flow keeps its backend when it moves between nodes. Affinity is stateless:
// it holds only while the backend set is unchanged, and each change to that
// set moves about 1/N of clients, N being the number of backends.
//
// +kubebuilder:validation:Enum=None;ClientIP;ClientIPAndProtocol
type NetworkServiceSessionAffinity string

const (
	// NetworkServiceSessionAffinityNone hashes the client's address and source
	// port, so each connection is balanced on its own.
	NetworkServiceSessionAffinityNone NetworkServiceSessionAffinity = "None"

	// NetworkServiceSessionAffinityClientIP hashes the client's address only,
	// so every connection from one address reaches the same backend, whatever
	// its port, protocol or service among the services sharing that backend
	// set.
	NetworkServiceSessionAffinityClientIP NetworkServiceSessionAffinity = "ClientIP"

	// NetworkServiceSessionAffinityClientIPAndProtocol hashes the client's
	// address and the IP protocol, so every connection from one address over
	// one protocol reaches the same backend, among the services sharing that
	// backend set.
	NetworkServiceSessionAffinityClientIPAndProtocol NetworkServiceSessionAffinity = "ClientIPAndProtocol"
)

// Ownership reasons for the Accepted condition on NetworkService and
// NetworkEgressPolicy. The gateways set them on a NetworkService in a project
// namespace, any namespace but the gateway namespace: OwnershipVerified once a VPC in its
// namespace carries its vpcRef, OwnershipDenied while none does. Nothing sets
// them on a NetworkEgressPolicy, or on a NetworkService in a gateway
// namespace, whose Accepted reports only that a gateway node is registered
// there.
const (
	// AcceptedReasonOwnershipVerified reports that a VPC in the object's
	// namespace carries the VPC identifier it references.
	AcceptedReasonOwnershipVerified string = "OwnershipVerified"

	// AcceptedReasonOwnershipDenied reports that no VPC in the object's
	// namespace carries the VPC identifier it references.
	AcceptedReasonOwnershipDenied string = "OwnershipDenied"
)

// NetworkService defines ingress load-balancing for a single tenant VPC, served
// by every NetworkGateway node identically (anycast Direct Server Return —
// see NetworkGateway's doc comment). vpcRef is an opaque string identifier
// because this kind carries identifiers from the VPC API in api/cloud/v1alpha1
// without a Kubernetes object reference.
//
// A NetworkService lives in one of two kinds of namespace. In the gateway
// namespace, the one holding NetworkGateways (galactic-system), it is written
// by the platform API that serves tenants, which verifies the tenant owns
// vpcRef before it writes the service; RBAC on the namespace decides who else
// may write it, and Accepted reports only that a gateway node is registered
// there. In a project namespace, any other, it is served only where the
// gateways have project services turned on, by every NetworkGateway in the
// gateway namespace, and trusted for nothing: it is Accepted
// (OwnershipVerified) only while every VIP address falls in a prefix the
// platform allocates load balancer addresses from (VIPOutsidePool
// otherwise), a VPC in its own namespace carries its vpcRef (OwnershipDenied
// otherwise), and no other service
// already serves one of its VIP addresses on its protocol and port
// (VIPClaimed); its backends come only from VPCAttachments in its own
// namespace. Either way, the BGPAdvertisements and ServiceVIPBindings made for
// it live in the gateway namespace.
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
//
// +kubebuilder:validation:XValidation:rule="!(self.protocol in ['tcp', 'udp', 'sctp']) || has(self.port) != has(self.portRange)",message="exactly one of port and portRange is required"
// +kubebuilder:validation:XValidation:rule="has(self.portRange) ? !has(self.backendPort) && self.protocol == 'udp' : !(self.protocol in ['tcp', 'udp', 'sctp']) || has(self.backendPort)",message="UDP ranges preserve ports and omit backendPort; singleton services require backendPort"
// +kubebuilder:validation:XValidation:rule="!has(self.portRange) || self.vipAddresses.all(v, isIP(v) && ip(v).family() == 6)",message="port ranges require IPv6 VIPs"
// +kubebuilder:validation:XValidation:rule="!has(self.portRange) || has(self.addressGroup)",message="port ranges require a complete address group"
// +kubebuilder:validation:XValidation:rule="!has(self.addressGroup) || (has(self.addressGroup.listeners) && size(self.addressGroup.listeners) > 0)",message="service address group requires a listener inventory"
// +kubebuilder:validation:XValidation:rule="!(self.protocol in ['esp', 'gre', 'icmp']) || !has(self.port)",message="port must not be set for esp, gre and icmp, which have no ports"
// +kubebuilder:validation:XValidation:rule="!(self.protocol in ['esp', 'gre', 'icmp']) || !has(self.backendPort)",message="backendPort must not be set for esp, gre and icmp, which have no ports"
// +kubebuilder:validation:XValidation:rule="self.protocol != 'udp' || !has(self.healthCheck) || has(self.healthCheck.port)",message="healthCheck.port is required for udp: a health check probes a TCP port"
type NetworkServiceSpec struct {
	// VPCRef is the opaque identifier of the target VPC this service applies
	// to, a VPC's status.vpc. In a gateway namespace, the platform API that
	// serves tenants verifies the tenant owns this VPC before it writes the
	// service. In a project namespace, the service is accepted only while a
	// VPC in that namespace carries this identifier.
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
	// 1-65535. It is required when PortRange is absent for tcp, udp and sctp
	// and must be unset for one without (esp, gre and icmp). Zero means unset
	// and is omitted when encoding, and an explicit 0 is refused.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// PortRange replaces Port for an inclusive IPv6 UDP interval. Backend ports
	// are preserved; BackendPort must be omitted.
	// +optional
	PortRange *PortRange `json:"portRange,omitempty"`

	// AddressGroup binds this listener to a complete, authoritative address inventory.
	// +optional
	AddressGroup *NetworkServiceAddressGroup `json:"addressGroup,omitempty"`

	// BackendSelector selects the VPCAttachments (galactic.datumapis.com/v1alpha1)
	// that serve this service, matched against each VPCAttachment object's own
	// labels: in any namespace for a service in a gateway namespace, and only
	// in its own namespace for a service in a project namespace. Only
	// attachments whose status.vpc equals VPCRef are candidates, whatever their
	// labels, so a selector cannot reach into another tenant's VPC. Each selected attachment contributes the
	// IPv6 addresses in its spec.interface.addresses as backends, on
	// BackendPort, for both VIPs: its node translates the IPv4 VIP's flows to
	// and from IPv6, and its IPv4 addresses are never backends. An attachment
	// with no status.node, or no IPv6 address, is not a backend until it has
	// both. An empty selector is rejected rather than read as "every
	// attachment in the VPC".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="(has(self.matchLabels) && size(self.matchLabels) > 0) || (has(self.matchExpressions) && size(self.matchExpressions) > 0)",message="backendSelector must not be empty"
	BackendSelector metav1.LabelSelector `json:"backendSelector"`

	// BackendPort is the destination port on every selected backend, 1-65535.
	// Like Port, it is required for tcp, udp and sctp and must be unset for
	// esp, gre and icmp. Zero means unset and is omitted when encoding, and an
	// explicit 0 is refused.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	BackendPort int32 `json:"backendPort,omitempty"`

	// SessionAffinity selects which connections from one client share a
	// backend: None, the default, balances each connection on its own;
	// ClientIP pins a client address to one backend; ClientIPAndProtocol pins
	// a client address and protocol to one. Two services pin a client to the
	// same backend only if both set the same affinity and select the same
	// backend addresses. A change takes effect on every gateway node without a
	// restart, and rehashes every connection of the service, so most open
	// connections reach a different backend afterwards.
	// +optional
	// +kubebuilder:default=None
	SessionAffinity NetworkServiceSessionAffinity `json:"sessionAffinity,omitempty"`

	// HealthCheck turns on health checks for the service's backends. Each
	// backend's own node opens a TCP connection to it on the health check
	// port, from the link-local address of the backend's host-side interface,
	// and publishes a decision in status.health of the backend's
	// ServiceVIPBindings. The gateway nodes take a backend whose decision is
	// Unhealthy out of the service's Maglev table, and keep every backend
	// when all of them are Unhealthy by default. FailClosed instead requires
	// fresh Healthy results for the current configuration and withdraws a VIP
	// with no healthy backends. Unset, no backend is probed and every
	// one stays in the table.
	//
	// Where interface traffic policy is enforced, the backend's policy must
	// allow TCP from fe80::/10 to the health check port on the Private path,
	// and the replies back.
	// +optional
	HealthCheck *NetworkServiceHealthCheck `json:"healthCheck,omitempty"`
}

const (
	// NetworkServiceHealthFailOpen retains unknown backends and all-unhealthy sets.
	NetworkServiceHealthFailOpen = "FailOpen"
	// NetworkServiceHealthFailClosed serves only fresh, verified healthy backends.
	NetworkServiceHealthFailClosed = "FailClosed"
)

// NetworkServiceHealthCheck configures the TCP health check of a
// NetworkService's backends. A probe succeeds when the TCP handshake completes
// within TimeoutSeconds, and fails when the connection is refused, reset or
// times out. A backend's decision changes after UnhealthyThreshold consecutive
// failures or HealthyThreshold consecutive successes, so a backend that
// alternates between the two keeps its current decision.
//
// +kubebuilder:validation:XValidation:rule="self.timeoutSeconds <= self.intervalSeconds",message="timeoutSeconds must not exceed intervalSeconds"
type NetworkServiceHealthCheck struct {
	// FailurePolicy determines whether unknown and all-unhealthy backends may
	// receive traffic. FailClosed requires a current Healthy decision and
	// withdraws the service when health filtering is unavailable.
	// +optional
	// +kubebuilder:default=FailOpen
	// +kubebuilder:validation:Enum=FailOpen;FailClosed
	FailurePolicy string `json:"failurePolicy,omitempty"`

	// Port is the TCP port probed on every backend, 1-65535. Unset, it is the
	// service's backendPort. A udp service must set it to a TCP port its
	// backends listen on, since a UDP datagram draws no reply a generic
	// probe can expect.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// IntervalSeconds is the time between two probes of one backend.
	// +optional
	// +kubebuilder:default=5
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=300
	IntervalSeconds int32 `json:"intervalSeconds,omitempty"`

	// TimeoutSeconds is how long a probe waits for the handshake. It must not
	// exceed IntervalSeconds.
	// +optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=60
	TimeoutSeconds int32 `json:"timeoutSeconds,omitempty"`

	// UnhealthyThreshold is the number of consecutive failed probes that
	// make a backend Unhealthy.
	// +optional
	// +kubebuilder:default=3
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	UnhealthyThreshold int32 `json:"unhealthyThreshold,omitempty"`

	// HealthyThreshold is the number of consecutive successful probes that
	// make a backend Healthy.
	// +optional
	// +kubebuilder:default=3
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	HealthyThreshold int32 `json:"healthyThreshold,omitempty"`
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
