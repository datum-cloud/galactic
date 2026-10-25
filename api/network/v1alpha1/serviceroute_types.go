package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// ServiceEndpoint publishes a platform service that can be reached through a
// VPC attachment. The object describes the service contract; the controller
// that owns the service is responsible for its health and implementation.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=svcendpoint
// +kubebuilder:printcolumn:name="ADDRESS",type="string",JSONPath=".spec.address"
// +kubebuilder:printcolumn:name="PORT",type="integer",JSONPath=".spec.port"
// +kubebuilder:printcolumn:name="DISTRIBUTION",type="string",JSONPath=".spec.distribution"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type ServiceEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ServiceEndpointSpec `json:"spec,omitempty"`

	// +optional
	Status ServiceEndpointStatus `json:"status,omitempty"`
}

// ServiceEndpointSpec defines a platform service address and its scope.
// +kubebuilder:validation:XValidation:rule="has(self.attachmentRef) != has(self.attachmentSelector)",message="exactly one of attachmentRef or attachmentSelector must be set"
// +kubebuilder:validation:XValidation:rule="(has(self.distribution) && self.distribution == 'Spread') == has(self.healthCheck)",message="healthCheck must be set when distribution is Spread, and only then"
// +kubebuilder:validation:XValidation:rule="!has(self.healthCheck) || has(self.healthCheck.port) || self.protocol == 'tcp'",message="a udp endpoint's healthCheck must set port"
type ServiceEndpointSpec struct {
	// ServiceClass identifies the platform capability implemented by this
	// endpoint, for example "ipv6-egress-dns".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	ServiceClass string `json:"serviceClass"`

	// Address is the stable address that consumers use to reach the service.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="isIP(self)",message="address must be an IP address"
	Address string `json:"address"`

	// Port is the service port.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// Protocol is the transport protocol accepted by the endpoint.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=tcp;udp
	Protocol NetworkServiceProtocol `json:"protocol"`

	// DeliveryMode defines how a backing attachment is selected relative to a
	// consumer. PreferNodeLocal uses a ready attachment on the consumer's node
	// when one exists and otherwise falls back to a ready remote attachment.
	// The dataplane preserves the consumer source address. If consumers with
	// overlapping address space present an identical TCP or UDP five-tuple to the
	// same replica, it rejects the later ambiguous flow fail-closed rather than
	// translate the source or risk returning traffic to the wrong VPC.
	// +kubebuilder:validation:Required
	DeliveryMode ServiceEndpointDeliveryMode `json:"deliveryMode"`

	// AttachmentRef identifies the Cloud API VPCAttachment that hosts this
	// endpoint when the service is delivered through a private VPC path.
	// The network API keeps this reference opaque; the consuming controller
	// resolves it against the Cloud API.
	// +optional
	AttachmentRef *ServiceEndpointAttachmentReference `json:"attachmentRef,omitempty"`

	// AttachmentSelector selects the Cloud API VPCAttachments that host replicas
	// of this endpoint. Labels used here must be assigned by the platform service
	// controller, not by tenants. The dataplane selects ready replicas for each
	// consumer according to DeliveryMode and Distribution.
	// +optional
	AttachmentSelector *metav1.LabelSelector `json:"attachmentSelector,omitempty"`

	// Region limits endpoint selection to a region. An empty value means the
	// endpoint is not region-scoped.
	// +optional
	Region string `json:"region,omitempty"`

	// Distribution says how a consumer's traffic reaches the producers on
	// its own node. Single, the default, allows one ready producer per node
	// and VPC and sends every consumer on that node to it; an endpoint that
	// selects more is refused. Spread sends new flows to any producer on the
	// consumer's node that its health check has not found Unhealthy: each
	// TCP connection stays with the producer that received its first packet,
	// and each UDP datagram picks a producer of its own, which suits
	// request/response protocols such as DNS but not ones that need a UDP
	// flow to stay on one producer. An Unhealthy producer keeps its existing
	// TCP connections and replies, and gets new flows again once it is
	// Healthy. When every producer on a node is Unhealthy, all of them stay
	// eligible. A node may hold at most 16 producers of a Spread endpoint.
	// +optional
	// +kubebuilder:validation:Enum=Single;Spread
	Distribution ServiceEndpointDistribution `json:"distribution,omitempty"`

	// HealthCheck configures the TCP health check of a Spread endpoint's
	// producers. Each producer's own node probes it and publishes the
	// decision in status.producers. Required when Distribution is Spread and
	// refused otherwise.
	//
	// Where interface traffic policy is enforced, the producer's policy must
	// allow TCP from fe80::/10 to the health check port on the Private path,
	// and the replies back.
	// +optional
	HealthCheck *ServiceEndpointHealthCheck `json:"healthCheck,omitempty"`
}

// ServiceEndpointDistribution selects how traffic spreads across the
// producers on one node.
type ServiceEndpointDistribution string

const (
	// ServiceEndpointDistributionSingle sends every consumer on a node to the
	// one ready producer there.
	ServiceEndpointDistributionSingle ServiceEndpointDistribution = "Single"

	// ServiceEndpointDistributionSpread spreads flows across the healthy
	// producers on the consumer's node.
	ServiceEndpointDistributionSpread ServiceEndpointDistribution = "Spread"
)

// ServiceEndpointMaxProducersPerNode is the most producers of one Spread
// endpoint that a node can hold.
const ServiceEndpointMaxProducersPerNode = 16

// ServiceEndpointHealthCheck configures the TCP health check of an endpoint's
// producers. A probe opens a TCP connection to the producer attachment's first
// IPv6 address, not the endpoint's address, on Port, through the producer's
// host-side interface and from that interface's link-local address. A producer
// with no IPv6 address is never probed and stays Unknown. A probe succeeds when the handshake completes within
// TimeoutSeconds, and fails when the connection is refused, reset or times
// out. A producer's decision changes after UnhealthyThreshold consecutive
// failures or HealthyThreshold consecutive successes. A crashed producer
// therefore stops receiving new flows within IntervalSeconds ×
// UnhealthyThreshold, plus TimeoutSeconds.
//
// +kubebuilder:validation:XValidation:rule="self.timeoutSeconds <= self.intervalSeconds",message="timeoutSeconds must not exceed intervalSeconds"
type ServiceEndpointHealthCheck struct {
	// Port is the TCP port probed on every producer, 1-65535. Unset, it is
	// the endpoint's port, which must then be a tcp port. A udp endpoint must
	// set it to a TCP port its producers listen on.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// IntervalSeconds is the time between two probes of one producer.
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
	// make a producer Unhealthy.
	// +optional
	// +kubebuilder:default=3
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	UnhealthyThreshold int32 `json:"unhealthyThreshold,omitempty"`

	// HealthyThreshold is the number of consecutive successful probes that
	// make a producer Healthy.
	// +optional
	// +kubebuilder:default=3
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	HealthyThreshold int32 `json:"healthyThreshold,omitempty"`
}

// ServiceEndpointStatus reports what the nodes observe of an endpoint.
type ServiceEndpointStatus struct {
	// Producers holds the health decision of every producer of a Spread
	// endpoint. Each node writes the entries of the producers on that node,
	// under its own field manager, and removes them when the producer stops
	// being selected. An entry whose attachmentUID no longer matches the
	// attachment of that name describes an earlier attachment and is ignored.
	// +optional
	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=4096
	Producers []ServiceEndpointProducerStatus `json:"producers,omitempty"`
}

// ServiceEndpointProducerStatus is one producer's health decision.
type ServiceEndpointProducerStatus struct {
	// Namespace is the producer VPCAttachment's namespace.
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`

	// Name is the producer VPCAttachment's name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// AttachmentUID is the UID of the VPCAttachment that was probed.
	// +kubebuilder:validation:Required
	AttachmentUID types.UID `json:"attachmentUID"`

	// Node is the node that hosts the producer and probes it.
	// +kubebuilder:validation:MinLength=1
	Node string `json:"node"`

	// Port is the TCP port that was probed.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// State is the decision. Healthy and Unknown producers receive new
	// flows; Unhealthy ones do not, unless every producer on the node is
	// Unhealthy.
	// +kubebuilder:validation:Required
	State BackendHealthState `json:"state"`

	// Reason is ProbeSucceeded, ProbeFailed, Pending or ProbeUnavailable.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=64
	Reason string `json:"reason"`

	// Message is the last probe error, when there is one.
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Message string `json:"message,omitempty"`

	// LastTransitionTime is when State last changed.
	// +kubebuilder:validation:Required
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`
}

// ServiceEndpointDeliveryMode defines the placement contract for a service.
// +kubebuilder:validation:Enum=NodeLocal;PreferNodeLocal
type ServiceEndpointDeliveryMode string

const (
	// ServiceEndpointDeliveryModeNodeLocal requires the endpoint's backing
	// attachment to be present on each node where selected consumers run.
	ServiceEndpointDeliveryModeNodeLocal ServiceEndpointDeliveryMode = "NodeLocal"

	// ServiceEndpointDeliveryModePreferNodeLocal selects a backing attachment on
	// the consumer's node when possible and otherwise tunnels to a ready remote
	// attachment while preserving the consumer source address.
	ServiceEndpointDeliveryModePreferNodeLocal ServiceEndpointDeliveryMode = "PreferNodeLocal"
)

// ServiceEndpointAttachmentReference identifies the private attachment that
// backs a platform service endpoint.
type ServiceEndpointAttachmentReference struct {
	// Namespace is the namespace containing the Cloud API VPCAttachment.
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`

	// Name is the Cloud API VPCAttachment name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// ServiceEndpointList is a list of ServiceEndpoint resources.
// +kubebuilder:object:root=true
type ServiceEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceEndpoint `json:"items"`
}

// ServiceRoutePolicy selects VPC attachments that should receive a route to a
// platform ServiceEndpoint. The selector is evaluated by the network control
// plane; Galactic compiles the selected attachments into dataplane state.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=svcroute
// +kubebuilder:printcolumn:name="SERVICE",type="string",JSONPath=".spec.serviceRef.name"
// +kubebuilder:printcolumn:name="REGION",type="string",JSONPath=".spec.region"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type ServiceRoutePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ServiceRoutePolicySpec   `json:"spec,omitempty"`
	Status ServiceRoutePolicyStatus `json:"status,omitempty"`
}

// ServiceRoutePolicySpec defines service selection and attachment eligibility.
// +kubebuilder:validation:XValidation:rule="!has(self.frontend) || has(self.consumerVPCRef)",message="frontend requires consumerVPCRef"
// +kubebuilder:validation:XValidation:rule="!has(self.frontend) || has(self.authorization)",message="frontend requires authorization"
type ServiceRoutePolicySpec struct {
	// ServiceRef identifies the ServiceEndpoint in this namespace.
	// +kubebuilder:validation:Required
	ServiceRef ServiceEndpointReference `json:"serviceRef"`

	// ConsumerVPCRef pins authorization to the immutable lifetime of the VPC
	// selected by AttachmentSelector. Galactic resolves the name through the
	// Cloud API and requires both the live name and UID to match.
	// +optional
	ConsumerVPCRef *ServiceRouteVPCReference `json:"consumerVPCRef,omitempty"`

	// Frontend is the address presented inside the consumer VPC. When set,
	// Galactic translates it to the ServiceEndpoint address and restores it on
	// replies.
	// +optional
	Frontend *ServiceRouteFrontend `json:"frontend,omitempty"`

	// Authorization defines the lifetime of translated service access.
	// +optional
	Authorization *ServiceRouteAuthorization `json:"authorization,omitempty"`

	// AttachmentSelector selects eligible VPC attachments by authoritative
	// labels. Labels that grant access to platform services must be assigned by
	// the network control plane, not by tenants.
	// +kubebuilder:validation:Required
	AttachmentSelector metav1.LabelSelector `json:"attachmentSelector"`

	// ProtocolPorts limits the traffic that the route is intended to carry.
	// An empty list means the endpoint's declared port and protocol are used.
	// +optional
	// +listType=atomic
	ProtocolPorts []ServiceRouteProtocolPort `json:"protocolPorts,omitempty"`

	// Region limits selected attachments to a region. An empty value means the
	// policy applies in every region where the endpoint is available.
	// +optional
	Region string `json:"region,omitempty"`
}

// ServiceRouteAuthorization defines persistent or time-bounded access.
// +kubebuilder:validation:XValidation:rule="has(self.persistent) && self.persistent ? !has(self.validUntil) : has(self.validUntil)",message="persistent access must omit validUntil; bounded access requires validUntil"
type ServiceRouteAuthorization struct {
	// Persistent retains access until policy withdrawal or VPC lifetime replacement.
	// +optional
	Persistent bool `json:"persistent,omitempty"`

	// ValidUntil is the absolute UTC deadline for requests and existing replies.
	// Node controllers reject deadlines more than two minutes in the future.
	// +optional
	ValidUntil metav1.Time `json:"validUntil,omitempty"`
}

// ServiceRouteVPCReference identifies one immutable Cloud API VPC lifetime.
type ServiceRouteVPCReference struct {
	// Name is the VPC name in the policy namespace.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// UID is the Kubernetes UID of that VPC lifetime.
	// +kubebuilder:validation:MinLength=1
	UID string `json:"uid"`
}

// ServiceRouteFrontend declares the consumer-facing service address.
type ServiceRouteFrontend struct {
	// Address is translated to the ServiceEndpoint address for requests and is
	// restored as the source address for replies.
	// +kubebuilder:validation:XValidation:rule="isIP(self)",message="address must be an IP address"
	Address string `json:"address"`
}

// ServiceRouteProtocolPort identifies an allowed transport protocol and port.
type ServiceRouteProtocolPort struct {
	// Protocol is the transport protocol.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=tcp;udp
	Protocol NetworkServiceProtocol `json:"protocol"`

	// Port is the transport port.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// ServiceEndpointReference identifies a ServiceEndpoint in the policy's
// namespace.
type ServiceEndpointReference struct {
	// Name is the ServiceEndpoint name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// ServiceRoutePolicyStatus contains policy conditions and fenced node reports.
type ServiceRoutePolicyStatus struct {
	// ObservedGeneration is the .metadata.generation this status was computed from.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions contains durable acceptance and service-availability state.
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Nodes contains short-lived acknowledgments written by trusted node controllers.
	// Consumers require current UID, generation, input digest, and unexpired reports.
	// +listType=map
	// +listMapKey=nodeName
	// +optional
	Nodes []ServiceRouteNodeStatus `json:"nodes,omitempty"`
}

// ServiceRouteNodeStatus acknowledges one node's current programmed path.
type ServiceRouteNodeStatus struct {
	NodeName           string      `json:"nodeName"`
	PolicyUID          string      `json:"policyUID"`
	ObservedGeneration int64       `json:"observedGeneration"`
	InputDigest        string      `json:"inputDigest"`
	Ready              bool        `json:"ready"`
	ValidUntil         metav1.Time `json:"validUntil"`
}

const (
	// ConditionTypeServiceRouteAccepted reports whether the policy is valid and
	// can be compiled by the dataplane controllers.
	ConditionTypeServiceRouteAccepted = "Accepted"
)

// ServiceRoutePolicyList is a list of ServiceRoutePolicy resources.
// +kubebuilder:object:root=true
type ServiceRoutePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceRoutePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(
		&ServiceEndpoint{}, &ServiceEndpointList{},
		&ServiceRoutePolicy{}, &ServiceRoutePolicyList{},
	)
}
