package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// ServiceEndpoint publishes a platform service that can be reached through a
// VPC attachment. The object describes the service contract; the controller
// that owns the service is responsible for its health and implementation.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=svcendpoint
// +kubebuilder:printcolumn:name="ADDRESS",type="string",JSONPath=".spec.address"
// +kubebuilder:printcolumn:name="PORT",type="integer",JSONPath=".spec.port"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type ServiceEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ServiceEndpointSpec `json:"spec,omitempty"`
}

// ServiceEndpointSpec defines a platform service address and its scope.
// +kubebuilder:validation:XValidation:rule="has(self.attachmentRef) != has(self.attachmentSelector)",message="exactly one of attachmentRef or attachmentSelector must be set"
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
	// controller, not by tenants. The dataplane selects one ready replica for
	// each consumer according to DeliveryMode.
	// +optional
	AttachmentSelector *metav1.LabelSelector `json:"attachmentSelector,omitempty"`

	// Region limits endpoint selection to a region. An empty value means the
	// endpoint is not region-scoped.
	// +optional
	Region string `json:"region,omitempty"`
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

	// Authorization bounds translated access independently of application leases.
	// Only trusted networking integration may renew this deadline.
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

// ServiceRouteAuthorization bounds one network authorization episode.
type ServiceRouteAuthorization struct {
	// ValidUntil is the absolute UTC deadline for requests and existing replies.
	// Node controllers reject deadlines more than two minutes in the future.
	ValidUntil metav1.Time `json:"validUntil"`
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
