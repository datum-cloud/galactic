package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkGateway marks a single dedicated gateway-role node as running the
// Maglev/DSR consistent-hash L4 load-balancer engine. Exactly one
// NetworkGateway exists per gateway node (spec.targetRef.name is the
// Kubernetes node name), mirroring the BGPRouter node-scoped root object
// pattern. NetworkService resources are served by every NetworkGateway in the
// namespace equally (anycast — see NetworkServiceStatus's doc comment); this
// object's only job is to identify which nodes participate at all and
// surface each node's engine health via Conditions.
//
// This design does no address rewriting on the load-balancing path at all
// (DSR — Direct Server Return): the gateway's XDP program picks a backend
// via consistent hashing on the flow's 5-tuple and pushes an SRv6 uSID outer
// header addressed to the backend's worker node directly, untouched
// otherwise. The backend node answers the client directly (see
// ServiceVIPBinding) — reply traffic never re-enters this gateway node, so
// unlike the Full-NAT design this type originally described, a gateway node
// has no SNAT source address of its own to publish and nothing analogous to
// sRv6Address/egressAddress/egressSID belongs on this status anymore.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=netgw
// +kubebuilder:printcolumn:name="TARGET",type="string",JSONPath=".spec.targetRef.name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type NetworkGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkGatewaySpec   `json:"spec,omitempty"`
	Status NetworkGatewayStatus `json:"status,omitempty"`
}

// NetworkGatewaySpec defines the desired state of a NetworkGateway.
type NetworkGatewaySpec struct {
	// TargetRef identifies the Node this gateway engine executes on.
	// +kubebuilder:validation:Required
	TargetRef TargetRef `json:"targetRef"`
}

// NetworkGatewayStatus defines the observed state of a NetworkGateway.
type NetworkGatewayStatus struct {
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

// NetworkGatewayList is a list of NetworkGateway resources.
// +kubebuilder:object:root=true
type NetworkGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkGateway `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkGateway{}, &NetworkGatewayList{})
}
