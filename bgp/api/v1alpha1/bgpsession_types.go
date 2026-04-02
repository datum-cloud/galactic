/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RouteReflectorConfig marks a session as a route reflector client relationship.
type RouteReflectorConfig struct {
	// ClusterID is the route reflector cluster ID.
	// +required
	ClusterID string `json:"clusterID"`
}

// EBGPSessionConfig holds eBGP-specific parameters for a BGPSession.
// Only meaningful when the local and remote endpoints have different AS numbers.
type EBGPSessionConfig struct {
	// MultiHop enables eBGP multi-hop when the peers are not directly connected.
	// Sets GoBGP EbgpMultihop.Enabled and EbgpMultihop.MultihopTtl.
	// +optional
	MultiHop *EBGPMultiHop `json:"multiHop,omitempty"`

	// TTLSecurity enables GTSM for this eBGP session.
	// Mutually exclusive with MultiHop.
	// +optional
	TTLSecurity *EBGPTTLSecurity `json:"ttlSecurity,omitempty"`
}

// EBGPMultiHop configures eBGP multi-hop.
type EBGPMultiHop struct {
	// TTL is the maximum number of hops permitted (1–255).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=255
	// +required
	TTL uint32 `json:"ttl"`
}

// EBGPTTLSecurity configures GTSM for eBGP sessions.
type EBGPTTLSecurity struct {
	// TTL is the expected minimum TTL for incoming eBGP packets.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=255
	// +required
	TTL uint32 `json:"ttl"`
}

// BGPSessionSpec declares a peering relationship between two BGPEndpoints.
type BGPSessionSpec struct {
	// LocalEndpoint references the local BGPEndpoint by name.
	// +required
	LocalEndpoint string `json:"localEndpoint"`

	// RemoteEndpoint references the remote BGPEndpoint by name.
	// +required
	RemoteEndpoint string `json:"remoteEndpoint"`

	// HoldTime is the BGP hold time in seconds. Defaults to 90.
	// +kubebuilder:validation:Minimum=3
	// +kubebuilder:default=90
	// +optional
	HoldTime int32 `json:"holdTime,omitempty"`

	// KeepaliveTime is the BGP keepalive interval in seconds. Defaults to 30.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=30
	// +optional
	KeepaliveTime int32 `json:"keepaliveTime,omitempty"`

	// RouteReflector configures this session for route reflector client behavior.
	// When set, the local speaker treats the remote peer as a route reflector client.
	// +optional
	RouteReflector *RouteReflectorConfig `json:"routeReflector,omitempty"`

	// EBGPConfig holds eBGP-specific session parameters.
	// Only meaningful when the local and remote endpoints have different AS numbers.
	// +optional
	EBGPConfig *EBGPSessionConfig `json:"ebgpConfig,omitempty"`
}

// BGPSessionStatus reflects the observed BGP session state.
// Operational counters (session state, received/advertised prefixes, flap count)
// are exposed as Prometheus metrics rather than CRD status fields to avoid
// high-frequency status writes from polling loops.
type BGPSessionStatus struct {
	// Conditions describe the current state of the session.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Condition types for BGPSession.
const (
	// BGPSessionEstablished indicates the BGP session is in Established state.
	BGPSessionEstablished = "SessionEstablished"
	// BGPSessionConfigured indicates the session has been successfully added to GoBGP.
	BGPSessionConfigured = "Configured"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:scope=Cluster,shortName=bgpsess
// +kubebuilder:printcolumn:name="Local",type=string,JSONPath=`.spec.localEndpoint`
// +kubebuilder:printcolumn:name="Remote",type=string,JSONPath=`.spec.remoteEndpoint`
// +kubebuilder:printcolumn:name="Configured",type=string,JSONPath=`.status.conditions[?(@.type=="Configured")].status`
// +kubebuilder:printcolumn:name="Established",type=string,JSONPath=`.status.conditions[?(@.type=="SessionEstablished")].status`

// BGPSession declares a BGP peering relationship between two BGPEndpoints.
// Sessions are created by BGPPeeringPolicy controllers or manually by platform operators.
// Each node's BGP controller reconciles all BGPSession resources into GoBGP AddPeer calls.
type BGPSession struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec BGPSessionSpec `json:"spec"`
	// +optional
	Status BGPSessionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BGPSessionList contains a list of BGPSession.
type BGPSessionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPSession `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BGPSession{}, &BGPSessionList{})
}
