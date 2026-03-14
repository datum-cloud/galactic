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
// Phase 2 — defined here so the schema is forward-compatible.
type RouteReflectorConfig struct {
	// ClusterID is the route reflector cluster ID.
	// +required
	ClusterID string `json:"clusterID"`
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
	// Phase 2 stub.
	// +optional
	RouteReflector *RouteReflectorConfig `json:"routeReflector,omitempty"`
}

// BGPSessionStatus reflects the observed BGP session state.
type BGPSessionStatus struct {
	// SessionState is the current BGP FSM state as reported by GoBGP.
	// One of: Unknown, Idle, Connect, Active, OpenSent, OpenConfirm, Established.
	// +optional
	SessionState string `json:"sessionState,omitempty"`

	// Conditions describe the current state of the session.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ReceivedPrefixes is the count of prefixes received from the remote peer.
	// +optional
	ReceivedPrefixes int64 `json:"receivedPrefixes,omitempty"`

	// AdvertisedPrefixes is the count of prefixes advertised to the remote peer.
	// +optional
	AdvertisedPrefixes int64 `json:"advertisedPrefixes,omitempty"`

	// LastTransitionTime is when the session state last changed.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// FlapCount is the number of times this session has gone from Established
	// to a non-Established state.
	// +optional
	FlapCount int64 `json:"flapCount,omitempty"`
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
// +kubebuilder:printcolumn:name="Session",type=string,JSONPath=`.status.sessionState`
// +kubebuilder:printcolumn:name="RX Prefixes",type=integer,JSONPath=`.status.receivedPrefixes`

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
