/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkFabricIdentitySpec carries the identity the fabric knows one network
// by.
type NetworkFabricIdentitySpec struct {
	// Identity is what the fabric knows the network by, the same in every
	// location the network reaches. The Route Target is derived from it, which
	// is what makes two locations of one network import each other's routes
	// rather than behave as two networks that share a name. The VRF device is
	// named from it for the same reason.
	//
	// It is an integer rather than an encoded string because a consumer builds
	// `ASN:<identity>` from it and encodes it for its own use. It is 32 bits
	// wide because that is what survives into the Route Target: the fabric
	// truncates, so a wider value would be uniqueness the platform believes it
	// has and the fabric does not.
	//
	// It is never zero and never changes. The fabric embeds it in import policy
	// in every location the network reaches, so a network that changed identity
	// would be a different network to everything already carrying its traffic.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="identity is immutable"
	Identity int64 `json:"identity"`

	// NetworkRef names the network this identity belongs to.
	//
	// It carries a name and no UID, deliberately. The identity is a permanent
	// property of a name in a namespace, not of one object's lifetime: a
	// network deleted and recreated under the same name inherits it. A UID here
	// would document the opposite of the rule.
	//
	// +kubebuilder:validation:Required
	NetworkRef NetworkFabricIdentityNetworkRef `json:"networkRef"`
}

// NetworkFabricIdentityNetworkRef identifies the network an identity was
// allocated for.
type NetworkFabricIdentityNetworkRef struct {
	// Name is the network's name.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Identity",type="integer",JSONPath=".spec.identity"
// +kubebuilder:printcolumn:name="Network",type="string",JSONPath=".spec.networkRef.name"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// NetworkFabricIdentity tells a location what identity the fabric knows a
// network by.
//
// There is one per network, not one per location. A VPC is the network's
// realization at a single location and takes its identity from here, which is
// what makes the locations of one network the same network on the fabric
// instead of unrelated ones that happen to share a name.
//
// This is platform-internal. It is written centrally and carried to the cells
// where the network is required; it never appears in a project control plane
// and no consumer reads or writes one. The identity is a value the fabric acts
// on directly, so it is kept to the platform rather than published beside the
// network it belongs to.
//
// This object is managed for you. It follows the Network it was allocated for.
type NetworkFabricIdentity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the whole of this object. There is no status: federation carries
	// configuration to a cell and deliberately does not carry status, so
	// anything a cell has to read has to be here.
	Spec NetworkFabricIdentitySpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkFabricIdentityList contains a list of NetworkFabricIdentity.
type NetworkFabricIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkFabricIdentity `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkFabricIdentity{}, &NetworkFabricIdentityList{})
}
