package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type MASQUEEndpointReference struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type MASQUEEndpointCertificateReference struct {
	Name string `json:"name"`
	// +kubebuilder:validation:Pattern="^[0-9a-f]{64}$"
	Revision string `json:"revision"`
}

// MASQUEEndpointSpec defines the shared endpoint registration and certificate.
//
// +kubebuilder:validation:XValidation:rule="self.cell == oldSelf.cell && self.hostname == oldSelf.hostname && self.metro == oldSelf.metro && self.provider == oldSelf.provider",message="endpoint identity is immutable"
// +kubebuilder:validation:XValidation:rule="self == oldSelf || self.revision > oldSelf.revision",message="changes require a greater revision"
type MASQUEEndpointSpec struct {
	Hostname string `json:"hostname"`
	Cell     string `json:"cell"`
	Metro    string `json:"metro"`
	Provider string `json:"provider"`
	// +kubebuilder:validation:Minimum=1
	Revision       int64                              `json:"revision"`
	CertificateRef MASQUEEndpointCertificateReference `json:"certificateRef"`
	Enabled        bool                               `json:"enabled"`
}

type MASQUEEndpointInstanceStatus struct {
	InstanceName               string `json:"instanceName"`
	ObservedRevision           int64  `json:"observedRevision"`
	AppliedRevision            int64  `json:"appliedRevision"`
	AppliedCertificateRevision string `json:"appliedCertificateRevision,omitempty"`
	// +kubebuilder:validation:Enum=Applied;Disabled;Error
	State             string      `json:"state"`
	ForwardingStopped bool        `json:"forwardingStopped"`
	LastHeartbeatTime metav1.Time `json:"lastHeartbeatTime"`
	Message           string      `json:"message,omitempty"`
}

type MASQUEEndpointStatus struct {
	// +listType=map
	// +listMapKey=instanceName
	Instances []MASQUEEndpointInstanceStatus `json:"instances,omitempty"`
}

// MASQUEEndpoint registers a hostname on existing cell provider capacity.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=galactic
type MASQUEEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              MASQUEEndpointSpec   `json:"spec"`
	Status            MASQUEEndpointStatus `json:"status,omitempty"`
}

// MASQUEEndpointList contains endpoint registrations.
//
// +kubebuilder:object:root=true
type MASQUEEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MASQUEEndpoint `json:"items"`
}
