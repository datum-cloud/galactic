package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// ServiceEndpointProducerReport holds one node's health decisions for the
// producers of one Spread ServiceEndpoint on that node. The galactic-router on
// that node is its only writer: it creates the report in the endpoint's
// namespace, owned by the endpoint, renews its entries every
// ServiceEndpointProducerReportRenewInterval, and deletes it when the node
// has no producers of the endpoint left. A node with producers of the
// endpoint deletes another node's report none of whose entries was renewed
// within ServiceEndpointProducerReportRetention, because that node is gone.
// When no node has producers of the endpoint left, nothing sweeps, and its
// reports, whose entries readers ignore once expired, go when the endpoint
// does. Each report holds at most ServiceEndpointMaxProducersPerNode
// entries, so an endpoint's producers can span any number of nodes.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=svcproducerreport
// +kubebuilder:printcolumn:name="ENDPOINT",type="string",JSONPath=".spec.endpointName"
// +kubebuilder:printcolumn:name="NODE",type="string",JSONPath=".spec.node"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type ServiceEndpointProducerReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ServiceEndpointProducerReportSpec `json:"spec"`
}

// ServiceEndpointProducerReportSpec is one node's report for one endpoint.
//
// +kubebuilder:validation:XValidation:rule="self.endpointName == oldSelf.endpointName && self.endpointUID == oldSelf.endpointUID && self.node == oldSelf.node",message="endpointName, endpointUID and node are immutable"
// +kubebuilder:validation:XValidation:rule="!has(self.producers) || self.producers.all(p, p.node == self.node)",message="every producer entry must name the report's node"
type ServiceEndpointProducerReportSpec struct {
	// EndpointName is the name of the ServiceEndpoint, in the report's
	// namespace, whose producers the report describes.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	EndpointName string `json:"endpointName"`

	// EndpointUID is the UID of that ServiceEndpoint. Readers ignore a report
	// whose EndpointUID does not match the current endpoint.
	// +kubebuilder:validation:Required
	EndpointUID types.UID `json:"endpointUID"`

	// Node is the node that hosts and probes the producers.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Node string `json:"node"`

	// Producers holds the health decision of each producer of the endpoint on
	// Node.
	// +optional
	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=16
	Producers []ServiceEndpointProducerStatus `json:"producers,omitempty"`
}

// ServiceEndpointProducerReportList is a list of ServiceEndpointProducerReport
// resources.
// +kubebuilder:object:root=true
type ServiceEndpointProducerReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceEndpointProducerReport `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ServiceEndpointProducerReport{}, &ServiceEndpointProducerReportList{})
}
