// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// FabricTopology generates the BGPPeers of one cell's fabric routers from
// FabricEndpoint records. It names the cell's member routers and the
// relationships between endpoints of one routing domain: a full mesh, route
// reflection, and external peers. For every relationship it creates the
// local side only: a peer on each member router toward each endpoint the
// relationship pairs it with. The cell on the other end generates the
// reciprocal peer from its own copy of the records and its own topology;
// the two ends agree only while those copies and relationships agree,
// which status.recordsDigest and status.relationshipsDigest let cells
// compare.
//
// Generated peers are ordinary BGPPeers, labelled as generated and
// annotated with the topology's UID, with no owner reference; the revision
// compiler reads them like any other peer. The topology never changes or
// deletes a peer it did not create, and reports a conflict where one is in
// its way. A session is identified by its router and remote address, so a
// peer keeps its name when the relationship or record producing it is
// renamed.
//
// A session the topology no longer generates is kept until one of its ends
// is out of service: the router is deleted, its FabricRouterDeployment
// committed a retiring release, the other cell deleted the endpoint record,
// or spec.drain names it. Entries in spec.drain stay until an operator
// removes them.
//
// Deleting the topology drops no session, whatever the deletion's
// propagation policy: generated peers have no owner reference for the
// garbage collector to follow, and before the topology goes the controller
// hands every peer it generated to manual control by removing its
// generated labels and UID, so the peers keep compiling as hand-authored
// ones. A topology created again reports them as conflicts
// rather than adopting them.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ftopo
// +kubebuilder:printcolumn:name="DOMAIN",type="string",JSONPath=".spec.routingDomain"
// +kubebuilder:printcolumn:name="CELL",type="string",JSONPath=".spec.cell"
// +kubebuilder:printcolumn:name="GENERATED",type="integer",JSONPath=".status.generated"
// +kubebuilder:printcolumn:name="CONFLICTING",type="integer",JSONPath=".status.conflicting"
// +kubebuilder:printcolumn:name="RETAINED",type="integer",JSONPath=".status.retained"
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 63",message="a topology's name is a label value, at most 63 characters"
type FabricTopology struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec   FabricTopologySpec   `json:"spec"`
	Status FabricTopologyStatus `json:"status,omitempty"`
}

// FabricTopologySpec is one cell's routing relationships.
//
// +kubebuilder:validation:XValidation:rule="self.routingDomain == oldSelf.routingDomain && self.cell == oldSelf.cell",message="routingDomain and cell are immutable"
// +kubebuilder:validation:XValidation:rule="has(self.mesh) || has(self.reflection) || has(self.external)",message="a topology has at least one relationship"
type FabricTopologySpec struct {
	// RoutingDomain is the fabric whose FabricEndpoints the topology reads.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	RoutingDomain string `json:"routingDomain"`

	// Cell is the cell the topology generates for. Endpoints of this cell
	// belong to routers that run here; every other endpoint is remote.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Cell string `json:"cell"`

	// Members are the fabric-class BGPRouters, in this namespace, the
	// topology generates peers on.
	Members FabricTopologyMembers `json:"members"`

	// Mesh relationships peer every selected endpoint with every other.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=8
	Mesh []FabricMeshRelationship `json:"mesh,omitempty"`

	// Reflection relationships peer every reflector with every client.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=8
	Reflection []FabricReflectionRelationship `json:"reflection,omitempty"`

	// External relationships peer members with routers no topology
	// manages, such as providers' and transits'.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=32
	External []FabricExternalRelationship `json:"external,omitempty"`

	// FailureDomainLabel is the Node label that gives a local endpoint
	// without spec.failureDomain its failure domain.
	// +kubebuilder:default="topology.kubernetes.io/zone"
	// +kubebuilder:validation:MaxLength=317
	// +kubebuilder:validation:Pattern=`^([a-z0-9]([-a-z0-9.]*[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`
	FailureDomainLabel string `json:"failureDomainLabel,omitempty"`

	// MaxSessionsPerRouter bounds the peers the topology generates on one
	// router. A topology that would exceed it changes nothing and reports
	// Accepted False.
	// +kubebuilder:default=64
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1024
	MaxSessionsPerRouter int32 `json:"maxSessionsPerRouter,omitempty"`

	// Drain releases the sessions of routers and endpoints whose removal
	// cannot be observed otherwise, such as a router on a node that will
	// never report its retirement.
	// +optional
	Drain *FabricTopologyDrain `json:"drain,omitempty"`
}

// FabricTopologyMembers selects BGPRouters by label, by name, or both.
//
// +kubebuilder:validation:XValidation:rule="has(self.routerSelector) || has(self.routers)",message="name a routerSelector or routers"
type FabricTopologyMembers struct {
	// RouterSelector selects BGPRouters by label.
	// +optional
	RouterSelector *metav1.LabelSelector `json:"routerSelector,omitempty"`

	// Routers names BGPRouters.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=256
	Routers []LocalObjectRef `json:"routers,omitempty"`
}

// FabricSessionFamily is an IP family a session runs over, and the unicast
// family it carries when no peer profile names its families.
//
// +kubebuilder:validation:Enum=ipv4;ipv6
type FabricSessionFamily string

const (
	FabricSessionFamilyIPv4 FabricSessionFamily = "ipv4"
	FabricSessionFamilyIPv6 FabricSessionFamily = "ipv6"
)

// FabricUpdateSource is where a generated session is sourced from.
//
// +kubebuilder:validation:Enum=EndpointAddress;None
type FabricUpdateSource string

const (
	// FabricUpdateSourceEndpointAddress sources the session from the local
	// router's own endpoint address on the transport.
	FabricUpdateSourceEndpointAddress FabricUpdateSource = "EndpointAddress"
	// FabricUpdateSourceNone leaves the source to the router's route to the
	// peer, for directly connected links.
	FabricUpdateSourceNone FabricUpdateSource = "None"
)

// FabricSessionSettings are the settings of the peers one side of a
// relationship generates. Route-reflector clients are set by the
// relationship, never here.
type FabricSessionSettings struct {
	// PeerProfileRef names the BGPPeerProfile of every generated peer. With
	// one, a peer activates the profile's families; without one, the
	// unicast family of the transport family it runs over.
	// +optional
	PeerProfileRef *LocalObjectRef `json:"peerProfileRef,omitempty"`

	// Transport overrides the profile's transport settings.
	// +optional
	Transport *BGPPeerTransport `json:"transport,omitempty"`

	// FamilySettings are per-family settings: import and export policies,
	// next-hop mode, local weight, prefix limits. Without a profile only
	// the entry for a peer's own family applies to it.
	// +optional
	// +listType=map
	// +listMapKey=afi
	// +listMapKey=safi
	// +kubebuilder:validation:MaxItems=2
	// +kubebuilder:validation:XValidation:rule="self.all(f, !has(f.routeReflectorClient))",message="the relationship sets routeReflectorClient"
	// +kubebuilder:validation:XValidation:rule="self.all(f, f.afi != 'l2vpn')",message="fabric sessions carry unicast families"
	FamilySettings []BGPPeerFamilySettings `json:"familySettings,omitempty"`
}

// FabricMeshRelationship peers every selected endpoint with every other on
// the same transport.
type FabricMeshRelationship struct {
	// Name identifies the relationship on its generated peers.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// Transports are the transports the mesh runs over. Two endpoints peer
	// over each transport both are on.
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Transports []string `json:"transports"`

	// Families are the IP families sessions run over: one session per
	// family both endpoints have an address in.
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=2
	Families []FabricSessionFamily `json:"families"`

	// UpdateSource is where sessions are sourced from.
	// +kubebuilder:default=EndpointAddress
	UpdateSource FabricUpdateSource `json:"updateSource,omitempty"`

	// EndpointSelector selects the mesh's endpoints by label. An empty
	// selector selects every endpoint of the routing domain.
	EndpointSelector metav1.LabelSelector `json:"endpointSelector"`

	// Settings apply to every generated peer.
	// +optional
	Settings FabricSessionSettings `json:"settings,omitempty"`
}

// FabricReflectionRelationship peers every reflector with every client on
// the same transport. Reflectors do not peer with each other here.
type FabricReflectionRelationship struct {
	// Name identifies the relationship on its generated peers.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// Transports are the transports reflection runs over.
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Transports []string `json:"transports"`

	// Families are the IP families sessions run over.
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=2
	Families []FabricSessionFamily `json:"families"`

	// UpdateSource is where sessions are sourced from.
	// +kubebuilder:default=EndpointAddress
	UpdateSource FabricUpdateSource `json:"updateSource,omitempty"`

	// ReflectorSelector selects the reflectors' endpoints by label.
	ReflectorSelector metav1.LabelSelector `json:"reflectorSelector"`

	// ClientSelector selects the clients' endpoints by label.
	ClientSelector metav1.LabelSelector `json:"clientSelector"`

	// Reflector applies to the peers a reflector generates toward its
	// clients, each of which is a route-reflector client in every family.
	// +optional
	Reflector FabricSessionSettings `json:"reflector,omitempty"`

	// Client applies to the peers a client generates toward its
	// reflectors.
	// +optional
	Client FabricSessionSettings `json:"client,omitempty"`
}

// FabricExternalRelationship peers member routers with routers outside
// every topology. Its peers are explicit: an external router has no
// endpoint record.
//
// +kubebuilder:validation:XValidation:rule="self.updateSource != 'EndpointAddress' || has(self.transport)",message="sourcing from the endpoint address needs the transport"
type FabricExternalRelationship struct {
	// Name identifies the relationship on its generated peers.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// Routers selects the members that peer with every external peer.
	Routers FabricTopologyMembers `json:"routers"`

	// Transport is the transport of the local endpoint sessions are
	// sourced from.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Transport *string `json:"transport,omitempty"`

	// UpdateSource is where sessions are sourced from.
	// +kubebuilder:default=EndpointAddress
	UpdateSource FabricUpdateSource `json:"updateSource,omitempty"`

	// Peers are the external routers.
	// +listType=map
	// +listMapKey=address
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	Peers []FabricExternalPeer `json:"peers"`

	// Settings apply to every generated peer.
	// +optional
	Settings FabricSessionSettings `json:"settings,omitempty"`
}

// FabricExternalPeer is one external router.
type FabricExternalPeer struct {
	// Address is the external router's address. A session runs in its
	// family.
	// +kubebuilder:validation:MaxLength=45
	// +kubebuilder:validation:XValidation:rule="isIP(self)",message="address must be an IP address"
	Address string `json:"address"`

	// ASN is the external router's ASN.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	ASN int64 `json:"asn"`
}

// FabricTopologyDrain names what may lose its retained sessions.
type FabricTopologyDrain struct {
	// Routers names BGPRouters of this cell. Every retained session from
	// or toward one is released.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=256
	Routers []LocalObjectRef `json:"routers,omitempty"`

	// Endpoints names FabricEndpoints, of any cell. Every retained session
	// toward or sourced from one is released.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=256
	Endpoints []LocalObjectRef `json:"endpoints,omitempty"`
}

// Labels and annotations on the BGPPeers a topology generates.
const (
	// LabelManagedBy marks a generated peer. A peer without it, or without
	// a controller reference to the topology, is never touched.
	LabelManagedBy = "app.kubernetes.io/managed-by"
	// ManagedByFabricTopology is LabelManagedBy's value.
	ManagedByFabricTopology = "fabric-topology"
	// LabelFabricTopology names the generating topology.
	LabelFabricTopology = "galactic.datumapis.com/fabric-topology"
	// LabelPeerFailureDomain is the failure domain of the peer's remote
	// end, when it has one.
	LabelPeerFailureDomain = "galactic.datumapis.com/peer-failure-domain"
	// LabelPeerCell is the cell of the peer's remote end; external peers
	// have none.
	LabelPeerCell = "galactic.datumapis.com/peer-cell"

	// AnnotationRelationship is the generating relationship, as
	// kind/name: mesh/NAME, reflection/NAME or external/NAME.
	AnnotationRelationship = "galactic.datumapis.com/fabric-relationship"
	// AnnotationLocalEndpoint names the local router's endpoint, when the
	// session uses one.
	AnnotationLocalEndpoint = "galactic.datumapis.com/local-endpoint"
	// AnnotationRemoteEndpoint names the remote router's endpoint.
	AnnotationRemoteEndpoint = "galactic.datumapis.com/remote-endpoint"
	// AnnotationRemoteEndpointUID is that endpoint's UID, so a deleted and
	// recreated record is told apart from the one the peer came from.
	AnnotationRemoteEndpointUID = "galactic.datumapis.com/remote-endpoint-uid"
	// AnnotationRemoteRouter names the remote router in its own cell.
	AnnotationRemoteRouter = "galactic.datumapis.com/remote-router"
	// AnnotationFabricTopologyUID is the generating topology's UID. A peer
	// whose UID differs, such as one a deleted topology of the same name
	// generated, is not the topology's.
	AnnotationFabricTopologyUID = "galactic.datumapis.com/fabric-topology-uid"
	// AnnotationReleasePendingSince is when the topology first found a
	// generated peer's router or record gone. The peer is released once the
	// absence has lasted the settle period, unless the release guard holds.
	AnnotationReleasePendingSince = "galactic.datumapis.com/release-pending-since"
	// AnnotationReleasedFromTopology names the deleted topology that handed
	// a peer to manual control.
	AnnotationReleasedFromTopology = "galactic.datumapis.com/released-from-fabric-topology"

	// FabricTopologyFinalizer holds a topology until its generated peers
	// are handed to manual control.
	FabricTopologyFinalizer = "galactic.datumapis.com/fabric-topology"
)

// Topology condition types. Accepted and Ready are shared with the other
// fabric kinds.
const (
	// FabricTopologyConditionResolvedRefs is True when every profile and
	// policy the relationships name exists.
	FabricTopologyConditionResolvedRefs = "ResolvedRefs"
	// FabricTopologyConditionReleaseHeld is True when the topology keeps
	// sessions it would release because their records or routers vanished
	// in numbers that look like a mistake rather than a removal.
	FabricTopologyConditionReleaseHeld = "ReleaseHeld"
	// FabricTopologyConditionConflicts is True when a session the topology
	// would generate is blocked by a peer it does not control, or two
	// relationships generate one session.
	FabricTopologyConditionConflicts = "Conflicts"
)

// Topology condition reasons.
const (
	FabricTopologyReasonAccepted          = "Accepted"
	FabricTopologyReasonInvalidSelector   = "InvalidSelector"
	FabricTopologyReasonTooManySessions   = "TooManySessions"
	FabricTopologyReasonResolved          = "Resolved"
	FabricTopologyReasonUnresolvedRef     = "UnresolvedRef"
	FabricTopologyReasonNoConflicts       = "NoConflicts"
	FabricTopologyReasonPeerConflict      = "PeerConflict"
	FabricTopologyReasonGenerated         = "Generated"
	FabricTopologyReasonMissingEndpoints  = "MissingEndpoints"
	FabricTopologyReasonNotAccepted       = "NotAccepted"
	FabricTopologyReasonConflictsBlocking = "ConflictsBlocking"
	FabricTopologyReasonReleaseHeld       = "ReleaseHeld"
	FabricTopologyReasonNothingHeld       = "NothingHeld"
)

// FabricTopologyStatus is what the generator did on its last pass.
type FabricTopologyStatus struct {
	// ObservedGeneration is the generation the status describes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Members counts the member routers.
	// +optional
	Members int32 `json:"members,omitempty"`

	// Generated counts the peers the topology generates and holds as
	// generated.
	// +optional
	Generated int32 `json:"generated,omitempty"`

	// Conflicting counts the sessions blocked by a conflict.
	// +optional
	Conflicting int32 `json:"conflicting,omitempty"`

	// MissingEndpoints counts the members with no usable endpoint in the
	// routing domain, and external sessions whose source endpoint is
	// missing.
	// +optional
	MissingEndpoints int32 `json:"missingEndpoints,omitempty"`

	// Retained counts the generated peers the topology no longer generates
	// and keeps until an end is out of service.
	// +optional
	Retained int32 `json:"retained,omitempty"`

	// RecordsDigest is the SHA-256 of every FabricEndpoint of the routing
	// domain this cell holds, by name and spec. Cells holding the same
	// records report the same digest.
	// +optional
	// +kubebuilder:validation:Pattern=`^([0-9a-f]{64})?$`
	RecordsDigest string `json:"recordsDigest,omitempty"`

	// RelationshipsDigest is the SHA-256 of the routing domain and the
	// mesh, reflection and external relationships. Cells generating the two
	// ends of one session from the same relationships report the same
	// digest.
	// +optional
	// +kubebuilder:validation:Pattern=`^([0-9a-f]{64})?$`
	RelationshipsDigest string `json:"relationshipsDigest,omitempty"`

	// Conditions are Accepted, ResolvedRefs, Conflicts, ReleaseHeld and
	// Ready.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// FabricTopologyList is a list of FabricTopology resources.
// +kubebuilder:object:root=true
type FabricTopologyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricTopology `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FabricTopology{}, &FabricTopologyList{})
}
