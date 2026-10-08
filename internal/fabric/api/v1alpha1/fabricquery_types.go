// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Labels NSO sets on every FabricQuery so janitors can find and expire
// requests without reading their specs.
const (
	// LabelRequestID carries spec.requestID.
	LabelRequestID = "network.datumapis.com/fabric-request-id"
	// LabelExpiresAt carries spec.expiresAt as Unix seconds.
	LabelExpiresAt = "network.datumapis.com/fabric-expires-at"
)

// Condition types. Their truth values and reasons are part of the contract.
const (
	ConditionAccepted = "Accepted"
	ConditionComplete = "Complete"
	ConditionFailed   = "Failed"
)

// Condition reasons.
const (
	ReasonPending          = "Pending"
	ReasonRunning          = "Running"
	ReasonSucceeded        = "Succeeded"
	ReasonPartialResults   = "PartialResults"
	ReasonExecutionFailed  = "ExecutionFailed"
	ReasonNoNodesAvailable = "NoNodesAvailable"
	ReasonDeadlineExceeded = "DeadlineExceeded"
	ReasonRejected         = "Rejected"
)

// QueryType is a looking-glass query type.
// +kubebuilder:validation:Enum=RouteLookup;ASPath;Community;LargeCommunity;BGPSummary;Ping;Traceroute
type QueryType string

// AddressFamily selects IPv4 or IPv6.
// +kubebuilder:validation:Enum=IPv4;IPv6
type AddressFamily string

// FabricQuery is one public looking-glass query's work for one edge cell.
// NSO owns its spec and lifecycle on the hub, Karmada propagates it to the
// one pinned member cluster, and that cell's fabric-api gateway writes its
// status. The spec is immutable.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=fq
// +kubebuilder:printcolumn:name="TYPE",type="string",JSONPath=".spec.query.type"
// +kubebuilder:printcolumn:name="TARGET",type="string",JSONPath=".spec.query.target"
// +kubebuilder:printcolumn:name="SITE",type="string",JSONPath=".spec.site"
// +kubebuilder:printcolumn:name="COMPLETE",type="string",JSONPath=".status.conditions[?(@.type==\"Complete\")].status"
// +kubebuilder:printcolumn:name="REASON",type="string",JSONPath=".status.conditions[?(@.type==\"Complete\")].reason"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type FabricQuery struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec FabricQuerySpec `json:"spec"`
	// +optional
	Status FabricQueryStatus `json:"status,omitempty"`
}

// FabricQuerySpec is a canonical query pinned to one cell.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable"
type FabricQuerySpec struct {
	// RequestID identifies the request across retries and is the nodes'
	// duplicate-suppression key.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9._-]*$`
	RequestID string `json:"requestID"`

	// Source names the public LookingGlassQuery this request serves.
	// +kubebuilder:validation:Required
	Source PublicQueryReference `json:"source"`

	// Query is the canonical query.
	// +kubebuilder:validation:Required
	Query QuerySpec `json:"query"`

	// Site is the location the cell serves; the cell's gateway executes
	// only queries for its own site.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Site string `json:"site"`

	// ClusterName is the Karmada member cluster the query is pinned to. A
	// gateway executes only queries naming its own cluster.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	ClusterName string `json:"clusterName"`

	// NodeSelector restricts execution to fabric-router pods on matching
	// nodes. Operator-set only; NSO never copies a tenant value here.
	// +optional
	NodeSelector *metav1.LabelSelector `json:"nodeSelector,omitempty"`

	// Budgets bounds results. Zero fields take the cell's ceilings, and no
	// field can raise a ceiling.
	// +optional
	Budgets ResultBudgets `json:"budgets,omitempty"`

	// ExpiresAt is the absolute expiration. Nothing executes after it.
	// +kubebuilder:validation:Required
	ExpiresAt metav1.Time `json:"expiresAt"`
}

// PublicQueryReference names the public query in its project control plane.
type PublicQueryReference struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=64
	UID string `json:"uid"`
	// Cluster is the project control plane.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=253
	Cluster string `json:"cluster"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// QuerySpec is a canonical looking-glass query.
// +kubebuilder:validation:XValidation:rule="self.type == 'BGPSummary' ? !has(self.target) || size(self.target) == 0 : has(self.target) && size(self.target) > 0",message="target is required, except for BGPSummary where it must be empty"
// +kubebuilder:validation:XValidation:rule="!has(self.hostname) || self.type == 'Ping' || self.type == 'Traceroute'",message="hostname is only for probes"
//
//nolint:lll // kubebuilder markers must stay on one line.
type QuerySpec struct {
	// +kubebuilder:validation:Required
	Type QueryType `json:"type"`
	// Target is the canonical target. For Ping and Traceroute it is the
	// resolved numeric destination, identical for every node.
	// +optional
	// +kubebuilder:validation:MaxLength=255
	Target string `json:"target,omitempty"`
	// +kubebuilder:validation:Required
	AddressFamily AddressFamily `json:"addressFamily"`
	// Hostname is the probe destination as the tenant wrote it, kept for
	// display. Cells never resolve it.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	Hostname string `json:"hostname,omitempty"`
}

// ResultBudgets bounds one request's results.
type ResultBudgets struct {
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=32
	MaxNodes int32 `json:"maxNodes,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=131072
	MaxNodeResponseBytes int32 `json:"maxNodeResponseBytes,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=393216
	MaxObjectBytes int32 `json:"maxObjectBytes,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	MaxPrefixes int32 `json:"maxPrefixes,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=8
	MaxPathsPerPrefix int32 `json:"maxPathsPerPrefix,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=64
	MaxCommunitiesPerPath int32 `json:"maxCommunitiesPerPath,omitempty"`
}

// FabricQueryStatus is the cell's execution record: a start marker, then one
// bounded terminal result. Once Complete is True it never changes.
type FabricQueryStatus struct {
	// RequestID echoes spec.requestID so status aggregation can check it.
	// +optional
	RequestID string `json:"requestID,omitempty"`
	// ProducerCluster is the cluster that wrote this status; status
	// aggregation refuses any producer other than spec.clusterName.
	// +optional
	ProducerCluster string `json:"producerCluster,omitempty"`
	// ObservedGeneration is the generation this status describes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Attempt counts executions started for this request. It rises only
	// when a gateway replaces one that stopped before persisting a result.
	// +optional
	Attempt int32 `json:"attempt,omitempty"`
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
	// Nodes is the fixed node snapshot taken when execution started.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=64
	Nodes []NodeTarget `json:"nodes,omitempty"`
	// Observations holds one entry per executed node, sorted by node.
	// +optional
	// +listType=map
	// +listMapKey=node
	// +kubebuilder:validation:MaxItems=32
	Observations []NodeObservation `json:"observations,omitempty"`
	// +optional
	Coverage Coverage `json:"coverage,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// NodeTarget is one node in the execution snapshot.
type NodeTarget struct {
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// +kubebuilder:validation:MaxLength=253
	Pod string `json:"pod"`
	// +kubebuilder:validation:MaxLength=64
	PodUID string `json:"podUID"`
	// +optional
	// +kubebuilder:validation:MaxLength=45
	HostIP string `json:"hostIP,omitempty"`
	// CertificatePod is the pod whose identity the node's sidecar presents.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	CertificatePod string `json:"certificatePod,omitempty"`
	// Selected is true for a node executed on. A discovered node that was
	// not ready or exceeded the node budget is recorded with Selected false
	// and OmittedReason set.
	Selected bool `json:"selected"`
	// +optional
	// +kubebuilder:validation:MaxLength=64
	OmittedReason string `json:"omittedReason,omitempty"`
}

// Coverage accounts for every node discovered.
type Coverage struct {
	Expected   int32 `json:"expected"`
	Successful int32 `json:"successful"`
	Failed     int32 `json:"failed"`
	Omitted    int32 `json:"omitted"`
}

// NodeObservation is one node's answer, or its error.
type NodeObservation struct {
	// +kubebuilder:validation:MaxLength=253
	Node string `json:"node"`
	// +optional
	SampleTime *metav1.Time `json:"sampleTime,omitempty"`
	// +optional
	DurationMilliseconds int64 `json:"durationMilliseconds,omitempty"`
	// ErrorCode is set when the node produced no answer.
	// +optional
	// +kubebuilder:validation:MaxLength=64
	ErrorCode string `json:"errorCode,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=256
	ErrorMessage string `json:"errorMessage,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=45
	RouterID string `json:"routerID,omitempty"`
	// +optional
	ASN int64 `json:"asn,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=64
	FRRVersion string `json:"frrVersion,omitempty"`
	// Matched counts matching prefixes; set only when MatchedIsExact.
	// +optional
	Matched *int32 `json:"matched,omitempty"`
	// +optional
	MatchedIsExact bool `json:"matchedIsExact,omitempty"`
	// +optional
	Truncated bool `json:"truncated,omitempty"`
	// +optional
	Routes *RouteResult `json:"routes,omitempty"`
	// +optional
	Summary *SummaryResult `json:"summary,omitempty"`
	// +optional
	Ping *PingResult `json:"ping,omitempty"`
	// +optional
	Traceroute *TracerouteResult `json:"traceroute,omitempty"`
}

// RouteResult is a lookup or search answer.
type RouteResult struct {
	// LookupKind is Exact, LongestMatch or Search.
	// +kubebuilder:validation:Enum=Exact;LongestMatch;Search
	LookupKind string `json:"lookupKind"`
	// +optional
	// +kubebuilder:validation:MaxItems=100
	Prefixes []PrefixObservation `json:"prefixes,omitempty"`
	// Index is set when a search was answered from the node's search index,
	// which follows bgpd's Loc-RIB over BMP; each prefix then carries its
	// selected path only.
	// +optional
	Index *IndexState `json:"index,omitempty"`
}

// IndexState is the freshness of a node's search index.
type IndexState struct {
	// SyncedAt is when the index's current BMP session delivered the full
	// table.
	// +optional
	SyncedAt *metav1.Time `json:"syncedAt,omitempty"`
	// LastUpdate is when the index last applied a route change.
	// +optional
	LastUpdate *metav1.Time `json:"lastUpdate,omitempty"`
	// Version counts route changes applied; it only grows.
	// +optional
	Version int64 `json:"version,omitempty"`
	// Routes is the number of prefixes the index holds.
	// +optional
	Routes int64 `json:"routes,omitempty"`
}

// PrefixObservation is one prefix as one router holds it.
type PrefixObservation struct {
	// +kubebuilder:validation:MaxLength=49
	Prefix string `json:"prefix"`
	// +optional
	// +kubebuilder:validation:MaxItems=8
	Paths []Path `json:"paths,omitempty"`
	// +optional
	TotalPaths int32 `json:"totalPaths,omitempty"`
	// +optional
	Installation *Installation `json:"installation,omitempty"`
}

// Path is one BGP path. Best describes the source router's own choice.
type Path struct {
	// +optional
	Best bool `json:"best,omitempty"`
	// +optional
	Multipath bool `json:"multipath,omitempty"`
	// +optional
	Valid bool `json:"valid,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=64
	SelectionReason string `json:"selectionReason,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	ASPath string `json:"asPath,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=64
	ASPathSegments []ASSegment `json:"asPathSegments,omitempty"`
	// Origin is the BGP ORIGIN attribute.
	// +optional
	// +kubebuilder:validation:MaxLength=16
	Origin string `json:"origin,omitempty"`
	// OriginASN is the originating AS; 0 when local or ambiguous.
	// +optional
	OriginASN int64 `json:"originASN,omitempty"`
	// +optional
	LocalPref *int64 `json:"localPref,omitempty"`
	// +optional
	MED *int64 `json:"med,omitempty"`
	// +optional
	Weight int64 `json:"weight,omitempty"`
	// +optional
	Local bool `json:"local,omitempty"`
	// +optional
	Aggregated bool `json:"aggregated,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=64
	Communities []string `json:"communities,omitempty"`
	// +optional
	TotalCommunities int32 `json:"totalCommunities,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=64
	LargeCommunities []string `json:"largeCommunities,omitempty"`
	// +optional
	TotalLargeCommunities int32 `json:"totalLargeCommunities,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=16
	NextHops []NextHop `json:"nextHops,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=45
	PeerAddress string `json:"peerAddress,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=45
	PeerRouterID string `json:"peerRouterID,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=253
	PeerHostname string `json:"peerHostname,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=32
	PeerType string `json:"peerType,omitempty"`
	// +optional
	LastUpdate *metav1.Time `json:"lastUpdate,omitempty"`
}

// ASSegment is one AS_PATH segment.
type ASSegment struct {
	// +kubebuilder:validation:Enum=as-sequence;as-set;as-confed-sequence;as-confed-set
	Type string `json:"type"`
	// +kubebuilder:validation:MaxItems=255
	ASNs []int64 `json:"asns"`
}

// NextHop is one BGP next hop.
type NextHop struct {
	// +kubebuilder:validation:MaxLength=45
	Address string `json:"address"`
	// +optional
	// +kubebuilder:validation:MaxLength=253
	Hostname string `json:"hostname,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=16
	Scope string `json:"scope,omitempty"`
	// +optional
	Accessible bool `json:"accessible,omitempty"`
	// +optional
	Used bool `json:"used,omitempty"`
}

// Installation is zebra's evidence for one prefix, sampled separately from
// the BGP answer.
type Installation struct {
	// +optional
	SampleTime *metav1.Time `json:"sampleTime,omitempty"`
	// +optional
	Present bool `json:"present,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=8
	Routes []ZebraRoute `json:"routes,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=64
	ErrorCode string `json:"errorCode,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=256
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// ZebraRoute is one zebra RIB route.
type ZebraRoute struct {
	// +kubebuilder:validation:MaxLength=32
	Protocol string `json:"protocol"`
	// +optional
	Selected bool `json:"selected,omitempty"`
	// +optional
	Installed bool `json:"installed,omitempty"`
	// +optional
	Distance int64 `json:"distance,omitempty"`
	// +optional
	Metric int64 `json:"metric,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=16
	NextHops []ZebraNextHop `json:"nextHops,omitempty"`
}

// ZebraNextHop is one zebra next hop.
type ZebraNextHop struct {
	// +optional
	// +kubebuilder:validation:MaxLength=45
	Address string `json:"address,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=16
	Interface string `json:"interface,omitempty"`
	// +optional
	Active bool `json:"active,omitempty"`
	// +optional
	FIB bool `json:"fib,omitempty"`
	// +optional
	Blackhole bool `json:"blackhole,omitempty"`
}

// SummaryResult is a BGP summary.
type SummaryResult struct {
	// +optional
	// +kubebuilder:validation:MaxLength=45
	RouterID string `json:"routerID,omitempty"`
	// +optional
	ASN int64 `json:"asn,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=256
	Peers            []Peer `json:"peers,omitempty"`
	TotalPeers       int32  `json:"totalPeers"`
	EstablishedPeers int32  `json:"establishedPeers"`
}

// Peer is one BGP session. A session that is down is data.
type Peer struct {
	// +kubebuilder:validation:MaxLength=45
	Address string `json:"address"`
	// +optional
	// +kubebuilder:validation:MaxLength=253
	Hostname string `json:"hostname,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=256
	Description string `json:"description,omitempty"`
	// +optional
	RemoteAS int64 `json:"remoteAS,omitempty"`
	// +optional
	LocalAS int64 `json:"localAS,omitempty"`
	// +kubebuilder:validation:MaxLength=32
	State string `json:"state"`
	// +optional
	Established bool `json:"established,omitempty"`
	// +optional
	UptimeSeconds int64 `json:"uptimeSeconds,omitempty"`
	// +optional
	PrefixesReceived int64 `json:"prefixesReceived,omitempty"`
	// +optional
	PrefixesSent int64 `json:"prefixesSent,omitempty"`
	// +optional
	MessagesReceived int64 `json:"messagesReceived,omitempty"`
	// +optional
	MessagesSent int64 `json:"messagesSent,omitempty"`
	// +optional
	ConnectionsEstablished int64 `json:"connectionsEstablished,omitempty"`
	// +optional
	ConnectionsDropped int64 `json:"connectionsDropped,omitempty"`
}

// PingResult is a ping's outcome; loss is data.
type PingResult struct {
	// +kubebuilder:validation:MaxLength=45
	Source string `json:"source"`
	// +kubebuilder:validation:MaxLength=45
	Destination string `json:"destination"`
	Sent        int32  `json:"sent"`
	Received    int32  `json:"received"`
	// +optional
	// +kubebuilder:validation:MaxItems=3
	Replies []ProbeReply `json:"replies,omitempty"`
	// +optional
	RTTMinMicroseconds int64 `json:"rttMinMicroseconds,omitempty"`
	// +optional
	RTTAvgMicroseconds int64 `json:"rttAvgMicroseconds,omitempty"`
	// +optional
	RTTMaxMicroseconds int64 `json:"rttMaxMicroseconds,omitempty"`
}

// TracerouteResult is a traceroute's outcome; silent hops are data.
type TracerouteResult struct {
	// +kubebuilder:validation:MaxLength=45
	Source string `json:"source"`
	// +kubebuilder:validation:MaxLength=45
	Destination string `json:"destination"`
	// +optional
	Reached bool `json:"reached,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=20
	Hops []Hop `json:"hops,omitempty"`
}

// Hop is one traceroute hop.
type Hop struct {
	TTL int32 `json:"ttl"`
	// +optional
	// +kubebuilder:validation:MaxItems=3
	Probes []ProbeReply `json:"probes,omitempty"`
}

// ProbeReply is one probe packet's outcome.
type ProbeReply struct {
	Sequence int32 `json:"sequence"`
	// +optional
	// +kubebuilder:validation:MaxLength=45
	Address string `json:"address,omitempty"`
	// +optional
	RTTMicroseconds int64 `json:"rttMicroseconds,omitempty"`
	// +optional
	Timeout bool `json:"timeout,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=32
	ICMPType string `json:"icmpType,omitempty"`
	// +optional
	ICMPCode int32 `json:"icmpCode,omitempty"`
}

// FabricQueryList is a list of FabricQuery.
// +kubebuilder:object:root=true
type FabricQueryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricQuery `json:"items"`
}
