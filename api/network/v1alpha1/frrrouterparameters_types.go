// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// FRRDefaultsProfile is FRR's `frr defaults` profile.
//
// +kubebuilder:validation:Enum=traditional;datacenter
type FRRDefaultsProfile string

const (
	// FRRDefaultsTraditional is FRR's traditional defaults profile.
	FRRDefaultsTraditional FRRDefaultsProfile = "traditional"
	// FRRDefaultsDatacenter is FRR's datacenter defaults profile.
	FRRDefaultsDatacenter FRRDefaultsProfile = "datacenter"
)

// FRRLogLevel is an FRR syslog level.
//
// +kubebuilder:validation:Enum=emergencies;alerts;critical;errors;warnings;notifications;informational;debugging
type FRRLogLevel string

// FRRLogLevelDebugging is FRR's lowest log level and its default.
const FRRLogLevelDebugging FRRLogLevel = "debugging"

// FRRLogFile is FRR's `log file` setting.
type FRRLogFile struct {
	// Path is the log file's absolute path in the router container.
	// +kubebuilder:validation:MinLength=2
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Pattern=`^/[^\s]*$`
	Path string `json:"path"`

	// Level is the lowest level written.
	Level FRRLogLevel `json:"level"`
}

// BMPMonitorMode selects which RIB a BMP target streams.
//
// +kubebuilder:validation:Enum=LocRIB;PrePolicy;PostPolicy
type BMPMonitorMode string

const (
	// BMPMonitorLocRIB streams the selected routes (`loc-rib`).
	BMPMonitorLocRIB BMPMonitorMode = "LocRIB"
	// BMPMonitorPrePolicy streams Adj-RIB-In before import policy.
	BMPMonitorPrePolicy BMPMonitorMode = "PrePolicy"
	// BMPMonitorPostPolicy streams Adj-RIB-In after import policy.
	BMPMonitorPostPolicy BMPMonitorMode = "PostPolicy"
)

// BMPMonitor streams one family's RIB to a BMP target.
//
// +kubebuilder:validation:XValidation:rule="(self.afi == 'ipv4' || self.afi == 'ipv6') && self.safi == 'unicast'",message="BMP monitors cover ipv4 or ipv6 unicast"
type BMPMonitor struct {
	// AFI is the address family indicator.
	AFI AFI `json:"afi"`

	// SAFI is the subsequent address family indicator.
	SAFI SAFI `json:"safi"`

	// Mode selects the RIB.
	Mode BMPMonitorMode `json:"mode"`
}

// BMPConnect is where FRR opens a BMP session.
//
// +kubebuilder:validation:XValidation:rule="!has(self.minRetryMilliseconds) || !has(self.maxRetryMilliseconds) || self.minRetryMilliseconds <= self.maxRetryMilliseconds",message="minRetryMilliseconds must not exceed maxRetryMilliseconds"
// +kubebuilder:validation:XValidation:rule="has(self.minRetryMilliseconds) && has(self.maxRetryMilliseconds)",message="FRR needs both minRetryMilliseconds and maxRetryMilliseconds on bmp connect"
type BMPConnect struct {
	// Address is the collector's IP address.
	// +kubebuilder:validation:MaxLength=45
	// +kubebuilder:validation:XValidation:rule="isIP(self)",message="address must be a valid IP address"
	Address string `json:"address"`

	// Port is the collector's TCP port.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// MinRetryMilliseconds is the shortest reconnect backoff. FRR's bmp
	// connect command takes both backoffs or neither parses.
	// +optional
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=86400000
	MinRetryMilliseconds *int32 `json:"minRetryMilliseconds,omitempty"`

	// MaxRetryMilliseconds is the longest reconnect backoff.
	// +optional
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=86400000
	MaxRetryMilliseconds *int32 `json:"maxRetryMilliseconds,omitempty"`

	// SourceInterface is the local interface whose address the session is
	// sourced from. Unset lets the kernel choose the source address.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=15
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_.@-]+$`
	SourceInterface *string `json:"sourceInterface,omitempty"`
}

// BMPTarget is one `bmp targets` block.
type BMPTarget struct {
	// Name is the target's FRR name.
	Name FRRObjectName `json:"name"`

	// Connect is the collector this target streams to.
	Connect BMPConnect `json:"connect"`

	// StatsIntervalMilliseconds is how often the target sends BMP
	// statistics reports. Unset sends none.
	// +optional
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=86400000
	StatsIntervalMilliseconds *int32 `json:"statsIntervalMilliseconds,omitempty"`

	// Monitors lists the RIBs streamed.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=6
	// +listType=map
	// +listMapKey=afi
	// +listMapKey=safi
	// +listMapKey=mode
	Monitors []BMPMonitor `json:"monitors"`
}

// FRRRouterParameters holds the FRR implementation settings a
// BGPRouterClass applies to every router of the class: daemon-wide lines
// that are not routing intent. Its spec is immutable, so a revision's
// parameters stay reproducible; a new parameter set is a new object.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=frrparams
// +kubebuilder:printcolumn:name="DEFAULTS",type="string",JSONPath=".spec.defaultsProfile"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type FRRRouterParameters struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:Required
	Spec   FRRRouterParametersSpec   `json:"spec"`
	Status FRRRouterParametersStatus `json:"status,omitempty"`
}

// FRRRouterParametersSpec defines FRR implementation settings.
//
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable; create a new FRRRouterParameters"
type FRRRouterParametersSpec struct {
	// DefaultsProfile is the `frr defaults` profile. Changing a router's
	// profile restarts bgpd.
	DefaultsProfile FRRDefaultsProfile `json:"defaultsProfile"`

	// HostnameSuffix is appended to the bound Node's name to form the
	// router hostname.
	// +optional
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9.-]*$`
	HostnameSuffix string `json:"hostnameSuffix,omitempty"`

	// LogFile is FRR's log file. Unset renders no log file line.
	// +optional
	LogFile *FRRLogFile `json:"logFile,omitempty"`

	// LogSyslog is the lowest level FRR sends to syslog. Unset renders no
	// log syslog line.
	// +optional
	LogSyslog *FRRLogLevel `json:"logSyslog,omitempty"`

	// LogNeighborChanges logs BGP session state changes.
	// +optional
	LogNeighborChanges bool `json:"logNeighborChanges,omitempty"`

	// IPv4UnicastDefault activates IPv4 unicast for every neighbor by
	// default. False renders `no bgp default ipv4-unicast`.
	// +optional
	IPv4UnicastDefault bool `json:"ipv4UnicastDefault,omitempty"`

	// AllowMartianNexthop accepts next hops FRR otherwise treats as
	// martian.
	// +optional
	AllowMartianNexthop bool `json:"allowMartianNexthop,omitempty"`

	// EBGPRequiresPolicy is FRR's RFC 8212 behavior: an eBGP session with
	// no policy in a direction exchanges no routes in it. Unset or true
	// keeps FRR's default, which is on; false renders
	// `no bgp ebgp-requires-policy`. False also lets the routers' peer
	// families leave exportPolicyRef unset, which exports every route the
	// router selects to that peer; any other class refuses a peer family
	// with no export policy.
	// +optional
	EBGPRequiresPolicy *bool `json:"ebgpRequiresPolicy,omitempty"`

	// BMPTargets lists the BMP collectors every router of the class streams
	// to. The router image must load bgpd's BMP module.
	// +optional
	// +kubebuilder:validation:MaxItems=4
	// +listType=map
	// +listMapKey=name
	BMPTargets []BMPTarget `json:"bmpTargets,omitempty"`
}

// FRRRouterParametersStatus defines the observed state of FRRRouterParameters.
type FRRRouterParametersStatus struct {
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

// FRRRouterParametersList is a list of FRRRouterParameters resources.
// +kubebuilder:object:root=true
type FRRRouterParametersList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FRRRouterParameters `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FRRRouterParameters{}, &FRRRouterParametersList{})
}
