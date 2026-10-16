package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// AFI is the Address Family Indicator for a BGP address family.
//
// +kubebuilder:validation:Enum=ipv4;ipv6;l2vpn
type AFI string

const (
	AFIIPv4  AFI = "ipv4"
	AFIIPv6  AFI = "ipv6"
	AFIL2VPN AFI = "l2vpn"
)

// SAFI is the Subsequent Address Family Indicator for a BGP address family.
//
// +kubebuilder:validation:Enum=unicast;evpn
type SAFI string

const (
	SAFIUnicast SAFI = "unicast"
	SAFIEVPN    SAFI = "evpn"
)

// AddressFamily is a BGP address family expressed as an AFI/SAFI pair.
// Valid combinations: ipv4/unicast, ipv6/unicast, l2vpn/evpn.
//
// +kubebuilder:validation:XValidation:rule="self.afi == 'ipv4' ? self.safi == 'unicast' : true",message="IPv4 only supports unicast SAFI"
// +kubebuilder:validation:XValidation:rule="self.afi == 'ipv6' ? self.safi == 'unicast' : true",message="IPv6 only supports unicast SAFI"
// +kubebuilder:validation:XValidation:rule="self.afi == 'l2vpn' ? self.safi == 'evpn' : true",message="L2VPN only supports evpn SAFI"
type AddressFamily struct {
	// AFI is the address family indicator.
	AFI AFI `json:"afi"`

	// SAFI is the subsequent address family indicator.
	SAFI SAFI `json:"safi"`
}

// SRv6Function is the RFC 8986 endpoint behavior applied to a decapsulated
// SRv6 packet, addressed via the uSID Argument space per RFC 9800.
//
// +kubebuilder:validation:Enum=End.DT4;End.DT6;End.DT46
type SRv6Function string

const (
	// SRv6FunctionEndDT4 decapsulates and looks up the packet in an IPv4 VRF.
	SRv6FunctionEndDT4 SRv6Function = "End.DT4"

	// SRv6FunctionEndDT6 decapsulates and looks up the packet in an IPv6 VRF.
	SRv6FunctionEndDT6 SRv6Function = "End.DT6"

	// SRv6FunctionEndDT46 decapsulates and looks up the packet in an IPv4 or
	// IPv6 VRF based on the inner packet's address family.
	SRv6FunctionEndDT46 SRv6Function = "End.DT46"
)

// TargetRef identifies the execution target for a BGPRouter.
// Supported values for kind: Node.
type TargetRef struct {
	// Kind is the target resource kind (e.g. Node).
	// +kubebuilder:validation:MinLength=1
	Kind string `json:"kind"`

	// Name is the name of the target resource.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// RouterRef is a direct reference to a single BGPRouter by name within the same namespace.
type RouterRef struct {
	// Name is the name of the BGPRouter.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// RouterSelector selects one or more BGPRouter resources by label within the same namespace.
type RouterSelector struct {
	// MatchLabels is a map of key/value label pairs to match.
	// +optional
	MatchLabels map[string]string `json:"matchLabels,omitempty"`

	// MatchExpressions is a list of label selector requirements.
	// +optional
	MatchExpressions []metav1.LabelSelectorRequirement `json:"matchExpressions,omitempty"`
}

// RouterTarget is embedded by resources that bind to one or more BGPRouters.
// Exactly one of routerRef or routerSelector must be set.
//
// +kubebuilder:validation:XValidation:rule="has(self.routerRef) != has(self.routerSelector)",message="Exactly one of routerRef or routerSelector must be set"
type RouterTarget struct {
	// RouterRef targets a single BGPRouter by name.
	// Mutually exclusive with routerSelector.
	// +optional
	RouterRef *RouterRef `json:"routerRef,omitempty"`

	// RouterSelector targets one or more BGPRouters by label.
	// Mutually exclusive with routerRef.
	// +optional
	RouterSelector *RouterSelector `json:"routerSelector,omitempty"`
}

// LocalSecretRef references a Secret within the same namespace.
// Cross-namespace references are not supported.
type LocalSecretRef struct {
	// Name is the name of the Secret.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// RouterStatus holds per-router reconciliation status used by BGPVRFInstance.
type RouterStatus struct {
	// RouterName is the name of the BGPRouter this entry describes.
	RouterName string `json:"routerName"`

	// Conditions are the per-router conditions.
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ResolvedConfig holds the configuration that was actually applied.
	//
	// +optional
	ResolvedConfig *ResolvedRouterConfig `json:"resolvedConfig,omitempty"`
}

// ResolvedRouterConfig holds the configuration resolved and applied to a specific router.
type ResolvedRouterConfig struct {
	// RouterID resolved for this router.
	// +optional
	RouterID string `json:"routerID,omitempty"`

	// ASNumber is the AS number configured.
	// +optional
	ASNumber *int64 `json:"asNumber,omitempty"`

	// AddressFamilies configured.
	// +optional
	AddressFamilies []AddressFamily `json:"addressFamilies,omitempty"`
}

// BGPPeerBFD defines BFD (Bidirectional Forwarding Detection) parameters for a BGP peer.
//
// BFD provides sub-second failure detection for BGP sessions, enabling fast
// convergence without relying on BGP hold timers (default 90s).
type BGPPeerBFD struct {
	// Enabled indicates whether BFD is enabled for this peer.
	// +optional
	Enabled bool `json:"enabled"`

	// MinimumTx is the minimum transmission interval in microseconds.
	// FRR / GoBGP use microseconds — the controller converts to milliseconds
	// when programming the runtime. Defaults to 300000 (300ms).
	// +optional
	MinimumTX *int32 `json:"minimumTx,omitempty"`

	// MinimumRx is the minimum reception interval in microseconds.
	// Defaults to 300000 (300ms).
	// +optional
	MinimumRX *int32 `json:"minimumRx,omitempty"`

	// DetectMultiplier is the number of missed packets before declaring the
	// BFD session down. Default is 3.
	// +kubebuilder:validation:Minimum=3
	// +kubebuilder:validation:Maximum=50
	// +optional
	DetectMultiplier *int32 `json:"detectMultiplier,omitempty"`

	// MultiHop enables BFD for eBGP multi-hop sessions (RFC 5883).
	// Must be true when ebgpMultiHop is true.
	// +optional
	MultiHop bool `json:"multiHop,omitempty"`
}

// BGPPeerGracefulRestart defines BGP graceful restart parameters for a peer.
//
// Graceful restart (RFC 4724) allows a BGP speaker to restart its control plane
// without tearing down sessions. Routes are preserved during the restart period,
// preventing MAC/IP flapping in EVPN deployments.
type BGPPeerGracefulRestart struct {
	// Enabled indicates whether graceful restart is enabled for this peer.
	// +optional
	Enabled bool `json:"enabled"`

	// RestartTime is the maximum time (in seconds) the peer expects the
	// local system to complete a graceful restart. Range: 1-1200.
	// Default: 120 seconds.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1200
	// +optional
	RestartTime *uint32 `json:"restartTime,omitempty"`
}

// BGPPeerAuthentication defines authentication configuration for a BGP peer.
//
// Supports both secret-ref-based (MD5/TCP-AO) and plain-text passwords.
// The plain-text password is primarily for non-production environments.
type BGPPeerAuthentication struct {
	// Password is a plain-text authentication password.
	// Prefer AuthSecretRef for production deployments.
	// +optional
	Password *string `json:"password,omitempty"`
}

// OriginType defines the BGP origin attribute values.
//
// +kubebuilder:validation:Enum=igp;egp;incomplete
type OriginType string

const (
	OriginIGP        OriginType = "igp"
	OriginEGP        OriginType = "egp"
	OriginIncomplete OriginType = "incomplete"
)
