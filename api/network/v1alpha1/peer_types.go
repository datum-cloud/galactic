package v1alpha1

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BGPPeerState represents the BGP Finite State Machine state of a session.
type BGPPeerState string

const (
	BGPPeerStateIdle        BGPPeerState = "Idle"
	BGPPeerStateConnect     BGPPeerState = "Connect"
	BGPPeerStateActive      BGPPeerState = "Active"
	BGPPeerStateOpenSent    BGPPeerState = "OpenSent"
	BGPPeerStateOpenConfirm BGPPeerState = "OpenConfirm"
	BGPPeerStateEstablished BGPPeerState = "Established"
)

// SendCommunityType controls which BGP community attributes are propagated
// to a peer.
//
// +kubebuilder:validation:Enum=standard;extended;large;both
type SendCommunityType string

const (
	// SendCommunityTypeStandard sends only standard communities (ASN:NN).
	SendCommunityTypeStandard SendCommunityType = "standard"

	// SendCommunityTypeExtended sends only extended communities (Type:Length:Value).
	SendCommunityTypeExtended SendCommunityType = "extended"

	// SendCommunityTypeLarge sends only large communities (ASN:NN:NN).
	SendCommunityTypeLarge SendCommunityType = "large"

	// SendCommunityTypeBoth sends both standard and extended communities.
	SendCommunityTypeBoth SendCommunityType = "both"
)

// MaxPrefixShutdownAction defines the action taken when a peer exceeds its
// maximum-prefix limit.
//
// +kubebuilder:validation:Enum=warning-only;restart;shutdown
type MaxPrefixShutdownAction string

const (
	// MaxPrefixShutdownActionWarningOnly logs a warning but keeps the session up.
	MaxPrefixShutdownActionWarningOnly MaxPrefixShutdownAction = "warning-only"

	// MaxPrefixShutdownActionRestart resets the BGP session when the limit is exceeded.
	MaxPrefixShutdownActionRestart MaxPrefixShutdownAction = "restart"

	// MaxPrefixShutdownActionShutdown tears down the BGP session when the limit is exceeded.
	MaxPrefixShutdownActionShutdown MaxPrefixShutdownAction = "shutdown"
)

// BGPMaximumPrefix defines the maximum number of routes accepted from a peer
// before triggering a shutdown action.
type BGPMaximumPrefix struct {
	// Limit is the maximum number of routes accepted from this peer.
	// +kubebuilder:validation:Minimum=1
	Limit int32 `json:"limit"`

	// ThresholdPercent is the percentage threshold at which a warning is
	// logged (e.g., 75 means warn at 75% of Limit). Range: 1-100.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	ThresholdPercent *int32 `json:"thresholdPercent,omitempty"`

	// ShutdownAction is the action taken when the Limit is exceeded.
	// +kubebuilder:validation:Required
	ShutdownAction MaxPrefixShutdownAction `json:"shutdownAction"`
}

// Condition type constants for BGPPeer.
//
// These follow Kubernetes condition conventions: a small set of stable,
// semantically-meaningful types whose Status/Reason/Message fields carry
// the dynamic detail (via Reason = FSM state, Message = explanation).
const (
	// ConditionTypeReady indicates whether the BGP session is fully up.
	// True when sessionState == Established; False otherwise with Reason
	// set to the current FSM state (e.g. "OpenSent", "Active").
	ConditionTypeReady string = "Ready"

	// ConditionTypeAccepted indicates whether the peer configuration has
	// been accepted by the BGP runtime (FRR/GoBGP, etc.).
	ConditionTypeAccepted string = "Accepted"
)

// Idle sub-reasons — used as Ready.Reason when sessionState == Idle.
const (
	// IdleReasonBackOff indicates exponential back-off before next
	// connection attempt.
	IdleReasonBackOff string = "BackOff"

	// IdleReasonConnectionRefused indicates the TCP connection was
	// actively refused by the peer.
	IdleReasonConnectionRefused string = "ConnectionRefused"

	// IdleReasonHoldTimerExpired indicates the peer failed to send
	// KEEPALIVE within the hold timer.
	IdleReasonHoldTimerExpired string = "HoldTimerExpired"

	// IdleReasonIdle is the default when the session is simply not
	// started (no recent failure).
	IdleReasonIdle string = "Idle"
)

// BGPPeer defines a BGP session to a remote peer. It binds to one or more
// BGPRouter instances via routerRef or routerSelector.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=bgppr
// +kubebuilder:printcolumn:name="ROUTER",type="string",JSONPath=".spec.routerRef.name"
// +kubebuilder:printcolumn:name="PEER-ADDRESS",type="string",JSONPath=".spec.address"
// +kubebuilder:printcolumn:name="PEER-ASN",type="integer",JSONPath=".spec.peerASN"
// +kubebuilder:printcolumn:name="STATE",type="string",JSONPath=".status.sessionState"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type BGPPeer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BGPPeerSpec   `json:"spec,omitempty"`
	Status BGPPeerStatus `json:"status,omitempty"`
}

// BGPPeerSpec defines the desired state of BGPPeer.
type BGPPeerSpec struct {
	RouterTarget `json:",inline"`

	// PeerASN is the remote AS number.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	PeerASN int64 `json:"peerASN"`

	// Address is the remote peer's IPv4 or IPv6 address.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:XValidation:rule="isIP(self)",message="address must be a valid IPv4 or IPv6 address"
	Address string `json:"address"`

	// RemotePort is the TCP port used to establish the BGP session with
	// this peer. Defaults to 179 (the IANA-assigned BGP port) if unset.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	RemotePort *int32 `json:"remotePort,omitempty"`

	// Description is a human-readable label for this peer (e.g., "spine-1").
	// +optional
	Description string `json:"description,omitempty"`

	// AuthSecretRef references a Secret in the same namespace containing the
	// MD5 TCP authentication password under the key "password".
	// +optional
	AuthSecretRef *LocalSecretRef `json:"authSecretRef,omitempty"`

	// AddressFamilies defines the address families negotiated on this session.
	// +kubebuilder:validation:MinItems=1
	AddressFamilies []AddressFamily `json:"addressFamilies"`

	// HoldTime is the BGP hold timer. Must be 0 (disabled) or >= 3s.
	// Defaults to 90s if unset.
	// +optional
	// +kubebuilder:validation:XValidation:rule="duration(self) == duration('0s') || duration(self) >= duration('3s')",message="holdTime must be 0 or >= 3s"
	HoldTime *metav1.Duration `json:"holdTime,omitempty"`

	// KeepaliveTime is the BGP keepalive interval. Must be <= HoldTime / 3.
	// Defaults to 30s if unset. Maximum is 30s; the controller enforces
	// the keepalive <= holdTime / 3 constraint with an Accepted=False condition.
	// +optional
	// +kubebuilder:validation:XValidation:rule="duration(self) == duration('0s') || duration(self) <= duration('30s')",message="keepaliveTime must be 0 or <= 30s"
	KeepaliveTime *metav1.Duration `json:"keepaliveTime,omitempty"`

	// EbgpMultiHop enables eBGP multihop when the peer is not directly connected.
	// When true, the TTL for BGP packets is set to 64 (vs. 1 for direct).
	// +optional
	EbgpMultiHop bool `json:"ebgpMultiHop,omitempty"`

	// BFD configures Bidirectional Forwarding Detection for fast failure
	// detection (sub-500ms). Without BFD, convergence relies on BGP hold
	// timers (default 90s).
	// +optional
	BFD *BGPPeerBFD `json:"bfd,omitempty"`

	// GracefulRestart configures BGP graceful restart for this peer.
	// Prevents route flapping during control-plane restarts.
	// +optional
	GracefulRestart *BGPPeerGracefulRestart `json:"gracefulRestart,omitempty"`

	// MultiSession enables BFD over MP-BGP (RFC 8935). When true, each
	// AFI/SAFI negotiates its own BFD session independently. When false
	// (default), a single BFD session covers all AFI/SAFIs.
	// +optional
	MultiSession bool `json:"multiSession,omitempty"`

	// RouteMapIn is the name of a BGPPolicy term set applied to routes
	// received from this peer (import direction). The name must match
	// a BGPPolicy resource in the same namespace.
	// +optional
	RouteMapIn string `json:"routeMapIn,omitempty"`

	// RouteMapOut is the name of a BGPPolicy term set applied to routes
	// advertised to this peer (export direction). The name must match
	// a BGPPolicy resource in the same namespace.
	// +optional
	RouteMapOut string `json:"routeMapOut,omitempty"`

	// NextHopSelf controls next-hop behavior for iBGP sessions.
	// When true, the local router's IP is used as next-hop for all
	// advertised routes. Common in EVPN iBGP peering.
	// +optional
	NextHopSelf bool `json:"nextHopSelf,omitempty"`

	// RemovePrivateAS strips private AS numbers (64512-65535, 4200000000-4294967294)
	// from the AS path on eBGP export. If set to a non-zero value, private ASNs
	// are replaced with the specified value before export.
	// +kubebuilder:validation:Minimum=0
	// +optional
	RemovePrivateAS *int32 `json:"removePrivateAS,omitempty"`

	// UpdateSource is the local IP address or interface name used as the
	// source for the BGP TCP session. Useful when the local router has
	// multiple addresses or when pinning to a specific loopback.
	// +optional
	UpdateSource *string `json:"updateSource,omitempty"`

	// SendCommunity controls which BGP community attributes are propagated
	// to this peer. When unset, communities are not sent.
	// +optional
	SendCommunity *SendCommunityType `json:"sendCommunity,omitempty"`

	// AllowASIn allows routes that contain the local ASN in the AS_PATH
	// to be accepted from this peer. The value specifies the maximum number
	// of times the local ASN may appear. Range: 1-10.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	AllowASIn *int32 `json:"allowASIn,omitempty"`

	// MaximumPrefix defines the maximum number of routes accepted from this
	// peer before triggering a shutdown action.
	// +optional
	MaximumPrefix *BGPMaximumPrefix `json:"maximumPrefix,omitempty"`

	// DefaultOriginRoute controls default route origination for this peer.
	// "igp" originates a default route with IGP origin.
	// "egp" originates a default route with EGP origin.
	// "incomplete" originates a default route with incomplete origin.
	// Empty or unset means no default route origination.
	// +kubebuilder:validation:Enum=igp;egp;incomplete
	// +optional
	DefaultOriginRoute *OriginType `json:"defaultOriginRoute,omitempty"`

	// Authentication configures peer authentication.
	// AuthSecretRef takes precedence when both are set.
	// +optional
	Authentication *BGPPeerAuthentication `json:"authentication,omitempty"`
}

// BGPPeerStatus defines the observed state of BGPPeer.
type BGPPeerStatus struct {
	// ObservedGeneration is the .metadata.generation this status was computed from.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// SessionState is the current BGP FSM state of this session.
	// +optional
	SessionState BGPPeerState `json:"sessionState,omitempty"`

	// LastEstablishedTime is the timestamp of the most recent Established transition.
	// +optional
	LastEstablishedTime *metav1.Time `json:"lastEstablishedTime,omitempty"`

	// Conditions contains the standard conditions for this resource.
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// BGPPeerList is a list of BGPPeer resources.
// +kubebuilder:object:root=true
type BGPPeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BGPPeer `json:"items"`
}

// updatePeerConditions updates the Ready condition based on the current
// BGP FSM state. It is a reference implementation for controller authors.
//
// The method mutates and returns the conditions slice in-place via
// metav1.SetStatusCondition, following Kubernetes condition conventions:
//   - Ready.Status = True only when session is Established
//   - Ready.Status = False for all intermediate states, with Reason set
//     to the FSM state string (e.g. "OpenSent", "Active")
//   - For Idle, Reason is delegated to the caller via the idleReason arg
//
// The ObservedGeneration is set to gen so consumers can correlate this
// status with the spec generation that produced it.
func (s *BGPPeerStatus) updatePeerConditions(state BGPPeerState, gen int64, idleReason string) {
	ready := metav1.Condition{
		Type:               ConditionTypeReady,
		ObservedGeneration: gen,
	}

	switch state {
	case BGPPeerStateEstablished:
		ready.Status = metav1.ConditionTrue
		ready.Reason = "Established"
		ready.Message = "BGP session is Established; address families negotiated."
	case BGPPeerStateOpenConfirm:
		ready.Status = metav1.ConditionFalse
		ready.Reason = "OpenConfirm"
		ready.Message = "BGP session in OpenConfirm state, awaiting KEEPALIVE."
	case BGPPeerStateOpenSent:
		ready.Status = metav1.ConditionFalse
		ready.Reason = "OpenSent"
		ready.Message = "BGP OPEN message sent, awaiting peer OPEN."
	case BGPPeerStateActive:
		ready.Status = metav1.ConditionFalse
		ready.Reason = "Active"
		ready.Message = "BGP session Active, attempting to establish TCP connection."
	case BGPPeerStateConnect:
		ready.Status = metav1.ConditionFalse
		ready.Reason = "Connect"
		ready.Message = "BGP session in Connect state, waiting for TCP connection."
	case BGPPeerStateIdle:
		ready.Status = metav1.ConditionFalse
		ready.Reason = idleReason
		ready.Message = "BGP session is Idle."
	default:
		// Unknown state — treat as idle with a generic reason.
		ready.Status = metav1.ConditionFalse
		ready.Reason = "Unknown"
		ready.Message = fmt.Sprintf("BGP session is in unknown state %q.", state)
	}

	meta.SetStatusCondition(&s.Conditions, ready)
}

// SetAcceptedCondition updates (or creates) the Accepted condition.
// Call this after validating and accepting the peer spec into the runtime.
func (s *BGPPeerStatus) SetAcceptedCondition(accepted bool, gen int64, reason, message string) {
	status := metav1.ConditionFalse
	if accepted {
		status = metav1.ConditionTrue
	}
	cond := metav1.Condition{
		Type:               ConditionTypeAccepted,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: gen,
	}
	meta.SetStatusCondition(&s.Conditions, cond)
}

func init() {
	SchemeBuilder.Register(&BGPPeer{}, &BGPPeerList{})
}
