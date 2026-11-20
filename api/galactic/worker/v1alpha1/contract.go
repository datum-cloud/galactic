// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package workerv1alpha1

// The names below are part of the published contract
// (docs/worker/contract.md). Clients compare against them; Worker emits them.

const (
	// Version is the API version this package serves.
	Version = "v1alpha1"
	// ErrorDomain is the google.rpc.ErrorInfo domain of every refusal.
	ErrorDomain = "worker.galactic.datumapis.com"
	// TokenAudience is the audience of the projected ServiceAccount token a
	// client presents.
	TokenAudience = "galactic-worker"
	// DefaultSocketPath is where Worker serves the API.
	DefaultSocketPath = "/run/galactic-worker/worker.sock"
	// SessionMetadataKey carries the session ID on every call but the first
	// GetCapabilities. A GetCapabilities that carries a live session ID
	// renews that session instead of starting a new one.
	SessionMetadataKey = "x-galactic-worker-session"
)

// ErrorInfo metadata keys.
const (
	// MetadataCurrentGeneration is the claim's current generation, on
	// StaleGeneration and GenerationConflict.
	MetadataCurrentGeneration = "current_generation"
	// MetadataServedVersions lists the versions Worker serves, comma
	// separated, on UnsupportedVersion.
	MetadataServedVersions = "served_versions"
)

// Capability names.
const (
	CapabilityLocalTap        = "local.tap"
	CapabilityLocalVethPair   = "local.veth_pair"
	CapabilityLocalRoutedLink = "local.routed_link"
	CapabilityLocalSocket     = "local.socket"
	CapabilityFabricSRv6      = "fabric.srv6"
	// CapabilityFabricRoutes allows a caller to hand Worker tenant routes
	// through the Routes service. Only galactic-router is granted it.
	CapabilityFabricRoutes = "fabric.routes"
)

// Capabilities lists every capability in the order GetCapabilities reports
// them.
var Capabilities = []string{
	CapabilityLocalTap, CapabilityLocalVethPair, CapabilityLocalRoutedLink,
	CapabilityLocalSocket, CapabilityFabricSRv6, CapabilityFabricRoutes,
}

// HandoffCapability is the Local capability a handoff kind needs, or "" for
// HANDOFF_UNSPECIFIED.
func HandoffCapability(h Handoff) string {
	switch h {
	case Handoff_HANDOFF_TAP:
		return CapabilityLocalTap
	case Handoff_HANDOFF_VETH_PAIR:
		return CapabilityLocalVethPair
	case Handoff_HANDOFF_ROUTED_LINK:
		return CapabilityLocalRoutedLink
	case Handoff_HANDOFF_SOCKET:
		return CapabilityLocalSocket
	default:
		return ""
	}
}

// Condition types.
const (
	ConditionAdmitted    = "Admitted"
	ConditionResolved    = "Resolved"
	ConditionProgrammed  = "Programmed"
	ConditionReady       = "Ready"
	ConditionWithdrawing = "Withdrawing"
)

// Refusal reasons, carried in google.rpc.ErrorInfo.
const (
	ReasonMalformedSpec                    = "MalformedSpec"
	ReasonWrongNode                        = "WrongNode"
	ReasonNoIdentity                       = "NoIdentity"
	ReasonIdentityExpired                  = "IdentityExpired"
	ReasonVPCNotAuthorized                 = "VPCNotAuthorized"
	ReasonAttachmentClaimedByAnotherCaller = "AttachmentClaimedByAnotherCaller"
	ReasonNotOwner                         = "NotOwner"
	ReasonCapabilityNotAllowed             = "CapabilityNotAllowed"
	ReasonUnsupportedVersion               = "UnsupportedVersion"
	ReasonClaimExists                      = "ClaimExists"
	ReasonClaimNotFound                    = "ClaimNotFound"
	ReasonGenerationConflict               = "GenerationConflict"
	// ReasonClaimHeldByAnotherPod refuses a call on a routed_link or socket
	// claim from a pod other than the one the claim's link serves, while
	// that pod still runs.
	ReasonClaimHeldByAnotherPod = "ClaimHeldByAnotherPod"
	ReasonNoSession             = "NoSession"
	ReasonStaleGeneration       = "StaleGeneration"
	ReasonResyncing             = "Resyncing"
	ReasonShuttingDown          = "ShuttingDown"
	ReasonClaimLimit            = "ClaimLimit"
	ReasonTableRangeExhausted   = "TableRangeExhausted"
)

// Status reasons, carried in conditions, destination status and
// capabilities.
const (
	ReasonPending                    = "Pending"
	ReasonAsExpected                 = "AsExpected"
	ReasonModeUnavailable            = "ModeUnavailable"
	ReasonDestinationKindUnsupported = "DestinationKindUnsupported"
	ReasonDestinationNotFound        = "DestinationNotFound"
	ReasonLocatorUnknown             = "LocatorUnknown"
	ReasonModuleNotRunning           = "ModuleNotRunning"
	ReasonDatapathNotLoaded          = "DatapathNotLoaded"
	ReasonHookUnsupported            = "HookUnsupported"
	ReasonHandoffInterfaceMissing    = "HandoffInterfaceMissing"
	ReasonProgrammingFailed          = "ProgrammingFailed"
	ReasonScopeOwnedElsewhere        = "ScopeOwnedElsewhere"
	ReasonAuthorizationRevoked       = "AuthorizationRevoked"
	ReasonLeaseExpired               = "LeaseExpired"
	ReasonReleased                   = "Released"
	// ReasonDestinationAddressUnknown is a destination whose attachment
	// records no address, such as a guest that manages its own addressing.
	ReasonDestinationAddressUnknown = "DestinationAddressUnknown"
	// ReasonForwardRouteMissing is a destination address no tenant route
	// covers.
	ReasonForwardRouteMissing = "ForwardRouteMissing"
	// ReasonRouteWithdrawn is a destination address whose tenant route was
	// withdrawn.
	ReasonRouteWithdrawn = "RouteWithdrawn"
	// ReasonRouteMismatch is a destination address whose covering route
	// leads to another node's locator, or does not encapsulate.
	ReasonRouteMismatch = "RouteMismatch"
	// ReasonUnderlayUnreachable is a destination whose locator has no
	// underlay route over an SRv6 uplink.
	ReasonUnderlayUnreachable = "UnderlayUnreachable"
	// ReasonNeighborUnresolved is a destination whose underlay next hop has
	// no resolved neighbor, or whose programmed next hop is out of date.
	ReasonNeighborUnresolved = "NeighborUnresolved"
	// ReasonReturnPathNotProgrammed is a destination whose return traffic
	// this node cannot yet decapsulate into the VPC's table.
	ReasonReturnPathNotProgrammed = "ReturnPathNotProgrammed"
	// ReasonRoutedLinkUnavailable marks local.routed_link and local.socket
	// on a Worker without CAP_SYS_PTRACE and CAP_SYS_ADMIN, which open and
	// enter a pod's network namespace for the link's pod end. Only a
	// placement that enables routed links grants them.
	ReasonRoutedLinkUnavailable = "RoutedLinkUnavailable"
	// ReasonHandoffHookMissing is a Local destination whose handoff program
	// is not on its hook: Worker's own tc program, or the program the
	// client attaches to the NAT end of a veth pair.
	ReasonHandoffHookMissing = "HandoffHookMissing"
	// ReasonDispatcherSlotUnclaimed is a local.tap destination with no
	// receiving device whose XDP dispatcher runs a live public slot.
	ReasonDispatcherSlotUnclaimed = "DispatcherSlotUnclaimed"
	// ReasonHandoffMTUTooSmall is a Local destination whose interface's MTU
	// is below the receiving path's, so a packet the path carries would
	// not reach the guest.
	ReasonHandoffMTUTooSmall = "HandoffMTUTooSmall"
)

// Handoff interface roles, carried in HandoffInterface.
const (
	// HandoffRoleNAT is the NAT end of a service-internal veth pair.
	HandoffRoleNAT = "nat"
	// HandoffRoleTenant is the tenant end of a service-internal veth pair.
	HandoffRoleTenant = "tenant"
	// HandoffRoleHost is the host end of a routed link.
	HandoffRoleHost = "host"
	// HandoffRolePod is the routed link's end in the caller's pod.
	HandoffRolePod = "pod"
)

// Route rejection reasons, carried in RejectedRoute.
const (
	// ReasonMalformedRoute is a route whose VPC, prefix or SID does not
	// parse.
	ReasonMalformedRoute = "MalformedRoute"
)
