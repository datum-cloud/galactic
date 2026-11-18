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
)

// Capabilities lists every capability in the order GetCapabilities reports
// them.
var Capabilities = []string{
	CapabilityLocalTap, CapabilityLocalVethPair, CapabilityLocalRoutedLink,
	CapabilityLocalSocket, CapabilityFabricSRv6,
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
	ReasonNoSession                        = "NoSession"
	ReasonStaleGeneration                  = "StaleGeneration"
	ReasonResyncing                        = "Resyncing"
	ReasonShuttingDown                     = "ShuttingDown"
	ReasonClaimLimit                       = "ClaimLimit"
	ReasonTableRangeExhausted              = "TableRangeExhausted"
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
)
