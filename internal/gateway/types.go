// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import "net/netip"

// DesiredBackend is a single backend endpoint a rule load-balances to,
// mirroring network.datumapis.com/v1alpha1's NetworkRuleBackend plus one
// field the CRD does not itself carry: USID, the SRv6 uSID of the worker
// node this backend is reachable through. The controller building
// DesiredRule resolves USID the same way any other cross-node SRv6
// destination is resolved (srv6.ComputeSID over the backend's BGPRouter/
// BGPAdvertisement — see internal/reconcile/reconcile.go's
// resolveSRv6SID), never by parsing it out of a packet.
type DesiredBackend struct {
	Address netip.Addr
	Port    uint16
	USID    netip.Addr
}

// DesiredRule is the engine's internal representation of one NetworkRule,
// assembled by the future NetworkGateway/NetworkRule controllers from the
// NetworkRule CRD plus the node's own primary/secondary role for it.
// Unlike an earlier, rejected design's identically-named type,
// there is no VNI or VRFTableID here at all: this engine has no VRF/
// Geneve dependency (see doc.go).
type DesiredRule struct {
	// Key uniquely identifies the rule (namespace/name of the source
	// NetworkRule), used as the map key in Engine's convergence pass.
	Key string

	// VPCRef/VPCAttachmentRef are opaque tenant identifiers, carried
	// through for telemetry labeling and admission-webhook auditing —
	// this engine's datapath itself never needs them (a VIP is globally
	// unique by construction, so no tenant dimension is needed to
	// disambiguate ingress traffic; see edgeprog's doc comment).
	VPCRef           string
	VPCAttachmentRef string

	// VIPAddresses are the ingress VIP addresses this rule provisions.
	VIPAddresses []netip.Addr

	// Protocol is "tcp" or "udp", matching
	// network.datumapis.com/v1alpha1's NetworkRuleProtocol enum values.
	Protocol string
	Port     uint16
	Backends []DesiredBackend

	// LocalPreference is the BGP local-preference this node should
	// advertise this rule's VIPs at: PrimaryLocalPref if this node is the
	// rule's primary_node, SecondaryLocalPref otherwise (localpref.go).
	// Both nodes always advertise — this field only affects preference,
	// never presence.
	LocalPref uint32

	// IsPrimary mirrors LocalPref == PrimaryLocalPref, kept as a separate
	// bool for callers (e.g. status reporting, telemetry) that want the
	// role without re-deriving it from the numeric preference.
	IsPrimary bool
}

// DesiredEgressPolicy is the engine's internal representation of one
// NetworkEgressPolicy (datum-cloud/enhancements#865): egress is on or off
// for a (vpcRef, vpcAttachmentRef) pair, existence-implies-enabled, so
// unlike DesiredRule there is no VIP/backend/port here at all — see
// network.datumapis.com/v1alpha1's NetworkEgressPolicySpec, which this
// mirrors field-for-field.
//
// Deliberately not added to EngineState/consumed by Engine.Reconcile in
// this phase: design plan §7.2 resolves *enablement* (should a tenant
// reach egress_sid at all) toward a routing-layer decision (does the
// tenant's VRF have a default route pointed there), not a per-packet
// datapath lookup, so Datapath gains no new per-call method for it either
// (§4.2). This type exists for NetworkGatewayReconciler's own
// bookkeeping/status use and as the shape a future per-tenant enforcement
// path would consume, if one is ever needed.
type DesiredEgressPolicy struct {
	VPCRef           string
	VPCAttachmentRef string
}

// EngineState is the full desired state for one gateway node's Engine,
// assembled by the NetworkGateway controller from every accepted
// NetworkRule in the node's PoP (both primary- and secondary-assigned —
// active-active means both gateway nodes serve every rule, see
// localpref.go).
type EngineState struct {
	// Rules is keyed by DesiredRule.Key.
	Rules map[string]DesiredRule
}

// RuleStatus is the observed state of a single rule after a convergence
// pass, analogous to model.AdvertisementStatus for the BGP runtime.
type RuleStatus struct {
	Key     string
	Applied bool
	Error   string
}

// EngineStatus is the observed state returned by Engine.Status, analogous
// to model.RuntimeStatus for the BGP runtime.
type EngineStatus struct {
	Healthy bool
	Rules   []RuleStatus
}
