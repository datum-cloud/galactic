// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"fmt"
	"net/netip"
)

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

// Key implements internal/maglev.Backend. address:port (the backend's own
// Pod address and port) is the chosen convention: it is stable across
// reconciles for the life of the backend, unique within one rule's backend
// set (two backends sharing an address:port would be indistinguishable
// targets anyway), and does not change if the backend's USID changes
// (its owning worker node's SRv6 path moving does not make it a
// *different* backend for Maglev's consistent-hash purposes). See
// kerneldatapath.go's buildMaglevTable for how this is used.
func (b DesiredBackend) Key() string {
	return fmt.Sprintf("%s:%d", b.Address, b.Port)
}

// DesiredRule is the engine's internal representation of one NetworkRule,
// assembled by the future NetworkGateway/NetworkRule controllers from the
// NetworkRule CRD. Unlike an earlier, rejected design's identically-named
// type, there is no VNI or VRFTableID here at all: this engine has no VRF/
// Geneve dependency (see doc.go). Unlike this engine's own Full-NAT
// predecessor, there is no primary/secondary placement field here either —
// DSR's anycast model means every gateway node serves every rule
// identically, with no BGP local-preference distinction to carry (see
// doc.go).
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
}

// EngineState is the full desired state for one gateway node's Engine,
// assembled by the NetworkGateway controller from every accepted
// NetworkRule in the node's PoP — every gateway node in the PoP serves
// every rule identically under DSR's anycast model, so there is no
// primary/secondary subset to distinguish here.
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
