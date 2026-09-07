// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"fmt"
	"net/netip"
)

// DesiredBackend is one backend endpoint a rule load-balances to. It mirrors
// the CRD's backend plus one field the CRD does not carry: the SRv6 uSID of the
// worker node the backend is reachable through. The controller resolves that
// the way any other cross-node SRv6 destination is resolved, from the backend's
// router and advertisement, never by parsing a packet.
type DesiredBackend struct {
	Address netip.Addr
	Port    uint16
	USID    netip.Addr
}

// Key implements maglev.Backend. The address and port are the chosen
// convention: stable across reconciles for the backend's life, unique within one
// rule's backend set, since two backends sharing them would be
// indistinguishable targets anyway, and unchanged if the backend's uSID changes.
// Its worker node's SRv6 path moving does not make it a different backend for
// consistent-hashing purposes.
func (b DesiredBackend) Key() string {
	return fmt.Sprintf("%s:%d", b.Address, b.Port)
}

// DesiredRule is the engine's representation of one NetworkRule, assembled by
// the reconcilers from the CRD. There is no tunnel identifier or VRF table here,
// this engine having no VRF dependency, and no placement field either, every
// gateway node serving every rule identically under anycast.
type DesiredRule struct {
	// Key uniquely identifies the rule (namespace/name of the source
	// NetworkRule), used as the map key in Engine's convergence pass.
	Key string

	// VPCRef and VPCAttachmentRef are opaque tenant identifiers, carried for
	// telemetry labels and admission auditing. The datapath never needs them: a
	// VIP is globally unique, so no tenant dimension disambiguates ingress
	// traffic.
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

// EngineState is the full desired state for one gateway node's engine,
// assembled from every accepted rule in the node's PoP. Every node in the PoP
// serves every rule identically under anycast, so there is no subset to
// distinguish here.
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
