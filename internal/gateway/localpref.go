// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

// Local-preference values for the design plan's Active-Active BGP model.
// Both gateway nodes in a PoP always advertise every rule they hold — these
// values only decide which path upstream routers prefer, never which node
// is allowed to advertise at all. See LocalPreference below.
const (
	// PrimaryLocalPref is advertised by the node that is a rule's
	// status.primaryNode.
	PrimaryLocalPref uint32 = 100

	// SecondaryLocalPref is advertised by the other gateway node(s) serving
	// the same rule. It must be lower than PrimaryLocalPref but non-zero
	// (a live, less-preferred path, not a withdrawn one) so that BGP
	// reconvergence — not a controller-driven health check — is what
	// fails traffic over if the primary's session or route withdraws.
	SecondaryLocalPref uint32 = 50
)

// LocalPreference returns the local-preference this gateway node should
// advertise a rule's VIPs at, given the rule's assigned primaryNode. This
// is a pure lookup, not a decision GoBGP makes independently — see
// internal/runtime/gobgp/paths.go's buildEVPNPaths, which already applies
// whatever value ends up on BGPAdvertisement.Spec.LocalPreference. The
// caller (the future NetworkGateway controller) is responsible for
// invoking this once per rule per reconcile and setting the result onto
// the BGPAdvertisement(s) it manages for that rule.
func LocalPreference(nodeName, primaryNode string) uint32 {
	if nodeName != "" && nodeName == primaryNode {
		return PrimaryLocalPref
	}
	return SecondaryLocalPref
}
