// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

// Translated-traffic slot layout of the nat_traffic map, mirroring the
// datapath's enums. Hand-kept in sync with the C source, like the drop
// reasons, because the generator produces no Go type for an enum used only
// as a literal constant.
const (
	TrafficFamilyNAT66 uint32 = 0
	TrafficFamilyNAT64 uint32 = 1

	TrafficDirectionOutbound uint32 = 0
	TrafficDirectionReturn   uint32 = 1

	TrafficActionRedirect uint32 = 0
	TrafficActionTX       uint32 = 1

	// TrafficSlots is the nat_traffic map's entry count, one per family,
	// direction and action.
	TrafficSlots uint32 = 8
)

// TrafficSlot returns the nat_traffic index for family, direction and action.
func TrafficSlot(family, direction, action uint32) uint32 {
	return family*4 + direction*2 + action
}

// Masquerade port allocation, mirroring the datapath's NAT_PAT_* constants:
// a claim probes up to PATProbeLimit candidates within PATPortRange ports
// starting at PATPortBase. The range is per destination address and port, not
// per masquerade address.
const (
	PATPortBase   uint16 = 32768
	PATPortRange  uint16 = 28000
	PATProbeLimit int    = 8
)

// Claim protocol indices of the nat_claims map, mirroring the datapath's
// count_claim: TCP, UDP, and ICMP Echo.
const (
	ClaimProtoTCP  uint32 = 0
	ClaimProtoUDP  uint32 = 1
	ClaimProtoICMP uint32 = 2

	// ClaimSlots is the nat_claims map's entry count: two families, three
	// protocols, and one slot per probe count up to PATProbeLimit.
	ClaimSlots uint32 = 2 * 3 * uint32(PATProbeLimit)
)

// ClaimSlot returns the nat_claims index for a claim of protocol proto in
// family (TrafficFamilyNAT66 or TrafficFamilyNAT64) that took probes probes,
// from 1 to PATProbeLimit.
func ClaimSlot(family, proto uint32, probes int) uint32 {
	limit := uint32(PATProbeLimit)
	return family*3*limit + proto*limit + uint32(probes-1) //nolint:gosec // probes is 1..PATProbeLimit
}
