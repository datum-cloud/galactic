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
