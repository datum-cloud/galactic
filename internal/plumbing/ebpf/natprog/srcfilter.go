// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natprog

// Source filter modes, mirroring the datapath's NAT_SRC_FILTER_* values in
// src_filter_config.mode. Zero is off, so an unwritten config map leaves the
// dispatcher's behaviour unchanged.
const (
	SrcFilterModeOff     uint32 = 0
	SrcFilterModeAudit   uint32 = 1
	SrcFilterModeEnforce uint32 = 2
)

// SrcAllowFlagAnyInterface mirrors NAT_SRC_ALLOW_ANY_IFACE: an allow-list entry
// carrying it is accepted on every uplink, whatever its interface mask.
const SrcAllowFlagAnyInterface uint32 = 0x1

// SrcFilterMaxSlot is the highest uplink slot nat_uplink_slot may hold, each
// slot being one bit of a 32-bit interface mask.
const SrcFilterMaxSlot uint8 = 31

// Indices into nat_src_filter_stats, mirroring the datapath's nat_src_stat
// enum. SrcStatSlots is the map's size, deliberately larger than SrcStatCount
// so a later counter is an append rather than a map layout change.
const (
	SrcStatChecked           uint32 = 0
	SrcStatAllowed           uint32 = 1
	SrcStatDenyPrefix        uint32 = 2
	SrcStatDenyInterface     uint32 = 3
	SrcStatDenyStructure     uint32 = 4
	SrcStatBypassUnpopulated uint32 = 5
	SrcStatCount             uint32 = 6
	SrcStatSlots             uint32 = 16
)

// SrcStatNames maps each SrcStat* index to a short, stable, metrics-friendly
// name.
var SrcStatNames = map[uint32]string{
	SrcStatChecked:           "checked",
	SrcStatAllowed:           "allowed",
	SrcStatDenyPrefix:        "deny_prefix",
	SrcStatDenyInterface:     "deny_interface",
	SrcStatDenyStructure:     "deny_structure",
	SrcStatBypassUnpopulated: "bypass_unpopulated",
}
