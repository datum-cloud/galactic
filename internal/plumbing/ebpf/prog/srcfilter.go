// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

// Source filter constants mirroring usid.c's enum src_filter_mode,
// SRCF_ANY_IFACE, SRC_FILTER_MAX_SLOTS and enum src_filter_stat. Hand-kept in
// sync with the C source for the same reason as the drop reasons: the generator
// produces no Go symbol for an enum used only as a literal or for a #define.
const (
	SrcFilterModeOff     uint32 = 0
	SrcFilterModeAudit   uint32 = 1
	SrcFilterModeEnforce uint32 = 2

	SrcFilterFlagAnyIface uint32 = 1 << 0

	SrcFilterMaxSlots = 32

	SrcFilterStatChecked           uint32 = 0
	SrcFilterStatAllowed           uint32 = 1
	SrcFilterStatDenyPrefix        uint32 = 2
	SrcFilterStatDenyIface         uint32 = 3
	SrcFilterStatBypassUnpopulated uint32 = 4
	SrcFilterStatCount             uint32 = 5
	SrcFilterStatSlots             uint32 = 8
)

// SrcFilterStatNames maps each src_filter_stats index to a short, stable,
// metrics-friendly name.
var SrcFilterStatNames = map[uint32]string{
	SrcFilterStatChecked:           "checked",
	SrcFilterStatAllowed:           "allowed",
	SrcFilterStatDenyPrefix:        "deny_prefix",
	SrcFilterStatDenyIface:         "deny_iface",
	SrcFilterStatBypassUnpopulated: "bypass_unpopulated",
}
