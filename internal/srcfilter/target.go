// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srcfilter

import "net/netip"

// MaxSlots is the number of distinct uplinks an entry's interface mask can
// name. Valid slots are 0 through MaxSlots-1.
const MaxSlots = 32

// Entry is one allowed source prefix.
type Entry struct {
	Prefix netip.Prefix
	// IfaceMask has bit N set for every uplink assigned slot N.
	IfaceMask uint32
	// AnyIface accepts the prefix on every interface, ignoring IfaceMask.
	AnyIface bool
}

// State is a filter's global state.
type State struct {
	Mode Mode
	// Populated reports that the allow-list reflects a complete sync. While
	// false the datapath lets every packet through.
	Populated bool
	// Generation is a counter bumped on every applied change.
	Generation uint64
}

// Target is a datapath's source filter as the Reconciler drives it. Every
// method must be safe to call again after a partial failure.
type Target interface {
	// ListAllow returns every allow entry.
	ListAllow() ([]Entry, error)
	// PutAllow creates or overwrites the entry for e.Prefix.
	PutAllow(e Entry) error
	// DeleteAllow removes the entry for p. An absent entry is not an error.
	DeleteAllow(p netip.Prefix) error
	// UplinkSlots returns every ifindex-to-slot assignment.
	UplinkSlots() (map[uint32]uint8, error)
	// SyncUplinkSlots makes the slot assignments exactly slots.
	SyncUplinkSlots(slots map[uint32]uint8) error
	// State returns the filter's global state.
	State() (State, error)
	// SetState writes the filter's global state.
	SetState(s State) error
}

// SlotAssigner returns the ifindex-to-slot assignment for a pass, given the
// uplink ifindexes the pass resolved and the assignment the Target holds now.
type SlotAssigner func(uplinks []uint32, current map[uint32]uint8) (map[uint32]uint8, error)
