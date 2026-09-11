// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natmap

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

// TenantState is one tenant's session accounting on this shard, keyed by the
// VRFID the datapath reads out of each flow's SRv6 Argument.
//
// Sessions counts live translated flows across both address families against
// one shared ceiling: both are rows in the same table scoped by the same VRFID,
// and there is no reason to give a tenant separate budgets for reaching an IPv4
// host and an IPv6 one.
//
// The two admission-failure counters are kept apart because an operator acts on
// them differently. AdmitFailLimit means the tenant asked for more than their
// own configured ceiling allows; AdmitFailUnavailable means this shard could not
// serve the address family they asked for at all. Summing them would make the
// most common question -- why did this particular connection fail --
// unanswerable from counters alone, which is the reason they exist.
type TenantState struct {
	// VRFID identifies the tenant. It is the value carried in the SRv6
	// Argument, not a separate identifier space.
	VRFID uint32

	// Sessions is the live translated-flow count. See Resync for why userspace
	// owns this number's accuracy rather than the datapath alone.
	Sessions uint64

	// Limit is this tenant's ceiling. Zero means the shard's configured default
	// applies; a zero default in turn means unlimited.
	Limit uint64

	// AdmitFailLimit counts flows refused because the tenant was at Limit.
	AdmitFailLimit uint64

	// AdmitFailUnavailable counts flows refused because this shard does not
	// serve the address family the flow needed.
	AdmitFailUnavailable uint64
}

// TenantStateTable is the read/write API for tenant_state_table.
type TenantStateTable struct {
	table Table
}

// NewTenantStateTable wraps table as a TenantStateTable. Production callers pass
// a kernel table over the loaded map; tests pass a fake.
func NewTenantStateTable(table Table) *TenantStateTable {
	return &TenantStateTable{table: table}
}

func fromWireTenantState(vrfID uint32, value natprog.NatTenantState) TenantState {
	return TenantState{
		VRFID:                vrfID,
		Sessions:             value.Sessions,
		Limit:                value.Limit,
		AdmitFailLimit:       value.AdmitFailLimit,
		AdmitFailUnavailable: value.AdmitFailUnavailable,
	}
}

// Get reads one tenant's row and reports whether the datapath has seen that
// tenant at all yet.
func (t *TenantStateTable) Get(vrfID uint32) (TenantState, bool, error) {
	var value natprog.NatTenantState
	if err := t.table.Lookup(vrfID, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return TenantState{}, false, nil
		}
		return TenantState{}, false, fmt.Errorf("natmap: tenant_state_table: get %d: %w", vrfID, err)
	}
	return fromWireTenantState(vrfID, value), true, nil
}

// List returns every tenant row currently held.
func (t *TenantStateTable) List() ([]TenantState, error) {
	var (
		states []TenantState
		vrfID  uint32
		value  natprog.NatTenantState
	)
	it := t.table.Iterate()
	for it.Next(&vrfID, &value) {
		states = append(states, fromWireTenantState(vrfID, value))
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("natmap: tenant_state_table: list: %w", err)
	}
	return states, nil
}

// SetLimit writes one tenant's ceiling, preserving the counters the datapath
// owns. Zero restores the shard default.
//
// Unlike ShardConfigTable.Set this cannot be a blind overwrite: every other
// field in the row is incremented by the datapath, so writing a whole value
// would discard counts taken between the read and the write. The race is
// narrowed, not closed -- a session admitted in that window is lost from the
// count -- which the next Resync corrects.
func (t *TenantStateTable) SetLimit(vrfID uint32, limit uint64) error {
	var value natprog.NatTenantState
	if err := t.table.Lookup(vrfID, &value); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("natmap: tenant_state_table: set limit %d: %w", vrfID, err)
	}
	value.Limit = limit
	if err := t.table.Put(vrfID, value); err != nil {
		return fmt.Errorf("natmap: tenant_state_table: set limit %d: %w", vrfID, err)
	}
	return nil
}

// Resync recomputes every tenant's live session count from the connection table
// and writes the corrected values back, returning what it wrote.
//
// This exists because the datapath's own count cannot stay accurate on its own.
// nat_conn_table is an LRU map, so the kernel evicts rows under pressure with
// nothing to decrement, and no datapath path ages an idle flow out. Left to
// itself the count only ever climbs, and every tenant eventually reads as over
// limit and stops being able to open connections -- a fail-closed limit
// degrading into a fail-closed shard.
//
// Counting forward rows alone is what makes the total right: every flow owns
// exactly one forward row and one reverse row, and only the forward row carries
// the tenant's VRFID. Counting every row would double each flow, and counting
// reverse rows would attribute them all to VRFID zero.
//
// A tenant whose rows have all gone resets to zero rather than being deleted:
// the row also carries that tenant's limit and their admission-failure history,
// none of which a quiet period should discard.
func (t *TenantStateTable) Resync(conns *ConnTable) ([]TenantState, error) {
	entries, err := conns.List()
	if err != nil {
		return nil, fmt.Errorf("natmap: tenant_state_table: resync: %w", err)
	}

	live := make(map[uint32]uint64, len(entries))
	for _, entry := range entries {
		if entry.TenantArg == 0 {
			continue // a reverse row; see this function's doc comment
		}
		live[uint32(entry.TenantArg)]++
	}

	existing, err := t.List()
	if err != nil {
		return nil, fmt.Errorf("natmap: tenant_state_table: resync: %w", err)
	}

	resynced := make([]TenantState, 0, len(existing))
	for _, state := range existing {
		counted := live[state.VRFID]
		if state.Sessions == counted {
			resynced = append(resynced, state)
			continue
		}
		var value natprog.NatTenantState
		if err := t.table.Lookup(state.VRFID, &value); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue // the tenant went away mid-sweep; the next pass covers it
			}
			return nil, fmt.Errorf("natmap: tenant_state_table: resync %d: %w", state.VRFID, err)
		}
		value.Sessions = counted
		if err := t.table.Put(state.VRFID, value); err != nil {
			return nil, fmt.Errorf("natmap: tenant_state_table: resync %d: %w", state.VRFID, err)
		}
		state.Sessions = counted
		resynced = append(resynced, state)
	}
	return resynced, nil
}
