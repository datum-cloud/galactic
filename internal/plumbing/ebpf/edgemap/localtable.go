// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgemap

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// LocalTable is edge_local_table: the backends this gateway node serves
// itself through Worker's Local local.tap handoff, keyed by backend uSID.
// edge_lb looks the selected backend's uSID up after Maglev selection. A row
// with a TAP hands the packet to Worker's local_rx; a row whose TAP is 0, a
// handoff not Ready, drops it; no row encapsulates it as before.
type LocalTable struct {
	table Table
	clock func() uint64
}

// LocalBackend is one edge_local_table row.
type LocalBackend struct {
	// SID is the backend uSID, as Backend.USID carries it.
	SID netip.Addr
	// TapIfindex is the TAP Worker hands the backend's packets to, or 0 while
	// the handoff is not Ready.
	TapIfindex uint32
	// Generation is the control plane's stamp on the row's last write.
	Generation uint64
}

// NewLocalTable wraps edge_local_table. Production callers pass
// KernelTable{Map: objs.EdgeLocalTable}; tests pass a fake.
func NewLocalTable(table Table) *LocalTable {
	return &LocalTable{table: table, clock: clockFn}
}

// Generation returns a snapshot of this table's monotonic clock, for
// SetLocalBackend and Reconcile, read as VIPTable.Generation is.
func (t *LocalTable) Generation() uint64 {
	return t.clock()
}

func toWireSID(sid netip.Addr) (edgeprog.EdgedsrEdgeLocalKey, error) {
	if !sid.Is6() || sid.Is4In6() {
		return edgeprog.EdgedsrEdgeLocalKey{}, fmt.Errorf("backend uSID %s is not an IPv6 address", sid)
	}
	return edgeprog.EdgedsrEdgeLocalKey{Usid: sid.As16()}, nil
}

// SetLocalBackend makes sid a Local backend handed to tapIfindex, or, with
// tapIfindex 0, a Local backend whose packets are dropped while its handoff is
// not Ready. It creates or overwrites the row.
func (t *LocalTable) SetLocalBackend(sid netip.Addr, tapIfindex uint32, generation uint64) error {
	key, err := toWireSID(sid)
	if err != nil {
		return fmt.Errorf("edgemap: edge_local_table: %w", err)
	}
	value := edgeprog.EdgedsrEdgeLocalValue{TapIfindex: tapIfindex, Generation: generation}
	if err := t.table.Put(key, value); err != nil {
		return fmt.Errorf("edgemap: edge_local_table: set %s: %w", sid, err)
	}
	return nil
}

// DeleteLocalBackend removes sid's row, so edge_lb encapsulates to it again.
// An absent row is not an error.
func (t *LocalTable) DeleteLocalBackend(sid netip.Addr) error {
	key, err := toWireSID(sid)
	if err != nil {
		return fmt.Errorf("edgemap: edge_local_table: %w", err)
	}
	if err := t.table.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("edgemap: edge_local_table: delete %s: %w", sid, err)
	}
	return nil
}

// List returns every row.
func (t *LocalTable) List() ([]LocalBackend, error) {
	var (
		key   edgeprog.EdgedsrEdgeLocalKey
		value edgeprog.EdgedsrEdgeLocalValue
		out   []LocalBackend
	)
	iter := t.table.Iterate()
	for iter.Next(&key, &value) {
		out = append(out, LocalBackend{SID: netip.AddrFrom16(key.Usid), TapIfindex: value.TapIfindex,
			Generation: value.Generation})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("edgemap: edge_local_table: list: %w", err)
	}
	return out, nil
}

// LocalBackends returns each row's TAP by backend uSID.
func (t *LocalTable) LocalBackends() (map[netip.Addr]uint32, error) {
	rows, err := t.List()
	if err != nil {
		return nil, err
	}
	out := make(map[netip.Addr]uint32, len(rows))
	for _, r := range rows {
		out[r.SID] = r.TapIfindex
	}
	return out, nil
}

// Reconcile removes every row whose uSID is absent from live, except one whose
// generation is at or above cutoff, which was written after the caller's
// snapshot and could race a fresh SetLocalBackend.
func (t *LocalTable) Reconcile(live map[netip.Addr]struct{}, cutoff uint64) (removed []netip.Addr, err error) {
	rows, err := t.List()
	if err != nil {
		return nil, fmt.Errorf("edgemap: edge_local_table: reconcile: %w", err)
	}
	var errs []error
	for _, r := range rows {
		if _, ok := live[r.SID]; ok || r.Generation >= cutoff {
			continue
		}
		if err := t.DeleteLocalBackend(r.SID); err != nil {
			errs = append(errs, fmt.Errorf("edgemap: edge_local_table: reconcile: %w", err))
			continue
		}
		removed = append(removed, r.SID)
	}
	return removed, errors.Join(errs...)
}

// ReadLocalHandoffs returns local_handoffs, the packets edge_lb handed to
// Worker's Local module, summed over CPUs. m is objs.LocalHandoffs.
func ReadLocalHandoffs(m *ebpf.Map) (uint64, error) {
	var perCPU []uint64
	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return 0, fmt.Errorf("edgemap: local_handoffs: %w", err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}

// ReadDropReasons returns drop_reasons summed over CPUs, by
// edgeprog.DropReasonNames name; an index without a name reads as
// unknown_<n>. m is objs.DropReasons.
func ReadDropReasons(m *ebpf.Map) (map[string]uint64, error) {
	out := make(map[string]uint64, edgeprog.DropReasonCount)
	for i := range edgeprog.DropReasonCount {
		var perCPU []uint64
		if err := m.Lookup(i, &perCPU); err != nil {
			return nil, fmt.Errorf("edgemap: drop_reasons[%d]: %w", i, err)
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		name, ok := edgeprog.DropReasonNames[i]
		if !ok {
			name = fmt.Sprintf("unknown_%d", i)
		}
		out[name] = total
	}
	return out, nil
}
