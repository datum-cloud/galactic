// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ifindexvrfmap

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// MaxHostOnlyPorts is how many host-only ports one attachment may list,
// fixed by host_only_ports_value's layout.
const MaxHostOnlyPorts = len(prog.UsidHostOnlyPortsValue{}.Tcp)

// HostOnlyPortTable is the read/write API for host_only_port_table: the TCP
// ports on one attachment that only the node may reach, keyed by its host-side
// interface's ifindex. tp_deliver drops a packet for one of them unless it is
// addressed to the guest's link-local address, which no other workload can
// route to.
//
// It shares ifindex_vrf_table's lifecycle, written at CNI ADD and removed at
// DEL.
type HostOnlyPortTable struct {
	table usidmap.Table
}

// NewHostOnlyPortTable wraps table as a HostOnlyPortTable. Production callers
// use OpenPinnedHostOnlyPorts; tests pass a fake.
func NewHostOnlyPortTable(table usidmap.Table) *HostOnlyPortTable {
	return &HostOnlyPortTable{table: table}
}

// OpenPinnedHostOnlyPorts opens host_only_port_table from its pinned path
// under pinDir. The returned map must be closed when the caller is done.
//
// The error wraps os.ErrNotExist when the running datapath predates this map.
func OpenPinnedHostOnlyPorts(pinDir string) (*HostOnlyPortTable, *ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapHostOnlyPortTable), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("ifindexvrfmap: open pinned map %q: %w", prog.UsidMapHostOnlyPortTable, err)
	}
	return NewHostOnlyPortTable(usidmap.KernelTable{Map: m}), m, nil
}

// Register writes, or overwrites, the host-only TCP ports for ifindex. ports
// must hold between one and MaxHostOnlyPorts distinct nonzero ports.
func (t *HostOnlyPortTable) Register(ifindex uint32, ports []uint16) error {
	if err := ValidateHostOnlyPorts(ports); err != nil {
		return fmt.Errorf("ifindexvrfmap: host_only_port_table: register ifindex=%d: %w", ifindex, err)
	}
	if len(ports) == 0 {
		return fmt.Errorf("ifindexvrfmap: host_only_port_table: register ifindex=%d: no ports", ifindex)
	}
	var v prog.UsidHostOnlyPortsValue
	copy(v.Tcp[:], ports)
	if err := t.table.Put(ifindex, v); err != nil {
		return fmt.Errorf("ifindexvrfmap: host_only_port_table: register ifindex=%d: %w", ifindex, err)
	}
	return nil
}

// Unregister removes the entry for ifindex if present. An already-absent entry
// is not an error: DEL is idempotent per the CNI spec.
func (t *HostOnlyPortTable) Unregister(ifindex uint32) error {
	if err := t.table.Delete(ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("ifindexvrfmap: host_only_port_table: unregister ifindex=%d: %w", ifindex, err)
	}
	return nil
}

// Get reads the host-only ports for ifindex, reporting whether an entry
// exists.
func (t *HostOnlyPortTable) Get(ifindex uint32) ([]uint16, bool, error) {
	var v prog.UsidHostOnlyPortsValue
	if err := t.table.Lookup(ifindex, &v); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("ifindexvrfmap: host_only_port_table: get ifindex=%d: %w", ifindex, err)
	}
	var ports []uint16
	for _, p := range v.Tcp {
		if p != 0 {
			ports = append(ports, p)
		}
	}
	return ports, true, nil
}

// ValidateHostOnlyPorts reports whether ports fits host_only_port_table: at
// most MaxHostOnlyPorts entries, none zero, none repeated. An empty list is
// valid and means the attachment has none.
func ValidateHostOnlyPorts(ports []uint16) error {
	if len(ports) > MaxHostOnlyPorts {
		return fmt.Errorf("%d host-only ports, at most %d allowed", len(ports), MaxHostOnlyPorts)
	}
	for i, p := range ports {
		if p == 0 {
			return errors.New("host-only port 0 is not a port")
		}
		if slices.Contains(ports[:i], p) {
			return fmt.Errorf("host-only port %d is listed twice", p)
		}
	}
	return nil
}
