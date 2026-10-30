// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ifindexvrfmap

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

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

// hostOnlyAltNameMarker separates a link's name from the host-only ports in
// the alternative name that records them on the link. The interface alias is
// not used: the tap and veth plugins keep the owning container's ID there.
const hostOnlyAltNameMarker = ".host-only-tcp="

// HostOnlyAltName returns the alternative name recording ports on the link
// named linkName, or "" for none. Alternative names are unique per host, so
// the link's own name leads. The name lives with the link, so it outlasts a
// recreated host_only_port_table and lets Restore rebuild the table's rows.
func HostOnlyAltName(linkName string, ports []uint16) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return linkName + hostOnlyAltNameMarker + strings.Join(parts, ",")
}

// ParseHostOnlyAltName reads the ports HostOnlyAltName recorded in altName,
// reporting whether altName is one.
func ParseHostOnlyAltName(altName string) ([]uint16, bool, error) {
	_, list, ok := strings.Cut(altName, hostOnlyAltNameMarker)
	if !ok {
		return nil, false, nil
	}
	var ports []uint16
	for _, field := range strings.Split(list, ",") {
		p, err := strconv.ParseUint(field, 10, 16)
		if err != nil {
			return nil, true, fmt.Errorf("host-only alternative name %q: %w", altName, err)
		}
		ports = append(ports, uint16(p))
	}
	if err := ValidateHostOnlyPorts(ports); err != nil {
		return nil, true, fmt.Errorf("host-only alternative name %q: %w", altName, err)
	}
	return ports, true, nil
}

// Restore writes the entry for every interface in altNames, keyed by ifindex,
// with an alternative name recording host-only ports and a missing entry, and
// returns how many it wrote. An entry that exists is left alone. Every
// interface is attempted; the error joins every failure.
func (t *HostOnlyPortTable) Restore(altNames map[uint32][]string) (int, error) {
	restored := 0
	var errs []error
	for ifindex, names := range altNames {
		ports, ok, err := hostOnlyPortsOf(names)
		if err != nil {
			errs = append(errs, fmt.Errorf("ifindex=%d: %w", ifindex, err))
			continue
		}
		if !ok {
			continue
		}
		if _, listed, err := t.Get(ifindex); err != nil || listed {
			errs = append(errs, err)
			continue
		}
		if err := t.Register(ifindex, ports); err != nil {
			errs = append(errs, err)
			continue
		}
		restored++
	}
	return restored, errors.Join(errs...)
}

// hostOnlyPortsOf returns the ports the first host-only alternative name in
// names records, reporting whether there is one.
func hostOnlyPortsOf(names []string) ([]uint16, bool, error) {
	for _, name := range names {
		if ports, ok, err := ParseHostOnlyAltName(name); ok {
			return ports, true, err
		}
	}
	return nil, false, nil
}
