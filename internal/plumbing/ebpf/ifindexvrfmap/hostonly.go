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

// hostOnlyAliasPrefix starts the interface alias that records an attachment's
// host-only ports on its host-side interface.
const hostOnlyAliasPrefix = "galactic-host-only-tcp="

// hostOnlyOwnerSep separates a host-only alias's port list from the owner it
// carries.
const hostOnlyOwnerSep = ";owner="

// HostOnlyAlias returns the interface alias recording ports and owner, the
// CNI container ID the link belongs to, or owner alone for no ports. The alias
// lives with the link, so it outlasts a recreated host_only_port_table and
// lets Restore rebuild the table's rows.
//
// The owner stays in the alias because the alias is also the link's ownership
// stamp: a DEL removes a host link only while its owner is the DEL's own
// container, and GC reclaims a dead attachment's link only while one of its
// dead containers owns it. An alias holding only ports would leave a
// host-only tap owned by no one, kept by its own DEL and left behind with its
// pod-subnet route.
func HostOnlyAlias(ports []uint16, owner string) string {
	if len(ports) == 0 {
		return owner
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	alias := hostOnlyAliasPrefix + strings.Join(parts, ",")
	if owner != "" {
		alias += hostOnlyOwnerSep + owner
	}
	return alias
}

// AliasOwner returns the owner a host link's alias records: the owner part of
// a host-only alias, or the whole alias otherwise. A host-only alias written
// before it carried an owner records none, and returns "".
func AliasOwner(alias string) string {
	rest, ok := strings.CutPrefix(alias, hostOnlyAliasPrefix)
	if !ok {
		return alias
	}
	_, owner, _ := strings.Cut(rest, hostOnlyOwnerSep)
	return owner
}

// ParseHostOnlyAlias reads the ports HostOnlyAlias recorded in alias,
// reporting whether alias is one.
func ParseHostOnlyAlias(alias string) ([]uint16, bool, error) {
	list, ok := strings.CutPrefix(alias, hostOnlyAliasPrefix)
	if !ok {
		return nil, false, nil
	}
	list, _, _ = strings.Cut(list, hostOnlyOwnerSep)
	var ports []uint16
	for _, field := range strings.Split(list, ",") {
		p, err := strconv.ParseUint(field, 10, 16)
		if err != nil {
			return nil, true, fmt.Errorf("host-only alias %q: %w", alias, err)
		}
		ports = append(ports, uint16(p))
	}
	if err := ValidateHostOnlyPorts(ports); err != nil {
		return nil, true, fmt.Errorf("host-only alias %q: %w", alias, err)
	}
	return ports, true, nil
}

// Restore writes the entry for every interface in aliases, keyed by ifindex,
// whose alias records host-only ports and whose entry is missing, and returns
// how many it wrote. An entry that exists is left alone. Every interface is
// attempted; the error joins every failure.
func (t *HostOnlyPortTable) Restore(aliases map[uint32]string) (int, error) {
	restored := 0
	var errs []error
	for ifindex, alias := range aliases {
		ports, ok, err := ParseHostOnlyAlias(alias)
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
