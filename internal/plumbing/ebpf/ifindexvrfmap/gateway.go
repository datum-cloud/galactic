// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ifindexvrfmap

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// GatewayTable is the read/write API for tenant_gw_table: the gateway
// addresses IPAM gave one attachment, keyed by its host-side interface's
// ifindex. usid_egress sends the ICMP Packet Too Big or Fragmentation Needed
// for a packet too big for the fabric from these addresses, so the tenant sees
// its own first hop report the smaller MTU. An attachment with no entry, or
// none in a family, gets no error in that family; its oversized packets are
// dropped and counted instead.
//
// It shares ifindex_vrf_table's lifecycle, written at CNI ADD and removed at
// DEL, so it needs no generation bookkeeping of its own.
type GatewayTable struct {
	table usidmap.Table
}

// NewGatewayTable wraps table as a GatewayTable. Production callers use
// OpenPinnedGateway; tests pass a fake.
func NewGatewayTable(table usidmap.Table) *GatewayTable {
	return &GatewayTable{table: table}
}

// OpenPinnedGateway opens tenant_gw_table from its pinned path under pinDir.
// The returned map must be closed when the caller is done.
//
// The error wraps os.ErrNotExist when the running datapath predates this map,
// for the same reason as OpenPinnedEgressKind.
func OpenPinnedGateway(pinDir string) (*GatewayTable, *ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapTenantGwTable), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("ifindexvrfmap: open pinned map %q: %w", prog.UsidMapTenantGwTable, err)
	}
	return NewGatewayTable(usidmap.KernelTable{Map: m}), m, nil
}

// Register writes, or overwrites, the gateways for ifindex. Either may be the
// zero netip.Addr, meaning the attachment has no gateway in that family. gw6
// must be IPv6 and gw4 IPv4 when set; an IPv4-mapped IPv6 address is accepted
// as gw4.
func (t *GatewayTable) Register(ifindex uint32, gw6, gw4 netip.Addr) error {
	var v prog.UsidTenantGwValue
	if gw6.IsValid() {
		if !gw6.Is6() || gw6.Is4In6() {
			return fmt.Errorf("ifindexvrfmap: tenant_gw_table: register ifindex=%d: IPv6 gateway %s is not IPv6",
				ifindex, gw6)
		}
		v.Gw6 = gw6.As16()
	}
	if gw4.IsValid() {
		gw4 = gw4.Unmap()
		if !gw4.Is4() {
			return fmt.Errorf("ifindexvrfmap: tenant_gw_table: register ifindex=%d: IPv4 gateway %s is not IPv4",
				ifindex, gw4)
		}
		v.Gw4 = gw4.As4()
	}
	if err := t.table.Put(ifindex, v); err != nil {
		return fmt.Errorf("ifindexvrfmap: tenant_gw_table: register ifindex=%d: %w", ifindex, err)
	}
	return nil
}

// Unregister removes the entry for ifindex if present. An already-absent entry
// is not an error: DEL is idempotent per the CNI spec.
func (t *GatewayTable) Unregister(ifindex uint32) error {
	if err := t.table.Delete(ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("ifindexvrfmap: tenant_gw_table: unregister ifindex=%d: %w", ifindex, err)
	}
	return nil
}

// Get reads the gateways for ifindex, reporting whether an entry exists. A
// family with no gateway reads as the zero netip.Addr.
func (t *GatewayTable) Get(ifindex uint32) (gw6, gw4 netip.Addr, ok bool, err error) {
	var v prog.UsidTenantGwValue
	if err := t.table.Lookup(ifindex, &v); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return netip.Addr{}, netip.Addr{}, false, nil
		}
		return netip.Addr{}, netip.Addr{}, false,
			fmt.Errorf("ifindexvrfmap: tenant_gw_table: get ifindex=%d: %w", ifindex, err)
	}
	if v.Gw6 != ([16]byte{}) {
		gw6 = netip.AddrFrom16(v.Gw6)
	}
	if v.Gw4 != ([4]byte{}) {
		gw4 = netip.AddrFrom4(v.Gw4)
	}
	return gw6, gw4, true, nil
}
