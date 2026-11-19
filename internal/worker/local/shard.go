// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
	"go.datum.net/galactic/internal/worker/module"
)

// LocalShardRow is one egress_local_shard row: the VPC whose VRF table keys
// it takes this node's NAT shard through its service-internal veth pair.
type LocalShardRow struct {
	// ShardSID is the local shard's SID.
	ShardSID netip.Addr
	// PairIfindex is the tenant end of the VPC's pair.
	PairIfindex uint32
}

// LocalShards reads and writes egress_local_shard, keyed by VRF table ID.
// usid_egress selects the local shard for a VPC's tenants only while its row
// exists, and the egress sweep steers ordered-mode routes by it, so a row
// exists only while the VPC's pair can carry them (docs/worker/contract.md,
// "Local NAT shards").
type LocalShards interface {
	Put(tableID uint32, row LocalShardRow) error
	// Delete removes tableID's row; a missing row is not an error.
	Delete(tableID uint32) error
	Get(tableID uint32) (LocalShardRow, bool, error)
	All() (map[uint32]LocalShardRow, error)
}

// shardWant is the Local NAT shard a VPC's veth_pair claim serves.
type shardWant struct {
	key module.ClaimKey
	sid netip.Addr
	// pair is the tenant end of the claim's pair.
	pair string
}

// pairServing returns why the pair p cannot carry a VPC's flows to its NAT
// shard, or "" when it can: both ends have carrier, the NAT end runs an XDP
// program natively, and the tenant end runs Local's return programs.
func (k *Kernel) pairServing(p pair) string {
	switch {
	case !lowerUp(p.tenant) || !lowerUp(p.nat):
		return "the pair has no carrier"
	case !k.pairNAPICurrent(p.tenant):
		return "Local's XDP program is not on " + p.tenant.Attrs().Name
	}
	if ok, err := k.filterCurrent(p.tenant.Attrs().Index, filterPairRx); err != nil || !ok {
		return "Local's tc program is not on " + p.tenant.Attrs().Name
	}
	xdp := p.nat.Attrs().Xdp
	if xdp == nil || !xdp.Attached {
		return "the NAT end " + p.nat.Attrs().Name + " carries no XDP program"
	}
	if mode, ok := xdpmode.FromAttachMode(xdp.AttachMode); !ok || mode != xdpmode.Native {
		return "the NAT end " + p.nat.Attrs().Name + " runs its XDP program in generic mode"
	}
	return ""
}

// ensureLocalShard writes the VPC's egress_local_shard row while the model
// wants a Local shard and its pair can carry the VPC's flows, and removes it
// otherwise. It also removes any row whose pair is gone, such as one left by
// a VPC whose VRF was removed. A pair that stops serving withdraws only its
// own VPC's row: other VPCs keep the shard.
func (p *pass) ensureLocalShard() error {
	if p.k.Shards == nil {
		return nil
	}
	rows, err := p.k.Shards.All()
	if errors.Is(err, os.ErrNotExist) {
		// A uSID datapath older than egress_local_shard: no VPC can take
		// the local shard, and Read reports why.
		return nil
	}
	if err != nil {
		return fmt.Errorf("local: read egress_local_shard: %w", err)
	}
	for table, row := range rows {
		if table == p.table {
			continue
		}
		if p.livePairTenant(row.PairIfindex) {
			continue
		}
		if err := fix(p.dry, true, func() error { return p.k.Shards.Delete(table) }); err != nil {
			return err
		}
	}
	if p.table == 0 {
		return nil
	}
	cur, have := rows[p.table]
	var want *LocalShardRow
	if s := p.m.shard; s != nil {
		if pr, ok := p.pairs[s.pair]; ok && p.k.pairServing(pr) == "" {
			want = &LocalShardRow{ShardSID: s.sid, PairIfindex: uint32(pr.tenant.Attrs().Index)}
		}
	}
	switch {
	case want != nil && (!have || cur != *want):
		return fix(p.dry, true, func() error { return p.k.Shards.Put(p.table, *want) })
	case want == nil && have:
		return fix(p.dry, true, func() error { return p.k.Shards.Delete(p.table) })
	}
	return nil
}

// livePairTenant reports whether ifindex is the tenant end of a pair Local
// created.
func (p *pass) livePairTenant(ifindex uint32) bool {
	for _, l := range p.h.byName {
		if uint32(l.Attrs().Index) != ifindex {
			continue
		}
		_, _, ok := parseAlias(l.Attrs().Alias)
		return ok && l.Type() == linkVeth
	}
	return false
}

// shardCheck checks a Local shard destination: its pair, through the
// claim's handoff check, and the VPC's egress_local_shard row, which makes
// the VPC's tenants take the shard.
func (k *Kernel) shardCheck(ck *check, table uint32, m *model, c module.Claim, d module.Destination) {
	if k.Shards == nil {
		ck.unprogrammed(workerv1alpha1.ReasonDatapathNotLoaded,
			"the uSID datapath has no egress_local_shard map; upgrade galactic-cni")
		return
	}
	if m.shard == nil || m.shard.key != c.Key {
		ck.unprogrammed(workerv1alpha1.ReasonProgrammingFailed,
			"another claim's pair serves the VPC's Local shard")
		return
	}
	row, have, err := k.Shards.Get(table)
	switch {
	case errors.Is(err, os.ErrNotExist):
		ck.unprogrammed(workerv1alpha1.ReasonDatapathNotLoaded,
			"the uSID datapath has no egress_local_shard map; upgrade galactic-cni")
	case err != nil:
		ck.notReady(true, false, workerv1alpha1.ReasonProgrammingFailed, err.Error())
	case !have || row.ShardSID != d.Shard.SID:
		ck.notReady(true, false, workerv1alpha1.ReasonLocalShardIneligible,
			"the VPC's tenants do not take the Local shard yet; they keep the remote shards")
	}
}

// tenantSID returns the SID that names the VPC of the tenant interfaces
// names on this node: this node's source SID completed with the VPC's
// Argument, as usid_egress writes it. It is the zero address until one of
// them has an ifindex_vrf_table row and the node's source SID is set.
func (k *Kernel) tenantSID(h *host, names []string) (netip.Addr, error) {
	ifv, src, err := k.identityMaps()
	if err != nil {
		return netip.Addr{}, err
	}
	var base [16]byte
	if err := src.Lookup(uint32(0), &base); err != nil {
		return netip.Addr{}, fmt.Errorf("local: read node_src_addr_table: %w", err)
	}
	if base == [16]byte{} {
		return netip.Addr{}, nil
	}
	for _, n := range names {
		l := h.byName[n]
		if l == nil {
			continue
		}
		var v struct {
			Block    uint64
			Argument uint16
			_        [6]byte
		}
		if err := ifv.Lookup(uint32(l.Attrs().Index), &v); err != nil {
			continue
		}
		return spliceArgument(base, v.Argument), nil
	}
	return netip.Addr{}, nil
}

// spliceArgument completes the node source SID base with argument in bits
// 69-80, the field usid_egress writes.
func spliceArgument(base [16]byte, argument uint16) netip.Addr {
	base[8] = base[8]&0xF0 | byte(argument>>8)&0x0F
	base[9] = byte(argument)
	return netip.AddrFrom16(base)
}

// identityMaps opens ifindex_vrf_table and node_src_addr_table, which
// galactic-cni pins, on first use.
func (k *Kernel) identityMaps() (*ebpf.Map, *ebpf.Map, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.ifindexVRF == nil {
		m, err := ebpf.LoadPinnedMap(filepath.Join(k.PinDir, "ifindex_vrf_table"), nil)
		if err != nil {
			return nil, nil, fmt.Errorf("local: open ifindex_vrf_table: %w", err)
		}
		k.ifindexVRF = m
	}
	if k.nodeSrc == nil {
		m, err := ebpf.LoadPinnedMap(filepath.Join(k.PinDir, "node_src_addr_table"), nil)
		if err != nil {
			return nil, nil, fmt.Errorf("local: open node_src_addr_table: %w", err)
		}
		k.nodeSrc = m
	}
	return k.ifindexVRF, k.nodeSrc, nil
}

// ensureForwarding turns IPv4 and IPv6 forwarding on for name, the NAT end
// of a pair: the NAT shard's program looks up the route for what it
// translates as a packet received there, and the kernel's FIB lookup
// refuses one from a device that does not forward.
func ensureForwarding(name string, dry bool) error {
	for _, f := range []string{"/proc/sys/net/ipv4/conf/" + name + "/forwarding",
		"/proc/sys/net/ipv6/conf/" + name + "/forwarding"} {
		b, err := os.ReadFile(f)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("local: read %s: %w", f, err)
		}
		if err := fix(dry, len(b) == 0 || b[0] != '1', func() error {
			if err := os.WriteFile(f, []byte("1"), 0o644); err != nil { //nolint:gosec // a sysctl
				return fmt.Errorf("local: write %s: %w", f, err)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
