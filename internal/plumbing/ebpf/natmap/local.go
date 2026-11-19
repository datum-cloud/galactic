// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package natmap

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

// LocalPair is one service-internal veth pair this shard serves a VPC on this
// node through (Galactic Worker's local.veth_pair handoff).
type LocalPair struct {
	// NATIfindex is the pair's NAT end, which nat_ingress runs on.
	NATIfindex uint32
	// TenantSID names the pair's VPC on this node: the node's source SID
	// completed with the VPC's Argument, as Worker reports it.
	TenantSID netip.Addr
	// NATMAC and TenantMAC are the pair's two ends' addresses; a reply
	// entering the pair is framed from the first to the second.
	NATMAC    net.HardwareAddr
	TenantMAC net.HardwareAddr
}

// LocalTables writes nat_local_pair and nat_local_return, which together
// route a pair's tenants into this shard and its replies back into the pair.
type LocalTables struct {
	Pair   Table
	Return Table
}

// Put writes both rows of p, return row first, so a forward the new pair
// row admits always finds its way back.
func (t LocalTables) Put(p LocalPair) error {
	if !p.TenantSID.Is6() || p.TenantSID.Is4In6() {
		return fmt.Errorf("natmap: local pair: tenant SID %s is not IPv6", p.TenantSID)
	}
	if p.NATIfindex == 0 {
		return errors.New("natmap: local pair: NAT end ifindex is 0")
	}
	if len(p.NATMAC) != 6 || len(p.TenantMAC) != 6 {
		return fmt.Errorf("natmap: local pair: MACs %s and %s must be 6 bytes", p.NATMAC, p.TenantMAC)
	}
	rk := natprog.NatNatLocalReturnKey{TenantSid: p.TenantSID.As16()}
	rv := natprog.NatNatLocalReturnValue{Ifindex: p.NATIfindex}
	copy(rv.Smac[:], p.NATMAC)
	copy(rv.Dmac[:], p.TenantMAC)
	if err := t.Return.Put(rk, rv); err != nil {
		return fmt.Errorf("natmap: nat_local_return: put %s: %w", p.TenantSID, err)
	}
	pv := natprog.NatNatLocalPairValue{TenantSid: p.TenantSID.As16()}
	if err := t.Pair.Put(p.NATIfindex, pv); err != nil {
		return fmt.Errorf("natmap: nat_local_pair: put %d: %w", p.NATIfindex, err)
	}
	return nil
}

// DeletePair removes the nat_local_pair row of a NAT end, so nothing more is
// accepted from it. A missing row is not an error.
func (t LocalTables) DeletePair(natIfindex uint32) error {
	if err := t.Pair.Delete(natIfindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("natmap: nat_local_pair: delete %d: %w", natIfindex, err)
	}
	return nil
}

// DeleteReturn removes the nat_local_return row of a tenant SID, so replies
// for it are no longer sent into a pair. A missing row is not an error.
func (t LocalTables) DeleteReturn(sid netip.Addr) error {
	if err := t.Return.Delete(natprog.NatNatLocalReturnKey{TenantSid: sid.As16()}); err != nil &&
		!errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("natmap: nat_local_return: delete %s: %w", sid, err)
	}
	return nil
}

// All returns every pair the two maps hold, joined by tenant SID. A pair row
// without a return row is reported with a zero return side.
func (t LocalTables) All() ([]LocalPair, error) {
	returns := map[netip.Addr]natprog.NatNatLocalReturnValue{}
	it := t.Return.Iterate()
	var rk natprog.NatNatLocalReturnKey
	var rv natprog.NatNatLocalReturnValue
	for it.Next(&rk, &rv) {
		returns[netip.AddrFrom16(rk.TenantSid)] = rv
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("natmap: nat_local_return: iterate: %w", err)
	}
	var out []LocalPair
	it = t.Pair.Iterate()
	var ifx uint32
	var pv natprog.NatNatLocalPairValue
	for it.Next(&ifx, &pv) {
		sid := netip.AddrFrom16(pv.TenantSid)
		p := LocalPair{NATIfindex: ifx, TenantSID: sid}
		if r, ok := returns[sid]; ok {
			p.NATMAC = net.HardwareAddr(append([]byte(nil), r.Smac[:]...))
			p.TenantMAC = net.HardwareAddr(append([]byte(nil), r.Dmac[:]...))
		}
		out = append(out, p)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("natmap: nat_local_pair: iterate: %w", err)
	}
	return out, nil
}

// ReturnSIDs returns every tenant SID nat_local_return holds.
func (t LocalTables) ReturnSIDs() ([]netip.Addr, error) {
	var out []netip.Addr
	it := t.Return.Iterate()
	var rk natprog.NatNatLocalReturnKey
	var rv natprog.NatNatLocalReturnValue
	for it.Next(&rk, &rv) {
		out = append(out, netip.AddrFrom16(rk.TenantSid))
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("natmap: nat_local_return: iterate: %w", err)
	}
	return out, nil
}

// VLANEgress is a VLAN device a Local forward may leave through: its lower
// device and tag.
type VLANEgress struct {
	Ifindex      uint32
	LowerIfindex uint32
	VID          uint16
	// Proto is the tag's EtherType: 0x8100, or 0x88a8 for 802.1ad.
	Proto uint16
}

// VLANTable writes nat_vlan_egress.
type VLANTable struct {
	Table Table
}

// Put writes v.
func (t VLANTable) Put(v VLANEgress) error {
	if v.VID == 0 || v.VID > 4094 {
		return fmt.Errorf("natmap: nat_vlan_egress: VLAN ID %d out of range", v.VID)
	}
	value := natprog.NatNatVlanEgressValue{LowerIfindex: v.LowerIfindex, Vid: htons(v.VID), Proto: htons(v.Proto)}
	if err := t.Table.Put(v.Ifindex, value); err != nil {
		return fmt.Errorf("natmap: nat_vlan_egress: put %d: %w", v.Ifindex, err)
	}
	return nil
}

// Delete removes ifindex's row. A missing row is not an error.
func (t VLANTable) Delete(ifindex uint32) error {
	if err := t.Table.Delete(ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("natmap: nat_vlan_egress: delete %d: %w", ifindex, err)
	}
	return nil
}

// All returns every row.
func (t VLANTable) All() (map[uint32]VLANEgress, error) {
	out := map[uint32]VLANEgress{}
	it := t.Table.Iterate()
	var k uint32
	var v natprog.NatNatVlanEgressValue
	for it.Next(&k, &v) {
		out[k] = VLANEgress{Ifindex: k, LowerIfindex: v.LowerIfindex, VID: ntohs(v.Vid), Proto: ntohs(v.Proto)}
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("natmap: nat_vlan_egress: iterate: %w", err)
	}
	return out, nil
}

// LocalStatTotals reads nat_local_stats, summed across CPUs.
func LocalStatTotals(reader CounterReader) ([natprog.LocalStatCount]uint64, error) {
	var totals [natprog.LocalStatCount]uint64
	for i := range uint32(natprog.LocalStatCount) {
		var perCPU []uint64
		if err := reader.Lookup(i, &perCPU); err != nil {
			return totals, fmt.Errorf("natmap: nat_local_stats: lookup[%d]: %w", i, err)
		}
		for _, v := range perCPU {
			totals[i] += v
		}
	}
	return totals, nil
}

// htons and ntohs convert between host order and the network order the
// datapath stores a VLAN tag's fields in.
func htons(v uint16) uint16 { return v<<8 | v>>8 }
func ntohs(v uint16) uint16 { return v<<8 | v>>8 }
