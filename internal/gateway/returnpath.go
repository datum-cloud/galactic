// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"net/netip"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// KernelReturnPath keeps edge_return's VIP address set for a node whose
// datapath is turned off. Such a node load-balances nothing and advertises no
// VIP, but a backend node can still send it replies, and only edge_return lets
// them through: the kernel would judge them against connection tracking that
// never saw the request and drop every TCP one.
type KernelReturnPath struct {
	vipTable *edgemap.VIPTable
}

// NewKernelReturnPath wraps a loaded edge program's maps. Unlike
// NewKernelDatapath it needs no encapsulation source, since edge_return pushes
// no header.
func NewKernelReturnPath(objs *edgeprog.EdgedsrObjects) *KernelReturnPath {
	return &KernelReturnPath{vipTable: edgemap.NewVIPTable(
		edgemap.KernelTable{Map: objs.VipTable}, edgemap.KernelTable{Map: objs.VipStatsTable},
		edgemap.KernelTable{Map: objs.VipAddrTable}, edgemap.KernelTable{Map: objs.VipReturnStatsTable})}
}

// SyncReturnAddrs makes edge_return claim replies from exactly addrs, and
// removes every rule the node held before its datapath was turned off.
func (p *KernelReturnPath) SyncReturnAddrs(addrs []netip.Addr) error {
	return p.vipTable.ReplaceReturnAddrs(addrs)
}
