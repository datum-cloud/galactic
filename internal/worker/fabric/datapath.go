// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabric

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/nodelocator"
	"go.datum.net/galactic/internal/nodevpc"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// Datapath is the host state the Fabric module reads and writes.
type Datapath interface {
	// Loaded returns nil when the pinned uSID maps are open.
	Loaded() error
	// TableID returns vpc's host VRF table, and false when the VRF does not
	// exist.
	TableID(vpc string) (uint32, bool, error)
	// Lookup returns the egress_route_table entry a packet to prefix in
	// table matches: the longest entry no longer than prefix.
	Lookup(table uint32, prefix netip.Prefix) (egressroutemap.Row, bool, error)
	// Write installs or replaces the entry for prefix in table,
	// encapsulating toward sid, resolving and soliciting its next hop.
	Write(table uint32, prefix netip.Prefix, sid netip.Addr) error
	// Remove deletes prefix's own entry in table when it encapsulates toward
	// sid, or toward any SID when sid is invalid. It keeps a pass-through or
	// shard group entry.
	Remove(table uint32, prefix netip.Prefix, sid netip.Addr) error
	// NextHop resolves sid's underlay next hop without soliciting it. Its
	// error wraps egressroutemap.ErrNoUplinkRoute or
	// egressroutemap.ErrNeighborUnresolved.
	NextHop(sid netip.Addr) (egressroutemap.NextHop, error)
	// ReturnPath returns nil when this node decapsulates vpc's SID into
	// vpc's table: its locator is in locator_table, and its BGPVRFInstance
	// and vrf_table row for vpc are in place.
	ReturnPath(ctx context.Context, vpc string) error
}

// Kernel is the Datapath of the calling process's network namespace, which
// must be the host's.
type Kernel struct {
	// PinDir is the bpffs directory of the pinned uSID maps.
	PinDir string
	// K8s reads BGPRouters and BGPVRFInstances.
	K8s client.Client
	// Namespace holds the node's BGPRouter and BGPVRFInstances.
	Namespace string
	// Node is this node.
	Node string

	mu       sync.Mutex
	table    *egressroutemap.EgressRouteTable
	closer   io.Closer
	registry *usidmap.Registry
	regClose io.Closer
}

var _ Datapath = (*Kernel)(nil)

// open returns the pinned egress_route_table and uSID registry, opening them
// on first use and after a failure.
func (k *Kernel) open() (*egressroutemap.EgressRouteTable, *usidmap.Registry, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.table == nil {
		t, c, err := egressroutemap.OpenPinnedEgressRouteTable(k.PinDir)
		if err != nil {
			return nil, nil, err
		}
		k.table, k.closer = t, c
	}
	if k.registry == nil {
		r, c, err := usidmap.OpenPinnedRegistry(k.PinDir)
		if err != nil {
			return nil, nil, err
		}
		k.registry, k.regClose = r, c
	}
	return k.table, k.registry, nil
}

// Close releases the maps this process opened.
func (k *Kernel) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	var errs []error
	if k.closer != nil {
		errs = append(errs, k.closer.Close())
	}
	if k.regClose != nil {
		errs = append(errs, k.regClose.Close())
	}
	k.table, k.closer, k.registry, k.regClose = nil, nil, nil, nil
	return errors.Join(errs...)
}

// Loaded implements Datapath.
func (k *Kernel) Loaded() error {
	_, _, err := k.open()
	return err
}

// TableID implements Datapath.
func (k *Kernel) TableID(vpc string) (uint32, bool, error) {
	id, err := vrf.TableID(vpc)
	switch {
	case errors.Is(err, vrf.ErrNotFound):
		return 0, false, nil
	case err != nil:
		return 0, false, err
	}
	return id, true, nil
}

// Lookup implements Datapath.
func (k *Kernel) Lookup(table uint32, prefix netip.Prefix) (egressroutemap.Row, bool, error) {
	t, _, err := k.open()
	if err != nil {
		return egressroutemap.Row{}, false, err
	}
	return t.LookupRow(table, ipNet(prefix))
}

// Write implements Datapath.
func (k *Kernel) Write(table uint32, prefix netip.Prefix, sid netip.Addr) error {
	t, _, err := k.open()
	if err != nil {
		return err
	}
	return t.Register(table, ipNet(prefix), net.IP(sid.AsSlice()))
}

// Remove implements Datapath.
func (k *Kernel) Remove(table uint32, prefix netip.Prefix, sid netip.Addr) error {
	t, _, err := k.open()
	if err != nil {
		return err
	}
	var want net.IP
	if sid.IsValid() {
		want = net.IP(sid.AsSlice())
	}
	return t.UnregisterIfSID(table, ipNet(prefix), want)
}

// NextHop implements Datapath.
func (k *Kernel) NextHop(sid netip.Addr) (egressroutemap.NextHop, error) {
	return egressroutemap.ResolveNextHop(net.IP(sid.AsSlice()))
}

// ReturnPath implements Datapath.
func (k *Kernel) ReturnPath(ctx context.Context, vpc string) error {
	_, reg, err := k.open()
	if err != nil {
		return err
	}
	own, err := nodelocator.Prefix(ctx, k.K8s, k.Namespace, k.Node)
	if err != nil {
		return err
	}
	if !own.IsValid() {
		return errors.New("this node has no SRv6 locator yet")
	}
	block, err := uformat.Block(own.Addr())
	if err != nil {
		return err
	}
	nodeID, err := uformat.NodeID(own.Addr())
	if err != nil {
		return err
	}
	if _, ok, err := reg.Locator.Get(block, nodeID); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("locator_table has no row for this node's locator %s", own)
	}
	cfg := nodevpc.Config{K8s: k.K8s, Namespace: k.Namespace, Node: k.Node, PinDir: k.PinDir}
	ok, err := nodevpc.InPlace(ctx, cfg, vpc)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("this node's BGPVRFInstance or vrf_table row for the VPC is not in place")
	}
	return nil
}

// ipNet converts a prefix to the net.IPNet egressroutemap takes, in the
// address family of its address.
func ipNet(p netip.Prefix) *net.IPNet {
	addr := p.Addr().Unmap()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(p.Bits(), bits)}
}
