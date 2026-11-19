// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fabrictest is an in-memory fabric.Datapath for tests.
package fabrictest

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"sync"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
)

// Datapath is an in-memory fabric.Datapath. Lookup is a longest-prefix match
// over exact entries, as egress_route_table's is.
type Datapath struct {
	mu        sync.Mutex
	loadErr   error
	tables    map[string]uint32
	rows      map[uint32]map[netip.Prefix]egressroutemap.Row
	hops      map[netip.Prefix]hopResult
	returnErr map[string]error
	writes    int
	removes   int
}

type hopResult struct {
	hop egressroutemap.NextHop
	err error
}

// New returns an empty datapath.
func New() *Datapath {
	return &Datapath{
		tables:    map[string]uint32{},
		rows:      map[uint32]map[netip.Prefix]egressroutemap.Row{},
		hops:      map[netip.Prefix]hopResult{},
		returnErr: map[string]error{},
	}
}

// SetLoaded sets the error Loaded returns.
func (d *Datapath) SetLoaded(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loadErr = err
}

// SetTable gives vpc a host VRF on table, or removes it when table is 0.
func (d *Datapath) SetTable(vpc string, table uint32) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if table == 0 {
		delete(d.tables, vpc)
		return
	}
	d.tables[vpc] = table
}

// Reach makes every SID in locator resolve through link toward a neighbor
// with MAC dmac.
func (d *Datapath) Reach(locator netip.Prefix, link int, dmac string) {
	mac, err := net.ParseMAC(dmac)
	if err != nil {
		panic(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hops[locator] = hopResult{hop: egressroutemap.NextHop{
		LinkIndex: link, Gateway: net.IP(locator.Addr().AsSlice()), DMAC: mac,
		SMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, byte(link)},
	}}
}

// Unreach makes every SID in locator fail to resolve with err, which wraps
// ErrNoUplinkRoute or ErrNeighborUnresolved. A neighbor failure keeps the
// link and gateway.
func (d *Datapath) Unreach(locator netip.Prefix, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.hops[locator]
	r.err = err
	if errors.Is(err, egressroutemap.ErrNoUplinkRoute) {
		r.hop = egressroutemap.NextHop{}
	} else {
		r.hop.DMAC = nil
	}
	d.hops[locator] = r
}

// SetReturn sets the error ReturnPath returns for vpc.
func (d *Datapath) SetReturn(vpc string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.returnErr[vpc] = err
}

// Put writes an entry directly, as another writer would.
func (d *Datapath) Put(table uint32, prefix netip.Prefix, row egressroutemap.Row) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.rows[table] == nil {
		d.rows[table] = map[netip.Prefix]egressroutemap.Row{}
	}
	d.rows[table][prefix.Masked()] = row
}

// Entries returns table's exact entries.
func (d *Datapath) Entries(table uint32) map[netip.Prefix]egressroutemap.Row {
	d.mu.Lock()
	defer d.mu.Unlock()
	return maps.Clone(d.rows[table])
}

// Counts returns how many writes and removals ran.
func (d *Datapath) Counts() (writes, removes int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.writes, d.removes
}

// Loaded implements fabric.Datapath.
func (d *Datapath) Loaded() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.loadErr
}

// TableID implements fabric.Datapath.
func (d *Datapath) TableID(vpc string) (uint32, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.tables[vpc]
	return t, ok, nil
}

// Lookup implements fabric.Datapath.
func (d *Datapath) Lookup(table uint32, prefix netip.Prefix) (egressroutemap.Row, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var (
		best egressroutemap.Row
		bits = -1
	)
	for p, r := range d.rows[table] {
		if p.Bits() <= prefix.Bits() && p.Contains(prefix.Addr()) && p.Bits() > bits {
			best, bits = r, p.Bits()
		}
	}
	return best, bits >= 0, nil
}

// Write implements fabric.Datapath.
func (d *Datapath) Write(table uint32, prefix netip.Prefix, sid netip.Addr) error {
	hop, err := d.NextHop(sid)
	if err != nil && !errors.Is(err, egressroutemap.ErrNeighborUnresolved) {
		return err
	}
	if err != nil {
		return fmt.Errorf("solicit: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.rows[table] == nil {
		d.rows[table] = map[netip.Prefix]egressroutemap.Row{}
	}
	d.rows[table][prefix.Masked()] = egressroutemap.Row{
		SID: net.IP(sid.AsSlice()), LinkIndex: hop.LinkIndex, DMAC: hop.DMAC, SMAC: hop.SMAC,
	}
	d.writes++
	return nil
}

// Remove implements fabric.Datapath.
func (d *Datapath) Remove(table uint32, prefix netip.Prefix, sid netip.Addr) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.rows[table][prefix.Masked()]
	if !ok || r.PassThrough || r.Sentinel {
		return nil
	}
	if got, _ := netip.AddrFromSlice(r.SID); sid.IsValid() && got.Unmap() != sid {
		return nil
	}
	delete(d.rows[table], prefix.Masked())
	d.removes++
	return nil
}

// NextHop implements fabric.Datapath.
func (d *Datapath) NextHop(sid netip.Addr) (egressroutemap.NextHop, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for loc, r := range d.hops {
		if loc.Contains(sid) {
			return r.hop, r.err
		}
	}
	return egressroutemap.NextHop{}, fmt.Errorf("%w: no route to %s", egressroutemap.ErrNoUplinkRoute, sid)
}

// ReturnPath implements fabric.Datapath.
func (d *Datapath) ReturnPath(_ context.Context, vpc string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.returnErr[vpc]
}
