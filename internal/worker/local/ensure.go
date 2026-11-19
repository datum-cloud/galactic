// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/localprog"
)

// applied is what ensure programmed, for Read.
type applied struct {
	// errs are the per-link errors ensure met, by the Local or tenant link
	// name; they do not fail the commit.
	errs map[string]error
}

// fix repairs the host with do when it is wrong. A dry run reports errDirty
// instead of writing.
func fix(dry, wrong bool, do func() error) error {
	switch {
	case !wrong:
		return nil
	case dry:
		return errDirty
	}
	return do()
}

// putRow writes want under key in mp unless it is already there.
func putRow[K, V comparable](mp *ebpf.Map, key K, want V, dry bool, what string) error {
	var cur V
	err := mp.Lookup(key, &cur)
	return fix(dry, err != nil || cur != want, func() error {
		if err := mp.Put(key, want); err != nil {
			return fmt.Errorf("local: write %s: %w", what, err)
		}
		return nil
	})
}

// pass is one run of ensure over a VPC scope.
type pass struct {
	k      *Kernel
	m      *model
	dry    bool
	objs   *localprog.Objects
	routes *egressroutemap.EgressRouteTable
	h      *host
	table  uint32
	vrfIdx int
	pairs  map[string]pair
	res    applied
}

// ensure makes the Local state of m's VPC match m: it creates and fixes what
// m wants and removes every Local link, row and filter of the VPC m does not
// want. A dry run writes nothing and returns errDirty at the first change.
// An error on one routed link, such as its pod having gone, is recorded in
// the result and does not stop the rest.
func (k *Kernel) ensure(m *model, dry bool) (applied, error) {
	p := &pass{k: k, m: m, dry: dry, pairs: map[string]pair{}, res: applied{errs: map[string]error{}}}
	var (
		err     error
		haveVRF bool
	)
	if p.objs, p.routes, err = k.open(); err != nil {
		return p.res, err
	}
	if p.table, p.vrfIdx, haveVRF, err = TableID(m.vpc); err != nil {
		return p.res, err
	}
	if p.h, err = readHost(); err != nil {
		return p.res, err
	}
	if !haveVRF {
		// Nothing to program into; whatever is left of the VPC goes.
		p.m, p.table, p.vrfIdx = &model{vpc: m.vpc}, 0, 0
		return p.res, p.removeStale()
	}
	if err := p.ensurePairs(); err != nil {
		return p.res, err
	}
	if err := p.ensureRoutedLinks(); err != nil {
		return p.res, err
	}
	if !dry && (len(m.pairs) > 0 || len(m.routed) > 0) {
		// The links just created must count as present below.
		if p.h, err = readHost(); err != nil {
			return p.res, err
		}
	}
	for _, name := range sortedKeys(m.tenants) {
		if err := p.ensureTenant(m.tenants[name]); err != nil {
			return p.res, err
		}
	}
	return p.res, p.removeStale()
}

// ensurePairs makes each pair exist with its row and filter.
func (p *pass) ensurePairs() error {
	for _, name := range sortedKeys(p.m.pairs) {
		got, err := p.k.ensurePair(p.h, p.m.pairs[name], p.vrfIdx, p.dry)
		if err != nil {
			return err
		}
		p.pairs[name] = got
		if err := putRow(p.objs.Maps.Pair, uint32(got.tenant.Attrs().Index),
			localprog.LocalLtPairValue{TableId: p.table}, p.dry, "pair row of "+name); err != nil {
			return err
		}
		if err := p.k.ensureFilter(got.tenant, filterPairRx, p.dry); err != nil {
			return err
		}
	}
	return nil
}

// ensureRoutedLinks makes each routed link exist. A link whose pod cannot be
// reached is recorded, not fatal.
func (p *pass) ensureRoutedLinks() error {
	if len(p.m.routed) == 0 {
		return nil
	}
	entries, err := p.routes.Entries(p.table)
	if err != nil {
		return err
	}
	for _, name := range sortedKeys(p.m.routed) {
		err := p.ensureRouted(p.m.routed[name], entries)
		switch {
		case err == nil:
		case errors.Is(err, ErrPodNotFound) || errors.Is(err, ErrPodHostNetwork):
			p.res.errs[name] = err
		default:
			return err
		}
	}
	return nil
}

// ensureTenant programs one tenant interface a claim delivers to: its link
// row, its TAP row for local.tap, its guest rows for local.veth_pair, and
// local_link_rx.
func (p *pass) ensureTenant(t *tenantWant) error {
	l := p.h.byName[t.name]
	if l == nil || l.Attrs().MasterIndex != p.vrfIdx {
		// Not attached yet, or being replaced; a link event requeues.
		return nil
	}
	idx := uint32(l.Attrs().Index)
	lv := localprog.LocalLtLinkValue{TableId: p.table}
	if pr, ok := p.pairs[t.pair]; ok {
		lv.PairIfindex = uint32(pr.tenant.Attrs().Index)
		copy(lv.PairSmac[:], pr.tenant.Attrs().HardwareAddr)
		copy(lv.PairDmac[:], pr.nat.Attrs().HardwareAddr)
	}
	if err := putRow(p.objs.Maps.Link, idx, lv, p.dry, "link row of "+t.name); err != nil {
		return err
	}
	if t.tap {
		tv := localprog.LocalLtTapValue{TableId: p.table}
		if t.nh.IsValid() {
			tv.Nh = t.nh.As16()
		}
		if err := putRow(p.objs.Maps.Tap, idx, tv, p.dry, "TAP row of "+t.name); err != nil {
			return err
		}
	}
	if t.pair != "" {
		for _, a := range t.guests {
			if err := putRow(p.objs.Maps.Guest, localprog.LocalLtGuestKey{TableId: p.table, Addr: a.As16()},
				localprog.LocalLtGuestValue{LinkIfindex: idx}, p.dry, "guest row "+a.String()); err != nil {
				return err
			}
		}
	}
	return p.k.ensureFilter(l, filterLinkRx, p.dry)
}

// removeStale removes the Local state of the VPC that the pass's model does
// not want: its Local links, the Local filters and rows of its tenant
// interfaces, its guest rows and pass-through entries, and every Local row
// whose interface is gone.
func (p *pass) removeStale() error {
	if err := p.removeLinks(); err != nil {
		return err
	}
	wanted, err := p.removeFilters()
	if err != nil {
		return err
	}
	if err := p.removeRows(wanted); err != nil {
		return err
	}
	if err := p.removeGuests(); err != nil {
		return err
	}
	return p.removePassThrough()
}

// wantsLink reports whether name is a Local link the model wants.
func (p *pass) wantsLink(name string) bool {
	if _, ok := p.m.pairs[name]; ok {
		return true
	}
	if _, ok := p.m.routed[name]; ok {
		return true
	}
	pr, ok := p.m.pairs[pairTenantOf(name)]
	return ok && pr.nat == name
}

// removeLinks deletes the VPC's Local links the model does not want.
func (p *pass) removeLinks() error {
	for name, l := range p.h.localLinks(p.m.vpc) {
		if p.wantsLink(name) {
			continue
		}
		if err := fix(p.dry, true, func() error {
			if err := netlink.LinkDel(l); err != nil && !errors.Is(err, unix.ENODEV) {
				return fmt.Errorf("local: delete %s: %w", name, err)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// removeFilters detaches the Local filter from every interface of the VPC's
// VRF the model does not want, and returns the ifindexes it does want.
func (p *pass) removeFilters() (map[int]bool, error) {
	wanted := map[int]bool{}
	for _, l := range p.h.enslaved(p.vrfIdx) {
		name := l.Attrs().Name
		_, tenant := p.m.tenants[name]
		if tenant || p.wantsLink(name) {
			wanted[l.Attrs().Index] = true
			continue
		}
		fname, _, ok, err := attach.LocalFilter(l.Attrs().Index)
		if err != nil {
			return nil, err
		}
		if err := fix(p.dry, ok, func() error { return attach.DetachLocal(name) }); err != nil {
			return nil, fmt.Errorf("local: detach %s from %s: %w", fname, name, err)
		}
	}
	return wanted, nil
}

// removeRows deletes the Local rows of interfaces that are gone, or are in
// the VPC's VRF and wanted by nothing, and the TAP rows of tenants no
// local.tap claim names.
func (p *pass) removeRows(wanted map[int]bool) error {
	for _, name := range sortedKeys(p.m.tenants) {
		l := p.h.byName[name]
		if p.m.tenants[name].tap || l == nil || l.Attrs().MasterIndex != p.vrfIdx {
			continue
		}
		if err := deleteRow(p.objs.Maps.Tap, uint32(l.Attrs().Index), p.dry); err != nil {
			return err
		}
	}
	stale := func(idx uint32) bool {
		l := p.h.byIdx[int(idx)]
		if l == nil {
			return true
		}
		return p.vrfIdx != 0 && l.Attrs().MasterIndex == p.vrfIdx && !wanted[int(idx)]
	}
	for _, mp := range []*ebpf.Map{p.objs.Maps.Tap, p.objs.Maps.Link, p.objs.Maps.Pair, p.objs.Maps.Guard} {
		keys, err := u32Keys(mp)
		if err != nil {
			return err
		}
		for _, idx := range keys {
			if !stale(idx) {
				continue
			}
			if err := deleteRow(mp, idx, p.dry); err != nil {
				return err
			}
		}
	}
	return nil
}

// removeGuests deletes the VPC's guest rows the model does not want, and
// every guest row whose interface is gone.
func (p *pass) removeGuests() error {
	want := map[netip.Addr]bool{}
	for _, t := range p.m.tenants {
		if t.pair == "" {
			continue
		}
		for _, a := range t.guests {
			want[a] = true
		}
	}
	var (
		key   localprog.LocalLtGuestKey
		val   localprog.LocalLtGuestValue
		stale []localprog.LocalLtGuestKey
	)
	it := p.objs.Maps.Guest.Iterate()
	for it.Next(&key, &val) {
		mine := p.table != 0 && key.TableId == p.table && !want[netip.AddrFrom16(key.Addr)]
		if mine || p.h.byIdx[int(val.LinkIfindex)] == nil {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("local: read guest rows: %w", err)
	}
	for _, key := range stale {
		if err := fix(p.dry, true, func() error { return ignoreMissing(p.objs.Maps.Guest.Delete(key)) }); err != nil {
			return err
		}
	}
	return nil
}

// removePassThrough deletes the VPC's Local pass-through entries no routed
// link wants.
func (p *pass) removePassThrough() error {
	if p.table == 0 {
		return nil
	}
	want := map[netip.Prefix]bool{}
	for _, r := range p.m.routed {
		for _, a := range r.addrs {
			want[netip.PrefixFrom(a, 128)] = true
		}
	}
	entries, err := p.routes.Entries(p.table)
	if err != nil {
		return err
	}
	for prefix, e := range entries {
		if !e.PassThrough || e.Owner != egressroutemap.PassThroughLocal || want[prefix] {
			continue
		}
		if err := fix(p.dry, true, func() error {
			_, err := p.routes.UnregisterPassThroughAs(p.table, ipnet(prefix), egressroutemap.PassThroughLocal)
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}
