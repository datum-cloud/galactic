// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/vishvananda/netlink"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/forwardgatemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/worker/module"
)

// Connector claims (D37). galactic-edge creates each Galactic Edge
// attachment's host link, stamps it with the attachment's ID
// (hostattach.LinkID), enslaves it to the VPC's VRF and writes its
// forwarding gate's link row, all before it requests the claim. The Local
// module registers the link with the uSID datapath (attachreg.RegisterHostLink)
// and keeps the VPC's PassThroughEdge entries in egress_route_table exactly
// the addresses and prefixes of the VPC's claimed edge links. It never
// creates or deletes an edge link, and never writes a forwarding gate: the
// gates stay with galactic-edge, under the edge gate scope.

// edgeLinkObs is one stamped edge host link of a VPC.
type edgeLinkObs struct {
	Name  string
	Index uint32
	// UID is the attachment UID the link's stamp names.
	UID string
	// Up is true when the link has carrier.
	Up bool
}

// edgeHost is the host access edge links need. Its methods run in the host
// network namespace and must not call the ownership fence.
type edgeHost interface {
	// Links returns the stamped edge host links of vpc.
	Links(vpc string) ([]edgeLinkObs, error)
	// GateAddr returns the address ifindex's forwarding gate link row
	// names, if it has one.
	GateAddr(ifindex uint32) (netip.Addr, bool, error)
	// Registered reports whether ifindex carries every row and program
	// Register writes, under the VRF with routing table table.
	Registered(table, ifindex uint32, name string, addr netip.Addr) (bool, error)
	// HasRows reports whether ifindex has an ifindex_vrf_table row.
	HasRows(ifindex uint32) (bool, error)
	// Register registers the link with the uSID datapath.
	Register(table, ifindex uint32, name string, addr netip.Addr) error
	// Unregister removes every row Register wrote for ifindex.
	Unregister(ifindex uint32) error
	// PassThrough returns every pass-through entry of table, true for one
	// PassThroughEdge owns. A wanted prefix another owner's entry already
	// passes to the kernel is left as it is (attachreg.SyncHostLinkRoutes).
	PassThrough(table uint32) (map[netip.Prefix]bool, error)
	// SyncPassThrough makes table's PassThroughEdge entries exactly want.
	SyncPassThrough(table uint32, want []netip.Prefix) error
}

// edgeOutcome is one connector claim's result.
type edgeOutcome struct {
	gen    uint64
	reason string
	msg    string
	// link is the claimed link, when the checks found it the claim's.
	link edgeLinkObs
	ok   bool
}

// edgePlan is the edge-link state of one VPC scope.
type edgePlan struct {
	table    uint32
	haveVRF  bool
	claims   map[module.ClaimKey]edgeOutcome
	register []edgeRegistration
	// stale are the stamped links of the VPC whose rows no claim keeps.
	stale []edgeLinkObs
	// passWant is every claimed link's address and prefix, sorted.
	passWant []netip.Prefix
	// passDirty is set when the VPC's PassThroughEdge entries differ from
	// passWant.
	passDirty bool
}

type edgeRegistration struct {
	link edgeLinkObs
	addr netip.Addr
}

// edgeClaims returns the connector claims of claims.
func edgeClaims(claims []module.Claim) []module.Claim {
	var out []module.Claim
	for _, c := range claims {
		if c.EdgeLink != nil {
			out = append(out, c)
		}
	}
	return out
}

// planEdge checks the scope's connector claims against the host. It writes
// nothing. A claim whose link is missing, or whose link is not its own,
// keeps no rows: its outcome says why.
func planEdge(h edgeHost, vpc string, table uint32, haveVRF bool, claims []module.Claim) (*edgePlan, error) {
	p := &edgePlan{table: table, haveVRF: haveVRF, claims: map[module.ClaimKey]edgeOutcome{}}
	edge := edgeClaims(claims)
	if !haveVRF {
		for _, c := range edge {
			p.claims[c.Key] = edgeOutcome{gen: c.Generation, reason: workerv1alpha1.ReasonHandoffInterfaceMissing,
				msg: "the VPC has no host VRF on this node yet"}
		}
		return p, nil
	}
	links, err := h.Links(vpc)
	if err != nil {
		return nil, err
	}
	byUID := map[string]edgeLinkObs{}
	byName := map[string]edgeLinkObs{}
	for _, l := range links {
		byUID[l.UID] = l
		byName[l.Name] = l
	}
	kept := map[uint32]bool{}
	pass := map[netip.Prefix]bool{}
	for _, c := range edge {
		o := edgeOutcome{gen: c.Generation}
		l, ok := byUID[c.Key.AttachmentUID]
		switch {
		case ok && l.Name == c.EdgeLink.Name:
		case byName[c.EdgeLink.Name].UID != "":
			// The named link is another attachment's: a claim replayed for
			// a link that was reused, or one naming the wrong link.
			o.reason, o.msg = workerv1alpha1.ReasonHandoffInterfaceNotOwned,
				fmt.Sprintf("link %s carries attachment %s's stamp", c.EdgeLink.Name, byName[c.EdgeLink.Name].UID)
			p.claims[c.Key] = o
			continue
		default:
			o.reason, o.msg = workerv1alpha1.ReasonHandoffInterfaceMissing,
				fmt.Sprintf("no host link %s carries the attachment's stamp in the VPC's VRF", c.EdgeLink.Name)
			p.claims[c.Key] = o
			continue
		}
		gate, gated, err := h.GateAddr(l.Index)
		if err != nil {
			return nil, err
		}
		switch {
		case !gated:
			// galactic-edge writes the gate's link row before it requests
			// the claim, so no forwarding program is attached to a link
			// that is not gated.
			o.reason, o.msg = workerv1alpha1.ReasonHandoffInterfaceMissing,
				fmt.Sprintf("link %s has no forwarding gate yet", l.Name)
			p.claims[c.Key] = o
			continue
		case gate != c.EdgeLink.Address:
			o.reason, o.msg = workerv1alpha1.ReasonHandoffInterfaceNotOwned,
				fmt.Sprintf("link %s's forwarding gate names %s, not the attachment's address %s",
					l.Name, gate, c.EdgeLink.Address)
			p.claims[c.Key] = o
			continue
		}
		o.link, o.ok = l, true
		p.claims[c.Key] = o
		kept[l.Index] = true
		reg, err := h.Registered(table, l.Index, l.Name, c.EdgeLink.Address)
		if err != nil {
			return nil, err
		}
		if !reg {
			p.register = append(p.register, edgeRegistration{link: l, addr: c.EdgeLink.Address})
		}
		pass[netip.PrefixFrom(c.EdgeLink.Address, c.EdgeLink.Address.BitLen())] = true
		for _, pfx := range c.EdgeLink.Prefixes {
			pass[pfx.Masked()] = true
		}
	}
	for _, l := range links {
		if kept[l.Index] {
			continue
		}
		has, err := h.HasRows(l.Index)
		if err != nil {
			return nil, err
		}
		if has {
			p.stale = append(p.stale, l)
		}
	}
	p.passWant = slices.SortedFunc(maps.Keys(pass), func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	have, err := h.PassThrough(table)
	if err != nil {
		return nil, err
	}
	for pfx := range pass {
		if _, ok := have[pfx]; !ok {
			p.passDirty = true
		}
	}
	for pfx, edge := range have {
		if edge && !pass[pfx] {
			p.passDirty = true
		}
	}
	return p, nil
}

// dirty reports whether applying p would write anything.
func (p *edgePlan) dirty() bool {
	return p.haveVRF && (len(p.register) > 0 || len(p.stale) > 0 || p.passDirty)
}

// applyEdge writes p. Stale links are unregistered first, so a link's
// ifindex that a new link reuses never keeps an earlier link's rows, then
// claimed links are registered, then the pass-through entries are synced.
// It runs inside the scope's fence commit.
func applyEdge(h edgeHost, p *edgePlan) error {
	if !p.haveVRF {
		return nil
	}
	var errs []error
	for _, l := range p.stale {
		if err := h.Unregister(l.Index); err != nil {
			errs = append(errs, fmt.Errorf("local: unregister edge link %s: %w", l.Name, err))
		}
	}
	for _, r := range p.register {
		if err := h.Register(p.table, r.link.Index, r.link.Name, r.addr); err != nil {
			errs = append(errs, fmt.Errorf("local: register edge link %s: %w", r.link.Name, err))
		}
	}
	if p.passDirty {
		if err := h.SyncPassThrough(p.table, p.passWant); err != nil {
			errs = append(errs, fmt.Errorf("local: sync edge pass-through entries: %w", err))
		}
	}
	return errors.Join(errs...)
}

// readEdge reports each connector claim's one destination from the host as
// it stands, and, under leftoverID, every stamped link of a claim that is no
// longer desired whose rows are still there, so Worker keeps that claim
// withdrawing until they are gone.
func readEdge(h edgeHost, node, vpc string, claims []module.Claim, state module.State) error {
	edge := edgeClaims(claims)
	table, _, haveVRF, err := tableID(vpc)
	if err != nil {
		return err
	}
	p, err := planEdge(h, vpc, table, haveVRF, edge)
	if err != nil {
		return err
	}
	for _, c := range edge {
		o := p.claims[c.Key]
		ck := newCheck(c.Generation)
		switch {
		case !o.ok:
			ck.unprogrammed(o.reason, o.msg)
		case slices.ContainsFunc(p.register, func(r edgeRegistration) bool { return r.link.Index == o.link.Index }):
			ck.unprogrammed(workerv1alpha1.ReasonPending, "the edge link is not registered yet")
		case p.passDirty:
			ck.unprogrammed(workerv1alpha1.ReasonPending, "the VPC's edge pass-through entries are not in place yet")
		case !o.link.Up:
			// galactic-edge brings the link up once the claim is
			// Programmed.
			ck.notReady(true, true, workerv1alpha1.ReasonHandoffInterfaceMissing,
				fmt.Sprintf("link %s has no carrier", o.link.Name))
		}
		if state[c.Key] == nil {
			state[c.Key] = map[string]module.DestinationState{}
		}
		for _, d := range c.Destinations {
			state[c.Key][d.ID] = ck.done()
		}
	}
	for _, l := range p.stale {
		k := module.ClaimKey{Node: node, VPC: vpc, AttachmentUID: l.UID}
		if state[k] == nil {
			state[k] = map[string]module.DestinationState{}
		}
		state[k][leftoverID] = module.DestinationState{Programmed: true,
			Reason: workerv1alpha1.ReasonReleased, Message: "edge link " + l.Name + " still registered"}
	}
	return nil
}

// tableID is TableID, replaceable in tests.
var tableID = TableID

// pinnedEdgeHost is edgeHost on the node's pinned uSID maps and its links.
type pinnedEdgeHost struct{ pinDir string }

var _ edgeHost = pinnedEdgeHost{}

// Links implements edgeHost.
func (h pinnedEdgeHost) Links(vpc string) ([]edgeLinkObs, error) {
	all, err := hostattach.ListHost()
	if err != nil {
		return nil, fmt.Errorf("local: list edge host links: %w", err)
	}
	var out []edgeLinkObs
	for _, a := range all {
		v, uid, ok := hostattach.ParseLinkID(a.ID)
		if !ok || v != vpc || a.HostIndex <= 0 {
			continue
		}
		l, err := netlink.LinkByIndex(a.HostIndex)
		if err != nil {
			var nf netlink.LinkNotFoundError
			if errors.As(err, &nf) {
				continue
			}
			return nil, fmt.Errorf("local: read edge link %s: %w", a.HostLink, err)
		}
		out = append(out, edgeLinkObs{Name: l.Attrs().Name, Index: uint32(a.HostIndex), UID: uid, Up: lowerUp(l)})
	}
	return out, nil
}

// GateAddr implements edgeHost.
func (h pinnedEdgeHost) GateAddr(ifindex uint32) (netip.Addr, bool, error) {
	gates, err := forwardgatemap.OpenPinned(h.pinDir)
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("local: open forwarding gates: %w", err)
	}
	defer func() { _ = gates.Close() }()
	return gates.Link(ifindex)
}

// Registered implements edgeHost.
func (h pinnedEdgeHost) Registered(table, ifindex uint32, name string, addr netip.Addr) (bool, error) {
	has, err := h.HasRows(ifindex)
	if err != nil || !has {
		return false, err
	}
	kinds, closer, err := ifindexvrfmap.OpenPinnedEgressKind(h.pinDir)
	if err != nil {
		return false, err
	}
	_, hasKind, err := kinds.Get(ifindex)
	_ = closer.Close()
	if err != nil || !hasKind {
		return false, err
	}
	if ok, err := attach.HasDeliver(name); err != nil || !ok {
		return false, err
	}
	return attach.HasEgressChain(name)
}

// HasRows implements edgeHost.
func (h pinnedEdgeHost) HasRows(ifindex uint32) (bool, error) {
	t, closer, err := ifindexvrfmap.OpenPinned(h.pinDir)
	if err != nil {
		return false, fmt.Errorf("local: open ifindex_vrf_table: %w", err)
	}
	defer func() { _ = closer.Close() }()
	_, ok, err := t.Get(ifindex)
	return ok, err
}

// Register implements edgeHost.
func (h pinnedEdgeHost) Register(table, ifindex uint32, name string, addr netip.Addr) error {
	return attachreg.RegisterHostLink(h.pinDir, table, ifindex, name, addr)
}

// Unregister implements edgeHost.
func (h pinnedEdgeHost) Unregister(ifindex uint32) error {
	return attachreg.UnregisterHostLink(h.pinDir, ifindex)
}

// PassThrough implements edgeHost.
func (h pinnedEdgeHost) PassThrough(table uint32) (map[netip.Prefix]bool, error) {
	t, closer, err := egressroutemap.OpenPinnedEgressRouteTable(h.pinDir)
	if err != nil {
		return nil, fmt.Errorf("local: open egress_route_table: %w", err)
	}
	defer func() { _ = closer.Close() }()
	entries, err := t.Entries(table)
	if err != nil {
		return nil, err
	}
	out := map[netip.Prefix]bool{}
	for p, e := range entries {
		if e.PassThrough {
			out[p] = e.Owner == egressroutemap.PassThroughEdge
		}
	}
	return out, nil
}

// SyncPassThrough implements edgeHost.
func (h pinnedEdgeHost) SyncPassThrough(table uint32, want []netip.Prefix) error {
	return attachreg.SyncHostLinkRoutes(h.pinDir, table, want)
}
