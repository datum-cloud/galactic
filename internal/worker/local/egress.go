// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
)

// A routed link's host end carries the node's egress datapath, as a tenant
// veth does: usid_service_egress and usid_egress on its tc ingress and
// tp_deliver on its tc egress, so the pod's traffic to a Fabric destination
// is encapsulated toward its SID by the egress_route_table entries of the
// VPC's table, and traffic to a Local destination passes on to the kernel.
// The egress programs check no source address, so the link's guard must
// decide every packet first: it runs at the head of the link's tcx ingress,
// which the kernel runs before every clsact filter. Local carries the egress
// datapath on the link only while the guard is first; otherwise the link
// keeps only its guard, its Local destinations stay reachable through the
// kernel, and its claim's Fabric destinations report
// ReasonRoutedLinkEgressUnavailable. The link is registered as an infra
// interface: the proxy's own egress is not subject to traffic policy, and
// each tenant's policy applies on the tenant's side.

// The guard and registration calls Local makes, replaceable in tests.
var (
	tcxGuardFn           = attach.TCXGuard
	ensureTCXGuardFn     = attach.EnsureTCXGuard
	registerHostLinkFn   = attachreg.RegisterHostLinkKind
	hostLinkRegisteredFn = attachreg.HostLinkRegistered
)

// ensureGuard puts the routed link r's guard in place on its host end *hl,
// keeping the link down while it has none, and reports whether the guard
// runs first on the link's tcx ingress, which the egress datapath needs. On
// a kernel without tcx the guard is Local's clsact filter. A guard that
// stays behind another program after one attempt to move it to the head is
// not moved again while that program stays first, so the link does not flap
// on every pass.
func (p *pass) ensureGuard(r routedWant, hl *netlink.Link) (bool, error) {
	idx := (*hl).Attrs().Index
	guard := p.objs.Programs.LinkGuard
	st, err := tcxGuardFn(guard, idx)
	if errors.Is(err, ebpf.ErrNotSupported) {
		p.res.egress[r.host] = fmt.Errorf("the kernel has no tcx, so the guard on %s cannot run before "+
			"the egress datapath: %w", r.host, err)
		return false, p.ensureClsactGuard(r, hl)
	}
	if err != nil {
		return false, fmt.Errorf("local: read the guard of %s: %w", r.host, err)
	}
	_, _, clsact, err := attach.LocalFilter(idx)
	if err != nil {
		return false, err
	}
	blocker := p.k.guardBlocker(idx)
	if st.Attached && len(st.Stale) == 0 && !clsact && (st.First || (blocker != 0 && blocker == st.Head)) {
		if !st.First {
			p.res.egress[r.host] = notFirst(r.host, st.Head)
		} else if blocker != 0 {
			p.k.setGuardBlocker(idx, 0)
		}
		return st.First, nil
	}
	if p.dry {
		return false, dirty("the guard of %s is not first on its tcx ingress", r.host)
	}
	// Moving an attached guard back to the head detaches it first, and a
	// link with no guard is unguarded: either way the link is down until
	// the guard is back.
	moving := st.Attached && !st.First && !slices.Contains(st.Stale, st.Head)
	if (moving || (!st.Guarded() && !clsact)) && (*hl).Attrs().Flags&net.FlagUp != 0 {
		if err := netlink.LinkSetDown(*hl); err != nil {
			return false, fmt.Errorf("local: set unguarded %s down: %w", r.host, err)
		}
		if *hl, err = netlink.LinkByName(r.host); err != nil {
			return false, err
		}
	}
	err = ensureTCXGuardFn(guard, r.host)
	switch {
	case err == nil:
		p.k.setGuardBlocker(idx, 0)
		return true, nil
	case errors.Is(err, ebpf.ErrNotSupported):
		p.res.egress[r.host] = fmt.Errorf("the kernel has no tcx, so the guard on %s cannot run before "+
			"the egress datapath: %w", r.host, err)
		return false, p.ensureClsactGuard(r, hl)
	case errors.Is(err, attach.ErrGuardNotFirst):
		after, qerr := tcxGuardFn(guard, idx)
		if qerr != nil {
			return false, fmt.Errorf("local: read the guard of %s: %w", r.host, qerr)
		}
		if !after.Attached {
			return false, fmt.Errorf("local: the guard of %s is not attached: %w", r.host, err)
		}
		p.k.setGuardBlocker(idx, after.Head)
		p.res.egress[r.host] = err
		return false, nil
	default:
		return false, fmt.Errorf("local: attach the guard to %s: %w", r.host, err)
	}
}

// notFirst is the error a routed link's egress reports while program head
// runs before its guard.
func notFirst(host string, head ebpf.ProgramID) error {
	return fmt.Errorf("%w on %s: program %d runs first", attach.ErrGuardNotFirst, host, head)
}

// ensureClsactGuard attaches the guard to the routed link r's host end *hl
// as Local's clsact filter, keeping the link down while it has none.
func (p *pass) ensureClsactGuard(r routedWant, hl *netlink.Link) error {
	guarded, err := p.k.filterCurrent((*hl).Attrs().Index, filterLinkGuard)
	if err != nil {
		return err
	}
	if !guarded && !p.dry && (*hl).Attrs().Flags&net.FlagUp != 0 {
		if err := netlink.LinkSetDown(*hl); err != nil {
			return fmt.Errorf("local: set unguarded %s down: %w", r.host, err)
		}
		if *hl, err = netlink.LinkByName(r.host); err != nil {
			return err
		}
	}
	return p.k.ensureFilter(*hl, filterLinkGuard, p.dry)
}

// ensureEgress registers the routed link r's host end hl with the egress
// datapath when want, and removes every row and program of it otherwise. A
// registration that fails is recorded for Read, and the link keeps no egress
// datapath.
func (p *pass) ensureEgress(r routedWant, hl netlink.Link, want bool) error {
	idx := uint32(hl.Attrs().Index)
	if want {
		ok, err := p.k.egressCurrent(p.table, idx, r.host)
		if err != nil || ok {
			return err
		}
		if p.dry {
			return dirty("routed link %s is not registered with the egress datapath", r.host)
		}
		err = p.k.registerEgress(p.table, idx, r.host)
		if err == nil {
			return nil
		}
		p.res.egress[r.host] = err
	}
	present, err := attachreg.HostLinkPresent(p.k.PinDir, idx, r.host)
	if err != nil || !present {
		return err
	}
	if p.dry {
		return dirty("routed link %s carries the egress datapath while its guard is not first", r.host)
	}
	if err := attachreg.DetachHostLink(p.k.PinDir, idx, r.host); err != nil {
		return fmt.Errorf("local: remove the egress datapath from %s: %w", r.host, err)
	}
	return nil
}

// egressCurrent reports whether the host end ifindex, named name, of a
// routed link in the VRF with routing table table is registered with the
// egress datapath, and this node's source SID is set as the egress datapath
// stamps it.
func (k *Kernel) egressCurrent(table, ifindex uint32, name string) (bool, error) {
	want, have, err := k.nodeSource()
	if err != nil {
		return false, err
	}
	if !have.IsValid() || (want.IsValid() && want != have) {
		return false, nil
	}
	return hostLinkRegisteredFn(k.PinDir, table, ifindex, name, tpmap.KindInfra)
}

// registerEgress sets this node's source SID and registers the routed link
// host end ifindex, named name, with the egress datapath as an infra
// interface.
func (k *Kernel) registerEgress(table, ifindex uint32, name string) error {
	if err := k.ensureNodeSource(); err != nil {
		return err
	}
	if err := registerHostLinkFn(k.PinDir, table, ifindex, name, netip.Addr{}, tpmap.KindInfra); err != nil {
		return fmt.Errorf("register %s with the egress datapath: %w", name, err)
	}
	return nil
}

// nodeSource returns the source SID this node's egress datapath stamps on
// what it encapsulates, derived from NodeLocator, and the one
// node_src_addr_table holds. Either is the invalid address when unknown.
func (k *Kernel) nodeSource() (want, have netip.Addr, err error) {
	t, closer, err := egressroutemap.OpenPinnedNodeSourceAddress(k.PinDir)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("local: open node_src_addr_table: %w", err)
	}
	defer func() { _ = closer.Close() }()
	cur, ok, err := t.Get()
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	if ok {
		have, _ = netip.AddrFromSlice(cur)
	}
	if k.NodeLocator == nil {
		return netip.Addr{}, have, nil
	}
	loc, err := k.NodeLocator()
	if err != nil {
		return netip.Addr{}, have, fmt.Errorf("local: read this node's SRv6 locator: %w", err)
	}
	if !loc.IsValid() {
		return netip.Addr{}, have, nil
	}
	want, err = nodeSIDBase(loc)
	return want, have, err
}

// ensureNodeSource writes this node's source SID into node_src_addr_table,
// as galactic-cni does, so a node with no tenant attachment can still
// encapsulate. It fails when the SID is unknown and the table holds none.
func (k *Kernel) ensureNodeSource() error {
	want, have, err := k.nodeSource()
	if err != nil {
		return err
	}
	if !want.IsValid() {
		if have.IsValid() {
			return nil
		}
		return errors.New("this node's SRv6 locator is unknown, so it has no source SID to encapsulate from")
	}
	if want == have {
		return nil
	}
	t, closer, err := egressroutemap.OpenPinnedNodeSourceAddress(k.PinDir)
	if err != nil {
		return fmt.Errorf("local: open node_src_addr_table: %w", err)
	}
	defer func() { _ = closer.Close() }()
	return t.Set(net.IP(want.AsSlice()))
}

// nodeSIDBase returns the End.DT46 SID base of the node whose locator, its
// Block and Node-ID, is loc: the value node_src_addr_table holds.
func nodeSIDBase(loc netip.Prefix) (netip.Addr, error) {
	block, err := uformat.Block(loc.Addr())
	if err != nil {
		return netip.Addr{}, err
	}
	nodeID, err := uformat.NodeID(loc.Addr())
	if err != nil {
		return netip.Addr{}, err
	}
	return uformat.Encode(uformat.Fields{Block: block, NodeID: nodeID, Function: uformat.FunctionEndDT46})
}

// guardBlocker returns the program that stayed ahead of the guard on
// ifindex after Local last tried to move the guard to the head, or 0.
func (k *Kernel) guardBlocker(ifindex int) ebpf.ProgramID {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.blockers[ifindex]
}

// setGuardBlocker records head as the program ahead of the guard on
// ifindex, and forgets it when head is 0.
func (k *Kernel) setGuardBlocker(ifindex int, head ebpf.ProgramID) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if head == 0 {
		delete(k.blockers, ifindex)
		return
	}
	if k.blockers == nil {
		k.blockers = map[int]ebpf.ProgramID{}
	}
	k.blockers[ifindex] = head
}

// egressBlock returns why the routed link r's host end l does not carry
// the egress datapath, and "" when it does. egressErr is the error the last
// pass recorded for it.
func (k *Kernel) egressBlock(r routedWant, l netlink.Link, table uint32, egressErr error) string {
	idx := l.Attrs().Index
	st, err := tcxGuardFn(k.objs.Programs.LinkGuard, idx)
	switch {
	case errors.Is(err, ebpf.ErrNotSupported):
		return "the kernel has no tcx, so the routed link's guard cannot run before the egress datapath"
	case err != nil:
		return "the routed link's guard cannot be read: " + err.Error()
	case !st.Attached:
		return "the routed link's guard is not on its tcx ingress"
	case !st.First:
		return notFirst(r.host, st.Head).Error()
	}
	ok, err := k.egressCurrent(table, uint32(idx), r.host)
	switch {
	case err != nil:
		return "the routed link's egress registration cannot be read: " + err.Error()
	case ok:
		return ""
	case egressErr != nil:
		return egressErr.Error()
	}
	return "the routed link is not registered with the egress datapath yet"
}
