// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/localprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
	"go.datum.net/galactic/internal/worker/module"
)

// leftoverID is the destination ID under which Read reports the Local links
// of a claim that is no longer desired, so Worker keeps the claim as
// withdrawing until they are gone.
const leftoverID = "local/handoff"

// readResult is one Read of a scope.
type readResult struct {
	state    module.State
	handoffs map[module.ClaimKey][]module.HandoffInterface
	// failedNeighbors is set when a destination's neighbor failed, which a
	// neighbor event clears.
	failedNeighbors bool
}

// check is one destination's evaluation, filled in order; the first failure
// of each of programmed, forward and return names the reason.
type check struct {
	st     module.DestinationState
	failed bool
	fwd    bool
	ret    bool
}

func newCheck(gen uint64) *check {
	return &check{st: module.DestinationState{Generation: gen, Programmed: true}, fwd: true, ret: true}
}

// unprogrammed records a failure that leaves the destination unprogrammed.
func (c *check) unprogrammed(reason, msg string) {
	if c.failed {
		return
	}
	c.failed = true
	c.st.Programmed, c.fwd, c.ret = false, false, false
	c.st.Reason, c.st.Message = reason, msg
}

// notReady records an observed failure of the forward path, the return path
// or both.
func (c *check) notReady(fwd, ret bool, reason, msg string) {
	if c.failed {
		return
	}
	if fwd {
		c.fwd = false
	}
	if ret {
		c.ret = false
	}
	if c.st.Reason == "" {
		c.st.Reason, c.st.Message = reason, msg
	}
}

func (c *check) done() module.DestinationState {
	c.st.ForwardReady, c.st.ReturnReady = c.fwd && c.st.Programmed, c.ret && c.st.Programmed
	c.st.Ready = c.st.ForwardReady && c.st.ReturnReady
	if c.st.Ready {
		c.st.Reason, c.st.Message = "", ""
	}
	return c.st
}

func lowerUp(l netlink.Link) bool { return l.Attrs().RawFlags&unix.IFF_LOWER_UP != 0 }

// read reports every Local destination of claims, the claims of vpc m was
// computed from, and the handoff interfaces of each. errs are the per-link
// errors the last ensure recorded.
func (k *Kernel) read(vpc, node string, claims []module.Claim, m *model, errs map[string]error) (readResult, error) {
	out := readResult{state: module.State{}, handoffs: map[module.ClaimKey][]module.HandoffInterface{}}
	fail := func(reason, msg string) readResult {
		for _, c := range claims {
			st := map[string]module.DestinationState{}
			for _, d := range c.Destinations {
				st[d.ID] = module.DestinationState{Generation: c.Generation, Reason: reason, Message: msg}
			}
			out.state[c.Key] = st
		}
		return out
	}
	objs, _, err := k.open()
	if err != nil {
		return fail(workerv1alpha1.ReasonDatapathNotLoaded, err.Error()), nil
	}
	_, vrfIdx, haveVRF, err := TableID(vpc)
	if err != nil {
		return out, err
	}
	h, err := readHost()
	if err != nil {
		return out, err
	}
	desiredKeys := map[module.ClaimKey]bool{}
	for _, c := range claims {
		desiredKeys[c.Key] = true
	}
	for _, l := range h.localLinks(vpc) {
		v, uid, ok := parseAlias(l.Attrs().Alias)
		if !ok {
			continue
		}
		key := module.ClaimKey{Node: node, VPC: v, AttachmentUID: uid}
		if !desiredKeys[key] {
			out.state[key] = map[string]module.DestinationState{leftoverID: {}}
		}
	}
	if !haveVRF {
		r := fail(workerv1alpha1.ReasonPending, "the VPC has no host VRF yet")
		for k, v := range out.state {
			r.state[k] = v
		}
		return r, nil
	}

	var rs []receiver
	if m.tap {
		if rs, err = k.receiverDevices(h); err != nil {
			return out, err
		}
	}

	for _, c := range claims {
		states := map[string]module.DestinationState{}
		// handoffCheck applies the checks of the claim's own handoff to a
		// destination's check.
		var handoffCheck func(ck *check, l netlink.Link)

		switch c.Handoff {
		case workerv1alpha1.Handoff_HANDOFF_TAP:
			handoffCheck = k.tapCheck(rs)
		case workerv1alpha1.Handoff_HANDOFF_VETH_PAIR:
			handoffCheck = k.pairCheck(h, m, c, vrfIdx, objs, &out)
		case workerv1alpha1.Handoff_HANDOFF_ROUTED_LINK, workerv1alpha1.Handoff_HANDOFF_SOCKET:
			handoffCheck = k.routedCheck(h, m, c, vrfIdx, objs, errs, &out)
		default:
			handoffCheck = func(ck *check, _ netlink.Link) {
				ck.unprogrammed(workerv1alpha1.ReasonHookUnsupported, "the handoff kind has no Local mechanism")
			}
		}

		for _, d := range c.Destinations {
			ck := newCheck(c.Generation)
			if other, ok := m.collisions[c.Key]; ok {
				ck.unprogrammed(workerv1alpha1.ReasonProgrammingFailed,
					"the claim's handoff links would take the names of claim "+other.String()+"'s")
				states[d.ID] = ck.done()
				continue
			}
			l := k.destinationCheck(ck, h, vrfIdx, c, d, objs, &out)
			handoffCheck(ck, l)
			states[d.ID] = ck.done()
		}
		out.state[c.Key] = states
	}
	return out, nil
}

// destinationCheck checks what every Local destination needs: its interface
// in the VPC's VRF with carrier and galactic-cni's chain, Local's rows and
// filter on it, and no failed neighbor. It returns the interface, or nil.
func (k *Kernel) destinationCheck(ck *check, h *host, vrfIdx int, c module.Claim, d module.Destination,
	objs *localprog.Objects, out *readResult) netlink.Link {
	if d.HostInterface == "" {
		ck.unprogrammed(workerv1alpha1.ReasonHandoffInterfaceMissing, "the destination's attachment is not attached yet")
		return nil
	}
	l := h.byName[d.HostInterface]
	if l == nil || l.Attrs().MasterIndex != vrfIdx {
		ck.unprogrammed(workerv1alpha1.ReasonHandoffInterfaceMissing,
			fmt.Sprintf("interface %s is not in the VPC's VRF", d.HostInterface))
		return nil
	}
	if c.Handoff == workerv1alpha1.Handoff_HANDOFF_TAP && l.Type() != linkTunTap {
		ck.unprogrammed(workerv1alpha1.ReasonHandoffInterfaceMissing,
			fmt.Sprintf("interface %s is a %s, not a TAP", d.HostInterface, l.Type()))
		return nil
	}
	idx := uint32(l.Attrs().Index)
	if c.Handoff == workerv1alpha1.Handoff_HANDOFF_TAP || c.Handoff == workerv1alpha1.Handoff_HANDOFF_VETH_PAIR {
		var lv localprog.LocalLtLinkValue
		if err := objs.Maps.Link.Lookup(idx, &lv); err != nil {
			ck.unprogrammed(workerv1alpha1.ReasonPending, "Local has not programmed "+d.HostInterface+" yet")
			return l
		}
		if c.Handoff == workerv1alpha1.Handoff_HANDOFF_TAP {
			var tv localprog.LocalLtTapValue
			if err := objs.Maps.Tap.Lookup(idx, &tv); err != nil {
				ck.unprogrammed(workerv1alpha1.ReasonPending, "Local has not authorized "+d.HostInterface+" yet")
				return l
			}
		}
		if c.Handoff == workerv1alpha1.Handoff_HANDOFF_VETH_PAIR {
			for _, a := range ipv6(d.Addresses) {
				var gv localprog.LocalLtGuestValue
				key := localprog.LocalLtGuestKey{TableId: lv.TableId, Addr: a.As16()}
				if err := objs.Maps.Guest.Lookup(key, &gv); err != nil || gv.LinkIfindex != idx {
					ck.unprogrammed(workerv1alpha1.ReasonPending, fmt.Sprintf("Local has not authorized %s yet", a))
					return l
				}
			}
		}
		ok, err := k.filterCurrent(int(idx), filterLinkRx)
		if err != nil || !ok {
			ck.notReady(false, true, workerv1alpha1.ReasonHandoffHookMissing,
				"Local's tc program is not on "+d.HostInterface)
		}
	}
	chain, err := attach.HasEgressChain(d.HostInterface)
	deliver, derr := attach.HasDeliver(d.HostInterface)
	if err != nil || derr != nil || !chain || !deliver {
		// Another tc owner, such as a node datapath adopting the
		// interface, removed galactic-cni's filters (contract amendment).
		ck.notReady(true, true, workerv1alpha1.ReasonHandoffInterfaceMissing,
			"galactic-cni's tc chain is missing on "+d.HostInterface)
	}
	if !lowerUp(l) {
		ck.notReady(true, true, workerv1alpha1.ReasonHandoffInterfaceMissing,
			fmt.Sprintf("interface %s has no carrier: its reader does not hold it", d.HostInterface))
	}
	neighs, err := netlink.NeighList(int(idx), netlink.FAMILY_V6)
	if err == nil {
		for _, a := range ipv6(d.Addresses) {
			for _, n := range neighs {
				if addr, ok := netip.AddrFromSlice(n.IP); ok && addr == a && n.State&netlink.NUD_FAILED != 0 {
					out.failedNeighbors = true
					ck.notReady(true, false, workerv1alpha1.ReasonNeighborUnresolved,
						fmt.Sprintf("the neighbor %s on %s failed to resolve", a, d.HostInterface))
				}
			}
		}
	}
	return l
}

// tapCheck checks a local.tap destination's receive path: a receiving device
// whose dispatcher runs a live public slot, carrying local_rx, with an MTU
// the TAP's covers.
func (k *Kernel) tapCheck(rs []receiver) func(*check, netlink.Link) {
	return func(ck *check, l netlink.Link) {
		if l == nil {
			return
		}
		var live []receiver
		var slotErr error
		for _, r := range rs {
			if r.slotErr == nil {
				live = append(live, r)
			} else {
				slotErr = r.slotErr
			}
		}
		if len(live) == 0 {
			msg := "no receiving device's XDP dispatcher runs a live public slot"
			if slotErr != nil {
				msg += ": " + slotErr.Error()
			}
			ck.notReady(true, false, workerv1alpha1.ReasonDispatcherSlotUnclaimed, msg)
			return
		}
		hooked := false
		for _, r := range live {
			if ok, err := k.filterCurrent(r.idx, filterRx); err == nil && ok {
				hooked = true
			}
			if r.mtu > l.Attrs().MTU {
				ck.notReady(true, false, workerv1alpha1.ReasonHandoffMTUTooSmall,
					fmt.Sprintf("%s's MTU %d is below receiving device %s's %d", l.Attrs().Name, l.Attrs().MTU,
						r.name, r.mtu))
			}
		}
		if !hooked {
			ck.notReady(true, false, workerv1alpha1.ReasonHandoffHookMissing,
				"Local's tc program is on no receiving device")
		}
	}
}

// pairCheck checks a local.veth_pair claim's pair: it exists in the VPC's
// VRF with Local's row and program on its tenant end, both ends have
// carrier, and the client's program runs native on the NAT end.
func (k *Kernel) pairCheck(h *host, m *model, c module.Claim, vrfIdx int, objs *localprog.Objects,
	out *readResult) func(*check, netlink.Link) {
	var p pairWant
	for _, pw := range m.pairs {
		if pw.key == c.Key {
			p = pw
		}
	}
	got, ok := h.readPair(p)
	if ok {
		out.handoffs[c.Key] = append(out.handoffs[c.Key],
			module.HandoffInterface{Role: workerv1alpha1.HandoffRoleNAT, Name: p.nat, Ifindex: int32(got.nat.Attrs().Index)},
			module.HandoffInterface{Role: workerv1alpha1.HandoffRoleTenant, Name: p.tenant,
				Ifindex: int32(got.tenant.Attrs().Index)})
	}
	return func(ck *check, l netlink.Link) {
		if !ok || got.tenant.Attrs().MasterIndex != vrfIdx {
			ck.unprogrammed(workerv1alpha1.ReasonPending, "the service-internal veth pair is not created yet")
			return
		}
		tidx := got.tenant.Attrs().Index
		var pv localprog.LocalLtPairValue
		if err := objs.Maps.Pair.Lookup(uint32(tidx), &pv); err != nil {
			ck.unprogrammed(workerv1alpha1.ReasonPending, "Local has not programmed the pair yet")
			return
		}
		if l != nil {
			var lv localprog.LocalLtLinkValue
			if err := objs.Maps.Link.Lookup(uint32(l.Attrs().Index), &lv); err == nil && lv.PairIfindex != uint32(tidx) {
				// Another pair of the VPC steers this tenant's flows.
				ck.notReady(false, true, workerv1alpha1.ReasonHandoffHookMissing,
					l.Attrs().Name+"'s flows enter another service-internal veth pair of the VPC")
			}
		}
		if ok, err := k.filterCurrent(tidx, filterPairRx); err != nil || !ok {
			ck.notReady(true, false, workerv1alpha1.ReasonHandoffHookMissing,
				"Local's tc program is not on "+p.tenant)
		}
		if !k.pairNAPICurrent(got.tenant) {
			ck.notReady(true, false, workerv1alpha1.ReasonHandoffHookMissing,
				"Local's XDP program is not on "+p.tenant)
		}
		if !lowerUp(got.tenant) || !lowerUp(got.nat) {
			ck.notReady(true, true, workerv1alpha1.ReasonHandoffInterfaceMissing, "the pair has no carrier")
		}
		xdp := got.nat.Attrs().Xdp
		if xdp == nil || !xdp.Attached {
			ck.notReady(false, true, workerv1alpha1.ReasonHandoffHookMissing,
				fmt.Sprintf("the NAT end %s carries no XDP program", p.nat))
		} else if mode, ok := xdpmode.FromAttachMode(xdp.AttachMode); !ok || mode != xdpmode.Native {
			// Generic XDP never sees what a tc program redirected into
			// the pair (contract amendment).
			ck.notReady(false, true, workerv1alpha1.ReasonHookUnsupported,
				fmt.Sprintf("the NAT end %s runs its XDP program in generic mode; attach it native", p.nat))
		}
		if l != nil && l.Attrs().MTU < got.tenant.Attrs().MTU {
			ck.notReady(true, false, workerv1alpha1.ReasonHandoffMTUTooSmall,
				fmt.Sprintf("%s's MTU %d is below the pair's %d", l.Attrs().Name, l.Attrs().MTU,
					got.tenant.Attrs().MTU))
		}
	}
}

// routedCheck checks a routed link: it exists from the VPC's VRF to the
// owner's current pod with Local's guard, and has carrier, which it has once
// the pod brings its end up.
func (k *Kernel) routedCheck(h *host, m *model, c module.Claim, vrfIdx int, objs *localprog.Objects,
	errs map[string]error, out *readResult) func(*check, netlink.Link) {
	var r routedWant
	for _, rw := range m.routed {
		if rw.key == c.Key {
			r = rw
		}
	}
	l := h.byName[r.host]
	// The link counts only while it reaches the owner's current pod.
	var podErr error
	present := false
	if podNS, err := k.Pods.Open(r.podUID); err != nil {
		podErr = err
	} else {
		_, present = h.readRouted(r, podNS)
		_ = podNS.Close()
	}
	if present {
		out.handoffs[c.Key] = append(out.handoffs[c.Key], module.HandoffInterface{
			Role: workerv1alpha1.HandoffRoleHost, Name: r.host, Ifindex: int32(l.Attrs().Index),
			LinkLocal: linkLocal(l)})
		if v, ok := l.(*netlink.Veth); ok {
			if peer, err := netlink.VethPeerIndex(v); err == nil {
				out.handoffs[c.Key] = append(out.handoffs[c.Key], module.HandoffInterface{
					Role: workerv1alpha1.HandoffRolePod, Name: r.pod, Ifindex: int32(peer)})
			}
		}
	}
	return func(ck *check, _ netlink.Link) {
		if podErr != nil {
			ck.unprogrammed(workerv1alpha1.ReasonHandoffInterfaceMissing, podErr.Error())
			return
		}
		if err := errs[r.host]; err != nil {
			reason := workerv1alpha1.ReasonProgrammingFailed
			if errors.Is(err, ErrPodNotFound) || errors.Is(err, ErrPodHostNetwork) {
				reason = workerv1alpha1.ReasonHandoffInterfaceMissing
			}
			ck.unprogrammed(reason, err.Error())
			return
		}
		if len(r.addrs) == 0 {
			ck.unprogrammed(workerv1alpha1.ReasonDestinationAddressUnknown,
				"the claim's attachment records no IPv6 address for the routed link's pod end")
			return
		}
		if !present || l.Attrs().MasterIndex != vrfIdx {
			ck.unprogrammed(workerv1alpha1.ReasonPending, "the routed link is not created yet")
			return
		}
		var gv localprog.LocalLtGuardValue
		if err := objs.Maps.Guard.Lookup(uint32(l.Attrs().Index), &gv); err != nil {
			ck.unprogrammed(workerv1alpha1.ReasonPending, "Local has not programmed the routed link's guard yet")
			return
		}
		if ok, err := k.filterCurrent(l.Attrs().Index, filterLinkGuard); err != nil || !ok {
			ck.notReady(true, true, workerv1alpha1.ReasonHandoffHookMissing,
				"Local's guard is not on "+r.host)
		}
		if !lowerUp(l) {
			ck.notReady(true, true, workerv1alpha1.ReasonHandoffInterfaceMissing,
				fmt.Sprintf("the routed link %s has no carrier: the pod has not brought its end up", r.host))
		}
	}
}

// linkLocal returns l's IPv6 link-local address once the kernel has assigned
// it and duplicate address detection has finished, or the invalid address.
func linkLocal(l netlink.Link) netip.Addr {
	addrs, err := netlink.AddrList(l, netlink.FAMILY_V6)
	if err != nil {
		return netip.Addr{}
	}
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if ok && ip.IsLinkLocalUnicast() && a.Flags&unix.IFA_F_TENTATIVE == 0 {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}
