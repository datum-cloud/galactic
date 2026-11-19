// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/localprog"
)

// ensureRouted makes r's link exist from the VPC's VRF to its pod, with its
// routes and pass-through entries in the VPC's table and its guard. entries
// are the table's exact entries, which ensureRouted updates as it writes.
func (p *pass) ensureRouted(r routedWant, entries map[netip.Prefix]egressroutemap.Entry) error {
	podNS, err := p.k.Pods.Open(r.podUID)
	if err != nil {
		return err
	}
	defer podNS.Close() //nolint:errcheck // our own descriptor
	got, ok := p.h.readRouted(r, podNS)
	if !ok {
		if p.dry {
			return errDirty
		}
		if got, err = p.k.createRouted(p.h, r, podNS); err != nil {
			return err
		}
	}
	hl := got.host
	if err := placeInVRF(hl, p.vrfIdx, p.dry); err != nil {
		return err
	}
	if err := p.ensureRoutes(r, hl.Attrs().Index, entries); err != nil {
		return err
	}
	gv := localprog.LocalLtGuardValue{Count: uint32(len(r.addrs))}
	for i, a := range r.addrs {
		gv.Addr[i] = a.As16()
	}
	if err := putRow(p.objs.Maps.Guard, uint32(hl.Attrs().Index), gv, p.dry, "guard of "+r.host); err != nil {
		return err
	}
	return p.k.ensureFilter(hl, filterLinkGuard, p.dry)
}

// createRouted creates r's link, its host end in the calling namespace and
// its pod end in podNS. A link of the same name to an earlier pod goes first.
func (k *Kernel) createRouted(h *host, r routedWant, podNS netns.NsHandle) (routedLink, error) {
	if err := h.collision(r.host, alias(r.key)); err != nil {
		return routedLink{}, err
	}
	if l := h.byName[r.host]; l != nil {
		// The owner's pod was replaced: the link to the old pod goes.
		if err := netlink.LinkDel(l); err != nil && !errors.Is(err, unix.ENODEV) {
			return routedLink{}, fmt.Errorf("local: delete routed link %s: %w", r.host, err)
		}
	}
	v := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: r.host, MTU: k.mtu()}, PeerName: r.pod}
	if err := netlink.LinkAdd(v); err != nil {
		return routedLink{}, fmt.Errorf("local: create routed link %s: %w", r.host, err)
	}
	pl, err := netlink.LinkByName(r.pod)
	if err != nil {
		return routedLink{}, fmt.Errorf("local: look up new pod end %s: %w", r.pod, err)
	}
	if err := netlink.LinkSetNsFd(pl, int(podNS)); err != nil {
		_ = netlink.LinkDel(pl)
		return routedLink{}, fmt.Errorf("local: move %s into the pod: %w", r.pod, err)
	}
	l, err := netlink.LinkByName(r.host)
	if err != nil {
		return routedLink{}, fmt.Errorf("local: look up new routed link %s: %w", r.host, err)
	}
	if err := netlink.LinkSetAlias(l, alias(r.key)); err != nil {
		return routedLink{}, fmt.Errorf("local: mark routed link %s: %w", r.host, err)
	}
	if err := setUpInPod(podNS, r.pod, alias(r.key)); err != nil {
		return routedLink{}, err
	}
	if l, err = netlink.LinkByName(r.host); err != nil {
		return routedLink{}, err
	}
	peer, err := netlink.VethPeerIndex(l.(*netlink.Veth))
	if err != nil {
		return routedLink{}, fmt.Errorf("local: read routed link peer: %w", err)
	}
	return routedLink{host: l, podIndex: peer}, nil
}

// placeInVRF enslaves l to vrfIdx and sets it up.
func placeInVRF(l netlink.Link, vrfIdx int, dry bool) error {
	name := l.Attrs().Name
	if err := fix(dry, l.Attrs().MasterIndex != vrfIdx, func() error {
		if err := netlink.LinkSetMasterByIndex(l, vrfIdx); err != nil {
			return fmt.Errorf("local: enslave %s: %w", name, err)
		}
		return nil
	}); err != nil {
		return err
	}
	return fix(dry, l.Attrs().Flags&net.FlagUp == 0, func() error {
		if err := netlink.LinkSetUp(l); err != nil {
			return fmt.Errorf("local: set %s up: %w", name, err)
		}
		return nil
	})
}

// ensureRoutes routes each of r's addresses to the host end hostIdx in the
// VPC's table, and writes its pass-through entry where the table holds no
// exact entry for it.
func (p *pass) ensureRoutes(r routedWant, hostIdx int, entries map[netip.Prefix]egressroutemap.Entry) error {
	for _, a := range r.addrs {
		dst := netip.PrefixFrom(a, 128)
		have, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
			&netlink.Route{Table: int(p.table), Dst: ipnet(dst), LinkIndex: hostIdx},
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST|netlink.RT_FILTER_OIF)
		if err != nil {
			return fmt.Errorf("local: list routes to %s: %w", dst, err)
		}
		if err := fix(p.dry, len(have) == 0, func() error {
			route := &netlink.Route{Table: int(p.table), Dst: ipnet(dst), LinkIndex: hostIdx,
				Scope: netlink.SCOPE_LINK}
			if err := netlink.RouteReplace(route); err != nil {
				return fmt.Errorf("local: route %s via %s: %w", dst, r.host, err)
			}
			return nil
		}); err != nil {
			return err
		}
		// An exact entry another writer holds is left alone: a
		// pass-through already passes the address on, and an encapsulating
		// entry is that writer's to change.
		_, exists := entries[dst]
		if err := fix(p.dry, !exists, func() error {
			return p.routes.RegisterPassThroughAs(p.table, ipnet(dst), egressroutemap.PassThroughLocal)
		}); err != nil {
			return err
		}
		if !exists {
			entries[dst] = egressroutemap.Entry{PassThrough: true, Owner: egressroutemap.PassThroughLocal}
		}
	}
	return nil
}
