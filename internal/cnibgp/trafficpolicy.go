// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/hostgw"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// errHostOnlyUnenforced refuses an interface that lists host-only ports on a
// node where tp_deliver, which enforces them, is not attached to it.
var errHostOnlyUnenforced = errors.New("host-only ports are listed but tp_deliver is not attached")

// errNoEnforcement refuses a managed interface on a node that has traffic
// policy on but cannot enforce it.
var errNoEnforcement = errors.New("traffic policy is on but this node cannot enforce it")

// activateTrafficPolicy finishes a new interface's traffic policy lifecycle,
// after registerEBPFDatapath attached usid_egress. It always writes the
// interface's policy row, with a fresh policy token, and its addresses, and
// attaches tp_deliver, so a node switched on later needs no recreation.
//
// While the node enforces or audits, the host side comes up only after every
// enforcement program has been read back from the interface, and the ADD is
// refused, leaving it down, when the node is not capable or registered
// nothing to enforce with. The interface then denies everything until
// galactic-router publishes its bindings. galactic-bgp owns the link's final
// state: it does not rely on the master plugin having read the same mode.
func activateTrafficPolicy(
	pinDir, vpc, vpcAttachment string, registered bool, ipamResult *cniipam.IPAMResult, guestHWAddr net.HardwareAddr,
) error {
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	if !registered {
		active, err := tpmap.Active(pinDir)
		if active || err != nil {
			return errors.Join(quarantineLink(hostName), err,
				fmt.Errorf("%w: the node has no SRv6 locator, so nothing is attached", errNoEnforcement))
		}
		return bringUp(pinDir, hostName, vpc, vpcAttachment, ipamResult, guestHWAddr)
	}
	maps, err := tpmap.OpenPinned(pinDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) { // an older datapath: nothing to activate
			return bringUp(pinDir, hostName, vpc, vpcAttachment, ipamResult, guestHWAddr)
		}
		return errors.Join(quarantineLink(hostName), fmt.Errorf("open traffic policy maps: %w", err))
	}
	defer maps.Close()
	state, err := maps.GetState()
	if err != nil {
		return err
	}
	active := state.Mode != tpmap.ModeOff
	// The master plugin read the mode earlier, and it may have changed
	// since. With policy on, the link is never up before verification, so a
	// link the master left up comes down first, before anything can refuse
	// the ADD; with it off, a link the master left down comes up at the end.
	if active {
		if err := quarantineLink(hostName); err != nil {
			return err
		}
		if !state.Capable {
			return fmt.Errorf("%w: the kernel failed the traffic policy preflight", errNoEnforcement)
		}
	}

	link, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("find host interface %q: %w", hostName, err)
	}
	ifindex := uint32(link.Attrs().Index) //nolint:gosec // a kernel ifindex
	// An ADD repeated on a live interface, such as a tap repair, keeps its
	// token, so its published bindings stay valid. A new interface has no
	// row: DEL removes it, galactic-cni removes any whose interface is gone,
	// and the kernel does not reuse an ifindex right away.
	var row prog.UsidTpIfaceValue
	token := uint64(0)
	if err := maps.Interfaces.Lookup(ifindex, &row); err == nil && row.Kind == tpmap.KindTenant {
		token = row.PolicyToken
	}
	if token == 0 {
		if token, err = tpmap.NewPolicyToken(); err != nil {
			return err
		}
	}
	if err := maps.PutInterface(ifindex, token, tpmap.KindTenant); err != nil {
		return err
	}
	for _, a := range interfaceAddrs(ipamResult) {
		if err := maps.PutInterfaceAddr(ifindex, a); err != nil {
			return err
		}
	}
	program, err := ebpf.LoadPinnedProgram(filepath.Join(pinDir, attach.TpDeliverPinName), nil)
	if err != nil {
		if !active {
			return bringUp(pinDir, hostName, vpc, vpcAttachment, ipamResult, guestHWAddr) // an older datapath without tp_deliver
		}
		return fmt.Errorf("load pinned tp_deliver: %w", err)
	}
	defer program.Close() //nolint:errcheck // the filter holds its own reference
	if err := attach.AttachDeliver(program, hostName); err != nil {
		return fmt.Errorf("attach tp_deliver to %s: %w", hostName, err)
	}
	if active {
		if err := verifyEnforcement(hostName); err != nil {
			return err
		}
	}
	return bringUp(pinDir, hostName, vpc, vpcAttachment, ipamResult, guestHWAddr)
}

// quarantineLink takes hostName down if it is up.
func quarantineLink(hostName string) error {
	link, err := netlink.LinkByName(hostName)
	if err != nil {
		return fmt.Errorf("find host interface %q: %w", hostName, err)
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		return nil
	}
	if err := netlink.LinkSetDown(link); err != nil {
		return fmt.Errorf("quarantine %s: %w", hostName, err)
	}
	return nil
}

// bringUp brings hostName up and then restores the attachment's host gateway
// (hostgw.RestoreHostGateway). The master plugin cannot add the pod-subnet
// routes while the link is down, and taking a link down drops its routes, its
// IPv6 addresses and its neighbor entries, so they are restored here, after
// the link's last transition. guestHWAddr is the guest-side veth's MAC, or nil
// for a tap. A missing link is left to the master plugin that owns it.
//
// A link listing host-only ports comes up only with tp_deliver attached, since
// nothing else enforces them; otherwise it is quarantined and the ADD refused.
func bringUp(
	pinDir, hostName, vpc, vpcAttachment string, ipamResult *cniipam.IPAMResult, guestHWAddr net.HardwareAddr,
) error {
	if err := refuseUnfencedHostOnlyPorts(pinDir, hostName); err != nil {
		return err
	}
	if err := ensureLinkUp(hostName); err != nil {
		return err
	}
	if _, err := netlink.LinkByName(hostName); err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("find host interface %q: %w", hostName, err)
	}
	if err := hostgw.RestoreHostGateway(vpc, vpcAttachment, ipamResult, guestHWAddr); err != nil {
		return fmt.Errorf("restore host gateway: %w", err)
	}
	return nil
}

// ensureLinkUp brings hostName up if it is down. A missing link is left to
// the master plugin that owns it.
func ensureLinkUp(hostName string) error {
	link, err := netlink.LinkByName(hostName)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("find host interface %q: %w", hostName, err)
	}
	if link.Attrs().Flags&net.FlagUp != 0 {
		return nil
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", hostName, err)
	}
	return nil
}

// refuseUnfencedHostOnlyPorts quarantines hostName and returns
// errHostOnlyUnenforced when it lists host-only ports and tp_deliver is not
// attached to it.
func refuseUnfencedHostOnlyPorts(pinDir, hostName string) error {
	link, err := netlink.LinkByName(hostName)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("find host interface %q: %w", hostName, err)
	}
	table, closer, err := ifindexvrfmap.OpenPinnedHostOnlyPorts(pinDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open host-only port table: %w", err)
	}
	defer func() { _ = closer.Close() }()
	ports, listed, err := table.Get(uint32(link.Attrs().Index)) //nolint:gosec // a kernel ifindex
	if err != nil || !listed {
		return err
	}
	attached, err := attach.HasDeliver(hostName)
	if err != nil || attached {
		return err
	}
	return errors.Join(quarantineLink(hostName), fmt.Errorf("%w: %s lists TCP %v", errHostOnlyUnenforced, hostName, ports))
}

// verifyEnforcement reads every enforcement program back from hostName's tc
// hooks before its link may come up.
func verifyEnforcement(hostName string) error {
	ok, err := attach.HasDeliver(hostName)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("tp_deliver is not attached to %s", hostName)
	}
	ok, err = attach.HasEgressChain(hostName)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the egress programs are not attached to %s", hostName)
	}
	return nil
}

// interfaceAddrs are the addresses IPAM assigned the workload, which the
// link-operation checks accept as an ARP or neighbor discovery source.
func interfaceAddrs(r *cniipam.IPAMResult) []netip.Addr {
	if r == nil {
		return nil
	}
	var out []netip.Addr
	if r.IPv6Subnet != nil {
		if a, ok := netip.AddrFromSlice(r.IPv6Subnet.IP.To16()); ok {
			out = append(out, a)
		}
	}
	if v4 := r.IPv4Address.To4(); v4 != nil {
		if a, ok := netip.AddrFromSlice(v4); ok {
			out = append(out, a)
		}
	}
	return out
}
