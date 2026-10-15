// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

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
func activateTrafficPolicy(pinDir, vpc, vpcAttachment string, registered bool, ipamResult *cniipam.IPAMResult) error {
	hostName := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
	if !registered {
		if tpmap.Active(pinDir) {
			return errors.Join(quarantineLink(hostName),
				fmt.Errorf("%w: the node has no SRv6 locator, so nothing is attached", errNoEnforcement))
		}
		return ensureLinkUp(hostName)
	}
	maps, err := tpmap.OpenPinned(pinDir)
	if err != nil {
		if tpmap.Active(pinDir) {
			return fmt.Errorf("open traffic policy maps: %w", err)
		}
		return ensureLinkUp(hostName) // an older datapath: nothing to activate
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
	token, err := tpmap.NewPolicyToken()
	if err != nil {
		return err
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
			return ensureLinkUp(hostName) // an older datapath without tp_deliver
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
	return ensureLinkUp(hostName)
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
