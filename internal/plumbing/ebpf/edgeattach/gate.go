// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeattach

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgepreflight"
)

// Attaching a native XDP program makes a driver reallocate its rings, and a
// driver that has to do that takes the link down while it does. On 10GBASE-T
// copper the relink alone runs to several seconds. On an ordinary uplink that
// is a visible but survivable blip. On a bond slave it is neither, for two
// reasons this file exists to address.
//
// First, attaching to every slave at once takes every member of the aggregate
// down inside the same second, so the node loses its uplink outright rather
// than riding out each bounce on the surviving member. waitBondSlaveReady
// makes the attach wait for each slave to rejoin its aggregate before the next
// one is touched.
//
// Second, a driver that cannot take a native program at all is found out by
// attaching, which means the healthy slaves attached ahead of it have already
// paid a bounce by the time the failure surfaces, and the rollback costs them
// another. checkNativeXDPSupport asks the kernel which interfaces support the
// program before any link is touched, so an unsupported one fails the process
// with nothing disturbed.
//
// Neither guard makes a bond whose link monitoring is switched off safe. With
// miimon at 0 the bonding driver never polls carrier, so a slave that bounces
// is left in a failed state that only a monitor it does not run would clear.
// These guards bound the damage; they do not repair a bond that cannot detect
// a link coming back.

// BondReadyTimeout bounds how long Attach waits for one bond slave to rejoin
// its aggregate before giving up on it. It covers a driver's ring realloc plus
// LACP re-convergence with the switch, so it is generous by design: the cost of
// waiting too long is a slow start, and the cost of waiting too little is
// attaching to the next slave while this one is still down.
var BondReadyTimeout = 45 * time.Second

// bondReadyPollInterval is how often the aggregate is re-read while waiting.
const bondReadyPollInterval = 250 * time.Millisecond

// LACP actor state bits, as carried in IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE
// and defined by IEEE 802.1AX. A port that is collecting and distributing is
// carrying traffic; one that is merely synchronized is not.
const (
	lacpStateCollecting   = 1 << 4
	lacpStateDistributing = 1 << 5
)

// linkByIndexFn is an override point, matching linkByNameFn and linkListFn, so
// the bond-mode lookup can be faked in tests.
var linkByIndexFn = netlink.LinkByIndex

// sleepFn is an override point so the readiness poll does not spend real time
// in tests.
var sleepFn = time.Sleep

// checkNativeXDPSupport refuses the whole attach if the kernel positively
// reports that one of ifaceNames cannot run a native XDP program.
//
// It refuses only on a definite answer. A kernel too old to serve the netdev
// generic netlink family, or a query that fails for its own reasons, leaves
// support unknown, and an unknown is not grounds to keep a gateway down: those
// log and proceed, which is the behavior every release before this one had.
func checkNativeXDPSupport(ifaceNames []string) error {
	for _, ifaceName := range ifaceNames {
		supported, err := edgepreflight.InterfaceXDPFn(ifaceName)
		switch {
		case errors.Is(err, edgepreflight.ErrXDPFeaturesUnavailable):
			slog.Warn("edgeattach: kernel cannot report per-interface XDP support, attaching without checking first "+
				"(a driver that cannot take the program will be found out by attaching, which bounces the link)",
				"interface", ifaceName)
		case err != nil:
			slog.Warn("edgeattach: could not read XDP support for interface, attaching without checking first",
				"interface", ifaceName, "err", err)
		case !supported:
			return fmt.Errorf(
				"edgeattach: interface %q (driver %q) does not support native XDP, refusing to attach the edge "+
					"gateway datapath to any interface: attaching to the rest would leave traffic arriving on %q "+
					"bypassing the datapath entirely, and on a bonded uplink it would take the link down",
				ifaceName, driverName(ifaceName), ifaceName)
		}
	}
	return nil
}

// driverName reports the kernel driver bound to ifaceName, for an error message
// naming the hardware an operator has to act on. Best-effort: an interface with
// no backing device, such as a veth, reports "unknown".
func driverName(ifaceName string) string {
	target, err := os.Readlink(filepath.Join("/sys/class/net", ifaceName, "device", "driver"))
	if err != nil {
		return "unknown"
	}
	return filepath.Base(target)
}

// waitBondSlaveReady blocks until ifaceName is carrying traffic in its bond
// again, or until BondReadyTimeout elapses.
//
// An interface that is not enslaved to a bond returns immediately: there is no
// aggregate to rejoin and no sibling link to protect. Note that the interface
// named in the gateway's configuration can itself be a slave rather than a
// master -- a deployment that points at one member of a bond directly still
// gets the wait, because the bounce still costs its siblings.
func waitBondSlaveReady(ifaceName string, timeout time.Duration) error {
	slave, masterIndex, ok, err := bondSlaveOf(ifaceName)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	lacp, err := bondUsesLACP(masterIndex)
	if err != nil {
		return err
	}

	deadline := time.Now().Add(timeout)
	for {
		if bondSlaveCarryingTraffic(slave, lacp) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf(
				"edgeattach: bond slave %q did not rejoin its aggregate within %s of the XDP attach "+
					"(mii status %d, LACP actor state %d); refusing to attach to any remaining slave, "+
					"because doing so would take the rest of the bond down with it",
				ifaceName, timeout, slave.MiiStatus, slave.AdActorOperPortState)
		}
		sleepFn(bondReadyPollInterval)

		slave, _, ok, err = bondSlaveOf(ifaceName)
		if err != nil {
			return err
		}
		if !ok {
			// It left the bond while we waited. There is no aggregate to
			// wait for any more, and nothing here can put it back.
			return nil
		}
	}
}

// bondSlaveOf reports ifaceName's bond membership, if it has one, along with
// the ifindex of the master it is enslaved to.
func bondSlaveOf(ifaceName string) (slave *netlink.BondSlave, masterIndex int, ok bool, err error) {
	l, err := linkByNameFn(ifaceName)
	if err != nil {
		return nil, 0, false, fmt.Errorf("edgeattach: find link %q: %w", ifaceName, err)
	}
	s, ok := l.Attrs().Slave.(*netlink.BondSlave)
	if !ok {
		return nil, 0, false, nil
	}
	return s, l.Attrs().MasterIndex, true, nil
}

// bondUsesLACP reports whether the bonding master at masterIndex runs 802.3ad.
// Only an LACP bond has actor port state to read; every other mode carries
// nothing beyond the MII status.
func bondUsesLACP(masterIndex int) (bool, error) {
	master, err := linkByIndexFn(masterIndex)
	if err != nil {
		return false, fmt.Errorf("edgeattach: find bonding master at index %d: %w", masterIndex, err)
	}
	b, ok := master.(*netlink.Bond)
	if !ok {
		return false, nil
	}
	return b.Mode == netlink.BOND_MODE_802_3AD, nil
}

// bondSlaveCarryingTraffic reports whether slave is back to carrying traffic.
//
// On an LACP bond that means more than carrier: a slave can hold carrier, sit
// in the aggregator and be synchronized while collecting and distributing are
// both clear, which is exactly the state an XDP attach leaves behind on a bond
// with link monitoring switched off, and in that state it moves no packets.
func bondSlaveCarryingTraffic(slave *netlink.BondSlave, lacp bool) bool {
	if slave.MiiStatus != netlink.BondLinkUp {
		return false
	}
	if !lacp {
		return true
	}
	const want = lacpStateCollecting | lacpStateDistributing
	return slave.AdActorOperPortState&want == want
}
