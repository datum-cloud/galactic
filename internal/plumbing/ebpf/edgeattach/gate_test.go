// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeattach

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgepreflight"
)

// fakeSlaveLink is a netlink.Link carrying bond slave data, the view
// waitBondSlaveReady reads.
type fakeSlaveLink struct {
	netlink.LinkAttrs
}

func (f *fakeSlaveLink) Attrs() *netlink.LinkAttrs { return &f.LinkAttrs }
func (f *fakeSlaveLink) Type() string              { return "veth" }

// Interface names these tests drive: one slave whose driver takes a native
// program, one whose driver does not.
const (
	gateSlave      = "enp3s0f1"
	gateSlaveNoXDP = "eno2"
	gateSlaveSib   = "enp6s0f1"
	gateMasterIdx  = 7
)

// slaveLink builds a link enslaved to the test bond with the given LACP actor
// state and MII status.
func slaveLink(name string, mii netlink.BondSlaveMiiStatus, actorState uint8) netlink.Link {
	return &fakeSlaveLink{LinkAttrs: netlink.LinkAttrs{
		Name:        name,
		MasterIndex: gateMasterIdx,
		Slave: &netlink.BondSlave{
			MiiStatus:            mii,
			AdActorOperPortState: actorState,
		},
	}}
}

// lacpMaster builds the 802.3ad bonding master these tests enslave to.
func lacpMaster() netlink.Link {
	b := netlink.NewLinkBond(netlink.LinkAttrs{Name: "bond0", Index: gateMasterIdx})
	b.Mode = netlink.BOND_MODE_802_3AD
	return b
}

const (
	// lacpCarrying is the actor state of a port that is collecting and
	// distributing: activity, aggregation, sync, collecting, distributing.
	lacpCarrying = 0x3d
	// lacpSyncOnly is the state an XDP attach leaves behind on a bond whose
	// link monitoring is off: synchronized, but neither collecting nor
	// distributing. A port in this state moves no packets.
	lacpSyncOnly = 0x0d
)

// restoreGateVars puts every override this file swaps back after a test.
func restoreGateVars(t *testing.T) {
	t.Helper()
	byName, byIndex, sleep, xdp := linkByNameFn, linkByIndexFn, sleepFn, edgepreflight.InterfaceXDPFn
	t.Cleanup(func() {
		linkByNameFn, linkByIndexFn, sleepFn, edgepreflight.InterfaceXDPFn = byName, byIndex, sleep, xdp
	})
}

func TestWaitBondSlaveReady_NonSlaveReturnsImmediately(t *testing.T) {
	restoreGateVars(t)

	linkByNameFn = func(name string) (netlink.Link, error) {
		return &fakeSlaveLink{LinkAttrs: netlink.LinkAttrs{Name: name}}, nil
	}
	sleepFn = func(time.Duration) { t.Fatal("a plain interface must not be polled") }

	if err := waitBondSlaveReady("eth0", time.Second); err != nil {
		t.Fatalf("waitBondSlaveReady on a non-slave: %v", err)
	}
}

func TestWaitBondSlaveReady_WaitsForCollectingAndDistributing(t *testing.T) {
	restoreGateVars(t)

	// The slave reports sync-only twice before it starts carrying traffic,
	// the sequence a real slave walks after its driver finishes the ring
	// realloc and LACP re-converges with the switch.
	states := []uint8{lacpSyncOnly, lacpSyncOnly, lacpCarrying}
	var reads int
	linkByNameFn = func(name string) (netlink.Link, error) {
		state := states[min(reads, len(states)-1)]
		reads++
		return slaveLink(name, netlink.BondLinkUp, state), nil
	}
	linkByIndexFn = func(int) (netlink.Link, error) { return lacpMaster(), nil }

	var slept int
	sleepFn = func(time.Duration) { slept++ }

	if err := waitBondSlaveReady(gateSlave, time.Minute); err != nil {
		t.Fatalf("waitBondSlaveReady: %v", err)
	}
	if slept != 2 {
		t.Errorf("polled %d times, want 2 (one per sync-only read)", slept)
	}
}

func TestWaitBondSlaveReady_SyncedButNotCarryingTimesOut(t *testing.T) {
	restoreGateVars(t)

	// Carrier is up and the port is synchronized, but collecting and
	// distributing never arrive. That is the state a slave is left in when
	// the bond cannot detect its link returning, and it is not readiness.
	linkByNameFn = func(name string) (netlink.Link, error) {
		return slaveLink(name, netlink.BondLinkUp, lacpSyncOnly), nil
	}
	linkByIndexFn = func(int) (netlink.Link, error) { return lacpMaster(), nil }
	sleepFn = func(time.Duration) {}

	err := waitBondSlaveReady(gateSlave, time.Millisecond)
	if err == nil {
		t.Fatal("a slave stuck synchronized-but-not-carrying must not report ready")
	}
	if !strings.Contains(err.Error(), "did not rejoin its aggregate") {
		t.Errorf("error does not name the failure: %v", err)
	}
}

func TestWaitBondSlaveReady_CarrierDownIsNotReady(t *testing.T) {
	restoreGateVars(t)

	// The first thing an XDP attach does to a slave is take carrier away
	// while the driver reallocates its rings. Until it comes back the slave
	// is not ready, whatever its actor state says.
	linkByNameFn = func(name string) (netlink.Link, error) {
		return slaveLink(name, netlink.BondLinkDown, lacpCarrying), nil
	}
	linkByIndexFn = func(int) (netlink.Link, error) { return lacpMaster(), nil }
	sleepFn = func(time.Duration) {}

	if err := waitBondSlaveReady(gateSlave, time.Millisecond); err == nil {
		t.Fatal("a slave with no carrier must not report ready")
	}
}

func TestWaitBondSlaveReady_NonLACPBondNeedsOnlyCarrier(t *testing.T) {
	restoreGateVars(t)

	// A balance-rr bond carries no actor state at all, so waiting for
	// collecting and distributing there would never return.
	linkByNameFn = func(name string) (netlink.Link, error) {
		return slaveLink(name, netlink.BondLinkUp, 0), nil
	}
	linkByIndexFn = func(int) (netlink.Link, error) {
		return netlink.NewLinkBond(netlink.LinkAttrs{Name: "bond0", Index: gateMasterIdx}), nil
	}
	sleepFn = func(time.Duration) { t.Fatal("a carrier-up non-LACP slave must not be polled") }

	if err := waitBondSlaveReady(gateSlave, time.Second); err != nil {
		t.Fatalf("waitBondSlaveReady on a non-LACP bond: %v", err)
	}
}

func TestCheckNativeXDPSupport_RefusesBeforeTouchingAnyLink(t *testing.T) {
	restoreGateVars(t)

	var asked []string
	edgepreflight.InterfaceXDPFn = func(name string) (bool, error) {
		asked = append(asked, name)
		return name != gateSlaveNoXDP, nil
	}

	err := checkNativeXDPSupport([]string{gateSlave, gateSlaveNoXDP})
	if err == nil {
		t.Fatal("an interface with no native XDP support must fail the whole attach")
	}
	if !strings.Contains(err.Error(), gateSlaveNoXDP) {
		t.Errorf("error does not name the unsupported interface: %v", err)
	}
	if len(asked) != 2 {
		t.Errorf("checked %v, want both interfaces checked", asked)
	}
}

func TestCheckNativeXDPSupport_UnknownSupportProceeds(t *testing.T) {
	restoreGateVars(t)

	// A kernel too old to answer, and a query that fails on its own terms,
	// both leave support unknown. Neither is grounds to hold the gateway
	// down, so both proceed with a warning.
	for name, probeErr := range map[string]error{
		"family unavailable": edgepreflight.ErrXDPFeaturesUnavailable,
		"query failed":       errors.New("netlink: connection reset"),
	} {
		t.Run(name, func(t *testing.T) {
			edgepreflight.InterfaceXDPFn = func(string) (bool, error) { return false, probeErr }
			if err := checkNativeXDPSupport([]string{gateSlave}); err != nil {
				t.Fatalf("unknown support must not refuse the attach: %v", err)
			}
		})
	}
}

func TestAttachSequentially_StopsAtTheFirstSlaveThatDoesNotComeBack(t *testing.T) {
	restoreGateVars(t)

	// The regression this whole change exists for: with two slaves and the
	// first one failing to rejoin, the second must never be attached. It is
	// the surviving uplink, and taking it down is what puts the node dark.
	edgepreflight.InterfaceXDPFn = func(string) (bool, error) { return true, nil }
	linkByNameFn = func(name string) (netlink.Link, error) {
		return slaveLink(name, netlink.BondLinkUp, lacpSyncOnly), nil
	}
	linkByIndexFn = func(int) (netlink.Link, error) { return lacpMaster(), nil }
	sleepFn = func(time.Duration) {}

	BondReadyTimeout = time.Millisecond
	t.Cleanup(func() { BondReadyTimeout = 45 * time.Second })

	var attached []string
	_, err := attachSequentially([]string{gateSlave, gateSlaveSib}, func(name string) (link.Link, error) {
		attached = append(attached, name)
		return nil, nil
	})
	if err == nil {
		t.Fatal("attach must fail when a slave does not rejoin its aggregate")
	}
	if want := []string{gateSlave}; !slices.Equal(attached, want) {
		t.Errorf("attached %v, want %v -- the second slave must be left alone", attached, want)
	}
}

func TestAttachSequentially_AttachesNothingWhenSupportIsMissing(t *testing.T) {
	restoreGateVars(t)

	edgepreflight.InterfaceXDPFn = func(name string) (bool, error) { return name != gateSlaveNoXDP, nil }

	var attached []string
	_, err := attachSequentially([]string{gateSlave, gateSlaveNoXDP}, func(name string) (link.Link, error) {
		attached = append(attached, name)
		return nil, nil
	})
	if err == nil {
		t.Fatal("attach must fail when an interface cannot take a native program")
	}
	if len(attached) != 0 {
		t.Errorf("attached %v, want nothing -- the check runs before any link is touched", attached)
	}
}
