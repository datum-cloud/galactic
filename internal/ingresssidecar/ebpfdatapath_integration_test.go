// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_NET_ADMIN/CAP_BPF) to create a VRF, " +
			"a veth pair, and load real BPF maps; re-run via sudo")
	}
}

// setUpTestPinDir mirrors internal/plumbing/srv6's own identically-named
// helper: loads the real usid.c program into a fresh, throwaway bpffs
// directory and points this package's own ebpfPinDir seam at it for the
// duration of the calling test.
func setUpTestPinDir(t *testing.T) {
	t.Helper()

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-ingresssidecar-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	prev := ebpfPinDir
	ebpfPinDir = pinDir
	t.Cleanup(func() { ebpfPinDir = prev })
}

// assertVethWiring checks the kernel-side mechanics ensureEgressDatapath is
// responsible for: inner enslaved into the VRF, a real path out of the
// VRF's own table, and usid_egress attached where it actually intercepts
// that traffic -- the peer's ingress hook, never the VRF's own egress.
func assertVethWiring(vrfLink *netlink.Vrf, innerLink, peerLink netlink.Link, tableID uint32) error {
	if innerLink.Attrs().MasterIndex != vrfLink.Attrs().Index {
		return fmt.Errorf("inner veth end master = %d, want VRF ifindex %d",
			innerLink.Attrs().MasterIndex, vrfLink.Attrs().Index)
	}

	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V6, &netlink.Route{Table: int(tableID)}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list routes in VRF table %d: %w", tableID, err)
	}
	var foundDefault bool
	for _, r := range routes {
		if r.LinkIndex == innerLink.Attrs().Index && (r.Dst == nil || r.Dst.String() == "::/0") {
			foundDefault = true
		}
	}
	if !foundDefault {
		return fmt.Errorf("no default route via the veth inner end in VRF table %d, want one (routes: %+v)",
			tableID, routes)
	}

	peerFilters, err := netlink.FilterList(peerLink, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return fmt.Errorf("list ingress filters on veth peer: %w", err)
	}
	if len(peerFilters) == 0 {
		return errors.New("no ingress filter on veth peer, want usid_egress attached there")
	}

	vrfFilters, err := netlink.FilterList(vrfLink, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return fmt.Errorf("list egress filters on VRF: %w", err)
	}
	if len(vrfFilters) != 0 {
		return fmt.Errorf("VRF has %d egress filter(s), want none -- usid_egress belongs on the veth peer, not here",
			len(vrfFilters))
	}
	return nil
}

// assertMapState checks vrf_table/ifindex_vrf_table read back exactly what
// ensureEgressDatapath's own doc comment promises: keyed by the veth
// peer's ifindex, never the VRF's own.
func assertMapState(
	ifindexTable *ifindexvrfmap.IfindexVRFTable, registry *usidmap.Registry,
	vrfLink *netlink.Vrf, peerLink netlink.Link, tableID uint32,
) error {
	entry, ok, err := ifindexTable.Get(uint32(peerLink.Attrs().Index))
	if err != nil {
		return fmt.Errorf("look up ifindex_vrf_table[peer]: %w", err)
	}
	if !ok {
		return errors.New("ifindex_vrf_table has no entry for the veth peer's ifindex")
	}
	if entry.Block != ingressSidecarBlock || entry.Argument != uint16(tableID) {
		return fmt.Errorf("ifindex_vrf_table[peer] = (block=%#x, argument=%d), want (block=%#x, argument=%d)",
			entry.Block, entry.Argument, ingressSidecarBlock, tableID)
	}

	if _, ok, err := ifindexTable.Get(uint32(vrfLink.Attrs().Index)); err != nil {
		return fmt.Errorf("look up ifindex_vrf_table[VRF]: %w", err)
	} else if ok {
		return errors.New("ifindex_vrf_table has an entry keyed by the VRF's own ifindex, want none")
	}

	vrfEntry, ok, err := registry.VRF.Get(ingressSidecarBlock, uint16(tableID))
	if err != nil {
		return fmt.Errorf("look up vrf_table entry: %w", err)
	}
	if !ok || vrfEntry.VRFTableID != tableID {
		return fmt.Errorf("vrf_table entry = (ok=%v, vrfTableID=%d), want (true, %d)", ok, vrfEntry.VRFTableID, tableID)
	}
	return nil
}

// assertTornDown checks removeEgressDatapath's own contract: the veth
// pair and both map entries are all gone.
func assertTornDown(
	ifindexTable *ifindexvrfmap.IfindexVRFTable, registry *usidmap.Registry,
	peerName string, peerIfindex uint32, tableID uint32,
) error {
	if _, err := netlink.LinkByName(peerName); err == nil {
		return errors.New("veth peer still exists after removeEgressDatapath")
	}
	if _, ok, err := ifindexTable.Get(peerIfindex); err != nil {
		return fmt.Errorf("look up ifindex_vrf_table[peer] after removal: %w", err)
	} else if ok {
		return errors.New("ifindex_vrf_table[peer] still present after removeEgressDatapath")
	}
	if _, ok, err := registry.VRF.Get(ingressSidecarBlock, uint16(tableID)); err != nil {
		return fmt.Errorf("look up vrf_table entry after removal: %w", err)
	} else if ok {
		return errors.New("vrf_table entry still present after removeEgressDatapath")
	}
	return nil
}

// TestEnsureEgressDatapath_AttachesToVethPeerNotVRF is this fix's own exit
// criterion: usid_egress must end up on a real interface's ingress hook
// that actually sees this VRF's traffic, not the VRF device's own TC
// egress hook -- packet-capture confirmed that hook never fires, for any
// tenant, however correctly vrf_table and egress_route_table were
// populated (this file's own doc comment on ensureEgressDatapath has the
// full account).
func TestEnsureEgressDatapath_AttachesToVethPeerNotVRF(t *testing.T) {
	requireRoot(t)
	setUpTestPinDir(t)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	const tableID = uint32(7)
	const vrfName = "ivstestvrf"

	err = nsObj.Do(func(_ ns.NetNS) error {
		vrfLink := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: vrfName}, Table: tableID}
		if err := netlink.LinkAdd(vrfLink); err != nil {
			return fmt.Errorf("add VRF: %w", err)
		}
		if err := netlink.LinkSetUp(vrfLink); err != nil {
			return fmt.Errorf("set VRF up: %w", err)
		}

		if err := ensureEgressDatapath("testvpc", tableID); err != nil {
			return fmt.Errorf("ensureEgressDatapath: %w", err)
		}

		inner, peer := egressVethNames(tableID)
		innerLink, err := netlink.LinkByName(inner)
		if err != nil {
			return fmt.Errorf("look up inner veth end %q: %w", inner, err)
		}
		peerLink, err := netlink.LinkByName(peer)
		if err != nil {
			return fmt.Errorf("look up veth peer %q: %w", peer, err)
		}

		if err := assertVethWiring(vrfLink, innerLink, peerLink, tableID); err != nil {
			return err
		}

		ifindexTable, closer, err := ifindexvrfmap.OpenPinned(ebpfPinDir)
		if err != nil {
			return fmt.Errorf("open pinned ifindex_vrf_table: %w", err)
		}
		defer func() { _ = closer.Close() }()

		registry, closer2, err := usidmap.OpenPinnedRegistry(ebpfPinDir)
		if err != nil {
			return fmt.Errorf("open pinned vrf_table: %w", err)
		}
		defer func() { _ = closer2.Close() }()

		if err := assertMapState(ifindexTable, registry, vrfLink, peerLink, tableID); err != nil {
			return err
		}

		if err := removeEgressDatapath(tableID); err != nil {
			return fmt.Errorf("removeEgressDatapath: %w", err)
		}
		return assertTornDown(ifindexTable, registry, peer, uint32(peerLink.Attrs().Index), tableID)
	})
	if err != nil {
		t.Fatal(err)
	}
}
