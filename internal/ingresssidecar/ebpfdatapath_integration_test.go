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
	"go.datum.net/galactic/internal/plumbing/ebpf/markvrfmap"
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

// assertTrunkWiring checks the kernel-side mechanics ensureTrunk is
// responsible for, once for the whole shared trunk (not per-VPC, unlike
// the removed per-VPC veth this test used to assert): inner deliberately
// NOT enslaved into any VRF (a single trunk cannot belong to more than one
// VPC's VRF), and usid_egress attached exactly once, on the peer's ingress
// hook -- never the trunk's own egress hook, the same "never fires" finding
// this test file has asserted since before the trunk existed (see
// ensureTrunk's own doc comment).
func assertTrunkWiring(innerLink, peerLink netlink.Link) error {
	if innerLink.Attrs().MasterIndex != 0 {
		return fmt.Errorf("trunk inner end has master ifindex %d, want 0 (unenslaved)", innerLink.Attrs().MasterIndex)
	}

	peerFilters, err := netlink.FilterList(peerLink, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return fmt.Errorf("list ingress filters on trunk peer: %w", err)
	}
	if len(peerFilters) != 1 {
		return fmt.Errorf("trunk peer has %d ingress filter(s), want exactly 1 (usid_egress, attached once)",
			len(peerFilters))
	}

	innerFilters, err := netlink.FilterList(innerLink, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return fmt.Errorf("list egress filters on trunk inner end: %w", err)
	}
	if len(innerFilters) != 0 {
		return fmt.Errorf("trunk inner end has %d egress filter(s), want none -- "+
			"usid_egress belongs on the peer's ingress hook, not here", len(innerFilters))
	}
	return nil
}

// assertVRFRoute checks that vrfLink's own table has the per-VPC default
// route ensureVRFRoute installs, via the shared trunk's inner end -- every
// VPC sharing the trunk gets its own route in its own table, all naming
// the same nexthop device.
func assertVRFRoute(vrfLink *netlink.Vrf, innerLink netlink.Link) error {
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V6, &netlink.Route{Table: int(vrfLink.Table)}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list routes in VRF table %d: %w", vrfLink.Table, err)
	}
	for _, r := range routes {
		if r.LinkIndex == innerLink.Attrs().Index && (r.Dst == nil || r.Dst.String() == "::/0") {
			return nil
		}
	}
	return fmt.Errorf("no default route via the trunk inner end in VRF table %d, want one (routes: %+v)",
		vrfLink.Table, routes)
}

// assertNoVRFRoute checks that removeVRFRoute actually removed vrfLink's
// own default route -- without touching the trunk itself.
func assertNoVRFRoute(vrfLink *netlink.Vrf) error {
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V6, &netlink.Route{Table: int(vrfLink.Table)}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list routes in VRF table %d: %w", vrfLink.Table, err)
	}
	for _, r := range routes {
		if r.Dst == nil || r.Dst.String() == "::/0" {
			return fmt.Errorf("VRF table %d still has a default route after removeVRFRoute: %+v", vrfLink.Table, r)
		}
	}
	return nil
}

// assertMapState checks vrf_table/mark_vrf_table read back exactly what
// ensureEgressDatapath's own doc comment promises for tableID's VPC, and
// that ifindex_vrf_table has no entry at all for the trunk peer's ifindex
// -- that absence is exactly what makes usid_egress's mark fallback engage
// for trunk-arriving traffic (usid.c's own dispatch comment).
func assertMapState(
	ifindexTable *ifindexvrfmap.IfindexVRFTable, markTable *markvrfmap.MarkVRFTable, registry *usidmap.Registry,
	peerLink netlink.Link, tableID uint32,
) error {
	if _, ok, err := ifindexTable.Get(uint32(peerLink.Attrs().Index)); err != nil {
		return fmt.Errorf("look up ifindex_vrf_table[trunk peer]: %w", err)
	} else if ok {
		return errors.New("ifindex_vrf_table has an entry for the trunk peer's ifindex, want none")
	}

	mark, err := markForTableID(tableID)
	if err != nil {
		return fmt.Errorf("markForTableID(%d): %w", tableID, err)
	}
	markEntry, ok, err := markTable.Get(mark)
	if err != nil {
		return fmt.Errorf("look up mark_vrf_table[%d]: %w", mark, err)
	}
	if !ok {
		return fmt.Errorf("mark_vrf_table has no entry for mark %d (table %d)", mark, tableID)
	}
	if markEntry.Block != ingressSidecarBlock || markEntry.Argument != uint16(tableID) {
		return fmt.Errorf("mark_vrf_table[%d] = (block=%#x, argument=%d), want (block=%#x, argument=%d)",
			mark, markEntry.Block, markEntry.Argument, ingressSidecarBlock, tableID)
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

// assertVPCTornDown checks removeEgressDatapath's own per-VPC contract:
// this VPC's own route and map entries are gone. Unlike the removed
// per-VPC veth this test used to assert, it does NOT check that any
// interface is gone -- the shared trunk is this process's own, not this
// one VPC's, and must survive (see assertTrunkSurvives).
func assertVPCTornDown(
	markTable *markvrfmap.MarkVRFTable, registry *usidmap.Registry, vrfLink *netlink.Vrf, tableID uint32,
) error {
	if err := assertNoVRFRoute(vrfLink); err != nil {
		return err
	}
	mark, err := markForTableID(tableID)
	if err != nil {
		return fmt.Errorf("markForTableID(%d): %w", tableID, err)
	}
	if _, ok, err := markTable.Get(mark); err != nil {
		return fmt.Errorf("look up mark_vrf_table[%d] after removal: %w", mark, err)
	} else if ok {
		return fmt.Errorf("mark_vrf_table[%d] still present after removeEgressDatapath", mark)
	}
	if _, ok, err := registry.VRF.Get(ingressSidecarBlock, uint16(tableID)); err != nil {
		return fmt.Errorf("look up vrf_table entry after removal: %w", err)
	} else if ok {
		return errors.New("vrf_table entry still present after removeEgressDatapath")
	}
	return nil
}

// assertTrunkSurvives checks that the shared trunk veth pair and its
// usid_egress attachment are both still exactly as they were -- the
// inverse of the old per-VPC test's "veth gone after removal" assertion,
// since the trunk is process-lifetime now, not per-VPC-lifetime (see
// removeEgressDatapath's own doc comment).
func assertTrunkSurvives() error {
	innerLink, err := netlink.LinkByName(trunkInnerName)
	if err != nil {
		return fmt.Errorf("trunk inner end %q gone, want it to persist: %w", trunkInnerName, err)
	}
	peerLink, err := netlink.LinkByName(trunkPeerName)
	if err != nil {
		return fmt.Errorf("trunk peer %q gone, want it to persist: %w", trunkPeerName, err)
	}
	return assertTrunkWiring(innerLink, peerLink)
}

// TestEnsureEgressDatapath_SharedTrunkAcrossVPCs is the trunk redesign's
// own exit criterion: two VPCs sharing this pod's one trunk must both
// resolve correctly (disambiguated by mark, since the trunk's single
// ifindex can't disambiguate them the way a per-attachment ifindex does),
// and tearing one VPC down must not disturb the trunk itself or the other
// VPC's still-live state -- the trunk only ever goes away with the
// process. This replaces TestEnsureEgressDatapath_AttachesToVethPeerNotVRF
// (the per-VPC-veth predecessor this design replaced); its own "attach on
// the peer's ingress, never the VRF/trunk's own egress" assertion survives
// here as assertTrunkWiring.
func TestEnsureEgressDatapath_SharedTrunkAcrossVPCs(t *testing.T) {
	requireRoot(t)
	setUpTestPinDir(t)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	const table1 = uint32(7)
	const table2 = uint32(8)
	const vrf1Name = "gttestvrf1"
	const vrf2Name = "gttestvrf2"

	err = nsObj.Do(func(_ ns.NetNS) error {
		vrf1 := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: vrf1Name}, Table: table1}
		if err := netlink.LinkAdd(vrf1); err != nil {
			return fmt.Errorf("add VRF 1: %w", err)
		}
		if err := netlink.LinkSetUp(vrf1); err != nil {
			return fmt.Errorf("set VRF 1 up: %w", err)
		}

		vrf2 := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: vrf2Name}, Table: table2}
		if err := netlink.LinkAdd(vrf2); err != nil {
			return fmt.Errorf("add VRF 2: %w", err)
		}
		if err := netlink.LinkSetUp(vrf2); err != nil {
			return fmt.Errorf("set VRF 2 up: %w", err)
		}

		// Two VPCs activating on this one pod -- both must converge onto
		// the same shared trunk, not a dedicated interface each.
		if err := ensureEgressDatapath(table1); err != nil {
			return fmt.Errorf("ensureEgressDatapath(table1): %w", err)
		}
		if err := ensureEgressDatapath(table2); err != nil {
			return fmt.Errorf("ensureEgressDatapath(table2): %w", err)
		}

		innerLink, err := netlink.LinkByName(trunkInnerName)
		if err != nil {
			return fmt.Errorf("look up trunk inner end %q: %w", trunkInnerName, err)
		}
		peerLink, err := netlink.LinkByName(trunkPeerName)
		if err != nil {
			return fmt.Errorf("look up trunk peer %q: %w", trunkPeerName, err)
		}

		if err := assertTrunkWiring(innerLink, peerLink); err != nil {
			return err
		}
		if err := assertVRFRoute(vrf1, innerLink); err != nil {
			return err
		}
		if err := assertVRFRoute(vrf2, innerLink); err != nil {
			return err
		}

		ifindexTable, closer, err := ifindexvrfmap.OpenPinned(ebpfPinDir)
		if err != nil {
			return fmt.Errorf("open pinned ifindex_vrf_table: %w", err)
		}
		defer func() { _ = closer.Close() }()

		markTable, mcloser, err := markvrfmap.OpenPinned(ebpfPinDir)
		if err != nil {
			return fmt.Errorf("open pinned mark_vrf_table: %w", err)
		}
		defer func() { _ = mcloser.Close() }()

		registry, rcloser, err := usidmap.OpenPinnedRegistry(ebpfPinDir)
		if err != nil {
			return fmt.Errorf("open pinned vrf_table: %w", err)
		}
		defer func() { _ = rcloser.Close() }()

		if err := assertMapState(ifindexTable, markTable, registry, peerLink, table1); err != nil {
			return fmt.Errorf("VPC 1: %w", err)
		}
		if err := assertMapState(ifindexTable, markTable, registry, peerLink, table2); err != nil {
			return fmt.Errorf("VPC 2: %w", err)
		}

		// Tear down VPC 1 only.
		if err := removeEgressDatapath(table1); err != nil {
			return fmt.Errorf("removeEgressDatapath(table1): %w", err)
		}
		if err := assertVPCTornDown(markTable, registry, vrf1, table1); err != nil {
			return fmt.Errorf("VPC 1 after its own removal: %w", err)
		}
		// The trunk, its attachment, and VPC 2's still-live state must all
		// survive VPC 1's teardown.
		if err := assertTrunkSurvives(); err != nil {
			return fmt.Errorf("after removing VPC 1: %w", err)
		}
		if err := assertMapState(ifindexTable, markTable, registry, peerLink, table2); err != nil {
			return fmt.Errorf("VPC 2 after VPC 1's removal: %w", err)
		}

		// Tear down VPC 2.
		if err := removeEgressDatapath(table2); err != nil {
			return fmt.Errorf("removeEgressDatapath(table2): %w", err)
		}
		if err := assertVPCTornDown(markTable, registry, vrf2, table2); err != nil {
			return fmt.Errorf("VPC 2 after its own removal: %w", err)
		}
		// Both VPCs are gone, but the shared trunk itself must still exist
		// -- it is process-lifetime, not per-VPC-lifetime.
		return assertTrunkSurvives()
	})
	if err != nil {
		t.Fatal(err)
	}
}
