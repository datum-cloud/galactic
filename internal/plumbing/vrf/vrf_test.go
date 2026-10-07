// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vrf_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_NET_ADMIN) to create real VRF interfaces; re-run via sudo")
	}
}

// TestAdd_SharedAcrossCallers is the core regression test for VRF-per-VPC
// sharing: two "attachments" (simulated here by two independent Add calls
// for the same VPC, exactly what two sibling CNI ADD invocations for
// different vpcAttachment values under one VPC do in production) must
// converge on the identical kernel VRF interface and routing table, not
// create — or worse, clobber — a second one.
func TestAdd_SharedAcrossCallers(t *testing.T) {
	requireRoot(t)
	const vpc = "vtshr"
	t.Cleanup(func() { _ = vrf.Delete(vpc) })

	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	firstTableID, err := vrf.TableID(vpc)
	if err != nil {
		t.Fatalf("TableID after first Add: %v", err)
	}

	// A second "attachment" on the same VPC.
	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("second Add: %v", err)
	}
	secondTableID, err := vrf.TableID(vpc)
	if err != nil {
		t.Fatalf("TableID after second Add: %v", err)
	}

	if firstTableID != secondTableID {
		t.Errorf("table ID changed across two Add calls for the same VPC: %d != %d — "+
			"a second attachment must reuse the first's VRF, not replace it", firstTableID, secondTableID)
	}

	if err := vrf.Exists(vpc); err != nil {
		t.Errorf("Exists after two Add calls: %v", err)
	}
}

// TestAdd_DifferentVPCsGetDistinctVRFs verifies the flip side of sharing:
// two different VPCs never collide on the same kernel VRF/table, even when
// created back-to-back.
func TestAdd_DifferentVPCsGetDistinctVRFs(t *testing.T) {
	requireRoot(t)
	const vpcA, vpcB = "vtda", "vtdb"
	t.Cleanup(func() { _ = vrf.Delete(vpcA) })
	t.Cleanup(func() { _ = vrf.Delete(vpcB) })

	if err := vrf.Add(vpcA); err != nil {
		t.Fatalf("Add(%q): %v", vpcA, err)
	}
	if err := vrf.Add(vpcB); err != nil {
		t.Fatalf("Add(%q): %v", vpcB, err)
	}

	tableA, err := vrf.TableID(vpcA)
	if err != nil {
		t.Fatalf("TableID(%q): %v", vpcA, err)
	}
	tableB, err := vrf.TableID(vpcB)
	if err != nil {
		t.Fatalf("TableID(%q): %v", vpcB, err)
	}
	if tableA == tableB {
		t.Errorf("two different VPCs resolved to the same table ID %d, want distinct", tableA)
	}

	nameA := intf.GenerateInterfaceNameVRF(vpcA)
	nameB := intf.GenerateInterfaceNameVRF(vpcB)
	if nameA == nameB {
		t.Fatalf("GenerateInterfaceNameVRF produced the same name %q for two different VPCs", nameA)
	}
}

// unreachableDefaultsIn returns the families for which tableID holds an
// unreachable default route at vrf.UnreachableDefaultMetric. It takes no
// *testing.T so goroutines can call it.
func unreachableDefaultsIn(tableID uint32) (map[int]bool, error) {
	found := map[int]bool{}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(family,
			&netlink.Route{Table: int(tableID)}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return nil, fmt.Errorf("list routes in table %d: %w", tableID, err)
		}
		for _, r := range routes {
			if r.Dst == nil {
				continue
			}
			ones, _ := r.Dst.Mask.Size()
			if r.Type == unix.RTN_UNREACHABLE && ones == 0 && r.Priority == vrf.UnreachableDefaultMetric {
				found[family] = true
			}
		}
	}
	return found, nil
}

// unreachableDefaults is unreachableDefaultsIn for the test goroutine.
func unreachableDefaults(t *testing.T, tableID uint32) map[int]bool {
	t.Helper()
	found, err := unreachableDefaultsIn(tableID)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// TestAdd_InstallsUnreachableDefaults is the regression test for tenant
// traffic leaking out of its VRF. Without an unreachable default in the VRF's
// table, a lookup that misses there falls through to the main table, and the
// host routes the tenant's packet out its own default interface.
func TestAdd_InstallsUnreachableDefaults(t *testing.T) {
	requireRoot(t)
	const vpc = "vtunr"
	t.Cleanup(func() { _ = vrf.Delete(vpc) })

	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("Add: %v", err)
	}
	tableID, err := vrf.TableID(vpc)
	if err != nil {
		t.Fatalf("TableID: %v", err)
	}

	got := unreachableDefaults(t, tableID)
	if !got[unix.AF_INET] || !got[unix.AF_INET6] {
		t.Fatalf("unreachable defaults in table %d = %v, want both IPv4 and IPv6", tableID, got)
	}

	// The second Add takes the already-exists path. It must leave the routes in
	// place, and must restore them on a VRF that lacks them, which is what a
	// VRF created before this fix looks like.
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		dst := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
		if family == unix.AF_INET6 {
			dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
		}
		if err := netlink.RouteDel(&netlink.Route{
			Dst: dst, Table: int(tableID), Type: unix.RTN_UNREACHABLE, Priority: vrf.UnreachableDefaultMetric,
		}); err != nil {
			t.Fatalf("delete unreachable default %s: %v", dst, err)
		}
	}
	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("second Add: %v", err)
	}
	got = unreachableDefaults(t, tableID)
	if !got[unix.AF_INET] || !got[unix.AF_INET6] {
		t.Errorf("unreachable defaults after re-Add of an existing VRF = %v, want both IPv4 and IPv6", got)
	}
}

// TestAdd_LookupMissDoesNotLeakToMainTable is the end-to-end regression test
// for the leak itself, as it was found on a lab node: a VRF lookup for an
// off-VRF destination resolved through the main table's default route and
// left by the host's own uplink. The main table here gets a default route of
// its own for each family, so a lookup that falls through has something real
// to land on, exactly as on a node. Inside the VRF, both lookups must fail.
func TestAdd_LookupMissDoesNotLeakToMainTable(t *testing.T) {
	requireRoot(t)
	const vpc = "vtlk"
	t.Cleanup(func() { _ = vrf.Delete(vpc) })

	uplink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "vrflkup0"}}
	if err := netlink.LinkAdd(uplink); err != nil {
		t.Fatalf("add stand-in uplink: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(uplink) })
	if err := netlink.LinkSetUp(uplink); err != nil {
		t.Fatalf("set uplink up: %v", err)
	}
	for _, addr := range []string{"192.0.2.10/24", "2001:db8:aa::10/64"} {
		a, err := netlink.ParseAddr(addr)
		if err != nil {
			t.Fatalf("parse %s: %v", addr, err)
		}
		a.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrAdd(uplink, a); err != nil {
			t.Fatalf("add %s to uplink: %v", addr, err)
		}
	}
	for _, gw := range []string{"192.0.2.1", "2001:db8:aa::1"} {
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: uplink.Attrs().Index, Gw: net.ParseIP(gw)}); err != nil {
			t.Fatalf("add main-table default via %s: %v", gw, err)
		}
	}

	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("Add: %v", err)
	}
	vrfName := intf.GenerateInterfaceNameVRF(vpc)

	for _, dst := range []string{"198.51.100.7", "2001:db8:64::a01:2802"} {
		// Sanity: the main table does route it, so a fall-through would succeed.
		if _, err := netlink.RouteGet(net.ParseIP(dst)); err != nil {
			t.Fatalf("main-table lookup for %s failed (%v); the test setup is not reproducing a node", dst, err)
		}
		routes, err := netlink.RouteGetWithOptions(net.ParseIP(dst), &netlink.RouteGetOptions{VrfName: vrfName})
		if err == nil {
			t.Errorf("lookup for %s in VRF %s = %v, want no route: it fell through to the main table", dst, vrfName, routes)
			continue
		}
		if !errors.Is(err, unix.EHOSTUNREACH) && !errors.Is(err, unix.ENETUNREACH) {
			t.Errorf("lookup for %s in VRF %s failed with %v, want host or network unreachable", dst, vrfName, err)
		}
	}
}

// TestAdd_RealDefaultRouteOutranksUnreachable guards the ingress sidecar,
// which installs a real IPv6 default in its VRF's table. The catch-all must
// only ever catch what nothing else does, so a default at the kernel's
// ordinary metric has to win the lookup.
func TestAdd_RealDefaultRouteOutranksUnreachable(t *testing.T) {
	requireRoot(t)
	const vpc = "vtrd"
	t.Cleanup(func() { _ = vrf.Delete(vpc) })

	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("Add: %v", err)
	}
	tableID, err := vrf.TableID(vpc)
	if err != nil {
		t.Fatalf("TableID: %v", err)
	}
	vrfLink, err := netlink.LinkByName(intf.GenerateInterfaceNameVRF(vpc))
	if err != nil {
		t.Fatalf("find VRF link: %v", err)
	}

	inner := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "vrfrdin0", MasterIndex: vrfLink.Attrs().Index}}
	if err := netlink.LinkAdd(inner); err != nil {
		t.Fatalf("add VRF member: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(inner) })
	if err := netlink.LinkSetUp(inner); err != nil {
		t.Fatalf("set member up: %v", err)
	}
	if err := netlink.RouteAdd(&netlink.Route{
		Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Table:     int(tableID),
		LinkIndex: inner.Attrs().Index,
	}); err != nil {
		t.Fatalf("add real default in VRF table: %v", err)
	}

	routes, err := netlink.RouteGetWithOptions(net.ParseIP("2001:db8:64::1"),
		&netlink.RouteGetOptions{VrfName: vrfLink.Attrs().Name})
	if err != nil {
		t.Fatalf("lookup in VRF with a real default = %v, want it routed via the real default", err)
	}
	if len(routes) == 0 || routes[0].LinkIndex != inner.Attrs().Index {
		t.Errorf("lookup in VRF resolved to %v, want the real default via %s", routes, inner.Name)
	}

	// Ensuring again must not displace the real route either.
	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("second Add: %v", err)
	}
	if routes, err := netlink.RouteGetWithOptions(net.ParseIP("2001:db8:64::1"),
		&netlink.RouteGetOptions{VrfName: vrfLink.Attrs().Name}); err != nil || routes[0].LinkIndex != inner.Attrs().Index {
		t.Errorf("after second Add, lookup = %v, %v, want the real default via %s", routes, err, inner.Name)
	}
}

// TestAdd_UnreachableDefaultsAreNotDuplicated checks the ensure is a replace,
// not an append: many Adds for one VPC, as every attachment's ADD does, leave
// exactly one catch-all per family.
func TestAdd_UnreachableDefaultsAreNotDuplicated(t *testing.T) {
	requireRoot(t)
	const vpc = "vtdup"
	t.Cleanup(func() { _ = vrf.Delete(vpc) })

	for i := range 5 {
		if err := vrf.Add(vpc); err != nil {
			t.Fatalf("Add #%d: %v", i+1, err)
		}
	}
	tableID, err := vrf.TableID(vpc)
	if err != nil {
		t.Fatalf("TableID: %v", err)
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: int(tableID)}, netlink.RT_FILTER_TABLE)
		if err != nil {
			t.Fatalf("list routes: %v", err)
		}
		n := 0
		for _, r := range routes {
			if r.Type == unix.RTN_UNREACHABLE {
				n++
			}
		}
		if n != 1 {
			t.Errorf("family %d: %d unreachable routes after 5 Adds, want exactly 1", family, n)
		}
	}
}

// TestAdd_ConcurrentCallersAllSeeUnreachableDefaults covers sibling ADDs racing
// on a VPC's first attachment: whichever creates the VRF, no caller returns
// before the catch-all is in place, and none of them errors.
func TestAdd_ConcurrentCallersAllSeeUnreachableDefaults(t *testing.T) {
	requireRoot(t)
	const vpc = "vtcc"
	t.Cleanup(func() { _ = vrf.Delete(vpc) })

	const callers = 8
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			if err := vrf.Add(vpc); err != nil {
				errs <- err
				return
			}
			tableID, err := vrf.TableID(vpc)
			if err != nil {
				errs <- err
				return
			}
			got, err := unreachableDefaultsIn(tableID)
			if err != nil {
				errs <- err
				return
			}
			if !got[unix.AF_INET] || !got[unix.AF_INET6] {
				errs <- fmt.Errorf("Add returned before both catch-alls were installed: %v", got)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestAdd_NameTakenByNonVRFIsAnError covers the already-exists branch finding
// an interface that is not a VRF. Treating it as success would leave the
// attachment routed in a table that does not exist, with no catch-all.
func TestAdd_NameTakenByNonVRFIsAnError(t *testing.T) {
	requireRoot(t)
	const vpc = "vtnv"
	squatter := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: intf.GenerateInterfaceNameVRF(vpc)}}
	if err := netlink.LinkAdd(squatter); err != nil {
		t.Fatalf("add squatting dummy: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(squatter) })

	if err := vrf.Add(vpc); err == nil {
		t.Error("Add with the VRF's name held by a dummy = nil, want an error")
	}
}

// TestDelete_RemovesUnreachableDefaults checks Delete's flush covers the
// catch-alls too, so a table ID freed here and reused by a later VRF starts
// empty rather than inheriting state.
func TestDelete_RemovesUnreachableDefaults(t *testing.T) {
	requireRoot(t)
	const vpc = "vtdel"
	t.Cleanup(func() { _ = vrf.Delete(vpc) })

	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("Add: %v", err)
	}
	tableID, err := vrf.TableID(vpc)
	if err != nil {
		t.Fatalf("TableID: %v", err)
	}
	if err := vrf.Delete(vpc); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := unreachableDefaults(t, tableID); len(got) != 0 {
		t.Errorf("table %d still holds unreachable defaults %v after Delete, want none", tableID, got)
	}
}

// TestDelete_Idempotent covers Delete's documented idempotency: deleting a
// VRF that was never created (or already gone) is not an error.
func TestDelete_Idempotent(t *testing.T) {
	requireRoot(t)
	if err := vrf.Delete("vtnone"); err != nil {
		t.Errorf("Delete on a nonexistent VRF = %v, want nil", err)
	}
}

// TestExists_NotFound covers Exists returning an error for a VPC with no
// kernel VRF at all.
func TestExists_NotFound(t *testing.T) {
	requireRoot(t)
	if err := vrf.Exists("vtnone"); err == nil {
		t.Error("Exists for a nonexistent VRF = nil, want an error")
	}
}

// TestTableID_NotFound covers TableID returning an error for a VPC with no
// kernel VRF at all, rather than a zero-value table ID that could be
// mistaken for a real one.
func TestTableID_NotFound(t *testing.T) {
	requireRoot(t)
	if _, err := vrf.TableID("vtnone"); err == nil {
		t.Error("TableID for a nonexistent VRF = nil error, want an error")
	}
}

// TestDelete_ThenAddRecreates covers the sequential-reuse case documented on
// Add/Delete: once every attachment on a VPC is gone and GC deletes the VRF,
// a later attachment on the same VPC gets a fresh VRF rather than erroring
// out because "something" still looks present.
func TestDelete_ThenAddRecreates(t *testing.T) {
	requireRoot(t)
	const vpc = "vtre1"
	t.Cleanup(func() { _ = vrf.Delete(vpc) })

	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := vrf.Delete(vpc); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := vrf.Exists(vpc); err == nil {
		t.Fatal("Exists after Delete = nil, want an error (VRF should be gone)")
	}
	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("Add after Delete: %v", err)
	}
	if err := vrf.Exists(vpc); err != nil {
		t.Errorf("Exists after re-Add: %v", err)
	}
}

// TestListVRFLinks_SurvivesLinkChurn lists VRFs while other goroutines add and
// remove unrelated links. A single-attempt dump fails this with
// ErrDumpInterrupted; the retrying dump must not.
//
// A few hundred stable links keep each dump long enough for a change to land
// inside it.
func TestListVRFLinks_SurvivesLinkChurn(t *testing.T) {
	requireRoot(t)

	const stable, churners = 300, 2
	for i := range stable {
		link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: fmt.Sprintf("vrfstab%d", i)}}
		if err := netlink.LinkAdd(link); err != nil {
			t.Fatalf("add stable link %d: %v", i, err)
		}
		t.Cleanup(func() { _ = netlink.LinkDel(link) })
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for c := range churners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: fmt.Sprintf("vrfchurn%d_%d", c, i%4)}}
				if err := netlink.LinkAdd(dummy); err == nil {
					_ = netlink.LinkDel(dummy)
				}
				// Bursts of changes, not a saturated loop: a node sees link
				// churn in bursts, and a loop that never pauses can outlast
				// any bounded retry.
				time.Sleep(2 * time.Millisecond)
			}
		}()
	}
	t.Cleanup(func() {
		close(stop)
		wg.Wait()
	})

	for i := range 100 {
		if _, err := vrf.ListVRFLinks(); err != nil {
			t.Fatalf("ListVRFLinks failed on iteration %d while links were changing: %v", i, err)
		}
	}
}

// TestAddInRange_AllocatesInsideTheRange covers the ingress sidecar's use of
// AddInRange (#716): its VRFs must take table IDs from its own range, never
// the host's.
func TestAddInRange_AllocatesInsideTheRange(t *testing.T) {
	requireRoot(t)
	const vpc = "vtrng"
	t.Cleanup(func() { _ = vrf.Delete(vpc) })

	minID, maxID := vrf.SidecarTableIDBase+1, vrf.SidecarTableIDBase+0xFFF
	if err := vrf.AddInRange(vpc, minID, maxID); err != nil {
		t.Fatalf("AddInRange: %v", err)
	}
	tableID, err := vrf.TableID(vpc)
	if err != nil {
		t.Fatalf("TableID: %v", err)
	}
	if tableID < minID || tableID > maxID {
		t.Fatalf("table ID %d outside [%d,%d]", tableID, minID, maxID)
	}

	// The same VPC from a caller with a different range is an error, not a
	// silent reuse of a table that may belong to the other writer.
	if err := vrf.Add(vpc); err == nil {
		t.Fatalf("Add of a VRF whose table %d is outside the host range = nil, want an error", tableID)
	}
}
