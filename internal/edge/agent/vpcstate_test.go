// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// addVRF stands in for nodevpc.Ensure on the test host: it creates vpc's
// host VRF on vpcAbsentTable unless it exists, so repeated calls change
// nothing, as Ensure's do.
func addVRF(vpc string) error {
	name := intf.GenerateInterfaceNameVRF(vpc)
	if _, err := netlink.LinkByName(name); err == nil {
		return nil
	}
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: name}, Table: vpcAbsentTable}
	if err := netlink.LinkAdd(vrf); err != nil {
		return err
	}
	return netlink.LinkSetUp(vrf)
}

// TestVPCStateCreated programs, on its first pass, an attachment whose gVPC
// has no workload on the node: VPCState creates the gVPC's host VRF and uSID
// entry, and the host link joins that VRF. When VPCState fails, the
// attachment is refused as HostVRFMissing, naming the failure, with no link
// up.
func TestVPCStateCreated(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vpc     string
		failReg error
		// create stands in for nodevpc.Ensure on the test host.
		create func(f *fixture, vpc string) error
		// wantProgrammed is whether the first pass programs the attachment.
		wantProgrammed bool
	}{
		{name: "no host VRF", vpc: vpcAbsent, wantProgrammed: true, create: func(f *fixture, vpc string) error {
			in(f.t, f.host, func() error {
				return addVRF(vpc)
			})
			return nil
		}},
		{name: "no uSID entry", vpc: vpcA, wantProgrammed: true,
			failReg: fmt.Errorf("%w: table %d", attachreg.ErrVRFNotRegistered, vrfTables[vpcA]),
			create: func(f *fixture, _ string) error {
				f.dp.Lock()
				defer f.dp.Unlock()
				f.dp.failRegister = nil
				return nil
			}},
		{name: "creation fails", vpc: vpcAbsent, create: func(*fixture, string) error {
			return errors.New("no BGPRouter found for node")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			a := f.agent()
			var calls []string
			a.VPCState = func(vpc string) error {
				calls = append(calls, vpc)
				return tc.create(f, vpc)
			}
			f.pod(pod1UID)
			f.dp.failRegister = tc.failReg
			f.attach("a", attA, pod1UID, tc.vpc, addr, true)
			f.reconcile(a)

			if len(calls) == 0 {
				t.Fatalf("VPCState not called for %s", tc.vpc)
			}
			for _, vpc := range calls {
				if vpc != tc.vpc {
					t.Fatalf("VPCState calls = %v, want only %s", calls, tc.vpc)
				}
			}
			c := f.condition("a", galacticv1alpha1.EdgeAttachmentProgrammed)
			if !tc.wantProgrammed {
				if c == nil || c.Status != metav1.ConditionFalse ||
					c.Reason != galacticv1alpha1.EdgeAttachmentReasonHostVRFMissing {
					t.Fatalf("Programmed = %+v, want False/%s", c, galacticv1alpha1.EdgeAttachmentReasonHostVRFMissing)
				}
				if !strings.Contains(c.Message, "no BGPRouter found") {
					t.Fatalf("message %q does not name VPCState's failure", c.Message)
				}
				for _, l := range f.links() {
					in(t, f.host, func() error {
						link, err := netlink.LinkByIndex(l.HostIndex)
						if err != nil {
							return err
						}
						if link.Attrs().Flags&net.FlagUp != 0 {
							t.Errorf("host link %s is up though the VPC's node state was not created", l.HostLink)
						}
						return nil
					})
				}
				return
			}
			if c == nil || c.Status != metav1.ConditionTrue {
				t.Fatalf("Programmed on the first pass = %+v, want True", c)
			}
			links := f.links()
			if len(links) != 1 {
				t.Fatalf("links %+v, want one", links)
			}
			in(t, f.host, func() error {
				link, err := netlink.LinkByIndex(links[0].HostIndex)
				if err != nil {
					return err
				}
				vrf, err := netlink.LinkByName(intf.GenerateInterfaceNameVRF(tc.vpc))
				if err != nil {
					return err
				}
				if link.Attrs().MasterIndex != vrf.Attrs().Index {
					t.Errorf("host link %s has master %d, want the VPC's host VRF %d",
						links[0].HostLink, link.Attrs().MasterIndex, vrf.Attrs().Index)
				}
				return nil
			})
		})
	}
}

// TestVPCStateLifecycle runs garbage collection's VRF reclaim against a host
// VRF the agent created for an attachment whose gVPC had no workload on the
// node. The VRF stays while the attachment is active, across an agent
// restart, and after the attachment is released while a workload of the
// gVPC has since arrived. Once that workload leaves too, the next reclaim
// removes it.
func TestVPCStateLifecycle(t *testing.T) {
	f := newFixture(t)
	guard := f.guard()
	create := func(vpc string) error {
		in(f.t, f.host, func() error {
			return addVRF(vpc)
		})
		return nil
	}
	keeps := func(stage string) {
		t.Helper()
		res := f.reclaimVRF(guard, vpcAbsent)
		if res.Errors != 0 || res.OrphanedVRFsRemoved != 0 || !f.vrfExists(vpcAbsent) {
			t.Fatalf("%s: reclaim %+v removed a VRF still in use", stage, res)
		}
	}

	f.pod(pod1UID)
	f.attach("a", attA, pod1UID, vpcAbsent, addr, true)
	first := f.agent()
	first.VPCState = create
	f.reconcile(first)
	f.programmed("a")
	keeps("active")

	restarted := f.agent()
	restarted.VPCState = create
	f.reconcile(restarted)
	f.programmed("a")
	keeps("restart")

	// A workload of the gVPC arrives: its CNI host link joins the VRF.
	const workload = "G0000000zH"
	in(t, f.host, func() error {
		vrf, err := netlink.LinkByName(intf.GenerateInterfaceNameVRF(vpcAbsent))
		if err != nil {
			return err
		}
		return netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
			Name: workload, MasterIndex: vrf.Attrs().Index}})
	})
	if err := f.client.Delete(context.Background(), f.get("a")); err != nil {
		t.Fatal(err)
	}
	f.reconcile(restarted)
	if l := f.links(); len(l) != 0 {
		t.Fatalf("links after release: %+v", l)
	}
	keeps("released with a workload")

	// The workload leaves, and nothing on the node uses the gVPC.
	in(t, f.host, func() error {
		l, err := netlink.LinkByName(workload)
		if err != nil {
			return err
		}
		return netlink.LinkDel(l)
	})
	res := f.reclaimVRF(guard, vpcAbsent)
	if res.Errors != 0 || res.OrphanedVRFsRemoved != 1 || f.vrfExists(vpcAbsent) {
		t.Fatalf("reclaim with no user = %+v, VRF present %t; want it removed", res, f.vrfExists(vpcAbsent))
	}
}

// TestVPCStateEachPass makes the gVPC's node state whole on every pass while
// an attachment is live, even when the VRF and its row are in place, so a
// BGPVRFInstance removed under the attachment is created again within one
// resync. A pass with no live attachment of the gVPC does not call it.
func TestVPCStateEachPass(t *testing.T) {
	f := newFixture(t)
	a := f.agent()
	var calls int
	a.VPCState = func(vpc string) error {
		if vpc != vpcA {
			t.Errorf("VPCState for %s, want %s", vpc, vpcA)
		}
		calls++
		return nil
	}
	f.pod(pod1UID)
	f.attach("a", attA, pod1UID, vpcA, addr, true)
	f.reconcile(a)
	f.programmed("a")
	f.reconcile(a)
	if calls != 2 {
		t.Fatalf("VPCState calls over two passes = %d, want 2", calls)
	}
	if err := f.client.Delete(context.Background(), f.get("a")); err != nil {
		t.Fatal(err)
	}
	f.reconcile(a)
	f.reconcile(a)
	if calls != 2 {
		t.Fatalf("VPCState calls after the attachment's release = %d, want still 2", calls)
	}
}

// TestVPCStateRepairFailureKeepsOutcomes fails the per-pass repair of a gVPC
// whose VRF and row a workload already provides: the attachment is still
// programmed and reported Programmed, since the repair is best effort.
func TestVPCStateRepairFailureKeepsOutcomes(t *testing.T) {
	f := newFixture(t)
	a := f.agent()
	a.VPCState = func(string) error { return errors.New("API server unavailable") }
	f.pod(pod1UID)
	f.attach("a", attA, pod1UID, vpcA, addr, true)
	f.reconcile(a)
	f.programmed("a")
}
