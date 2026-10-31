// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
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

// vpcAbsent has no canonical host VRF in the test host until a test creates
// it: no workload of it runs on the node.
const (
	vpcAbsent      = "00000000z"
	vpcAbsentTable = 1009
)

// TestHostVRFMissing reports an attachment whose gVPC has no host VRF on the
// node, or whose host VRF the datapath has no uSID entry for, as
// HostVRFMissing rather than a generic failure, and brings no link up for it.
// Once a workload of the gVPC provides both, the next pass programs it.
func TestHostVRFMissing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vpc     string
		failReg error
		// noLink is whether the attachment must get no host link at all.
		noLink bool
		// arrive stands in for a workload of the gVPC arriving on the node.
		arrive func(f *fixture)
	}{
		{name: "no host VRF", vpc: vpcAbsent, noLink: true, arrive: func(f *fixture) {
			in(f.t, f.host, func() error {
				vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: intf.GenerateInterfaceNameVRF(vpcAbsent)},
					Table: vpcAbsentTable}
				if err := netlink.LinkAdd(vrf); err != nil {
					return err
				}
				return netlink.LinkSetUp(vrf)
			})
		}},
		{name: "no uSID entry", vpc: vpcA,
			failReg: fmt.Errorf("%w: table %d", attachreg.ErrVRFNotRegistered, vrfTables[vpcA]),
			arrive:  func(f *fixture) { f.dp.failRegister = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			a := f.agent()
			f.pod(pod1UID)
			f.dp.failRegister = tc.failReg
			f.attach("a", attA, pod1UID, tc.vpc, addr, true)
			f.reconcile(a)
			c := f.condition("a", galacticv1alpha1.EdgeAttachmentProgrammed)
			if c == nil || c.Status != metav1.ConditionFalse ||
				c.Reason != galacticv1alpha1.EdgeAttachmentReasonHostVRFMissing {
				t.Fatalf("Programmed = %+v, want False/%s", c, galacticv1alpha1.EdgeAttachmentReasonHostVRFMissing)
			}
			if !strings.Contains(c.Message, "workload of the VPC") {
				t.Fatalf("message %q does not say a workload of the VPC must run on the node", c.Message)
			}
			links := f.links()
			if tc.noLink && len(links) != 0 {
				t.Fatalf("links %+v for an attachment whose gVPC has no host VRF, want none", links)
			}
			for _, l := range links {
				in(t, f.host, func() error {
					link, err := netlink.LinkByIndex(l.HostIndex)
					if err != nil {
						return err
					}
					if link.Attrs().Flags&net.FlagUp != 0 {
						t.Errorf("host link %s is up for an attachment whose VRF is not usable", l.HostLink)
					}
					return nil
				})
			}

			tc.arrive(f)
			f.reconcile(a)
			if c := f.condition("a", galacticv1alpha1.EdgeAttachmentProgrammed); c == nil ||
				c.Status != metav1.ConditionTrue {
				t.Fatalf("Programmed after a workload of the gVPC arrived = %+v, want True", c)
			}
		})
	}
}
