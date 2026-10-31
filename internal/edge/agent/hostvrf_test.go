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
)

// vpcAbsent has no canonical host VRF in the test host: no workload of it
// runs on the node.
const vpcAbsent = "00000000z"

// TestHostVRFMissing reports an attachment whose gVPC has no host VRF on the
// node, or whose host VRF the datapath has no uSID entry for, as
// HostVRFMissing rather than a generic failure, and brings no link up for it.
func TestHostVRFMissing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vpc     string
		failReg error
	}{
		{name: "no host VRF", vpc: vpcAbsent},
		{name: "no uSID entry", vpc: vpcA,
			failReg: fmt.Errorf("%w: table %d", attachreg.ErrVRFNotRegistered, vrfTables[vpcA])},
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
			for _, l := range f.links() {
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
		})
	}
}
