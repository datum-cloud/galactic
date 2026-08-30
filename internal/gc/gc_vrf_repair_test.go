// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

// withFakeLinks temporarily overrides listVRFLinksFn/listAllLinksFn for the
// duration of one test, restoring the real (kernel-touching) functions on
// cleanup -- the same seam attach.go's preflightCheckFn gives its own
// callers, so resolveVRFKernelState is testable without CAP_NET_ADMIN or a
// real kernel VRF interface.
func withFakeLinks(t *testing.T, vrfLinks []*netlink.Vrf, allLinks []netlink.Link) {
	t.Helper()
	origVRF, origAll := listVRFLinksFn, listAllLinksFn
	listVRFLinksFn = func() ([]*netlink.Vrf, error) { return vrfLinks, nil }
	listAllLinksFn = func() ([]netlink.Link, error) { return allLinks, nil }
	t.Cleanup(func() { listVRFLinksFn, listAllLinksFn = origVRF, origAll })
}

func TestResolveVRFKernelState(t *testing.T) {
	const nodeName = "worker-a"
	const vpc = "jU"
	instName := crdnames.BGPVRFInstanceName(vpc, nodeName)

	vrfLink := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: testVRFName, Index: 42},
		Table:     7,
	}

	t.Run("matches and reads egress kind from an enslaved veth", func(t *testing.T) {
		vethSlave := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "G000000jUabcH", MasterIndex: vrfLink.Index},
		}
		withFakeLinks(t, []*netlink.Vrf{vrfLink}, []netlink.Link{vethSlave})

		tableID, kind, ok, err := resolveVRFKernelState(nodeName, instName)
		if err != nil {
			t.Fatalf("resolveVRFKernelState: %v", err)
		}
		if !ok {
			t.Fatalf("resolveVRFKernelState() ok = false, want true")
		}
		if tableID != vrfLink.Table {
			t.Errorf("vrfTableID = %d, want %d", tableID, vrfLink.Table)
		}
		if kind != usidmap.EgressKindVeth {
			t.Errorf("egressKind = %d, want EgressKindVeth (%d)", kind, usidmap.EgressKindVeth)
		}
	})

	t.Run("matches and reads egress kind from an enslaved tap", func(t *testing.T) {
		tapSlave := &netlink.Tuntap{
			LinkAttrs: netlink.LinkAttrs{Name: "G000000jUabcH", MasterIndex: vrfLink.Index},
		}
		withFakeLinks(t, []*netlink.Vrf{vrfLink}, []netlink.Link{tapSlave})

		_, kind, ok, err := resolveVRFKernelState(nodeName, instName)
		if err != nil {
			t.Fatalf("resolveVRFKernelState: %v", err)
		}
		if !ok {
			t.Fatalf("resolveVRFKernelState() ok = false, want true")
		}
		if kind != usidmap.EgressKindTap {
			t.Errorf("egressKind = %d, want EgressKindTap (%d)", kind, usidmap.EgressKindTap)
		}
	})

	t.Run("matches with no enslaved interface defaults to veth", func(t *testing.T) {
		withFakeLinks(t, []*netlink.Vrf{vrfLink}, nil)

		tableID, kind, ok, err := resolveVRFKernelState(nodeName, instName)
		if err != nil {
			t.Fatalf("resolveVRFKernelState: %v", err)
		}
		if !ok {
			t.Fatalf("resolveVRFKernelState() ok = false, want true")
		}
		if tableID != vrfLink.Table {
			t.Errorf("vrfTableID = %d, want %d", tableID, vrfLink.Table)
		}
		if kind != usidmap.EgressKindVeth {
			t.Errorf("egressKind = %d, want EgressKindVeth (%d) as the no-slave default", kind, usidmap.EgressKindVeth)
		}
	})

	t.Run("no matching kernel VRF interface is not an error", func(t *testing.T) {
		other := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "G000000otherV", Index: 99}, Table: 3}
		withFakeLinks(t, []*netlink.Vrf{other}, nil)

		_, _, ok, err := resolveVRFKernelState(nodeName, instName)
		if err != nil {
			t.Fatalf("resolveVRFKernelState: %v", err)
		}
		if ok {
			t.Errorf("resolveVRFKernelState() ok = true, want false (no matching kernel VRF)")
		}
	})

	t.Run("propagates a listVRFLinksFn error", func(t *testing.T) {
		orig := listVRFLinksFn
		t.Cleanup(func() { listVRFLinksFn = orig })
		wantErr := errors.New("netlink boom")
		listVRFLinksFn = func() ([]*netlink.Vrf, error) { return nil, wantErr }

		_, _, _, err := resolveVRFKernelState(nodeName, instName)
		if !errors.Is(err, wantErr) {
			t.Errorf("resolveVRFKernelState() err = %v, want wrapping %v", err, wantErr)
		}
	})

	t.Run("legacy-encoded CRD name still resolves", func(t *testing.T) {
		// vpcKeys(vpc) joins both the raw VPC and its nameSegment-encoded
		// form, so a CRD named from the pre-encoding-change convention
		// (raw vpc, not crdnames.VPCSegment(vpc)) must resolve exactly the
		// same way a current-shape name does.
		legacyInstName := vpc + "-" + nodeName
		withFakeLinks(t, []*netlink.Vrf{vrfLink}, nil)

		_, _, ok, err := resolveVRFKernelState(nodeName, legacyInstName)
		if err != nil {
			t.Fatalf("resolveVRFKernelState: %v", err)
		}
		if !ok {
			t.Errorf("resolveVRFKernelState() ok = false, want true for legacy-shaped CRD name")
		}
	})
}
