// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/api/meta"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/edge/maintenance"
	"go.datum.net/galactic/internal/edge/ownership"
	"go.datum.net/galactic/internal/gc"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// guard returns garbage collection's view of the fixture's node, sharing the
// agent's write-fence directory.
func (f *fixture) guard() *maintenance.Guard {
	f.t.Helper()
	auth, err := ownership.Open(f.stateDir)
	if err != nil {
		f.t.Fatal(err)
	}
	return &maintenance.Guard{
		Reader: f.client, NodeName: node, Ownership: auth,
		HostLinks: func() ([]hostattach.ObservedAttachment, error) { return hostattach.List(f.hostNS) },
	}
}

// reclaimVRF runs garbage collection's removal of vpc's VRF in the test host,
// as it runs once no workload of vpc is left on the node.
func (f *fixture) reclaimVRF(guard gc.EdgeUsers, vpc string) gc.CleanupResult {
	f.t.Helper()
	var res gc.CleanupResult
	in(f.t, f.host, func() error {
		res = gc.RemoveOrphanedVRFs(context.Background(), []string{intf.GenerateInterfaceNameVRF(vpc)}, guard)
		return nil
	})
	return res
}

// vrfExists reports whether vpc's canonical host VRF is in the test host.
func (f *fixture) vrfExists(vpc string) bool {
	f.t.Helper()
	var found bool
	in(f.t, f.host, func() error {
		_, err := netlink.LinkByName(intf.GenerateInterfaceNameVRF(vpc))
		var notFound netlink.LinkNotFoundError
		switch {
		case err == nil:
			found = true
		case errors.As(err, &notFound):
		default:
			return err
		}
		return nil
	})
	return found
}

// TestMaintenanceAcrossTheLifecycle runs garbage collection's VRF reclaim for
// a VPC whose only user on the node is an edge attachment: while the
// attachment is being prepared, while it is active, after the agent restarts
// and after the attachment is replaced. The VRF stays each time, and the
// agent keeps programming through the maintenance writes. Once the last
// attachment is released, the next reclaim removes the VRF.
func TestMaintenanceAcrossTheLifecycle(t *testing.T) {
	f := newFixture(t)
	guard := f.guard()
	keeps := func(stage string) {
		t.Helper()
		res := f.reclaimVRF(guard, vpcA)
		if res.Errors != 0 || res.OrphanedVRFsRemoved != 0 || !f.vrfExists(vpcA) {
			t.Fatalf("%s: reclaim %+v removed the VRF an edge attachment uses", stage, res)
		}
	}

	// Preparation: admitted and allocated, nothing programmed yet.
	f.pod(pod1UID)
	f.attach("a", attA, pod1UID, vpcA, addr, false)
	keeps("preparation")

	// Active.
	first := f.agent()
	f.reconcile(first)
	f.programmed("a")
	index := f.hostLink("a").Attrs().Index
	keeps("active")
	f.reconcile(first)
	f.programmed("a")

	// Restart: a new process takes over a scope maintenance wrote since.
	restarted := f.agent()
	f.reconcile(restarted)
	f.programmed("a")
	if got := f.hostLink("a").Attrs().Index; got != index {
		t.Fatalf("restart recreated the attachment link: %d -> %d", index, got)
	}
	keeps("restart")

	// Replacement: a new attachment for another pod, then the old one goes.
	f.pod(pod2UID)
	f.attach("b", attB, pod2UID, vpcA, "fd00:aa::2", false)
	if err := f.client.Delete(context.Background(), f.get("a")); err != nil {
		t.Fatal(err)
	}
	keeps("replacement before the agent's pass")
	f.reconcile(restarted)
	f.programmed("b")
	if !meta.IsStatusConditionTrue(f.get("a").Status.Conditions, galacticv1alpha1.EdgeAttachmentReleased) {
		t.Fatal("replaced attachment not released")
	}
	keeps("replacement")

	// Release: the last attachment goes, and the VRF is reclaimed.
	if err := f.client.Delete(context.Background(), f.get("b")); err != nil {
		t.Fatal(err)
	}
	f.reconcile(restarted)
	if l := f.links(); len(l) != 0 {
		t.Fatalf("links after release: %+v", l)
	}
	res := f.reclaimVRF(guard, vpcA)
	if res.Errors != 0 || res.OrphanedVRFsRemoved != 1 || f.vrfExists(vpcA) {
		t.Fatalf("reclaim after release = %+v, VRF present %t; want it removed", res, f.vrfExists(vpcA))
	}
	if !f.vrfExists(vpcB) {
		t.Fatal("reclaim of one VPC removed another's VRF")
	}
}
