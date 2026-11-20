// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"errors"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/edge/maintenance"
	"go.datum.net/galactic/internal/ownership"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// handbackGuard returns the GC guard over a fence holding, for each VPC, the
// given owner: a handback label, a Worker incarnation, or another writer.
func handbackGuard(t *testing.T, owners map[string]string) (*maintenance.Guard, *ownership.Authority) {
	t.Helper()
	dir := t.TempDir()
	fence, err := ownership.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	worker := ownership.WorkerOwnerPrefix + edgeTestNode + ":stopped"
	for vpc, owner := range owners {
		scope := ownership.VPCScope(vpc)
		tk, err := fence.Claim(scope, worker)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fence.CommitSnapshot(tk, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if owner == worker {
			continue
		}
		if _, err := fence.Relinquish(scope, func(r ownership.Record) bool { return ownership.WorkerOwned(r.Owner) },
			ownership.HandbackOwnerPrefix+"t0"); err != nil {
			t.Fatal(err)
		}
		if !ownership.HandedBack(owner) {
			if _, err := fence.Takeover(scope, owner, func(r ownership.Record) bool {
				return ownership.HandedBack(r.Owner)
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	scheme := runtime.NewScheme()
	if err := galacticv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	g, err := maintenance.NewGuard(fake.NewClientBuilder().WithScheme(scheme).Build(), edgeTestNode, dir)
	if err != nil {
		t.Fatal(err)
	}
	g.HostLinks = func() ([]hostattach.ObservedAttachment, error) { return nil, nil }
	return g, fence
}

// TestGCReclaimsHandedBackScope checks that GC reclaims the VRF of a VPC the
// node no longer serves whose scope a Worker handback left, and releases the
// handback label, while it keeps a handed-back VPC's VRF that still holds a
// link, leaves a Worker-owned VPC to its Worker, and leaves the owner of a
// handed-back scope another writer took since.
func TestGCReclaimsHandedBackScope(t *testing.T) {
	requireRoot(t)
	const (
		unused  = "hA"
		inUse   = "hB"
		worker  = "hC"
		retaken = "hD"
	)
	label := ownership.HandbackOwnerPrefix + "t0"
	g, fence := handbackGuard(t, map[string]string{
		unused: label, inUse: label, worker: ownership.WorkerOwnerPrefix + edgeTestNode + ":stopped",
		retaken: "galactic-edge:" + edgeTestNode + ":1",
	})
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })
	k8s := routerOnlyClient(t)

	err = nsObj.Do(func(ns.NetNS) error {
		for i, vpc := range []string{unused, inUse, worker, retaken} {
			v := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: intf.GenerateInterfaceNameVRF(vpc)},
				Table: uint32(4100 + i)}
			if err := netlink.LinkAdd(v); err != nil {
				return err
			}
		}
		// A link enslaved to inUse's VRF keeps the VPC in use on the node.
		d := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "hbkeep0"}}
		if err := netlink.LinkAdd(d); err != nil {
			return err
		}
		master, err := netlink.LinkByName(intf.GenerateInterfaceNameVRF(inUse))
		if err != nil {
			return err
		}
		if err := netlink.LinkSetMaster(d, master); err != nil {
			return err
		}

		orphans, err := CollectOrphanedVRFs(context.Background(), k8s, edgeTestNamespace, edgeTestNode, g)
		if err != nil {
			return err
		}
		RemoveOrphanedVRFs(context.Background(), orphans, g)

		for vpc, want := range map[string]bool{unused: false, inUse: true, worker: true, retaken: false} {
			_, err := netlink.LinkByName(intf.GenerateInterfaceNameVRF(vpc))
			var nf netlink.LinkNotFoundError
			present := err == nil
			if err != nil && !errors.As(err, &nf) {
				return err
			}
			if present != want {
				t.Errorf("VPC %s: VRF present %t, want %t", vpc, present, want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	owner := func(vpc string) ownership.Record {
		r, err := fence.Read(ownership.VPCScope(vpc))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := owner(unused); r.Owner != "" || r.Transitioning {
		t.Errorf("the reclaimed handed-back scope is %+v, want released (unowned)", r)
	}
	if r := owner(inUse); r.Owner != label {
		t.Errorf("the handed-back scope still in use is %+v, want its label kept", r)
	}
	if r := owner(worker); !ownership.WorkerOwned(r.Owner) {
		t.Errorf("the Worker-owned scope is %+v, want it left to its Worker", r)
	}
	if r := owner(retaken); r.Owner != "galactic-edge:"+edgeTestNode+":1" {
		t.Errorf("a scope another writer took after the handback is %+v, want that writer kept", r)
	}
}
