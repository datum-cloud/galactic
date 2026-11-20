// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/edge/maintenance"
	"go.datum.net/galactic/internal/ownership"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/worker/handback"
	"go.datum.net/galactic/internal/worker/module"
)

// inNode runs Release in the rig's node namespace, where the handback
// process runs on a real node. The handback names each VPC as its fence
// scope does, without the zero padding the rig's claims use.
type inNode struct{ r *rig }

func (n inNode) Release(ctx context.Context, s module.Scope) error {
	var err error
	n.r.in(n.r.node, func() error {
		err = n.r.mod.Release(ctx, s)
		return nil
	})
	return err
}

// TestHandbackRoot checks a handback after Worker stopped with ready Local
// claims: garbage collection leaves the scopes while the dead incarnation
// owns them; the handback removes every link, filter and row Local wrote
// and keeps galactic-cni's chains and another owner's pass-through entry;
// and garbage collection reclaims the scopes afterwards.
func TestHandbackRoot(t *testing.T) {
	r := readyRig(t, "handback")
	a := r.vpcs[0]

	dir := t.TempDir()
	fence, err := ownership.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	dead := ownership.WorkerOwnerPrefix + testNode + ":00000000deadbeef"
	for _, v := range r.vpcs {
		tk, err := fence.Claim(ownership.VPCScope(v.vpc), dead)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fence.CommitSnapshot(tk, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	scheme := runtime.NewScheme()
	if err := galacticv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	g, err := maintenance.NewGuard(fake.NewClientBuilder().WithScheme(scheme).Build(), testNode, dir)
	if err != nil {
		t.Fatal(err)
	}
	g.HostLinks = func() ([]hostattach.ObservedAttachment, error) { return nil, nil }
	reclaimed := map[string]bool{}
	gc := func(vpc string) error {
		return g.Reclaim(context.Background(), vpc, func() error { reclaimed[vpc] = true; return nil })
	}
	for _, v := range r.vpcs {
		if err := gc(v.vpc); !errors.Is(err, ownership.ErrWorkerOwned) {
			t.Fatalf("GC of VPC %s before handback: %v, want ErrWorkerOwned", v.vpc, err)
		}
	}

	res, err := handback.Run(context.Background(), handback.Config{Fence: fence,
		Socket: filepath.Join(t.TempDir(), "worker.sock"), Local: inNode{r}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.HandedBack) != len(r.vpcs) || len(res.Released) != len(r.vpcs) {
		t.Fatalf("handback result %+v", res)
	}

	for _, v := range r.vpcs {
		if !r.planEmpty(v.vpc, nil) {
			t.Errorf("VPC %s: Local would still remove state after the handback", v.vpc)
		}
	}
	noLocalState(t, r)
	if row, ok, err := r.routes.LookupRow(a.table, ipnet(clientNet)); err != nil || !ok || !row.PassThrough {
		t.Fatalf("another owner's pass-through entry went: %+v %t %v", row, ok, err)
	}

	for _, v := range r.vpcs {
		if err := gc(v.vpc); err != nil || !reclaimed[v.vpc] {
			t.Fatalf("GC of VPC %s after handback: %v, reclaimed %t", v.vpc, err, reclaimed[v.vpc])
		}
	}
}

// noLocalState checks that no Local link, filter or row is left on the rig,
// and that galactic-cni's chains stay.
func noLocalState(t *testing.T, r *rig) {
	t.Helper()
	r.in(r.node, func() error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, l := range links {
			if intf.IsLocalLinkName(l.Attrs().Name) {
				t.Errorf("Local link %s outlived the handback", l.Attrs().Name)
			}
			if _, _, ok, err := attach.LocalFilter(l.Attrs().Index); err == nil && ok {
				t.Errorf("a Local filter outlived the handback on %s", l.Attrs().Name)
			}
		}
		for _, v := range r.vpcs {
			if chain, err := attach.HasEgressChain(v.tap); err != nil || !chain {
				t.Errorf("galactic-cni's chain on %s went with the handback (%v)", v.tap, err)
			}
		}
		return nil
	})
	for _, name := range localMaps {
		m, err := ebpf.LoadPinnedMap(filepath.Join(r.pin, "local", name), nil)
		if err != nil {
			t.Fatal(err)
		}
		k := make([]byte, m.KeySize())
		if err := m.NextKey(nil, &k); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Errorf("%s keeps rows after the handback (%v)", name, err)
		}
		_ = m.Close()
	}
}
