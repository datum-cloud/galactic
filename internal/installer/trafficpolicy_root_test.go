// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netns"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
)

// TestReconcileInterfaces_KeepsSidecarInfraRows runs the installer's startup
// interface reconcile in a private namespace against freshly loaded maps. A
// row for an interface that no longer exists is removed, but an ingress
// sidecar's infra row is kept: its veth peer lives in the gateway pod's
// namespace, so the host never finds its link, and the sidecar owns that row.
func TestReconcileInterfaces_KeepsSidecarInfraRows(t *testing.T) {
	requireRoot(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = orig.Close() }()
	ns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ns.Close(); _ = netns.Set(orig) }()

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-installer-trafficpolicy-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	policy, err := tpmap.OpenPinned(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()

	const goneTenant = uint32(4242)
	sidecarPeer := ifindexvrfmap.SidecarIfindexBase + 7
	token, err := tpmap.NewPolicyToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.PutInterface(goneTenant, token, tpmap.KindTenant); err != nil {
		t.Fatal(err)
	}
	if err := policy.PutInfra(sidecarPeer); err != nil {
		t.Fatal(err)
	}

	(&trafficPolicyState{maps: policy}).reconcileInterfaces()

	var row prog.UsidTpIfaceValue
	if err := policy.Interfaces.Lookup(goneTenant, &row); err == nil {
		t.Errorf("row for missing interface %d kept, want removed", goneTenant)
	}
	if err := policy.Interfaces.Lookup(sidecarPeer, &row); err != nil {
		t.Errorf("sidecar infra row %#x removed: %v", sidecarPeer, err)
	} else if row.Kind != tpmap.KindInfra {
		t.Errorf("sidecar row kind = %d, want infra (%d)", row.Kind, tpmap.KindInfra)
	}
}
