// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"go.datum.net/galactic/internal/cni/vpcfence"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/localprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// TestRoutedLinkSurvivesInstallerRepairRoot runs galactic-cni's start-up and
// repair passes over a node holding a Worker routed link: the egress
// reattach, tp_deliver reattach and identity sweep, the traffic policy
// interface reconcile, the host-only port restore and the retired sidecar
// return prune. None of them removes the link's rows or programs, and none
// puts anything ahead of its guard.
func TestRoutedLinkSurvivesInstallerRepairRoot(t *testing.T) {
	requireRoot(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = orig.Close() }()
	nsHandle, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nsHandle.Close(); _ = netns.Set(orig) }()
	prevDir := vpcfence.Dir
	vpcfence.Dir = t.TempDir()
	t.Cleanup(func() { vpcfence.Dir = prevDir })

	const (
		vpc   = "jU"
		table = 4121
		block = 0xfc0000010000
	)
	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-installer-routed-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir); _ = os.RemoveAll(pinDir + "-local") })
	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	local, err := localprog.Load(pinDir, pinDir+"-local")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = local.Close() })
	policy, err := tpmap.OpenPinned(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()

	vrfName := intf.GenerateInterfaceNameVRF(vpc)
	if err := netlink.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: vrfName}, Table: table}); err != nil {
		t.Fatal(err)
	}
	vrfLink, err := netlink.LinkByName(vrfName)
	if err != nil {
		t.Fatal(err)
	}
	host := intf.GenerateInterfaceNameLocal(vpc, "abc", intf.LocalRoleRoutedHost)
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: host,
		MasterIndex: vrfLink.Attrs().Index, Alias: attach.InternalAliasPrefix + vpc + "/envoy-1"},
		PeerName: intf.GenerateInterfaceNameLocal(vpc, "abc", intf.LocalRoleRoutedPod)}); err != nil {
		t.Fatal(err)
	}
	l, err := netlink.LinkByName(host)
	if err != nil {
		t.Fatal(err)
	}
	idx := l.Attrs().Index
	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closer.Close() }()
	if err := registry.VRF.Register(block, 0x21, table, usidmap.EgressKindVeth); err != nil {
		t.Fatal(err)
	}
	if err := attach.EnsureTCXGuard(local.Programs.LinkGuard, host); err != nil {
		t.Fatal(err)
	}
	if err := attachreg.RegisterHostLinkKind(pinDir, table, uint32(idx), host, netip.Addr{}, tpmap.KindInfra); err != nil {
		t.Fatal(err)
	}
	guardInfo, err := local.Programs.LinkGuard.Info()
	if err != nil {
		t.Fatal(err)
	}
	guardID, _ := guardInfo.ID()
	check := func(stage string) {
		t.Helper()
		res, err := link.QueryPrograms(link.QueryOptions{Target: idx, Attach: ebpf.AttachTCXIngress})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Programs) != 1 || res.Programs[0].ID != guardID {
			t.Fatalf("%s: tcx ingress = %+v, want only the guard %d", stage, res.Programs, guardID)
		}
		ok, err := attachreg.HostLinkRegistered(pinDir, table, uint32(idx), host, tpmap.KindInfra)
		if err != nil || !ok {
			t.Fatalf("%s: the routed link's egress registration = %t, %v", stage, ok, err)
		}
	}
	check("registered")

	// galactic-cni's start-up repair of every managed interface.
	if _, err := attach.ReattachEgress(objs.UsidServiceEgress, objs.UsidEgress,
		objs.AttachmentIdentityTable); err != nil {
		t.Fatal(err)
	}
	if _, err := attach.ReattachDeliver(objs.TpDeliver); err != nil {
		t.Fatal(err)
	}
	if _, err := attach.SweepAttachmentIdentities(objs.AttachmentIdentityTable); err != nil {
		t.Fatal(err)
	}
	check("after the egress reattach")

	(&trafficPolicyState{maps: policy}).reconcileInterfaces()
	check("after the traffic policy reconcile")

	if _, err := restoreHostOnlyPorts(pinDir); err != nil {
		t.Fatal(err)
	}
	check("after the host-only port restore")

	if _, err := pruneRetiredSidecarReturn(context.Background(), pinDir,
		func(uint16) (string, bool) { return "", false }); err != nil {
		t.Fatal(err)
	}
	check("after the retired sidecar return prune")
}
