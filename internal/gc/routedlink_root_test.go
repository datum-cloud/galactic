// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/localprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// TestRoutedLinkSurvivesGCRoot checks that GC's datapath repair and its
// host-link reclaim leave a Worker routed link alone: its host end, the guard
// at the head of its tcx ingress, and its egress datapath registered as an
// infra interface.
func TestRoutedLinkSurvivesGCRoot(t *testing.T) {
	requireRoot(t)
	const (
		nodeName = "routed-node"
		vpc      = "jU"
		vrfID    = 0x21
	)
	k8s := fake.NewClientBuilder().WithScheme(gcTestScheme(t)).WithObjects(
		&bgpv1alpha1.BGPRouter{
			ObjectMeta: metav1.ObjectMeta{Name: repairRouter, Namespace: repairNamespace},
			Spec: bgpv1alpha1.BGPRouterSpec{
				TargetRef: bgpv1alpha1.TargetRef{Kind: targetKindNode, Name: nodeName}, LocalASN: 65000,
				SRv6Locator: testLocator, NodeID: 5,
			},
		},
		&bgpv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{Name: crdnames.BGPVRFInstanceName(vpc, nodeName), Namespace: repairNamespace},
			Spec: bgpv1alpha1.BGPVRFInstanceSpec{
				RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: repairRouter}},
				VRFID:              vrfID,
				ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
				ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
			},
		},
	).Build()

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-gc-routed-%d", os.Getpid())
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
	block, err := uformat.Block(netip.MustParsePrefix(testLocator).Addr())
	if err != nil {
		t.Fatal(err)
	}

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })
	host := intf.GenerateInterfaceNameLocal(vpc, "abc", intf.LocalRoleRoutedHost)
	var table uint32
	var idx int
	in := func(fn func() error) {
		t.Helper()
		if err := nsObj.Do(func(ns.NetNS) error { return fn() }); err != nil {
			t.Fatal(err)
		}
	}
	in(func() error {
		if err := vrf.Add(vpc); err != nil {
			return err
		}
		if table, err = vrf.TableID(vpc); err != nil {
			return err
		}
		vrfLink, err := netlink.LinkByName(intf.GenerateInterfaceNameVRF(vpc))
		if err != nil {
			return err
		}
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: host,
			MasterIndex: vrfLink.Attrs().Index, Alias: attach.InternalAliasPrefix + vpc + "/envoy-1"},
			PeerName: intf.GenerateInterfaceNameLocal(vpc, "abc", intf.LocalRoleRoutedPod)}); err != nil {
			return err
		}
		l, err := netlink.LinkByName(host)
		if err != nil {
			return err
		}
		idx = l.Attrs().Index
		registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
		if err != nil {
			return err
		}
		defer func() { _ = closer.Close() }()
		if err := registry.VRF.Register(block, vrfID, table, usidmap.EgressKindVeth); err != nil {
			return err
		}
		if err := attach.EnsureTCXGuard(local.Programs.LinkGuard, host); err != nil {
			return err
		}
		return attachreg.RegisterHostLinkKind(pinDir, table, uint32(idx), host, netip.Addr{}, tpmap.KindInfra)
	})
	guardInfo, err := local.Programs.LinkGuard.Info()
	if err != nil {
		t.Fatal(err)
	}
	guardID, _ := guardInfo.ID()
	check := func(stage string) {
		t.Helper()
		in(func() error {
			if _, err := netlink.LinkByName(host); err != nil {
				t.Fatalf("%s: the routed link is gone: %v", stage, err)
			}
			res, err := link.QueryPrograms(link.QueryOptions{Target: idx, Attach: ebpf.AttachTCXIngress})
			if err != nil {
				return err
			}
			if len(res.Programs) == 0 || res.Programs[0].ID != guardID {
				t.Fatalf("%s: tcx ingress = %+v, want the guard %d first", stage, res.Programs, guardID)
			}
			ok, err := attachreg.HostLinkRegistered(pinDir, table, uint32(idx), host, tpmap.KindInfra)
			if err != nil || !ok {
				t.Fatalf("%s: the routed link's egress registration = %t, %v", stage, ok, err)
			}
			return nil
		})
	}
	check("registered")

	in(func() error {
		_, err := RepairAttachmentDatapath(context.Background(), k8s, DatapathRepairConfig{
			Namespace: repairNamespace, NodeName: nodeName, PinDir: pinDir,
		})
		return err
	})
	check("after datapath repair")

	in(func() error {
		n, err := reclaimHostLinks(OrphanedCRD{Name: crdnames.BGPAdvertisementName(vpc, "abc", nodeName),
			Namespace: repairNamespace, Kind: "BGPAdvertisement", Node: nodeName,
			DeadContainers: map[string]struct{}{"dead": {}}})
		if n != 0 {
			t.Errorf("host-link reclaim removed %d links", n)
		}
		return err
	})
	check("after host-link reclaim")
}
