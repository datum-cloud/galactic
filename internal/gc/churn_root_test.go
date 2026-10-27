// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/nldump/nldumptest"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// churnPasses is how many passes each churn test runs at least, enough for a
// single-attempt listing to meet an interruption.
const churnPasses = 200

// TestResolveVRFKernelState_UnderLinkChurn requires the VRF table and egress
// kind lookup the eBPF vrf_table sweep repairs from to succeed while links
// are added and removed on the node.
func TestResolveVRFKernelState_UnderLinkChurn(t *testing.T) {
	requireRoot(t)
	const (
		nodeName = "churn-node"
		vpc      = "jU"
	)
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	var wantTable uint32
	err = nsObj.Do(func(ns.NetNS) error {
		if err := vrf.Add(vpc); err != nil {
			return fmt.Errorf("vrf.Add: %w", err)
		}
		if _, err := tap.Add(vpc, "c1a", "owner", 1500); err != nil {
			return fmt.Errorf("tap.Add: %w", err)
		}
		wantTable, err = vrf.TableID(vpc)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	nldumptest.Churn(t, nsObj)

	inst := crdnames.BGPVRFInstanceName(vpc, nodeName)
	passes := nldumptest.UntilInterrupted(t, nsObj, []string{nldumptest.KindLink}, churnPasses, func() error {
		table, kind, ok, err := resolveVRFKernelState(nodeName, inst)
		if err != nil {
			return err
		}
		if !ok || table != wantTable || kind != usidmap.EgressKindTap {
			return fmt.Errorf("resolved table %d kind %d ok %v, want table %d kind %d",
				table, kind, ok, wantTable, usidmap.EgressKindTap)
		}
		return nil
	})
	t.Logf("%d passes", passes)
}

// TestRepairAttachmentDatapath_UnderChurn requires a datapath repair pass to
// complete, examining every attachment, while links and addresses are added
// and removed on the node.
func TestRepairAttachmentDatapath_UnderChurn(t *testing.T) {
	requireRoot(t)
	const (
		nodeName     = "churn-node"
		uplinkName   = "chup0"
		shardSID     = "2001:db8:ff01:9:e001::"
		shardLocator = "2001:db8:ff01:9::/64"
	)
	node := attachreg.Node{Locator: testLocator, NodeID: 5}
	egress := attachreg.EgressConfig{ShardSIDs: shardSID, NAT64Prefix: "64:ff9b::/96"}
	attachments := []rootAttachment{
		{vpc: "jU", vpcAttachment: "c1a", ifaceType: attachreg.InterfaceTypeVeth, vrfID: 0x21, ipam: &cniipam.IPAMResult{
			IPv6Subnet:  mustCIDR(t, "fd20:30:ff01::/96"),
			IPv6Gateway: net.ParseIP("fd20:30::1"),
			IPv4Address: net.ParseIP("10.1.0.5"),
			IPv4Gateway: net.ParseIP("172.21.1.1"),
		}},
		{vpc: "kV", vpcAttachment: "c1b", ifaceType: attachreg.InterfaceTypeTap, vrfID: 0x22, ipam: &cniipam.IPAMResult{
			IPv6Subnet:  mustCIDR(t, "fd20:31:ff02::/96"),
			IPv6Gateway: net.ParseIP("fd20:31::1"),
		}},
	}

	objects := make([]client.Object, 0, 1+2*len(attachments))
	objects = append(objects, &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: repairRouter, Namespace: repairNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: targetKindNode, Name: nodeName}, LocalASN: 65000,
			SRv6Locator: node.Locator, NodeID: node.NodeID,
		},
	})
	for _, a := range attachments {
		objects = append(objects, &bgpv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{Name: crdnames.BGPVRFInstanceName(a.vpc, nodeName), Namespace: repairNamespace},
			Spec: bgpv1alpha1.BGPVRFInstanceSpec{
				RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: repairRouter}},
				VRFID:              a.vrfID,
				ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
				ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
			},
		}, a.advertisement(nodeName))
	}
	k8s := fake.NewClientBuilder().WithScheme(gcTestScheme(t)).WithObjects(objects...).Build()

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-churn-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	objs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	t.Setenv(config.EnvCNIEBPFInterfaces, uplinkName)
	attach.InvalidateUplinkIndexes()
	t.Cleanup(attach.InvalidateUplinkIndexes)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	err = nsObj.Do(func(ns.NetNS) error {
		if err := setUpUplink(uplinkName, shardLocator); err != nil {
			return err
		}
		for _, a := range attachments {
			if err := createAttachment(a); err != nil {
				return err
			}
			if err := registerAttachment(a, node, pinDir, egress); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("register attachments: %v", err)
	}
	nldumptest.Churn(t, nsObj)

	passes := nldumptest.UntilInterrupted(t, nsObj, []string{nldumptest.KindLink}, churnPasses, func() error {
		result, err := RepairAttachmentDatapath(context.Background(), k8s, DatapathRepairConfig{
			Namespace: repairNamespace, NodeName: nodeName, PinDir: pinDir, Egress: egress,
		})
		if err != nil {
			return err
		}
		if result.Attachments != len(attachments) {
			return fmt.Errorf("repair examined %d attachments, want %d", result.Attachments, len(attachments))
		}
		return nil
	})
	t.Logf("%d passes", passes)
}
