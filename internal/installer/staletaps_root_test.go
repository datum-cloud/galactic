// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/cniipam"
	"go.datum.net/galactic/internal/hostgw"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// TestStaleTapReclaimOnKernel runs two reclaim passes in a private namespace
// against freshly loaded maps. A tap whose sandbox and BGPAdvertisement are
// both gone, still enslaved to its VRF with a pod-subnet route and traffic
// policy and ifindex rows, is removed with its route and rows. A tap whose
// VPCAttachment still exists is kept, detached or not.
func TestStaleTapReclaimOnKernel(t *testing.T) {
	requireRoot(t)
	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-installer-staletaps-%d", os.Getpid())
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
	vrfRows, vrfRowsMap, err := ifindexvrfmap.OpenPinned(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = vrfRowsMap.Close() }()

	unregister := staleTapUnregisterFn
	t.Cleanup(func() { staleTapUnregisterFn = unregister })
	staleTapUnregisterFn = func(ifindex uint32) error { return attachreg.UnregisterInterface(pinDir, ifindex) }

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })

	_, subnet, err := net.ParseCIDR("2001:db8:0:1::5:0:0/96")
	if err != nil {
		t.Fatal(err)
	}
	res := &cniipam.IPAMResult{IPv6Subnet: subnet, IPv6Gateway: net.ParseIP("2001:db8:0:1::1")}
	k8s := staleClient(t, interceptor.Funcs{}, vpcAttachment("live", staleVPC, "a2"))

	err = nsObj.Do(func(ns.NetNS) error {
		var staleIfindex uint32
		for _, att := range []string{"a1", "a2"} {
			if err := vrf.EnsureAndEnslave(staleVPC, func(*netlink.Vrf) error {
				_, err := tap.Add(staleVPC, att, staleOwner, 1500)
				return err
			}); err != nil {
				return fmt.Errorf("tap %s: %w", att, err)
			}
			link, err := netlink.LinkByName(intf.GenerateInterfaceNameHost(staleVPC, att))
			if err != nil {
				return err
			}
			if err := netlink.LinkSetUp(link); err != nil {
				return err
			}
			if att == "a1" {
				staleIfindex = uint32(link.Attrs().Index) //nolint:gosec // a kernel ifindex
			}
		}
		if err := hostgw.RestoreHostGateway(staleVPC, "a1", res, nil); err != nil {
			return fmt.Errorf("stale tap's route: %w", err)
		}
		if routes, err := subnetRoutes(subnet); err != nil || len(routes) == 0 {
			return fmt.Errorf("stale tap's route before reclaim: %v, err %w, want one", routes, err)
		}
		token, err := tpmap.NewPolicyToken()
		if err != nil {
			return err
		}
		if err := policy.PutInterface(staleIfindex, token, tpmap.KindTenant); err != nil {
			return err
		}
		if err := vrfRows.Register(staleIfindex, 1, 1); err != nil {
			return err
		}

		r := &staleTapReclaimer{}
		for pass := 1; pass <= 2; pass++ {
			got, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode)
			if err != nil {
				return fmt.Errorf("pass %d: %w", pass, err)
			}
			if want := pass - 1; got.Reclaimed != want {
				return fmt.Errorf("pass %d reclaimed %d, want %d", pass, got.Reclaimed, want)
			}
		}

		var notFound netlink.LinkNotFoundError
		if _, err := netlink.LinkByName(intf.GenerateInterfaceNameHost(staleVPC, "a1")); !errors.As(err, &notFound) {
			return fmt.Errorf("stale tap after reclaim: err = %w, want it gone", err)
		}
		if _, err := netlink.LinkByName(intf.GenerateInterfaceNameHost(staleVPC, "a2")); err != nil {
			return fmt.Errorf("live attachment's tap after reclaim: %w", err)
		}
		routes, err := subnetRoutes(subnet)
		if err != nil {
			return err
		}
		if len(routes) != 0 {
			return fmt.Errorf("stale tap's routes after reclaim: %v, want none", routes)
		}
		var row prog.UsidTpIfaceValue
		if err := policy.Interfaces.Lookup(staleIfindex, &row); err == nil {
			return errors.New("stale tap's traffic policy row kept, want removed")
		}
		if _, ok, err := vrfRows.Get(staleIfindex); err != nil || ok {
			return fmt.Errorf("stale tap's ifindex_vrf_table row: ok=%v err=%w, want removed", ok, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// subnetRoutes lists the IPv6 routes to subnet in every table, the VRF's
// included.
func subnetRoutes(subnet *net.IPNet) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Dst: subnet, Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
}
