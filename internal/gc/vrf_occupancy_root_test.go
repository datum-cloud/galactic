// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// routerOnlyClient holds this node's BGPRouter and nothing else, as GC finds
// a node whose VPCs' first ADDs have not yet written any BGPAdvertisement.
func routerOnlyClient(t *testing.T) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(gcTestScheme(t)).WithObjects(&bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: edgeTestRouter, Namespace: edgeTestNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: targetKindNode, Name: edgeTestNode},
			LocalASN:  65000, SRv6Locator: testLocator, NodeID: 5,
		},
	}).Build()
}

// gcVRFPass runs GC's VRF phase once.
func gcVRFPass(ctx context.Context, k8s client.Client) (CleanupResult, error) {
	orphans, err := CollectOrphanedVRFs(ctx, k8s, edgeTestNamespace, edgeTestNode, using())
	if err != nil {
		return CleanupResult{}, err
	}
	return RemoveOrphanedVRFs(ctx, orphans, using()), nil
}

// requireEnslaved fails unless the host link for vpc's attachment att is
// enslaved to vpc's VRF.
func requireEnslaved(vpc, att string) error {
	link, err := netlink.LinkByName(intf.GenerateInterfaceNameHost(vpc, att))
	if err != nil {
		return fmt.Errorf("host link for %s/%s: %w", vpc, att, err)
	}
	vrfLink, err := netlink.LinkByName(intf.GenerateInterfaceNameVRF(vpc))
	if err != nil {
		return fmt.Errorf("VRF for %s: %w", vpc, err)
	}
	if link.Attrs().MasterIndex != vrfLink.Attrs().Index {
		return fmt.Errorf("host link for %s/%s has master %d, VRF is %d",
			vpc, att, link.Attrs().MasterIndex, vrfLink.Attrs().Index)
	}
	return nil
}

// TestGCKeepsVRFHoldingHostLink is the window a VPC's first ADD leaves
// between enslaving its tap and writing its BGPAdvertisement. A GC pass in
// that window must keep the VRF, so that a second ADD on the VPC reuses it
// and the first tap stays enslaved.
func TestGCKeepsVRFHoldingHostLink(t *testing.T) {
	requireRoot(t)
	const vpc = "jU"
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })
	k8s := routerOnlyClient(t)

	err = nsObj.Do(func(ns.NetNS) error {
		if err := vrf.EnsureAndEnslave(vpc, func(*netlink.Vrf) error {
			_, err := tap.Add(vpc, "a1", "c1", 1500)
			return err
		}); err != nil {
			return err
		}
		res, err := gcVRFPass(context.Background(), k8s)
		if err != nil {
			return err
		}
		if res.OrphanedVRFsRemoved != 0 || res.Errors != 0 {
			return fmt.Errorf("GC pass = %+v, want the VRF kept", res)
		}
		if err := vrf.EnsureAndEnslave(vpc, func(*netlink.Vrf) error {
			_, err := tap.Add(vpc, "a2", "c2", 1500)
			return err
		}); err != nil {
			return err
		}
		for _, att := range []string{"a1", "a2"} {
			if err := requireEnslaved(vpc, att); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestConcurrentFirstADDsWithGC runs first ADDs for several VPCs at once,
// each attaching several taps, while GC's VRF phase runs repeatedly. No GC
// pass may delete a VRF with a link in it, so every tap ends enslaved to its
// VPC's VRF, and once the taps are gone GC reclaims every VRF.
func TestConcurrentFirstADDsWithGC(t *testing.T) {
	requireRoot(t)
	vpcs := []string{"jU", "kV", "lW", "mX"}
	const attachmentsPerVPC = 8

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })
	k8s := routerOnlyClient(t)
	ctx := context.Background()

	stop := make(chan struct{})
	gcErr := make(chan error, 1)
	var passes int
	go func() {
		gcErr <- nsObj.Do(func(ns.NetNS) error {
			for {
				select {
				case <-stop:
					return nil
				default:
				}
				res, err := gcVRFPass(ctx, k8s)
				if err != nil {
					return err
				}
				if res.Errors != 0 {
					return fmt.Errorf("GC pass %d: %+v", passes, res)
				}
				passes++
			}
		})
	}()

	var wg sync.WaitGroup
	addErrs := make(chan error, len(vpcs)*attachmentsPerVPC)
	for _, vpc := range vpcs {
		for i := range attachmentsPerVPC {
			wg.Add(1)
			go func() {
				defer wg.Done()
				att := fmt.Sprintf("a%d", i)
				addErrs <- nsObj.Do(func(ns.NetNS) error {
					return vrf.EnsureAndEnslave(vpc, func(*netlink.Vrf) error {
						_, err := tap.Add(vpc, att, "c-"+vpc+att, 1500)
						return err
					})
				})
			}()
		}
	}
	wg.Wait()
	close(stop)
	if err := <-gcErr; err != nil {
		t.Fatalf("GC: %v", err)
	}
	close(addErrs)
	for err := range addErrs {
		if err != nil {
			t.Errorf("ADD: %v", err)
		}
	}
	t.Logf("%d GC passes during the ADDs", passes)

	err = nsObj.Do(func(ns.NetNS) error {
		// One more pass with every ADD done must keep every VRF too.
		if res, err := gcVRFPass(ctx, k8s); err != nil || res.OrphanedVRFsRemoved != 0 {
			return fmt.Errorf("final GC pass = %+v, %w; want every VRF kept", res, err)
		}
		for _, vpc := range vpcs {
			for i := range attachmentsPerVPC {
				att := fmt.Sprintf("a%d", i)
				if err := requireEnslaved(vpc, att); err != nil {
					return err
				}
				if err := tap.Delete(vpc, att, "c-"+vpc+att); err != nil {
					return err
				}
			}
		}
		res, err := gcVRFPass(ctx, k8s)
		if err != nil {
			return err
		}
		if res.OrphanedVRFsRemoved != len(vpcs) {
			return fmt.Errorf("GC pass after DELs = %+v, want all %d VRFs removed", res, len(vpcs))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
