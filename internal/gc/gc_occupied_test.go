// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/types"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// indexedVRFLinks returns a kernel VRF for each of vpcs, with distinct
// ifindexes starting at 100.
func indexedVRFLinks(vpcs ...string) []*netlink.Vrf {
	links := vrfLinks(vpcs...)
	for i, l := range links {
		l.Index = 100 + i
	}
	return links
}

// hostLink returns a tap named for vpc's attachment att, enslaved to master.
func hostLink(vpc, att string, master *netlink.Vrf) netlink.Link {
	return &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{
		Name: intf.GenerateInterfaceNameHost(vpc, att), MasterIndex: master.Index,
	}}
}

// TestOccupiedVRFSurvivesBothPhases stands in for a VPC's first ADD between
// enslaving its host link and writing its BGPAdvertisement: VPC a's VRF holds
// a tap, and no object names a. Neither a's BGPVRFInstance nor its VRF is
// collected, while b's, which hold nothing, are.
func TestOccupiedVRFSurvivesBothPhases(t *testing.T) {
	ctx := context.Background()
	vrfs := indexedVRFLinks("a", "b")
	withFakeLinks(t, vrfs, []netlink.Link{hostLink("a", "att", vrfs[0])})
	k8s := edgeTestClient(t, "a", "b")

	orphans, err := CollectOrphanedCRDs(ctx, k8s, edgeTestNamespace, edgeTestNode, using())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		deadAdvertisementOrphan,
		"BGPVRFInstance/" + crdnames.BGPVRFInstanceName("b", edgeTestNode),
	}
	if got := orphanNames(orphans); !slices.Equal(got, want) {
		t.Fatalf("orphans = %v, want %v", got, want)
	}

	gotVRFs, err := CollectOrphanedVRFs(ctx, k8s, edgeTestNamespace, edgeTestNode, using())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{intf.GenerateInterfaceNameVRF("b")}; !slices.Equal(gotVRFs, want) {
		t.Fatalf("orphaned VRFs = %v, want %v", gotVRFs, want)
	}
}

// TestInstanceKeptWhenLinkJoinsAfterCollection collects b's BGPVRFInstance
// while b's VRF is empty, then enslaves a link to it before removal, as an
// ADD reusing the instance would. The removal, decided again under the VRF
// lock, keeps the instance and counts no error.
func TestInstanceKeptWhenLinkJoinsAfterCollection(t *testing.T) {
	ctx := context.Background()
	vrfs := indexedVRFLinks("a", "b")
	withFakeLinks(t, vrfs, nil)
	k8s := edgeTestClient(t, "a", "b")

	orphans, err := CollectOrphanedCRDs(ctx, k8s, edgeTestNamespace, edgeTestNode, using())
	if err != nil {
		t.Fatal(err)
	}
	var instances []OrphanedCRD
	for _, o := range orphans {
		if o.Kind == kindBGPVRFInstance {
			instances = append(instances, o)
		}
	}
	if len(instances) != 2 {
		t.Fatalf("collected instances = %v, want a's and b's", orphanNames(instances))
	}

	withFakeLinks(t, vrfs, []netlink.Link{hostLink("b", "att", vrfs[1])})
	res := RemoveOrphanedCRDs(ctx, k8s, instances, using())
	if res.Errors != 0 || res.OrphanedCRDsRemoved != 1 {
		t.Fatalf("remove = %+v, want only a's BGPVRFInstance removed", res)
	}
	var inst bgpv1alpha1.BGPVRFInstance
	key := types.NamespacedName{Namespace: edgeTestNamespace, Name: crdnames.BGPVRFInstanceName("b", edgeTestNode)}
	if err := k8s.Get(ctx, key, &inst); err != nil {
		t.Fatalf("b's BGPVRFInstance after GC: %v, want it kept", err)
	}
}
