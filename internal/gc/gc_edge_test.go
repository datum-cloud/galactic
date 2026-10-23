// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/edge/maintenance"
	"go.datum.net/galactic/internal/plumbing/intf"
)

const (
	edgeTestNamespace = "galactic-system"
	edgeTestNode      = "edge-1"
	edgeTestRouter    = "router-edge-1"
)

// edgeUsers is a fake EdgeUsers: vpcs are in use, and err, when set, makes
// the answer unknown. reclaimed records every VPC a reclaim ran for.
type edgeUsers struct {
	vpcs      map[string]struct{}
	err       error
	reclaimed []string
}

func (e *edgeUsers) VPCs(context.Context) (map[string]struct{}, error) {
	if e.err != nil {
		return nil, e.err
	}
	return e.vpcs, nil
}

func (e *edgeUsers) Reclaim(_ context.Context, vpc string, reclaim func() error) error {
	if e.err != nil {
		return e.err
	}
	if _, ok := e.vpcs[vpc]; ok {
		return fmt.Errorf("%w: VPC %s", maintenance.ErrInUse, vpc)
	}
	e.reclaimed = append(e.reclaimed, vpc)
	return reclaim()
}

func using(vpcs ...string) *edgeUsers {
	e := &edgeUsers{vpcs: map[string]struct{}{}}
	for _, v := range vpcs {
		e.vpcs[v] = struct{}{}
	}
	return e
}

// edgeTestClient holds this node's router, a BGPVRFInstance for each of vpcs
// and no BGPAdvertisement, as GC finds a node whose last workload of each VPC
// is gone. A dead workload's advertisement for the first VPC is left too.
func edgeTestClient(t *testing.T, vpcs ...string) client.Client {
	t.Helper()
	objs := make([]client.Object, 0, 2+len(vpcs))
	objs = append(objs, &bgpv1alpha1.BGPRouter{
		ObjectMeta: metav1.ObjectMeta{Name: edgeTestRouter, Namespace: edgeTestNamespace},
		Spec: bgpv1alpha1.BGPRouterSpec{
			TargetRef: bgpv1alpha1.TargetRef{Kind: targetKindNode, Name: edgeTestNode},
			LocalASN:  65000, SRv6Locator: testLocator, NodeID: 5,
		},
	}, &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: vpcs[0] + "-att", Namespace: edgeTestNamespace,
			Annotations: map[string]string{annotationNetNS + ".dead": "/var/run/netns/gc-edge-test-gone"},
		},
		Spec: bgpv1alpha1.BGPAdvertisementSpec{RouterRef: bgpv1alpha1.RouterRef{Name: edgeTestRouter}},
	})
	for i, vpc := range vpcs {
		objs = append(objs, &bgpv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{Name: crdnames.BGPVRFInstanceName(vpc, edgeTestNode), Namespace: edgeTestNamespace},
			Spec: bgpv1alpha1.BGPVRFInstanceSpec{
				RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: edgeTestRouter}},
				VRFID:              int32(10 + i),
				ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
				ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: testRouteTarget}},
			},
		})
	}
	return fake.NewClientBuilder().WithScheme(gcTestScheme(t)).WithObjects(objs...).Build()
}

func orphanNames(orphans []OrphanedCRD) []string {
	names := make([]string, 0, len(orphans))
	for _, o := range orphans {
		names = append(names, o.Kind+"/"+o.Name)
	}
	slices.Sort(names)
	return names
}

// vrfLinks returns a kernel VRF for each of vpcs.
func vrfLinks(vpcs ...string) []*netlink.Vrf {
	links := make([]*netlink.Vrf, 0, len(vpcs))
	for i, vpc := range vpcs {
		links = append(links, &netlink.Vrf{
			LinkAttrs: netlink.LinkAttrs{Name: intf.GenerateInterfaceNameVRF(vpc)}, Table: uint32(1001 + i),
		})
	}
	return links
}

// TestEdgeAttachmentKeepsBGPVRFInstance leaves an edge attachment as the
// only user of VPC a on the node: a's BGPVRFInstance is kept, b's, which
// nothing uses, is reclaimed through b's fence, and c's, whose VRF is gone,
// is deleted outright.
func TestEdgeAttachmentKeepsBGPVRFInstance(t *testing.T) {
	ctx := context.Background()
	withFakeLinks(t, vrfLinks("a", "b"), nil)
	k8s := edgeTestClient(t, "a", "b", "c")
	edge := using("a")
	orphans, err := CollectOrphanedCRDs(ctx, k8s, edgeTestNamespace, edgeTestNode, edge)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"BGPAdvertisement/a-att",
		"BGPVRFInstance/" + crdnames.BGPVRFInstanceName("b", edgeTestNode),
		"BGPVRFInstance/" + crdnames.BGPVRFInstanceName("c", edgeTestNode),
	}
	if got := orphanNames(orphans); !slices.Equal(got, want) {
		t.Fatalf("orphans = %v, want %v", got, want)
	}
	instance := func(vpc string) error {
		var inst bgpv1alpha1.BGPVRFInstance
		key := types.NamespacedName{Namespace: edgeTestNamespace, Name: crdnames.BGPVRFInstanceName(vpc, edgeTestNode)}
		return k8s.Get(ctx, key, &inst)
	}

	// An edge attachment starts using b after collection: the reclaim,
	// decided again under the fence, keeps it.
	edge.vpcs["b"] = struct{}{}
	res := RemoveOrphanedCRDs(ctx, k8s, orphans, edge)
	if res.Errors != 0 || res.OrphanedCRDsRemoved != 2 {
		t.Fatalf("remove = %+v, want the advertisement and c's BGPVRFInstance removed", res)
	}
	for _, vpc := range []string{"a", "b"} {
		if err := instance(vpc); err != nil {
			t.Errorf("%s's BGPVRFInstance after GC: %v", vpc, err)
		}
	}
	if err := instance("c"); !apierrors.IsNotFound(err) {
		t.Errorf("c's BGPVRFInstance after GC: %v, want it gone", err)
	}

	// Once nothing uses b, it is reclaimed through b's fence.
	delete(edge.vpcs, "b")
	orphans, err = CollectOrphanedCRDs(ctx, k8s, edgeTestNamespace, edgeTestNode, edge)
	if err != nil {
		t.Fatal(err)
	}
	if res := RemoveOrphanedCRDs(ctx, k8s, orphans, edge); res.Errors != 0 || res.OrphanedCRDsRemoved != 1 {
		t.Fatalf("remove = %+v, want b's BGPVRFInstance removed", res)
	}
	if !slices.Equal(edge.reclaimed, []string{"b"}) {
		t.Errorf("reclaims ran for %v, want only b's last one", edge.reclaimed)
	}
	if err := instance("b"); !apierrors.IsNotFound(err) {
		t.Fatalf("b's BGPVRFInstance after reclaim: %v, want it gone", err)
	}
}

// TestUnknownEdgeUseKeepsBGPVRFInstances fails the edge read: advertisements
// are still collected, BGPVRFInstances are not.
func TestUnknownEdgeUseKeepsBGPVRFInstances(t *testing.T) {
	k8s := edgeTestClient(t, "a", "b")
	withFakeLinks(t, vrfLinks("a", "b"), nil)
	orphans, err := CollectOrphanedCRDs(context.Background(), k8s, edgeTestNamespace, edgeTestNode,
		&edgeUsers{err: errors.New("forbidden")})
	if err == nil {
		t.Fatal("collection succeeded without knowing edge use")
	}
	if got := orphanNames(orphans); !slices.Equal(got, []string{"BGPAdvertisement/a-att"}) {
		t.Fatalf("orphans = %v, want only the advertisement", got)
	}
}

// TestEdgeAttachmentKeepsVRF collects VRFs with an edge attachment the only
// user of a's.
func TestEdgeAttachmentKeepsVRF(t *testing.T) {
	withFakeLinks(t, vrfLinks("a", "b"), nil)
	k8s := edgeTestClient(t, "a", "b")
	got, err := CollectOrphanedVRFs(context.Background(), k8s, edgeTestNamespace, edgeTestNode, using("a"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{intf.GenerateInterfaceNameVRF("b")}; !slices.Equal(got, want) {
		t.Fatalf("orphaned VRFs = %v, want %v", got, want)
	}
	if _, err := CollectOrphanedVRFs(context.Background(), k8s, edgeTestNamespace, edgeTestNode,
		&edgeUsers{err: errors.New("forbidden")}); err == nil {
		t.Fatal("VRF collection succeeded without knowing edge use")
	}
}

// TestInUseVRFIsNotRemoved removes a VRF an edge attachment started using
// after collection: nothing runs and nothing is counted.
func TestInUseVRFIsNotRemoved(t *testing.T) {
	edge := using("a")
	res := RemoveOrphanedVRFs(context.Background(), []string{intf.GenerateInterfaceNameVRF("a")}, edge)
	if res.Errors != 0 || res.OrphanedVRFsRemoved != 0 || len(edge.reclaimed) != 0 {
		t.Fatalf("remove = %+v, reclaims %v; want the VRF kept", res, edge.reclaimed)
	}
	unknown := &edgeUsers{err: errors.New("no fence")}
	res = RemoveOrphanedVRFs(context.Background(), []string{intf.GenerateInterfaceNameVRF("a")}, unknown)
	if res.Errors != 1 {
		t.Fatalf("remove without a fence = %+v, want one error", res)
	}
}
