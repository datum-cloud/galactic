// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"context"
	"errors"
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
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

const (
	reclaimVPC      = "jU"
	reclaimOtherVPC = "kV"
	// deadSandbox is a container ID longer than an annotation key keeps, so
	// the owner match has to go through the same truncation the CNI applies.
	deadSandbox  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	liveSandbox  = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	goneNetNSDir = "/var/run/netns/gc-hostlink-test-gone"
)

// fakeKernel is the set of links reclaimHostLinks sees: listed by
// listAllLinksFn, looked up by linkByNameFn and removed by linkDelFn.
type fakeKernel struct {
	links   map[string]netlink.Link
	deleted []string
	// relist, when set, replaces a link at lookup time, standing in for a
	// container taking it over between the listing and the lock.
	relist map[string]netlink.Link
	delErr error
}

func newFakeKernel(t *testing.T, links ...netlink.Link) *fakeKernel {
	t.Helper()
	k := &fakeKernel{links: map[string]netlink.Link{}}
	for _, l := range links {
		k.links[l.Attrs().Name] = l
	}
	origList, origByName, origDel := listAllLinksFn, linkByNameFn, linkDelFn
	listAllLinksFn = func() ([]netlink.Link, error) {
		out := make([]netlink.Link, 0, len(k.links))
		for _, l := range k.links {
			out = append(out, l)
		}
		return out, nil
	}
	linkByNameFn = func(name string) (netlink.Link, error) {
		if l, ok := k.relist[name]; ok {
			return l, nil
		}
		if l, ok := k.links[name]; ok {
			return l, nil
		}
		return nil, netlink.LinkNotFoundError{}
	}
	linkDelFn = func(l netlink.Link) error {
		if k.delErr != nil {
			return k.delErr
		}
		k.deleted = append(k.deleted, l.Attrs().Name)
		delete(k.links, l.Attrs().Name)
		return nil
	}
	t.Cleanup(func() { listAllLinksFn, linkByNameFn, linkDelFn = origList, origByName, origDel })
	return k
}

// hostTap returns a host tap for vpc's attachment att with the given owner
// alias and ifindex.
func hostTap(vpc, att, owner string, index int) netlink.Link {
	return &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{
		Name: intf.GenerateInterfaceNameHost(vpc, att), Alias: owner, Index: index,
	}}
}

// deadAttachment is the attachment whose sandbox is gone.
const deadAttachment = "a1"

// deadAttachmentClient holds this node's router and one BGPAdvertisement for
// reclaimVPC's deadAttachment, recording only deadSandbox, whose netns is
// gone.
func deadAttachmentClient(t *testing.T) client.Client {
	t.Helper()
	objs := []client.Object{
		&bgpv1alpha1.BGPRouter{
			ObjectMeta: metav1.ObjectMeta{Name: edgeTestRouter, Namespace: edgeTestNamespace},
			Spec: bgpv1alpha1.BGPRouterSpec{
				TargetRef: bgpv1alpha1.TargetRef{Kind: targetKindNode, Name: edgeTestNode},
				LocalASN:  65000, SRv6Locator: testLocator, NodeID: 5,
			},
		},
		&bgpv1alpha1.BGPAdvertisement{
			ObjectMeta: metav1.ObjectMeta{
				Name:        crdnames.BGPAdvertisementName(reclaimVPC, deadAttachment, edgeTestNode),
				Namespace:   edgeTestNamespace,
				Annotations: map[string]string{crdnames.NetNSKey(deadSandbox): goneNetNSDir},
			},
			Spec: bgpv1alpha1.BGPAdvertisementSpec{RouterRef: bgpv1alpha1.RouterRef{Name: edgeTestRouter}},
		},
	}
	return fake.NewClientBuilder().WithScheme(gcTestScheme(t)).WithObjects(objs...).Build()
}

// collectAdvertisements runs the CRD collection and returns only the
// BGPAdvertisement orphans.
func collectAdvertisements(t *testing.T, k8s client.Client) []OrphanedCRD {
	t.Helper()
	withFakeLinks(t, indexedVRFLinks(reclaimVPC), nil)
	orphans, err := CollectOrphanedCRDs(context.Background(), k8s, edgeTestNamespace, edgeTestNode, using())
	if err != nil {
		t.Fatal(err)
	}
	var advs []OrphanedCRD
	for _, o := range orphans {
		if o.Kind == kindBGPAdvertisement {
			advs = append(advs, o)
		}
	}
	if len(advs) != 1 {
		t.Fatalf("collected advertisements = %v, want the dead attachment's", orphanNames(advs))
	}
	return advs
}

// advertisementExists reports whether the dead attachment's advertisement is
// still there.
func advertisementExists(t *testing.T, k8s client.Client) bool {
	t.Helper()
	key := types.NamespacedName{
		Namespace: edgeTestNamespace, Name: crdnames.BGPAdvertisementName(reclaimVPC, deadAttachment, edgeTestNode),
	}
	err := k8s.Get(context.Background(), key, &bgpv1alpha1.BGPAdvertisement{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return err == nil
}

// TestDeadAttachmentHostLinkReclaimed is the regression for a tap left behind
// by a sandbox whose DEL never removed it: GC used to delete the dead
// attachment's advertisement and leave the tap, still enslaved and still
// carrying the pod-subnet route that refused every later attachment given the
// same address. The dead owner's tap now goes with the advertisement, while a
// live container's tap on the same VPC, a dead owner's tap on another VPC and
// an unstamped tap of another attachment are all kept.
func TestDeadAttachmentHostLinkReclaimed(t *testing.T) {
	k8s := deadAttachmentClient(t)
	advs := collectAdvertisements(t, k8s)
	k := newFakeKernel(t,
		hostTap(reclaimVPC, "a1", deadSandbox, 10),
		hostTap(reclaimVPC, "b2", liveSandbox, 11),
		hostTap(reclaimOtherVPC, "a1", deadSandbox, 12),
		hostTap(reclaimVPC, "c3", "", 13),
	)

	res := RemoveOrphanedCRDs(context.Background(), k8s, advs, using())

	if res.Errors != 0 || res.OrphanedCRDsRemoved != 1 || res.HostLinksRemoved != 1 {
		t.Fatalf("remove = %+v, want the advertisement and one host link removed", res)
	}
	if want := []string{intf.GenerateInterfaceNameHost(reclaimVPC, "a1")}; !slices.Equal(k.deleted, want) {
		t.Fatalf("deleted links = %v, want %v", k.deleted, want)
	}
	if advertisementExists(t, k8s) {
		t.Fatal("dead attachment's advertisement survived GC")
	}
}

// TestUnstampedHostLinkReclaimedByName covers a host link a build before the
// owner stamp left: it carries no owner, so it is reclaimed only because its
// name maps to the dead advertisement exactly.
func TestUnstampedHostLinkReclaimedByName(t *testing.T) {
	k8s := deadAttachmentClient(t)
	advs := collectAdvertisements(t, k8s)
	k := newFakeKernel(t, hostTap(reclaimVPC, "a1", "", 10))

	res := RemoveOrphanedCRDs(context.Background(), k8s, advs, using())

	if res.Errors != 0 || res.HostLinksRemoved != 1 || len(k.deleted) != 1 {
		t.Fatalf("remove = %+v, deleted %v, want the unstamped link removed", res, k.deleted)
	}
}

// TestHostLinkTakenOverIsKept lists the dead owner's tap, then has a new
// container adopt it before the VRF lock is taken, as a master plugin's ADD
// would. The decision, made again under the lock, keeps the tap; the dead
// advertisement still goes.
func TestHostLinkTakenOverIsKept(t *testing.T) {
	k8s := deadAttachmentClient(t)
	advs := collectAdvertisements(t, k8s)
	name := intf.GenerateInterfaceNameHost(reclaimVPC, "a1")
	k := newFakeKernel(t, hostTap(reclaimVPC, "a1", deadSandbox, 10))
	k.relist = map[string]netlink.Link{name: hostTap(reclaimVPC, "a1", liveSandbox, 10)}

	res := RemoveOrphanedCRDs(context.Background(), k8s, advs, using())

	if res.Errors != 0 || res.HostLinksRemoved != 0 || len(k.deleted) != 0 {
		t.Fatalf("remove = %+v, deleted %v, want the adopted tap kept", res, k.deleted)
	}
	if advertisementExists(t, k8s) {
		t.Fatal("dead attachment's advertisement survived GC")
	}
}

// TestHostLinkDeleteFailureKeepsAdvertisement fails the link removal: the
// advertisement, the only proof the link is dead, is kept for the next pass.
func TestHostLinkDeleteFailureKeepsAdvertisement(t *testing.T) {
	k8s := deadAttachmentClient(t)
	advs := collectAdvertisements(t, k8s)
	k := newFakeKernel(t, hostTap(reclaimVPC, "a1", deadSandbox, 10))
	k.delErr = errors.New("operation not permitted")

	res := RemoveOrphanedCRDs(context.Background(), k8s, advs, using())

	if res.Errors != 1 || res.OrphanedCRDsRemoved != 0 {
		t.Fatalf("remove = %+v, want one error and nothing removed", res)
	}
	if !advertisementExists(t, k8s) {
		t.Fatal("advertisement deleted although its host link could not be removed")
	}
}

// TestHostLinkAlreadyGone has the link vanish between the listing and the
// lock, as a late DEL would remove it: nothing to do, and no error.
func TestHostLinkAlreadyGone(t *testing.T) {
	k8s := deadAttachmentClient(t)
	advs := collectAdvertisements(t, k8s)
	k := newFakeKernel(t, hostTap(reclaimVPC, "a1", deadSandbox, 10))
	baseByName := linkByNameFn
	linkByNameFn = func(string) (netlink.Link, error) { return nil, netlink.LinkNotFoundError{} }
	t.Cleanup(func() { linkByNameFn = baseByName })

	res := RemoveOrphanedCRDs(context.Background(), k8s, advs, using())

	if res.Errors != 0 || res.OrphanedCRDsRemoved != 1 || res.HostLinksRemoved != 0 || len(k.deleted) != 0 {
		t.Fatalf("remove = %+v, deleted %v, want only the advertisement removed", res, k.deleted)
	}
}

// TestHostOnlyTapReclaimed covers a VM tap with host-only ports, whose alias
// records the ports as well as its owner. The dead owner's tap is reclaimed
// through that alias, while a live owner's host-only tap on the same VPC is
// kept. A host-only alias from a build before it kept the owner records none,
// so that tap is reclaimed only by its exact name.
func TestHostOnlyTapReclaimed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alias string
	}{
		{"owner recorded with the ports", ifindexvrfmap.HostOnlyAlias([]uint16{20000}, deadSandbox)},
		{"ports alias without an owner", ifindexvrfmap.HostOnlyAlias([]uint16{20000}, "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k8s := deadAttachmentClient(t)
			advs := collectAdvertisements(t, k8s)
			k := newFakeKernel(t,
				hostTap(reclaimVPC, deadAttachment, tc.alias, 10),
				hostTap(reclaimVPC, "b2", ifindexvrfmap.HostOnlyAlias([]uint16{20000}, liveSandbox), 11),
			)

			res := RemoveOrphanedCRDs(context.Background(), k8s, advs, using())

			want := []string{intf.GenerateInterfaceNameHost(reclaimVPC, deadAttachment)}
			if res.Errors != 0 || res.HostLinksRemoved != 1 || !slices.Equal(k.deleted, want) {
				t.Fatalf("remove = %+v, deleted %v, want only %v", res, k.deleted, want)
			}
		})
	}
}
