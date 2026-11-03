// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

const (
	staleNode       = "node-a"
	staleNamespace  = "galactic-system"
	staleVPC        = "Ab3"
	staleAttachment = "x7"
	staleOwner      = "0123456789ab"
	staleIndex      = 41
)

var staleName = intf.GenerateInterfaceNameHost(staleVPC, staleAttachment)

// staleTapLink returns a fabricated tap with the given name, index, owner
// stamp and attached queue count.
func staleTapLink(name string, index int, alias string, queues int) *netlink.Tuntap {
	return &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: name, Index: index, Alias: alias},
		Mode:      netlink.TUNTAP_MODE_TAP,
		Queues:    queues,
	}
}

// staleTapFixture substitutes the kernel and map calls a pass makes and
// records the removals it attempts.
type staleTapFixture struct {
	links        []netlink.Link
	unregistered []uint32
	deleted      []string
	events       []string
	unregErr     error
	deleteErr    error
}

func newStaleTapFixture(t *testing.T, links ...netlink.Link) *staleTapFixture {
	t.Helper()
	f := &staleTapFixture{links: links}
	listLinks, byName, locked, unregister, del := staleTapListLinksFn, staleTapLinkByNameFn,
		staleTapVRFLockedFn, staleTapUnregisterFn, staleTapDeleteFn
	t.Cleanup(func() {
		staleTapListLinksFn, staleTapLinkByNameFn, staleTapVRFLockedFn, staleTapUnregisterFn, staleTapDeleteFn =
			listLinks, byName, locked, unregister, del
	})
	staleTapListLinksFn = func() ([]netlink.Link, error) { return f.links, nil }
	staleTapLinkByNameFn = func(name string) (netlink.Link, error) {
		for _, l := range f.links {
			if l.Attrs().Name == name {
				return l, nil
			}
		}
		return nil, netlink.LinkNotFoundError{}
	}
	staleTapVRFLockedFn = func(fn func() error) error { return fn() }
	staleTapUnregisterFn = func(ifindex uint32) error {
		if f.unregErr != nil {
			return f.unregErr
		}
		f.unregistered = append(f.unregistered, ifindex)
		f.events = append(f.events, "unregister")
		return nil
	}
	staleTapDeleteFn = func(vpc, vpcAttachment, owner string) error {
		if f.deleteErr != nil {
			return f.deleteErr
		}
		name := intf.GenerateInterfaceNameHost(vpc, vpcAttachment)
		f.deleted = append(f.deleted, name+"/"+owner)
		f.events = append(f.events, "delete")
		kept := f.links[:0]
		for _, l := range f.links {
			if l.Attrs().Name != name {
				kept = append(kept, l)
			}
		}
		f.links = kept
		return nil
	}
	return f
}

// staleClient returns a fake client holding objs and one unrelated
// VPCAttachment, since a pass removes nothing while the cluster lists no
// identified attachment.
func staleClient(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	objs = append(objs, vpcAttachment("unrelated", staleVPC, "y9"))
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(bgpv1alpha1.AddToScheme(s))
	utilruntime.Must(cloudv1alpha1.AddToScheme(s))
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).WithInterceptorFuncs(funcs).Build()
}

func vpcAttachment(name, vpc, attachment string) *cloudv1alpha1.VPCAttachment {
	return &cloudv1alpha1.VPCAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant"},
		Status:     cloudv1alpha1.VPCAttachmentStatus{VPC: vpc, VPCAttachment: attachment},
	}
}

func advertisement(name string) *bgpv1alpha1.BGPAdvertisement {
	return &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: staleNamespace}}
}

// TestStaleTapReclaimRemovesOnSecondPass is the issue's reproduction: a
// stamped, detached tap with no BGPAdvertisement and no VPCAttachment is
// removed, with its eBPF rows first, once a second pass confirms it.
func TestStaleTapReclaimRemovesOnSecondPass(t *testing.T) {
	f := newStaleTapFixture(t, staleTapLink(staleName, staleIndex, staleOwner, 0))
	k8s := staleClient(t, interceptor.Funcs{})
	r := &staleTapReclaimer{}

	got, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode)
	if err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if got.Reclaimed != 0 || got.Pending != 1 || !got.Complete || len(f.deleted) != 0 {
		t.Fatalf("first pass = %+v, deleted %v; want only a pending candidate", got, f.deleted)
	}

	got, err = r.reclaim(context.Background(), k8s, staleNamespace, staleNode)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if got.Reclaimed != 1 || got.Pending != 0 {
		t.Fatalf("second pass = %+v; want one reclaimed", got)
	}
	if len(f.unregistered) != 1 || f.unregistered[0] != staleIndex {
		t.Errorf("unregistered %v; want [%d]", f.unregistered, staleIndex)
	}
	if want := staleName + "/" + staleOwner; len(f.deleted) != 1 || f.deleted[0] != want {
		t.Errorf("deleted %v; want [%s]", f.deleted, want)
	}
	if len(f.events) != 2 || f.events[0] != "unregister" || f.events[1] != "delete" {
		t.Errorf("events %v; want the eBPF rows removed before the tap", f.events)
	}
}

// TestStaleTapReclaimKeeps covers every tap a pass must never remove.
func TestStaleTapReclaimKeeps(t *testing.T) {
	hostOnlyAlias := ifindexvrfmap.HostOnlyAlias([]uint16{22}, staleOwner)
	cases := []struct {
		name string
		link netlink.Link
		objs []client.Object
	}{
		{name: "a VMM holds it", link: staleTapLink(staleName, staleIndex, staleOwner, 1)},
		{name: "a VMM holds only disabled queues", link: func() netlink.Link {
			l := staleTapLink(staleName, staleIndex, staleOwner, 0)
			l.DisabledQueues = 1
			return l
		}()},
		{name: "no owner stamp", link: staleTapLink(staleName, staleIndex, "", 0)},
		{name: "a malformed host-only stamp with no owner",
			link: staleTapLink(staleName, staleIndex, "galactic-host-only-tcp=notaport", 0)},
		{name: "an owner-less host-only stamp a VMM holds",
			link: staleTapLink(staleName, staleIndex, ifindexvrfmap.HostOnlyAlias([]uint16{22}, ""), 1)},
		{name: "an owner-less host-only stamp whose VPCAttachment exists",
			link: staleTapLink(staleName, staleIndex, ifindexvrfmap.HostOnlyAlias([]uint16{22}, ""), 0),
			objs: []client.Object{vpcAttachment("live", staleVPC, staleAttachment)}},
		{name: "an owner-less host-only stamp an advertisement names",
			link: staleTapLink(staleName, staleIndex, ifindexvrfmap.HostOnlyAlias([]uint16{22}, ""), 0),
			objs: []client.Object{advertisement(crdnames.BGPAdvertisementName(staleVPC, staleAttachment, staleNode))}},
		{name: "not a tenant host link", link: staleTapLink("tap0", staleIndex, staleOwner, 0)},
		{name: "a tun device", link: func() netlink.Link {
			l := staleTapLink(staleName, staleIndex, staleOwner, 0)
			l.Mode = netlink.TUNTAP_MODE_TUN
			return l
		}()},
		{name: "a veth", link: &netlink.Veth{LinkAttrs: netlink.LinkAttrs{
			Name: staleName, Index: staleIndex, Alias: staleOwner}}},
		{name: "a VPCAttachment carries its identity", link: staleTapLink(staleName, staleIndex, staleOwner, 0),
			objs: []client.Object{vpcAttachment("live", staleVPC, staleAttachment)}},
		{name: "a VPCAttachment carries its zero-padded identity",
			link: staleTapLink(staleName, staleIndex, staleOwner, 0),
			objs: []client.Object{vpcAttachment("live", "00"+staleVPC, "0"+staleAttachment)}},
		{name: "an advertisement names it", link: staleTapLink(staleName, staleIndex, staleOwner, 0),
			objs: []client.Object{advertisement(crdnames.BGPAdvertisementName(staleVPC, staleAttachment, staleNode))}},
		{name: "another node's advertisement names it", link: staleTapLink(staleName, staleIndex, staleOwner, 0),
			objs: []client.Object{advertisement(crdnames.BGPAdvertisementName(staleVPC, staleAttachment, "node-b"))}},
		{name: "a legacy advertisement names it", link: staleTapLink(staleName, staleIndex, staleOwner, 0),
			objs: []client.Object{advertisement(staleVPC + "-" + staleAttachment + "-" + staleNode)}},
		{name: "kept host-only stamp still reads its owner, but a VMM holds it",
			link: staleTapLink(staleName, staleIndex, hostOnlyAlias, 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newStaleTapFixture(t, tc.link)
			k8s := staleClient(t, interceptor.Funcs{}, tc.objs...)
			r := &staleTapReclaimer{}
			for range 3 {
				if _, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode); err != nil {
					t.Fatalf("reclaim: %v", err)
				}
			}
			if len(f.deleted) != 0 || len(f.unregistered) != 0 {
				t.Errorf("deleted %v, unregistered %v; want the tap kept", f.deleted, f.unregistered)
			}
		})
	}
}

// TestStaleTapReclaimHostOnlyStamp removes a stale tap whose alias also
// records host-only ports, deleting it as the owner the stamp names.
func TestStaleTapReclaimHostOnlyStamp(t *testing.T) {
	alias := ifindexvrfmap.HostOnlyAlias([]uint16{22}, staleOwner)
	f := newStaleTapFixture(t, staleTapLink(staleName, staleIndex, alias, 0))
	k8s := staleClient(t, interceptor.Funcs{})
	r := &staleTapReclaimer{}
	for range 2 {
		if _, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode); err != nil {
			t.Fatalf("reclaim: %v", err)
		}
	}
	if want := staleName + "/" + staleOwner; len(f.deleted) != 1 || f.deleted[0] != want {
		t.Errorf("deleted %v; want [%s]", f.deleted, want)
	}
}

// TestStaleTapReclaimOwnerlessHostOnlyStamp removes a stale tap whose
// host-only stamp names no owner, deleting it as the empty owner, and only on
// the second pass.
func TestStaleTapReclaimOwnerlessHostOnlyStamp(t *testing.T) {
	alias := ifindexvrfmap.HostOnlyAlias([]uint16{22}, "")
	f := newStaleTapFixture(t, staleTapLink(staleName, staleIndex, alias, 0))
	k8s := staleClient(t, interceptor.Funcs{})
	r := &staleTapReclaimer{}
	for pass, want := range []int{0, 1} {
		got, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode)
		if err != nil {
			t.Fatalf("pass %d: %v", pass+1, err)
		}
		if got.Reclaimed != want {
			t.Fatalf("pass %d = %+v; want %d reclaimed", pass+1, got, want)
		}
	}
	if want := staleName + "/"; len(f.deleted) != 1 || f.deleted[0] != want {
		t.Errorf("deleted %v; want [%s]", f.deleted, want)
	}
	if len(f.unregistered) != 1 || f.unregistered[0] != staleIndex {
		t.Errorf("unregistered %v; want [%d]", f.unregistered, staleIndex)
	}
}

// TestStaleTapReclaimRequiresSameTap keeps a candidate that changed between
// passes, whether a new ADD restamped it or it was recreated at another
// ifindex, and confirms it afresh.
func TestStaleTapReclaimRequiresSameTap(t *testing.T) {
	for _, tc := range []struct {
		name string
		next *netlink.Tuntap
	}{
		{name: "restamped", next: staleTapLink(staleName, staleIndex, "fedcba987654", 0)},
		{name: "recreated", next: staleTapLink(staleName, staleIndex+1, staleOwner, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStaleTapFixture(t, staleTapLink(staleName, staleIndex, staleOwner, 0))
			k8s := staleClient(t, interceptor.Funcs{})
			r := &staleTapReclaimer{}
			if _, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode); err != nil {
				t.Fatalf("first pass: %v", err)
			}
			f.links = []netlink.Link{tc.next}
			got, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode)
			if err != nil {
				t.Fatalf("second pass: %v", err)
			}
			if got.Reclaimed != 0 || got.Pending != 1 || len(f.deleted) != 0 {
				t.Fatalf("second pass = %+v, deleted %v; want the changed tap pending again", got, f.deleted)
			}
		})
	}
}

// TestStaleTapReclaimRechecksUnderLock keeps a confirmed candidate a VMM
// opened between the list and the VRF lock.
func TestStaleTapReclaimRechecksUnderLock(t *testing.T) {
	f := newStaleTapFixture(t, staleTapLink(staleName, staleIndex, staleOwner, 0))
	k8s := staleClient(t, interceptor.Funcs{})
	r := &staleTapReclaimer{}
	if _, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	staleTapLinkByNameFn = func(string) (netlink.Link, error) {
		return staleTapLink(staleName, staleIndex, staleOwner, 1), nil
	}
	got, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if got.Reclaimed != 0 || len(f.deleted) != 0 || len(f.unregistered) != 0 {
		t.Fatalf("second pass = %+v, deleted %v; want the opened tap kept", got, f.deleted)
	}
}

// TestStaleTapReclaimKeepsTapWhoseRowsRemain keeps a tap whose eBPF rows
// could not be removed, since nothing resolves its ifindex once it is gone,
// and removes it on the next pass that can.
func TestStaleTapReclaimKeepsTapWhoseRowsRemain(t *testing.T) {
	f := newStaleTapFixture(t, staleTapLink(staleName, staleIndex, staleOwner, 0))
	f.unregErr = errors.New("map busy")
	k8s := staleClient(t, interceptor.Funcs{})
	r := &staleTapReclaimer{}
	if _, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	got, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode)
	if err == nil || got.Pending != 1 || len(f.deleted) != 0 {
		t.Fatalf("second pass = %+v, err %v, deleted %v; want an error and the tap kept", got, err, f.deleted)
	}
	f.unregErr = nil
	got, err = r.reclaim(context.Background(), k8s, staleNamespace, staleNode)
	if err != nil || got.Reclaimed != 1 {
		t.Fatalf("third pass = %+v, err %v; want the tap reclaimed", got, err)
	}
}

// TestStaleTapReclaimListFailure removes nothing when either list fails, and
// reports the pass incomplete.
func TestStaleTapReclaimListFailure(t *testing.T) {
	for _, failing := range []string{"BGPAdvertisementList", "VPCAttachmentList"} {
		t.Run(failing, func(t *testing.T) {
			f := newStaleTapFixture(t, staleTapLink(staleName, staleIndex, staleOwner, 0))
			r := &staleTapReclaimer{}
			ok := staleClient(t, interceptor.Funcs{})
			if _, err := r.reclaim(context.Background(), ok, staleNamespace, staleNode); err != nil {
				t.Fatalf("first pass: %v", err)
			}
			broken := staleClient(t, interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					switch list.(type) {
					case *bgpv1alpha1.BGPAdvertisementList:
						if failing == "BGPAdvertisementList" {
							return errors.New("unavailable")
						}
					case *cloudv1alpha1.VPCAttachmentList:
						if failing == "VPCAttachmentList" {
							return errors.New("unavailable")
						}
					}
					return c.List(ctx, list, opts...)
				},
			})
			got, err := r.reclaim(context.Background(), broken, staleNamespace, staleNode)
			if err == nil || got.Complete || len(f.deleted) != 0 {
				t.Fatalf("pass = %+v, err %v, deleted %v; want an incomplete failed pass", got, err, f.deleted)
			}
		})
	}
}

// TestStaleTapReclaimNoIdentifiedAttachments removes nothing while the cluster
// lists no VPCAttachment carrying an identity, which is not proof that a tap
// is unowned.
func TestStaleTapReclaimNoIdentifiedAttachments(t *testing.T) {
	f := newStaleTapFixture(t, staleTapLink(staleName, staleIndex, staleOwner, 0))
	s := runtime.NewScheme()
	utilruntime.Must(bgpv1alpha1.AddToScheme(s))
	utilruntime.Must(cloudv1alpha1.AddToScheme(s))
	k8s := fake.NewClientBuilder().WithScheme(s).
		WithObjects(vpcAttachment("unidentified", "", "")).Build()
	r := &staleTapReclaimer{}
	for range 3 {
		got, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode)
		if !errors.Is(err, errNoIdentifiedAttachments) || got.Complete {
			t.Fatalf("pass = %+v, err %v; want an incomplete pass refused for no identified attachment", got, err)
		}
	}
	if len(f.deleted) != 0 || len(f.unregistered) != 0 {
		t.Errorf("deleted %v, unregistered %v; want the tap kept", f.deleted, f.unregistered)
	}
}

// TestStaleTapReclaimFailedPassResetsCandidates requires two consecutive
// passes that read everything: a failed pass between two good ones restarts
// the confirmation.
func TestStaleTapReclaimFailedPassResetsCandidates(t *testing.T) {
	f := newStaleTapFixture(t, staleTapLink(staleName, staleIndex, staleOwner, 0))
	ok := staleClient(t, interceptor.Funcs{})
	broken := staleClient(t, interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errors.New("unavailable")
		},
	})
	r := &staleTapReclaimer{}
	for i, k8s := range []client.Client{ok, broken, ok} {
		_, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode)
		if (i == 1) != (err != nil) {
			t.Fatalf("pass %d: err %v", i+1, err)
		}
	}
	if len(f.deleted) != 0 {
		t.Fatalf("deleted %v after a failed pass; want the confirmation restarted", f.deleted)
	}
	if _, err := r.reclaim(context.Background(), ok, staleNamespace, staleNode); err != nil {
		t.Fatalf("fourth pass: %v", err)
	}
	if len(f.deleted) != 1 {
		t.Errorf("deleted %v; want the tap removed after two good passes", f.deleted)
	}
}

// TestStaleTapReclaimRetriesFailedDelete keeps a candidate whose tap could not
// be deleted after its rows were removed, and removes it on a later pass.
func TestStaleTapReclaimRetriesFailedDelete(t *testing.T) {
	f := newStaleTapFixture(t, staleTapLink(staleName, staleIndex, staleOwner, 0))
	f.deleteErr = errors.New("device busy")
	k8s := staleClient(t, interceptor.Funcs{})
	r := &staleTapReclaimer{}
	if _, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	got, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode)
	if err == nil || got.Reclaimed != 0 || got.Pending != 1 {
		t.Fatalf("second pass = %+v, err %v; want a failed delete kept pending", got, err)
	}
	f.deleteErr = nil
	got, err = r.reclaim(context.Background(), k8s, staleNamespace, staleNode)
	if err != nil || got.Reclaimed != 1 {
		t.Fatalf("third pass = %+v, err %v; want the tap reclaimed", got, err)
	}
}

// TestStaleTapReclaimAdvertisedWithoutAttachments passes cleanly when every
// detached tap is advertised, even in a cluster with no VPCAttachment, such as
// one whose network definitions are written by hand.
func TestStaleTapReclaimAdvertisedWithoutAttachments(t *testing.T) {
	f := newStaleTapFixture(t, staleTapLink(staleName, staleIndex, staleOwner, 0))
	s := runtime.NewScheme()
	utilruntime.Must(bgpv1alpha1.AddToScheme(s))
	utilruntime.Must(cloudv1alpha1.AddToScheme(s))
	k8s := fake.NewClientBuilder().WithScheme(s).
		WithObjects(advertisement(crdnames.BGPAdvertisementName(staleVPC, staleAttachment, staleNode))).Build()
	r := &staleTapReclaimer{}
	for range 2 {
		got, err := r.reclaim(context.Background(), k8s, staleNamespace, staleNode)
		if err != nil || !got.Complete || got.Pending != 0 {
			t.Fatalf("pass = %+v, err %v; want a complete pass with nothing pending", got, err)
		}
	}
	if len(f.deleted) != 0 {
		t.Errorf("deleted %v; want the advertised tap kept", f.deleted)
	}
}
