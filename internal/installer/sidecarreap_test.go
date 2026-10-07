// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/vishvananda/netlink"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/crdnames"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// Host-side interface indexes the tests' advertisements record: one that names
// a live veth and one whose interface is gone.
const (
	liveHostIfindex = 24
	goneHostIfindex = 31
)

// stubHostLinks makes hostLinkByIndexFn report liveHostIfindex as a veth and
// every other index as absent.
func stubHostLinks(t *testing.T) {
	t.Helper()
	orig := hostLinkByIndexFn
	t.Cleanup(func() { hostLinkByIndexFn = orig })
	hostLinkByIndexFn = func(index int) (netlink.Link, error) {
		if index == liveHostIfindex {
			return &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Index: index}}, nil
		}
		return nil, netlink.LinkNotFoundError{}
	}
}

// stubPrune counts prunes, failing each with failWith when it is non-nil.
func stubPrune(t *testing.T, failWith *error) *int {
	t.Helper()
	orig := pruneSidecarRowsFn
	t.Cleanup(func() { pruneSidecarRowsFn = orig })
	calls := 0
	pruneSidecarRowsFn = func() (int, error) {
		calls++
		if failWith != nil && *failWith != nil {
			return 0, *failWith
		}
		return 3, nil
	}
	return &calls
}

// sidecarAdv is a sidecar gateway advertisement on testSidecarNode whose
// recorded host-side interface is hostIfindex.
func sidecarAdv(vpc string, hostIfindex int) *bgpv1alpha1.BGPAdvertisement {
	adv := gatewayAdv(vpc, testSidecarNode, testSidecarAddr+"/128", 1)
	adv.UID = types.UID("uid-" + vpc)
	adv.Annotations[crdnames.AnnotationIngressHostIfindex] = strconv.Itoa(hostIfindex)
	return adv
}

func advExists(t *testing.T, c client.Client, adv *bgpv1alpha1.BGPAdvertisement) bool {
	t.Helper()
	got := &bgpv1alpha1.BGPAdvertisement{}
	err := c.Get(context.Background(), client.ObjectKeyFromObject(adv), got)
	if apierrors.IsNotFound(err) {
		return false
	}
	if err != nil {
		t.Fatalf("Get %s: %v", adv.Name, err)
	}
	return true
}

func TestPlanSidecarReap(t *testing.T) {
	live := ingressAdvertisement{name: "live", liveness: sidecarLivenessLive}
	unknown := ingressAdvertisement{name: "unknown", liveness: sidecarLivenessUnknown}
	gone := ingressAdvertisement{name: "gone", liveness: sidecarLivenessGone}
	gone2 := ingressAdvertisement{name: "gone2", liveness: sidecarLivenessGone}

	tests := []struct {
		name            string
		advs            []ingressAdvertisement
		wantGone        int
		wantSidecarGone bool
	}{
		{name: "no advertisements is no evidence", advs: nil},
		{name: "a live sidecar", advs: []ingressAdvertisement{live}},
		{name: "every advertisement gone", advs: []ingressAdvertisement{gone, gone2}, wantGone: 2, wantSidecarGone: true},
		{name: "a replaced pod's leftovers beside a live one", advs: []ingressAdvertisement{live, gone}, wantGone: 1},
		{name: "unknown keeps the rows", advs: []ingressAdvertisement{unknown, gone}, wantGone: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := planSidecarReap(tt.advs)
			if len(plan.gone) != tt.wantGone {
				t.Errorf("gone = %d advertisements, want %d", len(plan.gone), tt.wantGone)
			}
			if plan.sidecarGone != tt.wantSidecarGone {
				t.Errorf("sidecarGone = %t, want %t", plan.sidecarGone, tt.wantSidecarGone)
			}
		})
	}
}

func TestSidecarLivenessOf(t *testing.T) {
	orig := hostLinkByIndexFn
	t.Cleanup(func() { hostLinkByIndexFn = orig })

	annotated := func(ifindex int) map[string]string {
		return sidecarAdv("2", ifindex).Annotations
	}
	tests := []struct {
		name        string
		annotations map[string]string
		link        netlink.Link
		err         error
		want        sidecarLiveness
	}{
		{name: "no entry point recorded", annotations: nil, want: sidecarLivenessUnknown},
		{name: "veth present", annotations: annotated(7), link: &netlink.Veth{}, want: sidecarLivenessLive},
		{name: "interface absent", annotations: annotated(7), err: netlink.LinkNotFoundError{}, want: sidecarLivenessGone},
		{
			name: "index reused by another kind of link", annotations: annotated(7),
			link: &netlink.Dummy{}, want: sidecarLivenessGone,
		},
		{name: "lookup failed", annotations: annotated(7), err: errors.New("netlink busy"), want: sidecarLivenessUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostLinkByIndexFn = func(int) (netlink.Link, error) { return tt.link, tt.err }
			if got := sidecarLivenessOf(tt.annotations); got != tt.want {
				t.Errorf("sidecarLivenessOf() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestSidecarReaper_GoneSidecarIsRemovedOnTheSecondPass covers a sidecar pod
// deleted with no replacement: the first pass only records what it saw, and
// the second removes the map rows and then the advertisements.
func TestSidecarReaper_GoneSidecarIsRemovedOnTheSecondPass(t *testing.T) {
	stubHostLinks(t)
	prunes := stubPrune(t, nil)
	advA, advB := sidecarAdv("2", goneHostIfindex), sidecarAdv("3", goneHostIfindex)
	c := newAdvClient(t, advA, advB)
	r := &sidecarReaper{}

	if err := r.reap(context.Background(), c, testNamespace, testSidecarNode); err != nil {
		t.Fatalf("first reap: %v", err)
	}
	if *prunes != 0 || !advExists(t, c, advA) || !advExists(t, c, advB) {
		t.Fatalf("first pass removed something (prunes=%d); want it only to record the evidence", *prunes)
	}

	if err := r.reap(context.Background(), c, testNamespace, testSidecarNode); err != nil {
		t.Fatalf("second reap: %v", err)
	}
	if *prunes != 1 {
		t.Errorf("prunes = %d, want 1", *prunes)
	}
	if advExists(t, c, advA) || advExists(t, c, advB) {
		t.Error("a gone sidecar's advertisements survived the second pass")
	}
}

// TestSidecarReaper_ReplacedPodsLeftoversGoAtOnce covers a replaced pod: its
// replacement is live, so the leftover advertisement goes on the first pass
// and no map row is touched, since the live sidecar removes its predecessor's.
func TestSidecarReaper_ReplacedPodsLeftoversGoAtOnce(t *testing.T) {
	stubHostLinks(t)
	prunes := stubPrune(t, nil)
	live, leftover := sidecarAdv("2", liveHostIfindex), sidecarAdv("3", goneHostIfindex)
	c := newAdvClient(t, live, leftover)
	r := &sidecarReaper{}

	for range 2 {
		if err := r.reap(context.Background(), c, testNamespace, testSidecarNode); err != nil {
			t.Fatalf("reap: %v", err)
		}
	}
	if *prunes != 0 {
		t.Errorf("prunes = %d, want none beside a live sidecar", *prunes)
	}
	if !advExists(t, c, live) {
		t.Error("the live sidecar's advertisement was deleted")
	}
	if advExists(t, c, leftover) {
		t.Error("the replaced pod's leftover advertisement survived")
	}
}

// TestSidecarReaper_RepublishBetweenPassesKeepsTheRows covers a replacement
// pod that wrote its rows just before the first pass and republished just
// after it. The advertisement then differs on the second pass, which must not
// remove the rows the new pod already relies on.
func TestSidecarReaper_RepublishBetweenPassesKeepsTheRows(t *testing.T) {
	stubHostLinks(t)
	prunes := stubPrune(t, nil)
	adv := sidecarAdv("2", goneHostIfindex)
	c := newAdvClient(t, adv)
	r := &sidecarReaper{}

	if err := r.reap(context.Background(), c, testNamespace, testSidecarNode); err != nil {
		t.Fatalf("first reap: %v", err)
	}

	current := &bgpv1alpha1.BGPAdvertisement{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(adv), current); err != nil {
		t.Fatal(err)
	}
	current.Annotations[crdnames.AnnotationIngressHostIfindex] = strconv.Itoa(liveHostIfindex)
	if err := c.Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}

	if err := r.reap(context.Background(), c, testNamespace, testSidecarNode); err != nil {
		t.Fatalf("second reap: %v", err)
	}
	if *prunes != 0 {
		t.Errorf("prunes = %d, want none once the sidecar republished", *prunes)
	}
	if !advExists(t, c, adv) {
		t.Error("the republished advertisement was deleted")
	}
}

// TestSidecarReaper_FailedPruneKeepsTheEvidence verifies the advertisements
// stay when the rows could not be removed, so the next pass retries.
func TestSidecarReaper_FailedPruneKeepsTheEvidence(t *testing.T) {
	stubHostLinks(t)
	failWith := errors.New("map busy")
	prunes := stubPrune(t, &failWith)
	adv := sidecarAdv("2", goneHostIfindex)
	c := newAdvClient(t, adv)
	r := &sidecarReaper{}

	_ = r.reap(context.Background(), c, testNamespace, testSidecarNode)
	if err := r.reap(context.Background(), c, testNamespace, testSidecarNode); !errors.Is(err, failWith) {
		t.Fatalf("second reap = %v, want %v", err, failWith)
	}
	if !advExists(t, c, adv) {
		t.Fatal("advertisement deleted although its rows were not removed")
	}

	failWith = nil
	if err := r.reap(context.Background(), c, testNamespace, testSidecarNode); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if *prunes != 2 || advExists(t, c, adv) {
		t.Errorf("after the retry prunes = %d and advertisement present = %t, want 2 and false",
			*prunes, advExists(t, c, adv))
	}
}

// TestSidecarReaper_LeavesOtherAdvertisementsAlone verifies a pod attachment's
// advertisement and another node's sidecar advertisement are never judged,
// even when the interface they record is gone on this host.
func TestSidecarReaper_LeavesOtherAdvertisementsAlone(t *testing.T) {
	stubHostLinks(t)
	prunes := stubPrune(t, nil)
	pod := podAdv("2", "att1", testSidecarNode, testSidecarAddr+"/128", 1)
	pod.Annotations[crdnames.AnnotationIngressHostIfindex] = strconv.Itoa(goneHostIfindex)
	other := gatewayAdv("2", "worker-other", testSidecarAddr+"/128", 1)
	other.Annotations[crdnames.AnnotationIngressHostIfindex] = strconv.Itoa(goneHostIfindex)
	c := newAdvClient(t, pod, other)
	r := &sidecarReaper{}

	for range 2 {
		if err := r.reap(context.Background(), c, testNamespace, testSidecarNode); err != nil {
			t.Fatalf("reap: %v", err)
		}
	}
	if *prunes != 0 || !advExists(t, c, pod) || !advExists(t, c, other) {
		t.Errorf("reaper acted on advertisements it does not own (prunes=%d)", *prunes)
	}
}

// TestPruneAllSidecarRows_NoDatapathIsQuiet verifies a node whose datapath is
// not loaded, so nothing is pinned, reports nothing to remove rather than an
// error every sweep.
func TestPruneAllSidecarRows_NoDatapathIsQuiet(t *testing.T) {
	removed, err := pruneAllSidecarRows(t.TempDir())
	if err != nil || removed != 0 {
		t.Errorf("pruneAllSidecarRows() = %d, %v; want 0, nil", removed, err)
	}
}
