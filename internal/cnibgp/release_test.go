// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
)

const (
	relNS, relVPC, relAtt, relNode = "galactic-system", "1n", "bQy", "node-b"
	oldSandbox, newSandbox         = "old-sandbox", "new-sandbox"
)

// withLiveNetNS makes netNSExistsFn report only the given paths live.
func withLiveNetNS(t *testing.T, live ...string) {
	t.Helper()
	orig := netNSExistsFn
	netNSExistsFn = func(path string) bool {
		for _, l := range live {
			if l == path {
				return true
			}
		}
		return false
	}
	t.Cleanup(func() { netNSExistsFn = orig })
}

func recordedAdvertisement(node string, sandboxes ...string) *bgpv1alpha1.BGPAdvertisement {
	adv := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{
		Name: crdnames.BGPAdvertisementName(relVPC, relAtt, node), Namespace: relNS,
		Annotations: map[string]string{},
	}}
	for _, s := range sandboxes {
		adv.Annotations[crdnames.NetNSKey(s)] = "/var/run/netns/" + s
		adv.Annotations[crdnames.SubnetKeyIPv6(s)] = "fd20::" + s + "/96"
	}
	return adv
}

func getAdvertisement(t *testing.T, k8s client.Client, node string) (*bgpv1alpha1.BGPAdvertisement, bool) {
	t.Helper()
	var adv bgpv1alpha1.BGPAdvertisement
	err := k8s.Get(context.Background(), client.ObjectKey{
		Namespace: relNS, Name: crdnames.BGPAdvertisementName(relVPC, relAtt, node),
	}, &adv)
	if apierrors.IsNotFound(err) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return &adv, true
}

// TestReleaseDeletesLastContainersAdvertisement: DEL of the only container an
// advertisement records deletes it, even while that container's netns still
// exists during teardown.
func TestReleaseDeletesLastContainersAdvertisement(t *testing.T) {
	withLiveNetNS(t, "/var/run/netns/"+oldSandbox)
	k8s := fakeClient(recordedAdvertisement(relNode, oldSandbox))
	if err := releaseAdvertisement(context.Background(), k8s, relNS, relVPC, relAtt, relNode, oldSandbox); err != nil {
		t.Fatal(err)
	}
	if _, ok := getAdvertisement(t, k8s, relNode); ok {
		t.Fatal("advertisement kept after its last container's DEL")
	}
}

// TestReleaseKeepsReplacementsAdvertisement: when a replacement container's
// ADD ran before the old one's DEL, the DEL removes only its own entries and
// the advertisement stays, advertising only the replacement's prefix.
func TestReleaseKeepsReplacementsAdvertisement(t *testing.T) {
	withLiveNetNS(t, "/var/run/netns/"+oldSandbox, "/var/run/netns/"+newSandbox)
	k8s := fakeClient(recordedAdvertisement(relNode, oldSandbox, newSandbox))
	if err := releaseAdvertisement(context.Background(), k8s, relNS, relVPC, relAtt, relNode, oldSandbox); err != nil {
		t.Fatal(err)
	}
	adv, ok := getAdvertisement(t, k8s, relNode)
	if !ok {
		t.Fatal("replacement's advertisement deleted")
	}
	if _, ok := adv.Annotations[crdnames.NetNSKey(oldSandbox)]; ok {
		t.Error("old container still recorded")
	}
	if _, ok := adv.Annotations[crdnames.NetNSKey(newSandbox)]; !ok {
		t.Error("replacement no longer recorded")
	}
	if len(adv.Spec.Prefixes) != 1 || string(adv.Spec.Prefixes[0]) != "fd20::"+newSandbox+"/96" {
		t.Errorf("prefixes = %v, want only the replacement's", adv.Spec.Prefixes)
	}
}

// TestReleaseWithoutAdvertisement: a DEL with nothing to release succeeds.
func TestReleaseWithoutAdvertisement(t *testing.T) {
	if err := releaseAdvertisement(context.Background(), fakeClient(), relNS, relVPC, relAtt, relNode,
		oldSandbox); err != nil {
		t.Fatal(err)
	}
}

// TestAddDeletesOlderOtherNodesAdvertisements: an ADD deletes the
// attachment's older advertisements on other nodes, never its own, a newer
// one, a legacy-named one, or another attachment's.
func TestAddDeletesOlderOtherNodesAdvertisements(t *testing.T) {
	t0 := metav1.NewTime(time.Date(2026, 11, 12, 18, 0, 0, 0, time.UTC))
	t1 := metav1.NewTime(t0.Add(time.Minute))
	t2 := metav1.NewTime(t0.Add(2 * time.Minute))
	at := func(adv *bgpv1alpha1.BGPAdvertisement, ts metav1.Time) *bgpv1alpha1.BGPAdvertisement {
		adv.CreationTimestamp = ts
		return adv
	}
	own := at(recordedAdvertisement(relNode, newSandbox), t1)
	older := at(recordedAdvertisement("node-a", oldSandbox), t0)
	legacy := at(&bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{
		Name: relVPC + "-" + relAtt + "-node-l", Namespace: relNS}}, t0)
	newer := at(recordedAdvertisement("node-c", oldSandbox), t2)
	unrelated := at(&bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{
		Name: crdnames.BGPAdvertisementName(relVPC, "bQz", "node-a"), Namespace: relNS}}, t0)
	k8s := fakeClient(own, older, legacy, newer, unrelated)
	if err := deleteOtherNodeAdvertisements(context.Background(), k8s, relNS, relVPC, relAtt, relNode, own); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		adv  *bgpv1alpha1.BGPAdvertisement
		kept bool
	}{{own, true}, {older, false}, {legacy, true}, {newer, true}, {unrelated, true}} {
		err := k8s.Get(context.Background(), client.ObjectKeyFromObject(c.adv), &bgpv1alpha1.BGPAdvertisement{})
		if kept := err == nil; kept != c.kept {
			t.Errorf("%s kept = %v, want %v (err %v)", c.adv.Name, kept, c.kept, err)
		}
	}
}

// TestReleaseLeavesUnrecordedAdvertisement: an advertisement recording no
// container at all has unknown liveness, so DEL leaves it to GC.
func TestReleaseLeavesUnrecordedAdvertisement(t *testing.T) {
	k8s := fakeClient(recordedAdvertisement(relNode))
	if err := releaseAdvertisement(context.Background(), k8s, relNS, relVPC, relAtt, relNode, oldSandbox); err != nil {
		t.Fatal(err)
	}
	if _, ok := getAdvertisement(t, k8s, relNode); !ok {
		t.Fatal("unrecorded advertisement deleted")
	}
}
