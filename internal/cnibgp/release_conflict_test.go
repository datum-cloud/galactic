// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
)

const racingSandbox = "racing-sandbox"

func recordRacingADD(ctx context.Context, t *testing.T, c client.WithWatch, key client.ObjectKey) {
	t.Helper()
	var live bgpv1alpha1.BGPAdvertisement
	if err := c.Get(ctx, key, &live); err != nil {
		t.Fatal(err)
	}
	live.Annotations[crdnames.NetNSKey(racingSandbox)] = "/var/run/netns/" + racingSandbox
	live.Annotations[crdnames.SubnetKeyIPv6(racingSandbox)] = "fd20::" + racingSandbox + "/96"
	if err := c.Update(ctx, &live); err != nil {
		t.Fatal(err)
	}
}

// TestReleaseDeleteRetriesWhenADDRaces: an ADD recording a new container
// between DEL's read and its delete makes the delete conflict, and the retry
// keeps the advertisement for the new container.
func TestReleaseDeleteRetriesWhenADDRaces(t *testing.T) {
	withLiveNetNS(t, "/var/run/netns/"+racingSandbox)
	raced := false
	k8s := fake.NewClientBuilder().WithScheme(testScheme).
		WithObjects(recordedAdvertisement(relNode, oldSandbox)).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if !raced {
					raced = true
					recordRacingADD(ctx, t, c, client.ObjectKeyFromObject(obj))
				}
				return c.Delete(ctx, obj, opts...)
			},
		}).Build()
	if err := releaseAdvertisement(context.Background(), k8s, relNS, relVPC, relAtt, relNode, oldSandbox); err != nil {
		t.Fatal(err)
	}
	if !raced {
		t.Fatal("DEL never tried to delete the advertisement")
	}
	adv, ok := getAdvertisement(t, k8s, relNode)
	if !ok {
		t.Fatal("racing ADD's advertisement deleted")
	}
	if _, ok := adv.Annotations[crdnames.NetNSKey(racingSandbox)]; !ok {
		t.Error("racing container no longer recorded")
	}
	if _, ok := adv.Annotations[crdnames.NetNSKey(oldSandbox)]; ok {
		t.Error("released container still recorded")
	}
}

// TestReleaseUpdateRetriesWhenADDRaces: an ADD recording a new container
// between DEL's read and its update makes the update conflict, and the retry
// keeps both the replacement and the racing container.
func TestReleaseUpdateRetriesWhenADDRaces(t *testing.T) {
	withLiveNetNS(t, "/var/run/netns/"+newSandbox, "/var/run/netns/"+racingSandbox)
	raced := false
	k8s := fake.NewClientBuilder().WithScheme(testScheme).
		WithObjects(recordedAdvertisement(relNode, oldSandbox, newSandbox)).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if !raced {
					raced = true
					recordRacingADD(ctx, t, c, client.ObjectKeyFromObject(obj))
				}
				return c.Update(ctx, obj, opts...)
			},
		}).Build()
	if err := releaseAdvertisement(context.Background(), k8s, relNS, relVPC, relAtt, relNode, oldSandbox); err != nil {
		t.Fatal(err)
	}
	if !raced {
		t.Fatal("DEL never tried to update the advertisement")
	}
	adv, ok := getAdvertisement(t, k8s, relNode)
	if !ok {
		t.Fatal("advertisement deleted")
	}
	for _, s := range []string{newSandbox, racingSandbox} {
		if _, ok := adv.Annotations[crdnames.NetNSKey(s)]; !ok {
			t.Errorf("%s no longer recorded", s)
		}
	}
	if _, ok := adv.Annotations[crdnames.NetNSKey(oldSandbox)]; ok {
		t.Error("released container still recorded")
	}
	if len(adv.Spec.Prefixes) != 2 {
		t.Errorf("prefixes = %v, want the replacement's and the racing container's", adv.Spec.Prefixes)
	}
}

// TestAddKeepsSameSecondOtherNodeAdvertisement: another node's advertisement
// created in the same second as this node's is not provably older, so ADD
// leaves it for that node's own cleanup.
func TestAddKeepsSameSecondOtherNodeAdvertisement(t *testing.T) {
	ts := metav1.NewTime(time.Date(2026, 11, 12, 18, 0, 0, 0, time.UTC))
	own := recordedAdvertisement(relNode, newSandbox)
	own.CreationTimestamp = ts
	sibling := recordedAdvertisement("node-a", oldSandbox)
	sibling.CreationTimestamp = ts
	k8s := fakeClient(own, sibling)
	if err := deleteOtherNodeAdvertisements(context.Background(), k8s, relNS, relVPC, relAtt, relNode, own); err != nil {
		t.Fatal(err)
	}
	if _, ok := getAdvertisement(t, k8s, "node-a"); !ok {
		t.Fatal("same-second advertisement on another node deleted")
	}
}
