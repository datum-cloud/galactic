// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "go.datum.net/galactic/api/network/v1alpha1"
)

type advertisementReadFailure struct {
	client.Reader
	name string
}

func (r advertisementReadFailure) Get(
	ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
) error {
	if key.Name == r.name {
		return errors.New("authority unavailable")
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func TestBuildDesiredRouterIsolatesUnreadableAuthority(t *testing.T) {
	for _, failed := range []string{"bad-ad", "bad-anchor"} {
		t.Run(failed, func(t *testing.T) {
			router := &api.BGPRouter{
				ObjectMeta: metav1.ObjectMeta{Name: "router", Namespace: testNamespace},
				Spec:       api.BGPRouterSpec{TargetRef: api.TargetRef{Name: "node"}},
			}
			goodAnchor := &api.NetworkServiceAddress{
				ObjectMeta: metav1.ObjectMeta{Name: "good-anchor", Namespace: testNamespace, UID: "good-uid"},
			}
			badAnchor := goodAnchor.DeepCopy()
			badAnchor.Name = "bad-anchor"
			badAnchor.UID = "bad-uid"
			good := &api.BGPAdvertisement{
				ObjectMeta: metav1.ObjectMeta{
					Name: "good-ad", Namespace: testNamespace, UID: "good-ad-uid",
					Finalizers: []string{CoordinatedAdvertisementFinalizer},
					Labels: map[string]string{
						serviceAddressLabel: goodAnchor.Name, serviceAddressUIDLabel: string(goodAnchor.UID),
					},
				},
				Spec: api.BGPAdvertisementSpec{
					RouterRef:     api.RouterRef{Name: router.Name},
					AddressFamily: api.AddressFamily{AFI: api.AFIIPv6, SAFI: api.SAFIUnicast},
					Prefixes:      []api.Prefix{"2001:db8::1/128"},
				},
			}
			bad := good.DeepCopy()
			bad.Name = "bad-ad"
			bad.UID = "bad-ad-uid"
			bad.Labels = map[string]string{serviceAddressLabel: badAnchor.Name, serviceAddressUIDLabel: string(badAnchor.UID)}
			legacy := good.DeepCopy()
			legacy.Name = "authority-legacy"
			legacy.Labels = nil
			legacy.Finalizers = nil
			expired := legacy.DeepCopy()
			expired.Name = "expired"
			past := metav1.NewTime(time.Now().Add(-time.Minute))
			expired.Spec.ExpiresAt = &past
			c := indexedFakeClient(t, router, goodAnchor, badAnchor, good, bad, legacy, expired)
			r := New(c, "node", "2001:db8::2")
			r.SetAPIReader(advertisementReadFailure{Reader: c, name: failed})
			desired, err := r.BuildDesiredRouter(context.Background(), router)
			if err != nil {
				t.Fatal(err)
			}
			names := make([]string, 0, len(desired.Advertisements))
			for _, ad := range desired.Advertisements {
				names = append(names, ad.Name)
			}
			slices.Sort(names)
			if !slices.Equal(names, []string{"authority-legacy", "good-ad"}) {
				t.Fatalf("unrelated routes or lease filtering changed: %v", names)
			}
		})
	}
}
