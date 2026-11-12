// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
)

// TestMarkReplacedAdvertisements: an ADD marks only the other nodes'
// advertisements for its own attachment, never its own or another
// attachment's.
func TestMarkReplacedAdvertisements(t *testing.T) {
	const ns, vpc, att, other = "galactic-system", "1n", "bQy", "bQz"
	adv := func(name string) *bgpv1alpha1.BGPAdvertisement {
		return &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
	}
	own := adv(crdnames.BGPAdvertisementName(vpc, att, "node-b"))
	old := adv(crdnames.BGPAdvertisementName(vpc, att, "node-a"))
	unrelated := adv(crdnames.BGPAdvertisementName(vpc, other, "node-a"))
	k8s := fakeClient(own, old, unrelated)

	if err := markReplacedAdvertisements(context.Background(), k8s, ns, vpc, att, "node-b"); err != nil {
		t.Fatal(err)
	}
	want := map[*bgpv1alpha1.BGPAdvertisement]string{own: "", old: "node-b", unrelated: ""}
	for a, by := range want {
		var got bgpv1alpha1.BGPAdvertisement
		if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(a), &got); err != nil {
			t.Fatal(err)
		}
		if got.Annotations[crdnames.AnnotationReplacedBy] != by {
			t.Errorf("%s replaced-by = %q, want %q", a.Name, got.Annotations[crdnames.AnnotationReplacedBy], by)
		}
	}
}
