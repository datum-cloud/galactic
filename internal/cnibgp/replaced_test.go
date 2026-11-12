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

	marked, err := markReplacedAdvertisements(context.Background(), k8s, ns, vpc, att, "node-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(marked) != 1 || marked[0] != old.Name {
		t.Fatalf("marked = %v, want [%s]", marked, old.Name)
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

// TestUnmarkLeavesLaterMarks: rolling back an ADD removes only the marks that
// still name its node, never one a later ADD on another node wrote.
func TestUnmarkLeavesLaterMarks(t *testing.T) {
	const ns = "galactic-system"
	mine := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{
		Name: "a", Namespace: ns, Annotations: map[string]string{crdnames.AnnotationReplacedBy: "node-b"},
	}}
	later := &bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{
		Name: "c", Namespace: ns, Annotations: map[string]string{crdnames.AnnotationReplacedBy: "node-d"},
	}}
	k8s := fakeClient(mine, later)
	unmarkReplacedAdvertisements(context.Background(), k8s, ns, "node-b", []string{"a", "c", "gone"})
	for name, want := range map[string]string{"a": "", "c": "node-d"} {
		var got bgpv1alpha1.BGPAdvertisement
		if err := k8s.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &got); err != nil {
			t.Fatal(err)
		}
		if got.Annotations[crdnames.AnnotationReplacedBy] != want {
			t.Errorf("%s replaced-by = %q, want %q", name, got.Annotations[crdnames.AnnotationReplacedBy], want)
		}
	}
}
