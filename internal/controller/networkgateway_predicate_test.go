// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/event"

	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

func testAdvertisement(generation int64, srv6 bool) *bgpv1alpha1.BGPAdvertisement {
	adv := &bgpv1alpha1.BGPAdvertisement{}
	adv.Name = "adv"
	adv.Namespace = "ns"
	adv.Generation = generation
	if srv6 {
		adv.Spec.VRFID = ptr(int32(7))
		adv.Spec.Function = ptr(bgpv1alpha1.SRv6FunctionEndDT6)
	}
	return adv
}

func TestBackendAdvertisementPredicate(t *testing.T) {
	p := backendAdvertisementPredicate()

	t.Run("create or delete without VRFID and Function is dropped", func(t *testing.T) {
		adv := testAdvertisement(1, false)
		if p.Create(event.CreateEvent{Object: adv}) {
			t.Error("Create passed an advertisement that cannot locate a backend")
		}
		if p.Delete(event.DeleteEvent{Object: adv}) {
			t.Error("Delete passed an advertisement that cannot locate a backend")
		}
	})

	t.Run("create or delete with VRFID and Function passes", func(t *testing.T) {
		adv := testAdvertisement(1, true)
		if !p.Create(event.CreateEvent{Object: adv}) {
			t.Error("Create dropped a backend advertisement")
		}
		if !p.Delete(event.DeleteEvent{Object: adv}) {
			t.Error("Delete dropped a backend advertisement")
		}
	})

	t.Run("gateway VIP advertisement heals on delete or edit but not create", func(t *testing.T) {
		vipAdv := func(generation int64) *bgpv1alpha1.BGPAdvertisement {
			adv := testAdvertisement(generation, false)
			adv.Labels = map[string]string{networkRuleLabel: "rule"}
			return adv
		}
		if p.Create(event.CreateEvent{Object: vipAdv(1)}) {
			t.Error("Create passed the gateway's own VIP advertisement")
		}
		if !p.Delete(event.DeleteEvent{Object: vipAdv(1)}) {
			t.Error("Delete dropped a gateway VIP advertisement")
		}
		if !p.Update(event.UpdateEvent{ObjectOld: vipAdv(1), ObjectNew: vipAdv(2)}) {
			t.Error("Update dropped a spec edit to a gateway VIP advertisement")
		}
		if p.Update(event.UpdateEvent{ObjectOld: vipAdv(1), ObjectNew: vipAdv(1)}) {
			t.Error("Update passed a status-only change to a gateway VIP advertisement")
		}
	})

	tests := []struct {
		name     string
		old, new *bgpv1alpha1.BGPAdvertisement
		want     bool
	}{
		{"status-only update", testAdvertisement(1, true), testAdvertisement(1, true), false},
		{"spec change on a backend advertisement", testAdvertisement(1, true), testAdvertisement(2, true), true},
		{"spec change on a VIP advertisement", testAdvertisement(1, false), testAdvertisement(2, false), false},
		{"VRFID and Function removed", testAdvertisement(1, true), testAdvertisement(2, false), true},
		{"VRFID and Function added", testAdvertisement(1, false), testAdvertisement(2, true), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.Update(event.UpdateEvent{ObjectOld: tt.old, ObjectNew: tt.new}); got != tt.want {
				t.Errorf("Update = %v, want %v", got, tt.want)
			}
		})
	}
}
