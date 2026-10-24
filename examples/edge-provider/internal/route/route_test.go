// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"net/netip"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

const (
	attA  = "ea-a"
	instA = "ei-a"
	podA  = "pod-a"
)

func TestName(t *testing.T) {
	// The derivation is part of the provider's own contract between its
	// instances: changing it would make a replacement contend for a
	// different object than the instance it replaces.
	got := Name("2b1f6d0c-6c7f-4f3e-9d3e-5a5f0c1e2d3a", netip.MustParsePrefix("fd00:ed9e:1:100::/64"))
	if got != "er-3b6d4979c850fdb3bb2fdbd05e495b53" {
		t.Fatalf("name %q", got)
	}
	if Name("v", netip.MustParsePrefix("fd00::1/64")) != Name("v", netip.MustParsePrefix("fd00::/64")) {
		t.Fatal("an unmasked prefix names a different route")
	}
	if Name("v", netip.MustParsePrefix("fd00::/64")) == Name("w", netip.MustParsePrefix("fd00::/64")) {
		t.Fatal("two VPCs share a route name")
	}
}

func TestNext(t *testing.T) {
	me := Holder{Attachment: attA, PodUID: podA, Instance: instA, InstanceEpoch: 2}
	mine := galacticv1alpha1.EdgeRouteClaim{Attachment: attA, HolderPodUID: podA, HolderInstance: instA,
		InstanceEpoch: 2, Epoch: 4}
	accepted := func(epoch int64, ok bool) galacticv1alpha1.EdgeRouteStatus {
		s := metav1.ConditionTrue
		if !ok {
			s = metav1.ConditionFalse
		}
		return galacticv1alpha1.EdgeRouteStatus{
			Accepted:   &galacticv1alpha1.EdgeRouteHolder{Epoch: epoch},
			Conditions: []metav1.Condition{{Type: galacticv1alpha1.EdgeRouteAccepted, Status: s}},
		}
	}
	other := mine
	other.Attachment, other.HolderPodUID, other.HolderInstance = "ea-b", "pod-b", "ei-b"
	oldEpoch := mine
	oldEpoch.InstanceEpoch = 1
	released := mine
	released.Released = true
	for _, tc := range []struct {
		name    string
		cur     *galacticv1alpha1.EdgeRouteClaim
		status  galacticv1alpha1.EdgeRouteStatus
		epoch   int64
		changed bool
	}{
		{"unclaimed", nil, galacticv1alpha1.EdgeRouteStatus{}, 1, true},
		{"already mine", &mine, accepted(4, true), 4, false},
		{"mine, not yet accepted", &mine, galacticv1alpha1.EdgeRouteStatus{}, 4, false},
		{"another holder", &other, accepted(4, true), 5, true},
		{"my older instance epoch", &oldEpoch, accepted(4, true), 5, true},
		{"released", &released, accepted(4, true), 5, true},
		{"revoked", &mine, accepted(4, false), 5, true},
		{"gate closed", &mine, galacticv1alpha1.EdgeRouteStatus{ClosedEpoch: 4}, 5, true},
		{"older gate closed", &mine, galacticv1alpha1.EdgeRouteStatus{ClosedEpoch: 3}, 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next, changed := Next(tc.cur, tc.status, me)
			if changed != tc.changed || next.Epoch != tc.epoch {
				t.Fatalf("got epoch %d changed %v, want %d %v", next.Epoch, changed, tc.epoch, tc.changed)
			}
			if next.Released || next.Attachment != me.Attachment || next.HolderPodUID != me.PodUID ||
				next.HolderInstance != me.Instance || next.InstanceEpoch != me.InstanceEpoch {
				t.Fatalf("claim %+v does not name the holder", next)
			}
		})
	}
}

func TestNextLeavesAnotherClaimWhileAccepted(t *testing.T) {
	me := Holder{Attachment: attA, PodUID: podA, Instance: instA, InstanceEpoch: 2}
	theirs := galacticv1alpha1.EdgeRouteClaim{Attachment: "ea-b", HolderPodUID: "pod-b", HolderInstance: "ei-b",
		InstanceEpoch: 1, Epoch: 5}
	status := galacticv1alpha1.EdgeRouteStatus{
		Accepted:   &galacticv1alpha1.EdgeRouteHolder{Epoch: 4, Attachment: attA, Instance: instA, InstanceEpoch: 2},
		Conditions: []metav1.Condition{{Type: galacticv1alpha1.EdgeRouteAccepted, Status: metav1.ConditionTrue}},
	}
	// Core still holds this instance as the accepted holder, so another
	// instance's claim waits for core, not for this instance to fight it.
	if next, changed := Next(&theirs, status, me); changed || next != theirs {
		t.Fatalf("took the route back while accepted: %+v", next)
	}
	// After a restart in place the instance epoch moved on, and the
	// accepted holder no longer names this process: it claims again.
	restarted := me
	restarted.InstanceEpoch = 3
	if next, changed := Next(&theirs, status, restarted); !changed || next.Epoch != 6 {
		t.Fatalf("restarted instance did not claim: %+v %v", next, changed)
	}
	// Once revoked, the old acceptance protects nothing.
	status.Conditions[0].Status = metav1.ConditionFalse
	if _, changed := Next(&theirs, status, me); !changed {
		t.Fatal("did not claim after its acceptance was revoked")
	}
}
