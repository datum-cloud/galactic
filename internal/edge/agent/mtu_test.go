// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/hostattach"
)

// encapMTU returns an Agent.EncapMTU that reads limit, or fails with err.
func encapMTU(limit int, err error) func() (int, error) {
	return func() (int, error) { return limit, err }
}

// TestProgramChecksUnderlayMTU checks program's underlay ceiling with no
// kernel: a refused attachment stops before its pod's namespace is looked at,
// and one the check lets through goes on to it, here failing there because
// the pod has none.
func TestProgramChecksUnderlayMTU(t *testing.T) {
	att := &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: edgeNS, UID: types.UID(attA)},
		Status:     galacticv1alpha1.EdgeAttachmentStatus{NodeName: node, VPC: vpcA, Address: addr},
	}
	noPod := podNS{err: ErrNamespaceUnavailable}
	tests := []struct {
		name     string
		encapMTU func() (int, error)
		want     string
	}{
		{"NoCheck", nil, ReasonNamespaceUnavailable},
		{"LimitOff", encapMTU(0, nil), ReasonNamespaceUnavailable},
		{"LimitAboveMTU", encapMTU(mtu+40, nil), ReasonNamespaceUnavailable},
		{"LimitAtMTU", encapMTU(mtu, nil), ReasonNamespaceUnavailable},
		{"LimitBelowMTU", encapMTU(mtu-40, nil), ReasonMTUExceedsUnderlay},
		{"ReadFails", encapMTU(0, errors.New("map not pinned")), ReasonDatapathFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agent{NodeName: node, MTU: mtu, EncapMTU: tt.encapMTU}
			o := a.program(att, noPod, hostattach.ObservedAttachment{})
			if o.status != metav1.ConditionFalse || o.reason != tt.want {
				t.Errorf("program = %s/%s (%s), want False/%s", o.status, o.reason, o.message, tt.want)
			}
		})
	}
}

// TestUnderlayMTUCeiling programs an attachment only while --mtu fits the
// fabric underlay once encapsulated. A refused attachment gets no host link;
// one programmed before the limit dropped below --mtu keeps its link and
// reports the condition.
func TestUnderlayMTUCeiling(t *testing.T) {
	f := newFixture(t)
	a := f.agent()
	limit := mtu - 40
	a.EncapMTU = func() (int, error) { return limit, nil }
	f.pod(pod1UID)
	f.attach("a", attA, pod1UID, vpcA, addr, false)
	f.reconcile(a)

	c := f.condition("a", galacticv1alpha1.EdgeAttachmentProgrammed)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != ReasonMTUExceedsUnderlay {
		t.Fatalf("Programmed = %+v, want False/%s", c, ReasonMTUExceedsUnderlay)
	}
	if l := f.links(); len(l) != 0 {
		t.Fatalf("refused attachment provisioned links %+v", l)
	}

	limit = mtu
	f.reconcile(a)
	f.programmed("a")
	link := f.hostLink("a").Attrs().Index

	limit = mtu - 40
	f.reconcile(a)
	c = f.condition("a", galacticv1alpha1.EdgeAttachmentProgrammed)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != ReasonMTUExceedsUnderlay {
		t.Fatalf("Programmed = %+v, want False/%s once the limit drops", c, ReasonMTUExceedsUnderlay)
	}
	if got := f.hostLink("a").Attrs().Index; got != link {
		t.Errorf("host link replaced (%d -> %d), want it left as it was", link, got)
	}
}
