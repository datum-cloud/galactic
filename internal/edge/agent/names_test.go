// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

func TestDesiredNames(t *testing.T) {
	att := &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID("22222222-0000-0000-0000-00000000000a")},
		Spec: galacticv1alpha1.EdgeAttachmentSpec{
			PacketDevice: &galacticv1alpha1.EdgePacketDevice{Owner: 1000, Group: 1001},
		},
		Status: galacticv1alpha1.EdgeAttachmentStatus{VPC: "abc", Address: "fd00::1"},
	}
	a, err := desired(att, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.HostLink) != 15 || a.HostLink[:10] != "E000000abc" || a.HostVRF != "G000000abcV" {
		t.Errorf("host link %q, VRF %q", a.HostLink, a.HostVRF)
	}
	if a.HostLink[0] == 'G' {
		t.Error("host link in the CNI's name pattern")
	}
	if a.TUN == nil || a.TUN.Owner != 1000 || a.TUN.Group != 1001 || len(a.TUN.Name) > 15 {
		t.Errorf("TUN %+v", a.TUN)
	}
	if a.PodTable < podTableBase || a.PodTable >= podTableBase+podTableSpan {
		t.Errorf("pod table %#x outside its range", a.PodTable)
	}
	vpc, uid, ok := parseID(a.ID)
	if !ok || vpc != "abc" || uid != string(att.UID) {
		t.Errorf("parseID(%q) = %q, %q, %t", a.ID, vpc, uid, ok)
	}
	again, _ := desired(att, 1500)
	if again.HostLink != a.HostLink || again.PodTable != a.PodTable {
		t.Error("names are not stable")
	}
	att.UID = "22222222-0000-0000-0000-00000000000b"
	if other, _ := desired(att, 1500); other.HostLink == a.HostLink || other.ID == a.ID {
		t.Error("a recreated attachment reuses its predecessor's names")
	}
	if _, _, ok := parseID("legacy-id"); ok {
		t.Error("parseID accepted an ID without a VPC")
	}
}

func TestNetnsFromInfo(t *testing.T) {
	info := `{"runtimeSpec":{"linux":{"namespaces":[{"type":"pid"},` +
		`{"type":"network","path":"/var/run/netns/cni-1234"}]}}}`
	if got, err := netnsFromInfo(info); err != nil || got != "/var/run/netns/cni-1234" {
		t.Fatalf("netnsFromInfo = %q, %v", got, err)
	}
	for _, bad := range []string{"", "{}", `{"runtimeSpec":{"linux":{"namespaces":[{"type":"network"}]}}}`} {
		if _, err := netnsFromInfo(bad); !errors.Is(err, ErrNamespaceUnavailable) {
			t.Errorf("netnsFromInfo(%q) = %v", bad, err)
		}
	}
}

func TestOlderIncarnation(t *testing.T) {
	early := NewOwner("n", time.Unix(100, 0), "a")
	late := NewOwner("n", time.Unix(200, 0), "b")
	if !olderIncarnation(early, late) || olderIncarnation(late, early) || olderIncarnation(late, late) {
		t.Error("incarnations not ordered by start time")
	}
	for _, other := range []string{"", "galactic-cni/x", "galactic-edge/n/unordered"} {
		if olderIncarnation(other, late) {
			t.Errorf("would take over %q", other)
		}
	}
}
