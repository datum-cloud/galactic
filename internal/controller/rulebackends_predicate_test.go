// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
)

func TestVPCAttachmentBackendChanged(t *testing.T) {
	p := vpcAttachmentBackendChanged()
	base := newBackendAttachment(testVPCRef)

	if !p.Create(event.CreateEvent{Object: base.DeepCopy()}) {
		t.Error("Create dropped an attachment")
	}
	if !p.Delete(event.DeleteEvent{Object: base.DeepCopy()}) {
		t.Error("Delete dropped an attachment")
	}
	if !p.Generic(event.GenericEvent{Object: base.DeepCopy()}) {
		t.Error("Generic dropped an attachment")
	}

	tests := []struct {
		name   string
		mutate func(a *cloudv1alpha1.VPCAttachment)
		want   bool
	}{
		{"no change", func(*cloudv1alpha1.VPCAttachment) {}, false},
		{"conditions only", func(a *cloudv1alpha1.VPCAttachment) {
			a.Status.Conditions = []metav1.Condition{{Type: ConditionReady, Status: metav1.ConditionTrue}}
		}, false},
		{"generation and other status", func(a *cloudv1alpha1.VPCAttachment) {
			a.Generation++
			a.Status.ObservedGeneration++
			a.Status.ContainerID = strings.Repeat("a", 46)
			a.Status.PodName = "pod"
		}, false},
		{"interface name", func(a *cloudv1alpha1.VPCAttachment) {
			a.Spec.Interface.Name = "eth1"
		}, false},
		{"label value changed", func(a *cloudv1alpha1.VPCAttachment) {
			a.Labels[testBackendLabel] = "not-a-backend"
		}, true},
		{"label added", func(a *cloudv1alpha1.VPCAttachment) {
			a.Labels["extra"] = "x"
		}, true},
		{"status.vpc changed", func(a *cloudv1alpha1.VPCAttachment) {
			a.Status.VPC = "other-vpc"
		}, true},
		{"status.node changed", func(a *cloudv1alpha1.VPCAttachment) {
			a.Status.Node = testOtherNode
		}, true},
		{"status.node cleared", func(a *cloudv1alpha1.VPCAttachment) {
			a.Status.Node = ""
		}, true},
		{"address changed", func(a *cloudv1alpha1.VPCAttachment) {
			a.Spec.Interface.Addresses = []cloudv1alpha1.IPAddress{"fd00:10::99/64"}
		}, true},
		{"address added", func(a *cloudv1alpha1.VPCAttachment) {
			a.Spec.Interface.Addresses = append(a.Spec.Interface.Addresses, "fd00:10::99/64")
		}, true},
		{"mode changed", func(a *cloudv1alpha1.VPCAttachment) {
			a.Spec.Interface.Mode = cloudv1alpha1.VPCAttachmentInterfaceModeHypervisor
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newAtt := base.DeepCopy()
			tt.mutate(newAtt)
			if got := p.Update(event.UpdateEvent{ObjectOld: base.DeepCopy(), ObjectNew: newAtt}); got != tt.want {
				t.Errorf("Update = %v, want %v", got, tt.want)
			}
		})
	}
}
