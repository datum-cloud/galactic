// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

func TestIsRetiredSidecarReturnRow(t *testing.T) {
	const block = uint64(0x20010db88002)
	tests := []struct {
		name       string
		block      uint64
		argument   uint16
		tableID    uint32
		egressKind uint32
		want       bool
	}{
		{"RetiredRow", block, 5, sidecarReturnTableBase + 5, usidmap.EgressKindVeth, true},
		{"MaxArgument", block, uformat.ArgumentMax, sidecarReturnTableMax, usidmap.EgressKindVeth, true},
		{"HostVRFTable", block, 5, 42, usidmap.EgressKindVeth, false},
		{"OtherArgumentsTable", block, 5, sidecarReturnTableBase + 6, usidmap.EgressKindVeth, false},
		{"TapKind", block, 5, sidecarReturnTableBase + 5, usidmap.EgressKindTap, false},
		{"SidecarBlock", uformat.BlockIngressSidecar, 5, sidecarReturnTableBase + 5, usidmap.EgressKindVeth, false},
		{"ZeroArgument", block, 0, sidecarReturnTableBase, usidmap.EgressKindVeth, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRetiredSidecarReturnRow(tt.block, tt.argument, tt.tableID, tt.egressKind); got != tt.want {
				t.Errorf("isRetiredSidecarReturnRow(%#x, %d, %#x, %d) = %v, want %v",
					tt.block, tt.argument, tt.tableID, tt.egressKind, got, tt.want)
			}
		})
	}
}

func vrfInstance(name, routerName string, vrfID int32) *bgpv1alpha1.BGPVRFInstance {
	inst := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
	}
	inst.Spec.RouterRef = &bgpv1alpha1.RouterRef{Name: routerName}
	inst.Spec.VRFID = vrfID
	return inst
}

// TestSidecarReturnVPCs: only this node's Galactic router's instances count,
// and a VRFID two VPCs claim resolves to neither.
func TestSidecarReturnVPCs(t *testing.T) {
	mine := router("node-a", testLocator, 1)
	mine.Name = "router-a"
	other := router("node-b", testLocator, 2)
	other.Name = "router-b"

	objs := []client.Object{
		mine, other,
		vrfInstance(crdnames.BGPVRFInstanceName("vpcone", "node-a"), "router-a", 5),
		vrfInstance(crdnames.BGPVRFInstanceName("vpctwo", "node-b"), "router-b", 6),
		vrfInstance(crdnames.BGPVRFInstanceName("vpcthree", "node-a"), "router-a", 7),
		vrfInstance(crdnames.BGPVRFInstanceName("vpcfour", "node-a")+"-dup", "router-a", 7),
	}
	scheme := runtime.NewScheme()
	if err := bgpv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

	got, err := sidecarReturnVPCs(context.Background(), c, testNamespace, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if got[5] != (sidecarReturnVPC{"vpcone", "router-a"}) {
		t.Errorf("VRFID 5 = %v, want vpcone", got[5])
	}
	if _, ok := got[6]; ok {
		t.Errorf("VRFID 6 resolved from another node's router: %v", got[6])
	}
	if _, ok := got[7]; ok {
		t.Errorf("VRFID 7, claimed by two VPCs, resolved to %v", got[7])
	}
}
