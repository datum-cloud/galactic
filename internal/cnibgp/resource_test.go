// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/crdnames"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const testNodeName = "dfw-worker"
const testNamespace = "galactic-system"

// TestResourceTrackerCleanup_DeletesFreshlyCreatedVRFInstance covers the
// regression this test guards against: allocateArgument's read-then-write
// can race two different VPCs' first attachment on the same node onto the
// same "lowest free slot," which checkArgumentCollision then rejects. If
// rollback never deleted the just-created (and now known-invalid)
// BGPVRFInstance, every retry would hit the identical collision forever —
// nothing else clears it, since GC only reclaims once every BGPAdvertisement
// for the VPC is gone, not a collision. vrfInstanceCreated=true (this ADD's
// own CreateOrUpdate reported OperationResultCreated) is what makes deleting
// it here safe: this exact ADD invocation just created it moments ago, so no
// sibling attachment could have started depending on it yet.
func TestResourceTrackerCleanup_DeletesFreshlyCreatedVRFInstance(t *testing.T) {
	name := crdnames.BGPVRFInstanceName(testVPC, testNodeName)
	existing := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
	}
	k8s := fakeClient(existing)

	rt := &resourceTracker{
		vpc: testVPC, vpcAttachment: testAttachment, nodeName: testNodeName,
		namespace: testNamespace, k8s: k8s,
		publishResult: publishResult{vrfInstanceCreated: true},
	}
	rt.cleanup(context.Background())

	got := &bgpv1alpha1.BGPVRFInstance{}
	err := k8s.Get(context.Background(), client.ObjectKey{Name: name, Namespace: testNamespace}, got)
	if !apierrors.IsNotFound(err) {
		t.Errorf("BGPVRFInstance %q after cleanup: err=%v, want NotFound (deleted)", name, err)
	}
}

// TestResourceTrackerCleanup_PreservesReusedVRFInstance covers the sharing
// side: when this ADD's own CreateOrUpdate found the BGPVRFInstance already
// live (a sibling attachment created it), vrfInstanceCreated stays false —
// cleanup on this attachment's own failed ADD must leave that sibling's VRF
// alone.
func TestResourceTrackerCleanup_PreservesReusedVRFInstance(t *testing.T) {
	name := crdnames.BGPVRFInstanceName(testVPC, testNodeName)
	existing := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec:       bgpv1alpha1.BGPVRFInstanceSpec{VRFID: 7},
	}
	k8s := fakeClient(existing)

	rt := &resourceTracker{
		vpc: testVPC, vpcAttachment: testAttachment, nodeName: testNodeName,
		namespace: testNamespace, k8s: k8s,
		publishResult: publishResult{vrfInstanceCreated: false}, // this attachment only reused a sibling's CRD
	}
	rt.cleanup(context.Background())

	got := &bgpv1alpha1.BGPVRFInstance{}
	if err := k8s.Get(context.Background(), client.ObjectKey{Name: name, Namespace: testNamespace}, got); err != nil {
		t.Fatalf("BGPVRFInstance %q after cleanup: %v, want it to still exist", name, err)
	}
	if got.Spec.VRFID != 7 {
		t.Errorf("BGPVRFInstance survived with VRFID = %d, want unchanged 7", got.Spec.VRFID)
	}
}

// TestResourceTrackerCleanup_NeverUnregistersEBPFEntry documents that
// cleanup has nothing left to do for the eBPF vrf_table registration at
// all — there's no field to unregister it with, unlike the BGPVRFInstance
// CRD above. A zero-value tracker (as if the ADD failed before creating
// anything) must not panic.
func TestResourceTrackerCleanup_NeverUnregistersEBPFEntry(t *testing.T) {
	rt := &resourceTracker{}
	rt.cleanup(context.Background()) // should not panic; nothing to roll back
}

// TestResourceTrackerCleanup_DeletesOwnAdvertisementOnly covers the
// still-1:1 BGPAdvertisement case alongside the now-conditional
// BGPVRFInstance case, so the two don't regress into sharing the same
// on/off switch.
func TestResourceTrackerCleanup_DeletesOwnAdvertisementOnly(t *testing.T) {
	advName := crdnames.BGPAdvertisementName(testVPC, testAttachment, testNodeName)
	existing := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: advName, Namespace: testNamespace},
	}
	k8s := fakeClient(existing)

	rt := &resourceTracker{
		vpc: testVPC, vpcAttachment: testAttachment, nodeName: testNodeName,
		namespace: testNamespace, k8s: k8s,
		publishResult: publishResult{advertisementCreated: true},
	}
	rt.cleanup(context.Background())

	got := &bgpv1alpha1.BGPAdvertisement{}
	err := k8s.Get(context.Background(), client.ObjectKey{Name: advName, Namespace: testNamespace}, got)
	if !apierrors.IsNotFound(err) {
		t.Errorf("BGPAdvertisement %q after cleanup: err=%v, want NotFound (deleted)", advName, err)
	}
}
