// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"fmt"
	"os"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/vrf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const testDefaultNamespace = "default"

// ---- resourceTracker.cleanup: zero-value / partial state -------------------

// TestResourceTrackerCleanup_ZeroValue verifies cleanup with a zero-value
// tracker doesn't panic — it's called from cmdAdd's defer, and the caller
// may have failed before setting any fields (e.g. newK8sClient itself
// failed, so tracker.k8s is nil).
func TestResourceTrackerCleanup_ZeroValue(t *testing.T) {
	tracker := &resourceTracker{}
	tracker.cleanup(context.Background()) // must not panic
}

// TestResourceTrackerCleanup_NilK8sClientSkipsCRDDeletes verifies cleanup
// doesn't attempt a Delete through a nil client even when the created-flags
// say there's something to roll back — this shouldn't happen in practice
// (tracker.k8s is set right after newK8sClient succeeds, before anything
// else can set vrfInstanceCreated/advertisementCreated), but cleanup's own
// nil check is what actually prevents the panic if it ever does.
func TestResourceTrackerCleanup_NilK8sClientSkipsCRDDeletes(t *testing.T) {
	tracker := &resourceTracker{
		vpc:           testVPC,
		vpcAttachment: testAttachment,
		namespace:     testDefaultNamespace,
		publishResult: publishResult{
			vrfInstanceCreated:   true,
			advertisementCreated: true,
		},
	}
	tracker.cleanup(context.Background()) // must not panic
}

// ---- resourceTracker.cleanup: CRD rollback ---------------------------------

// TestResourceTrackerCleanup_DeletesOnlyWhatWasCreated exercises cleanup's
// actual wiring end to end: given a tracker whose publishResult says only
// the BGPVRFInstance was created (advertisementCreated stays false, as it
// would if publishBGPState failed between the two), cleanup must delete the
// BGPVRFInstance and leave any BGPAdvertisement alone.
func TestResourceTrackerCleanup_DeletesOnlyWhatWasCreated(t *testing.T) {
	namespace := testDefaultNamespace
	vrfName := crdnames.BGPVRFInstanceName(testVPC, testAttachment)
	advName := crdnames.BGPAdvertisementName(testVPC, testAttachment)

	existingVRFInst := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: vrfName, Namespace: namespace},
	}
	// A BGPAdvertisement that was NOT created by this ADD (e.g. left over
	// from another container sharing the same attachment) — cleanup must
	// not touch it, since advertisementCreated is false.
	untouchedAdv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: advName, Namespace: namespace},
	}

	k8s := fakeClient(existingVRFInst, untouchedAdv)
	tracker := &resourceTracker{
		vpc:           testVPC,
		vpcAttachment: testAttachment,
		namespace:     namespace,
		k8s:           k8s,
		publishResult: publishResult{vrfInstanceCreated: true},
	}

	tracker.cleanup(context.Background())

	if err := k8s.Get(context.Background(), client.ObjectKey{Name: vrfName, Namespace: namespace},
		&bgpv1alpha1.BGPVRFInstance{}); err == nil {
		t.Error("BGPVRFInstance still exists after cleanup, want deleted")
	}
	if err := k8s.Get(context.Background(), client.ObjectKey{Name: advName, Namespace: namespace},
		&bgpv1alpha1.BGPAdvertisement{}); err != nil {
		t.Errorf("BGPAdvertisement Get after cleanup = %v, want it left untouched (advertisementCreated was false)", err)
	}
}

// TestResourceTrackerCleanup_DeletesBothCRDsWhenBothCreated covers the
// common failure path: both CRDs were created, then something later in
// publishBGPState (or types.PrintResult) failed, so both must roll back.
func TestResourceTrackerCleanup_DeletesBothCRDsWhenBothCreated(t *testing.T) {
	namespace := testDefaultNamespace
	vrfName := crdnames.BGPVRFInstanceName(testVPC, testAttachment)
	advName := crdnames.BGPAdvertisementName(testVPC, testAttachment)

	k8s := fakeClient(
		&bgpv1alpha1.BGPVRFInstance{ObjectMeta: metav1.ObjectMeta{Name: vrfName, Namespace: namespace}},
		&bgpv1alpha1.BGPAdvertisement{ObjectMeta: metav1.ObjectMeta{Name: advName, Namespace: namespace}},
	)
	tracker := &resourceTracker{
		vpc:           testVPC,
		vpcAttachment: testAttachment,
		namespace:     namespace,
		k8s:           k8s,
		publishResult: publishResult{vrfInstanceCreated: true, advertisementCreated: true},
	}

	tracker.cleanup(context.Background())

	if err := k8s.Get(context.Background(), client.ObjectKey{Name: vrfName, Namespace: namespace},
		&bgpv1alpha1.BGPVRFInstance{}); err == nil {
		t.Error("BGPVRFInstance still exists after cleanup, want deleted")
	}
	if err := k8s.Get(context.Background(), client.ObjectKey{Name: advName, Namespace: namespace},
		&bgpv1alpha1.BGPAdvertisement{}); err == nil {
		t.Error("BGPAdvertisement still exists after cleanup, want deleted")
	}
}

// TestResourceTrackerCleanup_MissingCRDsAreNotError covers cleanup's use of
// client.IgnoreNotFound: a CRD already gone (e.g. a retry after a partial
// prior rollback) must not surface as an error — cleanup never returns one.
func TestResourceTrackerCleanup_MissingCRDsAreNotError(t *testing.T) {
	tracker := &resourceTracker{
		vpc:           testVPC,
		vpcAttachment: testAttachment,
		namespace:     testDefaultNamespace,
		k8s:           fakeClient(),
		publishResult: publishResult{vrfInstanceCreated: true, advertisementCreated: true},
	}

	tracker.cleanup(context.Background()) // must not panic; nothing to delete
}

// ---- resourceTracker.cleanup: eBPF rollback --------------------------------

// TestResourceTrackerCleanup_UnregistersOwnEBPFEntry covers the eBPF branch
// of cleanup's own wiring (not unregisterEBPFDatapath in isolation, which
// bgp_ebpf_test.go already covers): a tracker with ebpfRegistered=true must
// resolve this attachment's own VRF table id and remove exactly the
// vrf_table entry it registered.
func TestResourceTrackerCleanup_UnregistersOwnEBPFEntry(t *testing.T) {
	requireRoot(t)

	if err := vrf.Add(testVPC, testAttachment); err != nil {
		t.Fatalf("vrf.Add: %v", err)
	}
	t.Cleanup(func() { _ = vrf.Delete(testVPC, testAttachment) })
	vrfTableID, err := vrf.TableID(testVPC, testAttachment)
	if err != nil {
		t.Fatalf("vrf.TableID: %v", err)
	}

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-bgp-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	// cleanup (resource.go) reads the pin directory from the package-level
	// ebpfPinDir var, not attach.PinDir directly — point it at this test's
	// own throwaway directory instead of the real production one.
	origPinDir := ebpfPinDir
	ebpfPinDir = pinDir
	t.Cleanup(func() { ebpfPinDir = origPinDir })

	loaderObjs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load: %v", err)
	}
	t.Cleanup(func() { _ = loaderObjs.Close() })

	reg, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatalf("OpenPinnedRegistry: %v", err)
	}
	defer func() { _ = closer.Close() }()

	const testBlock uint64 = 0x0102030405
	const testArgument uint16 = 0x042
	if err := reg.VRF.Register(testBlock, testArgument, vrfTableID, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("seed vrf_table entry: %v", err)
	}

	tracker := &resourceTracker{
		vpc:           testVPC,
		vpcAttachment: testAttachment,
		publishResult: publishResult{
			ebpfRegistered: true,
			ebpfBlock:      testBlock,
			ebpfArgument:   testArgument,
		},
	}

	tracker.cleanup(context.Background())

	if _, ok, err := reg.VRF.Get(testBlock, testArgument); err != nil || ok {
		t.Errorf("vrf_table entry after cleanup: ok=%v err=%v, want ok=false", ok, err)
	}
}

// TestResourceTrackerCleanup_LeavesEBPFEntryOwnedByAnotherAttachment is the
// rollback-collision race exercised at resourceTracker.cleanup's own level
// (bgp_ebpf_test.go's TestUnregisterEBPFDatapath_LeavesEntryOwnedByAnotherAttachment
// covers the same guard one layer lower, calling unregisterEBPFDatapath
// directly). retryK8sOps can re-run publishBGPState's whole closure without
// re-registering the eBPF entry, so a later attempt's checkArgumentCollision
// failure can trigger cleanup after the (block, argument) slot this
// attachment originally wrote has already been overwritten by the very
// other attachment the collision was detected against. cleanup must resolve
// its own vrf.TableID and leave the slot alone when it no longer matches,
// rather than deleting a live attachment's forwarding entry.
func TestResourceTrackerCleanup_LeavesEBPFEntryOwnedByAnotherAttachment(t *testing.T) {
	requireRoot(t)

	if err := vrf.Add(testVPC, testAttachment); err != nil {
		t.Fatalf("vrf.Add: %v", err)
	}
	t.Cleanup(func() { _ = vrf.Delete(testVPC, testAttachment) })

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-bgp-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	// cleanup (resource.go) reads the pin directory from the package-level
	// ebpfPinDir var, not attach.PinDir directly — point it at this test's
	// own throwaway directory instead of the real production one.
	origPinDir := ebpfPinDir
	ebpfPinDir = pinDir
	t.Cleanup(func() { ebpfPinDir = origPinDir })

	loaderObjs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load: %v", err)
	}
	t.Cleanup(func() { _ = loaderObjs.Close() })

	reg, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatalf("OpenPinnedRegistry: %v", err)
	}
	defer func() { _ = closer.Close() }()

	const testBlock uint64 = 0x0102030405
	const testArgument uint16 = 0x042
	const anotherAttachmentsVRFTableID uint32 = 0x9999

	// Simulate the colliding (winning) attachment having since overwritten
	// this same (block, argument) slot with its own, different VRF table id.
	if err := reg.VRF.Register(testBlock, testArgument, anotherAttachmentsVRFTableID, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("seed vrf_table entry: %v", err)
	}

	tracker := &resourceTracker{
		vpc:           testVPC,
		vpcAttachment: testAttachment,
		publishResult: publishResult{
			ebpfRegistered: true,
			ebpfBlock:      testBlock,
			ebpfArgument:   testArgument,
		},
	}

	tracker.cleanup(context.Background())

	entry, ok, err := reg.VRF.Get(testBlock, testArgument)
	if err != nil || !ok {
		t.Fatalf("vrf_table entry after cleanup: ok=%v err=%v, want ok=true (must survive, it's not this attachment's)",
			ok, err)
	}
	if entry.VRFTableID != anotherAttachmentsVRFTableID {
		t.Errorf("vrf_table entry VRFTableID after cleanup = %#x, want unchanged %#x",
			entry.VRFTableID, anotherAttachmentsVRFTableID)
	}
}
