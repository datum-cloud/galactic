// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"os"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// TestResourceTrackerCleanup_UnregistersEBPFVRFEntry: a failed ADD's rollback
// (resourceTracker.cleanup) cleans up both the kernel route (existing
// behavior, already covered by TestResourceTrackerCleanupPartialState) and
// the eBPF vrf_table map entry, when one was actually registered. cleanup's
// own unregister step always targets the real, production attach.PinDir (it
// is not parameterized), so this test loads/pins the real datapath there for
// the duration of the test, cleaning it up fully afterward.
//
// cleanup's unregister step recomputes this attachment's own VRF table id
// (vrf.TableID) and only deletes the vrf_table entry if it still resolves
// there, so a real VRF interface for (testVPC, testAttachment) must exist
// for the duration of this test.
func TestResourceTrackerCleanup_UnregistersEBPFVRFEntry(t *testing.T) {
	requireRoot(t)

	if err := vrf.Add(testVPC, testAttachment); err != nil {
		t.Fatalf("vrf.Add: %v", err)
	}
	t.Cleanup(func() { _ = vrf.Delete(testVPC, testAttachment) })
	vrfTableID, err := vrf.TableID(testVPC, testAttachment)
	if err != nil {
		t.Fatalf("vrf.TableID: %v", err)
	}

	loaderObjs, err := attach.Load(attach.PinDir)
	if err != nil {
		t.Fatalf("attach.Load(attach.PinDir): %v", err)
	}
	t.Cleanup(func() { _ = loaderObjs.Close() })
	t.Cleanup(func() { _ = os.RemoveAll(attach.PinDir) })

	reg, closer, err := usidmap.OpenPinnedRegistry(attach.PinDir)
	if err != nil {
		t.Fatalf("OpenPinnedRegistry(attach.PinDir): %v", err)
	}
	defer func() { _ = closer.Close() }()

	const testBlock uint64 = 0x0102030405
	const testArgument uint16 = 0x042

	if err := reg.VRF.Register(testBlock, testArgument, vrfTableID, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("seed vrf_table entry: %v", err)
	}
	if _, ok, err := reg.VRF.Get(testBlock, testArgument); err != nil || !ok {
		t.Fatalf("seeded entry not visible before cleanup: ok=%v err=%v", ok, err)
	}

	tracker := &resourceTracker{
		vpc:            testVPC,
		vpcAttachment:  testAttachment,
		namespace:      "ebpf-cleanup-test",
		ebpfRegistered: true,
		ebpfBlock:      testBlock,
		ebpfArgument:   testArgument,
	}
	tracker.cleanup(t.Context())

	if _, ok, err := reg.VRF.Get(testBlock, testArgument); err != nil || ok {
		t.Errorf("vrf_table entry after cleanup: ok=%v err=%v, want ok=false (unregistered)", ok, err)
	}
}

// TestResourceTrackerCleanup_LeavesEBPFVRFEntryOwnedByAnotherAttachment
// covers the race this fix closes: retryK8sOps can re-run
// PublishBGPStateK8s's whole closure on a later attempt without
// re-registering the eBPF entry, so by the time a later attempt's
// checkArgumentCollision failure triggers this rollback, the (block,
// argument) slot this attachment originally wrote may have since been
// overwritten by the very other attachment the collision was detected
// against -- unregistering unconditionally would delete a live
// attachment's forwarding entry instead of this rolled-back one's own. If
// the current entry's VRFTableID no longer matches this attachment's own
// (recomputed fresh, not read from the tracker), cleanup must leave it in
// place.
func TestResourceTrackerCleanup_LeavesEBPFVRFEntryOwnedByAnotherAttachment(t *testing.T) {
	requireRoot(t)

	if err := vrf.Add(testVPC, testAttachment); err != nil {
		t.Fatalf("vrf.Add: %v", err)
	}
	t.Cleanup(func() { _ = vrf.Delete(testVPC, testAttachment) })

	loaderObjs, err := attach.Load(attach.PinDir)
	if err != nil {
		t.Fatalf("attach.Load(attach.PinDir): %v", err)
	}
	t.Cleanup(func() { _ = loaderObjs.Close() })
	t.Cleanup(func() { _ = os.RemoveAll(attach.PinDir) })

	reg, closer, err := usidmap.OpenPinnedRegistry(attach.PinDir)
	if err != nil {
		t.Fatalf("OpenPinnedRegistry(attach.PinDir): %v", err)
	}
	defer func() { _ = closer.Close() }()

	const testBlock uint64 = 0x0102030405
	const testArgument uint16 = 0x042
	const anotherAttachmentsVRFTableID uint32 = 0x9999

	// Simulate the colliding attachment having since overwritten this same
	// (block, argument) slot with its own, different VRF table id.
	if err := reg.VRF.Register(testBlock, testArgument, anotherAttachmentsVRFTableID, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("seed vrf_table entry: %v", err)
	}

	tracker := &resourceTracker{
		vpc:            testVPC,
		vpcAttachment:  testAttachment,
		namespace:      "ebpf-cleanup-test",
		ebpfRegistered: true,
		ebpfBlock:      testBlock,
		ebpfArgument:   testArgument,
	}
	tracker.cleanup(t.Context())

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
