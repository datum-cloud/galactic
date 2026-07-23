// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cni

import (
	"fmt"
	"os"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// TestRegisterEBPFDatapath_NotConfiguredIsNoOp covers the short-circuit for
// a node whose BGPRouter has no SRv6Locator/NodeID configured at all: SRv6
// is intentionally not set up for this attachment, so registerEBPFDatapath
// must do nothing (no error, no attempt to open any pinned map).
func TestRegisterEBPFDatapath_NotConfiguredIsNoOp(t *testing.T) {
	cfg := bgpConfig{srv6Locator: "", nodeID: 0}
	registered, _, err := registerEBPFDatapath(
		cfg, testVPC, testAttachment, interfaceTypeVeth, 42, "/sys/fs/bpf/galactic-does-not-exist")
	if err != nil {
		t.Errorf("registerEBPFDatapath with unconfigured BGPRouter = %v, want nil (no-op)", err)
	}
	if registered {
		t.Error("registerEBPFDatapath with unconfigured BGPRouter reported registered=true, want false")
	}
}

// TestRegisterEBPFDatapath_RegistersAllThreeTables is Milestone 7.1's exit
// criterion: a single registerEBPFDatapath call populates locator_table,
// function_table, and vrf_table consistently for the same (vpc,
// vpcAttachment), against real pinned eBPF maps under a throwaway pin
// directory -- not the production attach.PinDir.
func TestRegisterEBPFDatapath_RegistersAllThreeTables(t *testing.T) {
	requireRoot(t)

	const (
		vpc           = testVPC
		vpcAttachment = testAttachment
		locator       = "2001:db8:1::/48"
		nodeID        = int32(5)
		vrfID         = int32(42)
	)

	if err := vrf.Add(vpc, vpcAttachment); err != nil {
		t.Fatalf("vrf.Add: %v", err)
	}
	t.Cleanup(func() { _ = vrf.Delete(vpc, vpcAttachment) })

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-bgp-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	loaderObjs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load (simulating the run container having already loaded the datapath): %v", err)
	}
	t.Cleanup(func() { _ = loaderObjs.Close() })

	cfg := bgpConfig{srv6Locator: locator, nodeID: nodeID}
	registered, _, err := registerEBPFDatapath(cfg, vpc, vpcAttachment, interfaceTypeVeth, uint16(vrfID), pinDir)
	if err != nil {
		t.Fatalf("registerEBPFDatapath: %v", err)
	}
	if !registered {
		t.Fatal("registerEBPFDatapath reported registered=false, want true")
	}

	reg, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatalf("OpenPinnedRegistry: %v", err)
	}
	defer func() { _ = closer.Close() }()

	vrfTableID, err := vrf.TableID(vpc, vpcAttachment)
	if err != nil {
		t.Fatalf("vrf.TableID: %v", err)
	}

	entries, err := reg.VRF.List()
	if err != nil {
		t.Fatalf("VRF.List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("vrf_table entries = %+v, want exactly 1", entries)
	}
	if entries[0].VRFTableID != vrfTableID {
		t.Errorf("vrf_table entry VRFTableID = %#x, want %#x (this attachment's real VRF table id)",
			entries[0].VRFTableID, vrfTableID)
	}
	if entries[0].EgressKind != usidmap.EgressKindVeth {
		t.Errorf("vrf_table entry EgressKind = %d, want %d (EgressKindVeth, from InterfaceType %q)",
			entries[0].EgressKind, usidmap.EgressKindVeth, interfaceTypeVeth)
	}

	locEntries, err := reg.Locator.List()
	if err != nil {
		t.Fatalf("Locator.List: %v", err)
	}
	if len(locEntries) != 1 || locEntries[0].NodeID != uint16(nodeID) {
		t.Errorf("locator_table entries = %+v, want exactly one with NodeID %#x", locEntries, nodeID)
	}

	fnEntries, err := reg.Function.List()
	if err != nil {
		t.Fatalf("Function.List: %v", err)
	}
	if len(fnEntries) != 1 {
		t.Errorf("function_table entries = %+v, want exactly 1", fnEntries)
	}
}

// TestResourceTrackerCleanup_UnregistersEBPFVRFEntry is Milestone 7.2's
// exit criterion: a failed ADD's rollback (resourceTracker.cleanup) cleans
// up both the kernel route (existing behavior, already covered by
// TestResourceTrackerCleanupPartialState) and the new eBPF vrf_table map
// entry, when one was actually registered. cleanup's own unregister step
// always targets the real, production attach.PinDir (it is not
// parameterized, unlike registerEBPFDatapath -- see resource.go), so this
// test loads/pins the real datapath there for the duration of the test,
// cleaning it up fully afterward; this mirrors the same "real global
// state" pattern this file's other resourceTracker tests already use for
// vrf.Delete/veth.Delete.
func TestResourceTrackerCleanup_UnregistersEBPFVRFEntry(t *testing.T) {
	requireRoot(t)

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

	if err := reg.VRF.Register(testBlock, testArgument, 0x2A2A2A, usidmap.EgressKindVeth); err != nil {
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
