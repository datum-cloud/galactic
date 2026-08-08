// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// requireRoot skips the test unless running as root — pinned eBPF maps and
// real VRF/netlink state need CAP_NET_ADMIN/CAP_BPF and a real kernel. See
// internal/cni's own requireRoot for the project-wide pattern.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_NET_ADMIN/CAP_BPF); run under scripts/ci.sh unittest-root")
	}
}

// TestRegisterEBPFDatapath_NotConfiguredIsNoOp covers the short-circuit for
// a node whose BGPRouter has no SRv6Locator/NodeID configured at all: SRv6
// is intentionally not set up for this attachment, so registerEBPFDatapath
// must do nothing (no error, no attempt to open any pinned map).
func TestRegisterEBPFDatapath_NotConfiguredIsNoOp(t *testing.T) {
	cfg := bgpConfig{srv6Locator: "", nodeID: 0}
	registered, _, err := registerEBPFDatapath(
		cfg, testVPC, testAttachment, ifaceTypeVeth, 42, "/sys/fs/bpf/galactic-does-not-exist")
	if err != nil {
		t.Errorf("registerEBPFDatapath with unconfigured BGPRouter = %v, want nil (no-op)", err)
	}
	if registered {
		t.Error("registerEBPFDatapath with unconfigured BGPRouter reported registered=true, want false")
	}
}

// TestRegisterEBPFDatapath_RejectsOutOfRangeNodeID covers registerEBPFDatapath's
// bounds check on the raw nodeID *before* it narrows to uint16 for
// registration: an out-of-[uformat.NodeIDMin,NodeIDMax] value (here, one
// that wraps to an in-range-looking uint16 if narrowed unchecked -- 0x10001
// wraps to 1) must be rejected here, before any pinned map is even opened.
func TestRegisterEBPFDatapath_RejectsOutOfRangeNodeID(t *testing.T) {
	cfg := bgpConfig{srv6Locator: "2001:db8:1::/48", nodeID: 0x10001} // wraps to uint16(1) if narrowed unchecked
	registered, _, err := registerEBPFDatapath(
		cfg, testVPC, testAttachment, ifaceTypeVeth, 42, "/sys/fs/bpf/galactic-does-not-exist")
	if err == nil {
		t.Fatal("registerEBPFDatapath with nodeID=0x10001 = nil error, want an out-of-range rejection")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("registerEBPFDatapath error = %q, want it to mention the nodeID being out of range", err.Error())
	}
	if registered {
		t.Error("registerEBPFDatapath with an out-of-range nodeID reported registered=true, want false")
	}
}

// TestRegisterEBPFDatapath_RegistersAllThreeTables: a single
// registerEBPFDatapath call populates locator_table, function_table, and
// vrf_table consistently for the same (vpc, vpcAttachment), against real
// pinned eBPF maps under a throwaway pin directory — not the production
// attach.PinDir.
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
	registered, _, err := registerEBPFDatapath(cfg, vpc, vpcAttachment, ifaceTypeVeth, uint16(vrfID), pinDir)
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
		t.Errorf("vrf_table entry EgressKind = %d, want %d (EgressKindVeth, from interfaceType %q)",
			entries[0].EgressKind, usidmap.EgressKindVeth, ifaceTypeVeth)
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

// TestUnregisterEBPFDatapath_RemovesOwnEntry covers UnregisterEBPFDatapath's
// normal path: an entry this attachment registered gets removed when its
// VRFTableID still matches.
func TestUnregisterEBPFDatapath_RemovesOwnEntry(t *testing.T) {
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

	if err := UnregisterEBPFDatapath(testBlock, testArgument, vrfTableID, pinDir); err != nil {
		t.Fatalf("UnregisterEBPFDatapath: %v", err)
	}

	if _, ok, err := reg.VRF.Get(testBlock, testArgument); err != nil || ok {
		t.Errorf("vrf_table entry after unregister: ok=%v err=%v, want ok=false", ok, err)
	}
}

// TestUnregisterEBPFDatapath_LeavesEntryOwnedByAnotherAttachment covers the
// race UnregisterEBPFDatapath guards against: retryK8sOps can re-run
// PublishBGPStateK8s's whole closure on a later attempt without
// re-registering the eBPF entry, so by the time a later attempt's
// checkArgumentCollision failure triggers a caller's rollback, the (block,
// argument) slot this attachment originally wrote may have since been
// overwritten by the very other attachment the collision was detected
// against. Unregistering unconditionally would delete a live attachment's
// forwarding entry instead of this rolled-back one's own.
func TestUnregisterEBPFDatapath_LeavesEntryOwnedByAnotherAttachment(t *testing.T) {
	requireRoot(t)

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-bgp-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
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
	const thisAttachmentsVRFTableID uint32 = 0x1111

	// Simulate the colliding attachment having since overwritten this same
	// (block, argument) slot with its own, different VRF table id.
	if err := reg.VRF.Register(testBlock, testArgument, anotherAttachmentsVRFTableID, usidmap.EgressKindVeth); err != nil {
		t.Fatalf("seed vrf_table entry: %v", err)
	}

	if err := UnregisterEBPFDatapath(testBlock, testArgument, thisAttachmentsVRFTableID, pinDir); err != nil {
		t.Fatalf("UnregisterEBPFDatapath: %v", err)
	}

	entry, ok, err := reg.VRF.Get(testBlock, testArgument)
	if err != nil || !ok {
		t.Fatalf("vrf_table entry after unregister: ok=%v err=%v, want ok=true (must survive, it's not this attachment's)",
			ok, err)
	}
	if entry.VRFTableID != anotherAttachmentsVRFTableID {
		t.Errorf("vrf_table entry VRFTableID after unregister = %#x, want unchanged %#x",
			entry.VRFTableID, anotherAttachmentsVRFTableID)
	}
}
