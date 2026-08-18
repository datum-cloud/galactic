// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/cni/veth"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
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

// blockFromLocator mirrors registerEBPFDatapath's own locator-to-Block
// derivation, mirroring internal/gc/gc_ebpf_test.go's identical helper.
func blockFromLocator(locator string) (uint64, error) {
	prefix, err := netip.ParsePrefix(locator)
	if err != nil {
		return 0, err
	}
	return uformat.Block(prefix.Addr())
}

// TestRegisterEBPFDatapath_NotConfiguredIsNoOp covers the short-circuit for
// a node whose BGPRouter has no SRv6Locator/NodeID configured at all: SRv6
// is intentionally not set up for this attachment, so registerEBPFDatapath
// must do nothing (no error, no attempt to open any pinned map).
func TestRegisterEBPFDatapath_NotConfiguredIsNoOp(t *testing.T) {
	cfg := bgpConfig{srv6Locator: "", nodeID: 0}
	registered, err := registerEBPFDatapath(
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
	registered, err := registerEBPFDatapath(
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
// vrf_table consistently for the same VPC, against real pinned eBPF maps
// under a throwaway pin directory — not the production attach.PinDir.
func TestRegisterEBPFDatapath_RegistersAllThreeTables(t *testing.T) {
	requireRoot(t)

	const (
		vpc     = testVPC
		locator = "2001:db8:1::/48"
		nodeID  = int32(5)
		vrfID   = int32(42)
	)

	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("vrf.Add: %v", err)
	}
	t.Cleanup(func() { _ = vrf.Delete(vpc) })

	if err := veth.Add(vpc, testAttachment, 1500); err != nil {
		t.Fatalf("veth.Add: %v", err)
	}
	t.Cleanup(func() { _ = veth.Delete(vpc, testAttachment) })
	hostLinkObj, err := netlink.LinkByName(intf.GenerateInterfaceNameHost(vpc, testAttachment))
	if err != nil {
		t.Fatalf("look up host interface: %v", err)
	}
	hostLink := uint32(hostLinkObj.Attrs().Index)

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-bgp-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	loaderObjs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load (simulating the run container having already loaded the datapath): %v", err)
	}
	t.Cleanup(func() { _ = loaderObjs.Close() })

	cfg := bgpConfig{srv6Locator: locator, nodeID: nodeID}
	registered, err := registerEBPFDatapath(cfg, vpc, testAttachment, ifaceTypeVeth, uint16(vrfID), pinDir)
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

	ifindexTable, ifindexCloser, err := ifindexvrfmap.OpenPinned(pinDir)
	if err != nil {
		t.Fatalf("ifindexvrfmap.OpenPinned: %v", err)
	}
	defer func() { _ = ifindexCloser.Close() }()

	block, err := blockFromLocator(locator)
	if err != nil {
		t.Fatalf("derive block: %v", err)
	}
	ifEntry, ok, err := ifindexTable.Get(hostLink)
	if err != nil {
		t.Fatalf("ifindexvrfmap.Get: %v", err)
	}
	if !ok {
		t.Fatalf("ifindex_vrf_table entry for host ifindex %d not found", hostLink)
	}
	if ifEntry.Block != block || ifEntry.Argument != uint16(vrfID) {
		t.Errorf("ifindex_vrf_table entry = %+v, want Block=%#x Argument=%#x", ifEntry, block, uint16(vrfID))
	}

	vrfTableID, err := vrf.TableID(vpc)
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
		t.Errorf("vrf_table entry VRFTableID = %#x, want %#x (this VPC's real VRF table id)",
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

	// Regression guard for a real bug found live: usid_egress was compiled
	// and loaded (attach.Load pins it, alongside every map) but nothing
	// ever attached it anywhere -- confirmed live via `tc filter show`
	// against a real backend's own host-side veth showing no filter at
	// all, on either direction. This is why every reply a DSR/veth
	// backend ever sent silently kept its own real address instead of the
	// VIP a client actually connected to, and no forward-path validation
	// this redesign ran ever caught it. Asserts registerEBPFDatapath's
	// own attachUsidEgress call actually put a filter on this attachment's
	// host interface's ingress hook, not just that it returned no error.
	filters, err := netlink.FilterList(hostLinkObj, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		t.Fatalf("FilterList(ingress) on host interface: %v", err)
	}
	var foundEgressFilter bool
	for _, f := range filters {
		if bpfFilter, ok := f.(*netlink.BpfFilter); ok && bpfFilter.Name == "galactic_usid_egress" {
			foundEgressFilter = true
		}
	}
	if !foundEgressFilter {
		t.Errorf("no galactic_usid_egress tc filter found on host interface %q ingress hook -- "+
			"registerEBPFDatapath must attach usid_egress there", intf.GenerateInterfaceNameHost(vpc, testAttachment))
	}
}

// TestRegisterEBPFDatapath_SecondAttachmentSharesEntry covers the whole
// point of keying vrf_table registration by VPC alone: a second attachment
// on the same VPC (different Argument would be a bug — allocateArgument's
// idempotent-by-name lookup is what keeps every attachment on this VPC/node
// converging on one shared Argument, exercised at the cnibgp package level
// in bgp_test.go) re-registering the identical (block, argument) key is a
// harmless idempotent overwrite, not a collision — repeat registration is
// the ordinary case (see usidmap.VRF.Register's own doc comment), and here
// specifically it's what two live sibling attachments both depend on.
func TestRegisterEBPFDatapath_SecondAttachmentSharesEntry(t *testing.T) {
	requireRoot(t)

	const (
		vpc     = testVPC
		locator = "2001:db8:1::/48"
		nodeID  = int32(5)
		vrfID   = int32(42)
	)

	const (
		firstAttachment  = testAttachment
		secondAttachment = "def2"
	)

	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("vrf.Add: %v", err)
	}
	t.Cleanup(func() { _ = vrf.Delete(vpc) })

	if err := veth.Add(vpc, firstAttachment, 1500); err != nil {
		t.Fatalf("veth.Add(first): %v", err)
	}
	t.Cleanup(func() { _ = veth.Delete(vpc, firstAttachment) })
	if err := veth.Add(vpc, secondAttachment, 1500); err != nil {
		t.Fatalf("veth.Add(second): %v", err)
	}
	t.Cleanup(func() { _ = veth.Delete(vpc, secondAttachment) })

	pinDir := fmt.Sprintf("/sys/fs/bpf/galactic-bgp-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	loaderObjs, err := attach.Load(pinDir)
	if err != nil {
		t.Fatalf("attach.Load: %v", err)
	}
	t.Cleanup(func() { _ = loaderObjs.Close() })

	cfg := bgpConfig{srv6Locator: locator, nodeID: nodeID}
	if _, err := registerEBPFDatapath(cfg, vpc, firstAttachment, ifaceTypeVeth, uint16(vrfID), pinDir); err != nil {
		t.Fatalf("first attachment's registerEBPFDatapath: %v", err)
	}
	// A second attachment on the same VPC/node resolves the same Argument
	// (allocateArgument's idempotent lookup) and re-registers the same key.
	registered, err := registerEBPFDatapath(cfg, vpc, secondAttachment, ifaceTypeVeth, uint16(vrfID), pinDir)
	if err != nil {
		t.Fatalf("second attachment's registerEBPFDatapath: %v", err)
	}
	if !registered {
		t.Fatal("second attachment's registerEBPFDatapath reported registered=false, want true")
	}

	reg, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		t.Fatalf("OpenPinnedRegistry: %v", err)
	}
	defer func() { _ = closer.Close() }()

	entries, err := reg.VRF.List()
	if err != nil {
		t.Fatalf("VRF.List: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("vrf_table entries after two attachments share one VPC = %+v, want exactly 1 (shared, not duplicated)",
			entries)
	}
}
