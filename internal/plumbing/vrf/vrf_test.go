// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vrf_test

import (
	"os"
	"testing"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_NET_ADMIN) to create real VRF interfaces; re-run via sudo")
	}
}

// TestAdd_SharedAcrossCallers is the core regression test for VRF-per-VPC
// sharing: two "attachments" (simulated here by two independent Add calls
// for the same VPC, exactly what two sibling CNI ADD invocations for
// different vpcAttachment values under one VPC do in production) must
// converge on the identical kernel VRF interface and routing table, not
// create — or worse, clobber — a second one.
func TestAdd_SharedAcrossCallers(t *testing.T) {
	requireRoot(t)
	const vpc = "vtshr"
	t.Cleanup(func() { _ = vrf.Delete(vpc) })

	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	firstTableID, err := vrf.TableID(vpc)
	if err != nil {
		t.Fatalf("TableID after first Add: %v", err)
	}

	// A second "attachment" on the same VPC.
	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("second Add: %v", err)
	}
	secondTableID, err := vrf.TableID(vpc)
	if err != nil {
		t.Fatalf("TableID after second Add: %v", err)
	}

	if firstTableID != secondTableID {
		t.Errorf("table ID changed across two Add calls for the same VPC: %d != %d — "+
			"a second attachment must reuse the first's VRF, not replace it", firstTableID, secondTableID)
	}

	if err := vrf.Exists(vpc); err != nil {
		t.Errorf("Exists after two Add calls: %v", err)
	}
}

// TestAdd_DifferentVPCsGetDistinctVRFs verifies the flip side of sharing:
// two different VPCs never collide on the same kernel VRF/table, even when
// created back-to-back.
func TestAdd_DifferentVPCsGetDistinctVRFs(t *testing.T) {
	requireRoot(t)
	const vpcA, vpcB = "vtda", "vtdb"
	t.Cleanup(func() { _ = vrf.Delete(vpcA) })
	t.Cleanup(func() { _ = vrf.Delete(vpcB) })

	if err := vrf.Add(vpcA); err != nil {
		t.Fatalf("Add(%q): %v", vpcA, err)
	}
	if err := vrf.Add(vpcB); err != nil {
		t.Fatalf("Add(%q): %v", vpcB, err)
	}

	tableA, err := vrf.TableID(vpcA)
	if err != nil {
		t.Fatalf("TableID(%q): %v", vpcA, err)
	}
	tableB, err := vrf.TableID(vpcB)
	if err != nil {
		t.Fatalf("TableID(%q): %v", vpcB, err)
	}
	if tableA == tableB {
		t.Errorf("two different VPCs resolved to the same table ID %d, want distinct", tableA)
	}

	nameA := intf.GenerateInterfaceNameVRF(vpcA)
	nameB := intf.GenerateInterfaceNameVRF(vpcB)
	if nameA == nameB {
		t.Fatalf("GenerateInterfaceNameVRF produced the same name %q for two different VPCs", nameA)
	}
}

// TestDelete_Idempotent covers Delete's documented idempotency: deleting a
// VRF that was never created (or already gone) is not an error.
func TestDelete_Idempotent(t *testing.T) {
	requireRoot(t)
	if err := vrf.Delete("vtnone"); err != nil {
		t.Errorf("Delete on a nonexistent VRF = %v, want nil", err)
	}
}

// TestExists_NotFound covers Exists returning an error for a VPC with no
// kernel VRF at all.
func TestExists_NotFound(t *testing.T) {
	requireRoot(t)
	if err := vrf.Exists("vtnone"); err == nil {
		t.Error("Exists for a nonexistent VRF = nil, want an error")
	}
}

// TestTableID_NotFound covers TableID returning an error for a VPC with no
// kernel VRF at all, rather than a zero-value table ID that could be
// mistaken for a real one.
func TestTableID_NotFound(t *testing.T) {
	requireRoot(t)
	if _, err := vrf.TableID("vtnone"); err == nil {
		t.Error("TableID for a nonexistent VRF = nil error, want an error")
	}
}

// TestDelete_ThenAddRecreates covers the sequential-reuse case documented on
// Add/Delete: once every attachment on a VPC is gone and GC deletes the VRF,
// a later attachment on the same VPC gets a fresh VRF rather than erroring
// out because "something" still looks present.
func TestDelete_ThenAddRecreates(t *testing.T) {
	requireRoot(t)
	const vpc = "vtre1"
	t.Cleanup(func() { _ = vrf.Delete(vpc) })

	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := vrf.Delete(vpc); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := vrf.Exists(vpc); err == nil {
		t.Fatal("Exists after Delete = nil, want an error (VRF should be gone)")
	}
	if err := vrf.Add(vpc); err != nil {
		t.Fatalf("Add after Delete: %v", err)
	}
	if err := vrf.Exists(vpc); err != nil {
		t.Errorf("Exists after re-Add: %v", err)
	}
}

// TestResolveVPC covers both current and legacy Galactic VRF interface name
// shapes, plus non-Galactic names (datum-cloud/enhancements#865's
// internal/egressroute needs this to identify which local VRF interfaces
// are its own).
func TestResolveVPC(t *testing.T) {
	tests := []struct {
		name    string
		wantVPC string
		wantOK  bool
	}{
		{name: "G000000123V", wantVPC: "123", wantOK: true},           // current per-VPC shape
		{name: "G000000123abcV", wantVPC: "123", wantOK: true},        // legacy shape (VPCAttachment segment)
		{name: "eth0", wantOK: false},                                 // not a Galactic VRF at all
		{name: "Gzzz_nonexistent_vpczzz_nonexistentV", wantOK: false}, // wrong shape entirely
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vpc, ok := vrf.ResolveVPC(tc.name)
			if ok != tc.wantOK {
				t.Fatalf("ResolveVPC(%q) ok = %v, want %v", tc.name, ok, tc.wantOK)
			}
			if ok && vpc != tc.wantVPC {
				t.Errorf("ResolveVPC(%q) vpc = %q, want %q", tc.name, vpc, tc.wantVPC)
			}
		})
	}
}
