// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package veth

import (
	"errors"
	"os"
	"testing"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// testVPC and testAttachment name a VPC and attachment whose deterministic
// kernel interface names (VRF, host veth, guest veth) the root-gated tests
// below exercise against a real kernel. They are intentionally NOT the
// "abc"/"def" identifiers the internal/cni and internal/cnibgp suites reuse:
// the root-gated package binaries run concurrently against the same host
// kernel, and internal/cni's TestCmdCheckValidConfigMissingResources asserts
// that VRF/interface pair is absent. Creating it from here under the same
// names would race that CHECK test into spuriously passing.
const (
	testVPC        = "vethadp"
	testAttachment = "oba"
)

// requireRoot skips the test when not running as root. VRF and veth
// operations need CAP_SYS_ADMIN; this matches the project-wide pattern that
// scripts/ci.sh unittest-root discovers and runs as root.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_SYS_ADMIN); run under scripts/ci.sh unittest-root")
	}
}

func TestIsLinkNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"os.IsNotExist", errors.New("no such device"), true},
		{"no such device", errors.New("link not found: no such device"), true},
		{"not found", errors.New("failed to find link: not found"), true},
		{"unrelated", errors.New("permission denied"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLinkNotFoundError(tt.err); got != tt.want {
				t.Errorf("isLinkNotFoundError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsIptablesRuleNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"rule not found", errors.New("iptables: No chain/target/match by given name. (rule not found)"), true},
		{"no rule found", errors.New("rule not found in table filter"), true},
		{"unrelated", errors.New("permission denied"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isIptablesRuleNotFoundError(tt.err); got != tt.want {
				t.Errorf("isIptablesRuleNotFoundError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAddAdoptRollbackDoesNotDeletePriorOwnersVeth reproduces #544: a
// replacement container's ADD on the same attachment takes the veth pair over
// from a still-terminating predecessor, and a later failure must not remove
// the pair out from under that live predecessor. The fix makes a taken-over
// ADD's rollback hand the pair back to its prior owner (whose own DEL reclaims
// it) instead of deleting it.
func TestAddAdoptRollbackDoesNotDeletePriorOwnersVeth(t *testing.T) {
	requireRoot(t)

	if err := vrf.Add(testVPC); err != nil {
		t.Fatalf("vrf.Add: %v", err)
	}
	t.Cleanup(func() { _ = vrf.Delete(testVPC) })

	hostName := intf.GenerateInterfaceNameHost(testVPC, testAttachment)

	// Predecessor container attaches: creates the pair, owned by testOwnerA.
	res, err := Add(testVPC, testAttachment, testOwnerA, 1500)
	if err != nil {
		t.Fatalf("Add(owner %q): %v", testOwnerA, err)
	}
	if res.Adopted {
		t.Fatalf("first Add reported Adopted=true; want a fresh pair")
	}

	// Replacement container's ADD runs while its predecessor is still
	// terminating: it takes the existing pair over. The result must say so and
	// remember who owned it before, so a rollback can hand it back.
	res, err = Add(testVPC, testAttachment, testOwnerB, 1500)
	if err != nil {
		t.Fatalf("Add(owner %q): %v", testOwnerB, err)
	}
	if !res.Adopted {
		t.Fatalf("second Add reported Adopted=false; want takeover of existing pair")
	}
	if res.PriorOwner != testOwnerA {
		t.Fatalf("second Add PriorOwner = %q, want %q", res.PriorOwner, testOwnerA)
	}

	// The replacement's ADD then fails after the veth step. Its rollback must
	// not delete the pair -- a still-terminating predecessor holds the
	// attachment -- but hand it back to that predecessor.
	if err := RestoreOwner(testVPC, testAttachment, res.PriorOwner); err != nil {
		t.Fatalf("RestoreOwner(%q): %v", res.PriorOwner, err)
	}

	// The predecessor's interface must still exist (not torn down by the
	// failed ADD's rollback)...
	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		t.Fatalf("host veth %q was deleted by a taken-over ADD's rollback: %v", hostName, err)
	}
	// ...and must be back under the prior owner, so the predecessor's own DEL
	// (arriving once it finishes terminating) reclaims it.
	if !OwnedBy(hostLink, testOwnerA) {
		t.Fatalf("after rollback, host veth not owned by %q (alias %q)", testOwnerA, hostLink.Attrs().Alias)
	}

	// The predecessor's DEL should now reclaim the pair as usual.
	if err := Delete(testVPC, testAttachment, testOwnerA); err != nil {
		t.Fatalf("predecessor DEL after rollback: %v", err)
	}
	if _, err := netlink.LinkByName(hostName); err == nil {
		t.Fatalf("host veth %q still present after predecessor DEL", hostName)
	}
}

// TestRestoreOwnerNoOpWhenLinkGone verifies RestoreOwner is a no-op, not an
// error, when the host veth has already disappeared -- the case where the
// predecessor's own DEL won the race before the failed ADD's rollback ran.
func TestRestoreOwnerNoOpWhenLinkGone(t *testing.T) {
	requireRoot(t)

	if err := RestoreOwner(testVPC, testAttachment, testOwnerA); err != nil {
		t.Fatalf("RestoreOwner for absent veth returned error: %v", err)
	}
}
