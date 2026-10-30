// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vrf_test

import (
	"errors"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// inScratchNetNS runs fn in a new network namespace, failing the test on
// its error.
func inScratchNetNS(t *testing.T, fn func() error) {
	t.Helper()
	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	t.Cleanup(func() { _ = nsObj.Close() })
	if err := nsObj.Do(func(ns.NetNS) error { return fn() }); err != nil {
		t.Fatal(err)
	}
}

// TestEnsureAndEnslave_CreatesThenReuses requires the first call to create
// the VRF and hand it to the callback, and a second to hand over the same
// one.
func TestEnsureAndEnslave_CreatesThenReuses(t *testing.T) {
	requireRoot(t)
	const vpc = "veae"
	inScratchNetNS(t, func() error {
		var first, second *netlink.Vrf
		if err := vrf.EnsureAndEnslave(vpc, func(v *netlink.Vrf) error { first = v; return nil }); err != nil {
			t.Fatalf("first EnsureAndEnslave: %v", err)
		}
		if err := vrf.EnsureAndEnslave(vpc, func(v *netlink.Vrf) error { second = v; return nil }); err != nil {
			t.Fatalf("second EnsureAndEnslave: %v", err)
		}
		if first == nil || second == nil || first.Index != second.Index || first.Table != second.Table {
			t.Fatalf("callbacks got %+v then %+v, want the same VRF twice", first, second)
		}
		if first.Name != intf.GenerateInterfaceNameVRF(vpc) {
			t.Errorf("VRF name = %q, want %q", first.Name, intf.GenerateInterfaceNameVRF(vpc))
		}
		return nil
	})
}

// TestEnsureAndEnslave_ReturnsCallbackError passes the callback's error back
// unwrapped and leaves the VRF in place.
func TestEnsureAndEnslave_ReturnsCallbackError(t *testing.T) {
	requireRoot(t)
	const vpc = "veaerr"
	errAttach := errors.New("attach failed")
	inScratchNetNS(t, func() error {
		if err := vrf.EnsureAndEnslave(vpc, func(*netlink.Vrf) error { return errAttach }); !errors.Is(err, errAttach) {
			t.Fatalf("EnsureAndEnslave = %v, want the callback's error", err)
		}
		return vrf.Exists(vpc)
	})
}

// TestDeleteIfUnused keeps a VRF with a link enslaved to it, then removes it
// once the link has left, and reports an absent VRF as not removed.
func TestDeleteIfUnused(t *testing.T) {
	requireRoot(t)
	const vpc = "vdiu"
	name := intf.GenerateInterfaceNameVRF(vpc)
	inScratchNetNS(t, func() error {
		dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "vdiu-slave"}}
		if err := vrf.EnsureAndEnslave(vpc, func(v *netlink.Vrf) error {
			if err := netlink.LinkAdd(dummy); err != nil {
				return err
			}
			return netlink.LinkSetMaster(dummy, v)
		}); err != nil {
			t.Fatalf("EnsureAndEnslave: %v", err)
		}

		removed, err := vrf.DeleteIfUnused(name)
		if !errors.Is(err, vrf.ErrInUse) || removed {
			t.Fatalf("DeleteIfUnused with a slave = %v, %v; want ErrInUse and not removed", removed, err)
		}
		if err := vrf.Exists(vpc); err != nil {
			t.Fatalf("VRF after refused delete: %v", err)
		}

		if err := netlink.LinkSetNoMaster(dummy); err != nil {
			t.Fatal(err)
		}
		removed, err = vrf.DeleteIfUnused(name)
		if err != nil || !removed {
			t.Fatalf("DeleteIfUnused without slaves = %v, %v; want removed", removed, err)
		}
		if err := vrf.Exists(vpc); err == nil {
			t.Fatal("VRF still present after DeleteIfUnused")
		}

		removed, err = vrf.DeleteIfUnused(name)
		if err != nil || removed {
			t.Fatalf("DeleteIfUnused on an absent VRF = %v, %v; want nothing removed and no error", removed, err)
		}

		if removed, err := vrf.DeleteIfUnused("vdiu-slave"); err == nil || removed {
			t.Fatalf("DeleteIfUnused on a non-VRF = %v, %v; want an error", removed, err)
		}
		return nil
	})
}
