// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// The sweep keys identities by ifindex, not by VPC attachment, so a tap that
// still carries the egress chain keeps its identity whatever happened to the
// attachment it was created for. Only an identity whose link is gone, or no
// longer carries the chain, is removed.
func TestSweepAttachmentIdentities_KeepsLiveAttachedLinks(t *testing.T) {
	requireRoot(t)
	pin := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-identity-sweep-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pin) })

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	err = nsObj.Do(func(_ ns.NetNS) error {
		objs, err := Load(pin)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		defer func() { _ = objs.Close() }()
		identities := objs.AttachmentIdentityTable

		addLink := func(l netlink.Link) (uint32, error) {
			if err := netlink.LinkAdd(l); err != nil {
				return 0, fmt.Errorf("add %s: %w", l.Attrs().Name, err)
			}
			if err := netlink.LinkSetUp(l); err != nil {
				return 0, fmt.Errorf("set %s up: %w", l.Attrs().Name, err)
			}
			got, err := netlink.LinkByName(l.Attrs().Name)
			if err != nil {
				return 0, err
			}
			return uint32(got.Attrs().Index), nil //nolint:gosec // a kernel ifindex
		}

		tap := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: "tap0"}, Mode: netlink.TUNTAP_MODE_TAP}
		tapIndex, err := addLink(tap)
		if err != nil {
			return err
		}
		err = AttachEgressWithIdentity(objs.UsidServiceEgress, objs.UsidEgress, identities, tapIndex, "tap0")
		if err != nil {
			return fmt.Errorf("attach tap0: %w", err)
		}
		var tapToken uint64
		if err := identities.Lookup(tapIndex, &tapToken); err != nil {
			return fmt.Errorf("tap0 identity after attach: %w", err)
		}

		bareIndex, err := addLink(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "bare0"}})
		if err != nil {
			return err
		}
		goneIndex, err := addLink(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "gone0"}})
		if err != nil {
			return err
		}
		if err := netlink.LinkDel(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "gone0"}}); err != nil {
			return err
		}
		for _, index := range []uint32{bareIndex, goneIndex} {
			if err := identities.Put(index, uint64(7)); err != nil {
				return fmt.Errorf("seed identity ifindex=%d: %w", index, err)
			}
		}

		removed, err := SweepAttachmentIdentities(identities)
		if err != nil {
			return fmt.Errorf("sweep: %w", err)
		}
		if removed != 2 {
			return fmt.Errorf("removed = %d, want 2 (bare0 and gone0)", removed)
		}
		var token uint64
		if err := identities.Lookup(tapIndex, &token); err != nil || token != tapToken {
			return fmt.Errorf("tap0 identity = (%d, %w), want %d kept", token, err, tapToken)
		}
		for _, index := range []uint32{bareIndex, goneIndex} {
			if err := identities.Lookup(index, &token); !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("identity ifindex=%d = (%d, %w), want removed", index, token, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
