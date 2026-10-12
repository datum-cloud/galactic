// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgeattach

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"go.datum.net/galactic/internal/plumbing/ebpf/xdpattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
)

// TestAttach_GenericModeIsWhatTheKernelReports attaches the edge program in
// generic mode, as a bnxt_en host does, and checks the kernel reports SKB
// mode, and that a Set reads coverage back by mode: a Set in generic mode
// counts the interface, and one in native mode over the same link does not.
func TestAttach_GenericModeIsWhatTheKernelReports(t *testing.T) {
	requireRoot(t)

	pinDir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-edge-mode-test-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	const ifaceName, peerName = "edgemode0", "edgemode1"

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	err = nsObj.Do(func(_ ns.NetNS) error {
		veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: ifaceName}, PeerName: peerName}
		if err := netlink.LinkAdd(veth); err != nil {
			return fmt.Errorf("add veth pair: %w", err)
		}
		l, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return err
		}

		objs, err := Load(pinDir, nil)
		if err != nil {
			return fmt.Errorf("load: %w", err)
		}
		defer func() { _ = objs.Close() }()

		links, err := Attach(objs.EdgeLb, []string{ifaceName}, xdpmode.Generic)
		if err != nil {
			return fmt.Errorf("attach in generic mode: %w", err)
		}
		defer func() { _ = links[0].Close() }()

		l, err = netlink.LinkByName(ifaceName)
		if err != nil {
			return err
		}
		if xdp := l.Attrs().Xdp; xdp == nil || !xdp.Attached || xdp.AttachMode != nl.XDP_ATTACHED_SKB {
			return fmt.Errorf("kernel reports XDP %+v, want an SKB-mode attachment", xdp)
		}

		generic, err := xdpattach.NewSet(objs.EdgeLb, []string{ifaceName}, links, xdpmode.Generic)
		if err != nil {
			return err
		}
		if got := generic.Attached(); !slices.Equal(got, []string{ifaceName}) {
			return fmt.Errorf("generic Set Attached() = %v, want [%s]", got, ifaceName)
		}
		native, err := xdpattach.NewSet(objs.EdgeLb, []string{ifaceName}, links, xdpmode.Native)
		if err != nil {
			return err
		}
		if got := native.Attached(); len(got) != 0 {
			return fmt.Errorf("native Set over a generic link: Attached() = %v, want none", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
