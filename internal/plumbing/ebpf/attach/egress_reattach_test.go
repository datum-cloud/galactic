// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// A new load moves both legacy-only and two-program attachments onto its own
// service egress chain. Without that, the attachment keeps running old
// programs against old copies of maps, and rows written after the reload never
// reach it. Unrelated filters are untouched, and a second pass changes nothing.
func TestReattachEgress_MovesAttachmentsToTheNewProgram(t *testing.T) {
	requireRoot(t)

	oldPin := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-reattach-old-%d", os.Getpid()))
	newPin := filepath.Join("/sys/fs/bpf", fmt.Sprintf("galactic-reattach-new-%d", os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(oldPin); _ = os.RemoveAll(newPin) })

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	err = nsObj.Do(func(_ ns.NetNS) error {
		// legacy0 stands in for an attachment created before the service
		// classifier existed, tenant0 for a current attachment, and uplink0
		// for a shared uplink carrying usid_ingress instead.
		links := []netlink.Link{
			&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "legacy0"}, PeerName: "legacy0p"},
			&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "tenant0"}, PeerName: "tenant0p"},
			&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "uplink0"}},
		}
		for _, l := range links {
			if err := netlink.LinkAdd(l); err != nil {
				return fmt.Errorf("add %s: %w", l.Attrs().Name, err)
			}
			if err := netlink.LinkSetUp(l); err != nil {
				return fmt.Errorf("set %s up: %w", l.Attrs().Name, err)
			}
		}

		previous, err := Load(oldPin)
		if err != nil {
			return fmt.Errorf("load previous build: %w", err)
		}
		defer func() { _ = previous.Close() }()
		if err := attachOne(previous.UsidEgress, "legacy0", egressFilterName, netlink.HANDLE_MIN_INGRESS); err != nil {
			return fmt.Errorf("attach legacy-only usid_egress: %w", err)
		}
		if err := AttachEgress(previous.UsidServiceEgress, previous.UsidEgress, "tenant0"); err != nil {
			return fmt.Errorf("attach previous egress chain: %w", err)
		}
		if err := Attach(previous.UsidIngress, []string{"uplink0"}); err != nil {
			return fmt.Errorf("attach previous usid_ingress: %w", err)
		}

		current, err := Load(newPin)
		if err != nil {
			return fmt.Errorf("load current build: %w", err)
		}
		defer func() { _ = current.Close() }()

		replaced, err := ReattachEgress(current.UsidServiceEgress, current.UsidEgress)
		if err != nil {
			return fmt.Errorf("ReattachEgress: %w", err)
		}
		if replaced != 2 {
			t.Errorf("first pass replaced %d attachment chains, want 2", replaced)
		}
		for _, link := range []string{"legacy0", "tenant0"} {
			if got, want := filterProgID(t, link, serviceEgressFilterName), progID(t, current.UsidServiceEgress); got != want {
				t.Errorf("%s's service filter runs program %d, want the current build's %d", link, got, want)
			}
			if got, want := filterProgID(t, link, egressFilterName), progID(t, current.UsidEgress); got != want {
				t.Errorf("%s's usid_egress filter runs program %d, want the current build's %d", link, got, want)
			}
		}
		if got, want := filterProgID(t, "uplink0", filterName), progID(t, previous.UsidIngress); got != want {
			t.Errorf("uplink0's usid_ingress filter runs program %d, want it untouched at %d", got, want)
		}

		replaced, err = ReattachEgress(current.UsidServiceEgress, current.UsidEgress)
		if err != nil {
			return fmt.Errorf("second ReattachEgress: %w", err)
		}
		if replaced != 0 {
			t.Errorf("second pass replaced %d filters, want 0", replaced)
		}
		for _, link := range []string{"legacy0", "tenant0"} {
			if n := countFilters(t, link); n != 2 {
				t.Errorf("%s has %d ingress filters after two passes, want 2", link, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func progID(t *testing.T, p *ebpf.Program) uint32 {
	t.Helper()
	info, err := p.Info()
	if err != nil {
		t.Fatalf("program info: %v", err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatal("kernel did not report a program id")
	}
	return uint32(id)
}

// filterProgID returns the program id of the named BPF filter on link's
// ingress hook, or 0 if there is none.
func filterProgID(t *testing.T, link, name string) uint32 {
	t.Helper()
	l, err := netlink.LinkByName(link)
	if err != nil {
		t.Fatalf("look up %s: %v", link, err)
	}
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		t.Fatalf("list %s filters: %v", link, err)
	}
	for _, f := range filters {
		if bpf, ok := f.(*netlink.BpfFilter); ok && bpf.Name == name {
			return uint32(bpf.Id)
		}
	}
	return 0
}

func countFilters(t *testing.T, link string) int {
	t.Helper()
	l, err := netlink.LinkByName(link)
	if err != nil {
		t.Fatalf("look up %s: %v", link, err)
	}
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		t.Fatalf("list %s filters: %v", link, err)
	}
	return len(filters)
}
