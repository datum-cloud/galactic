// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package tap

import (
	"errors"
	"os"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/intf"
)

func TestIsLinkNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "os.IsNotExist",
			err:  os.ErrNotExist,
			want: true,
		},
		{
			name: "no such device",
			err:  errors.New("link not found: no such device"),
			want: true,
		},
		{
			name: "not found",
			err:  errors.New("failed: not found"),
			want: true,
		},
		{
			name: "unrelated error",
			err:  errors.New("permission denied"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLinkNotFoundError(tt.err)
			if got != tt.want {
				t.Errorf("isLinkNotFoundError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestUpdateForwardRuleInvalidAction(t *testing.T) {
	err := updateForwardRule("tap0", "invalid")
	if err == nil {
		t.Fatal("expected error for invalid action, got nil")
	}
	if err.Error() != "invalid action: 'invalid' (must be 'add' or 'delete')" {
		t.Errorf("unexpected error: %v", err)
	}
}

// requireRoot skips the test when not running as root.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root")
	}
}

func TestDeleteNonExistent(t *testing.T) {
	requireRoot(t)

	// Delete with a name that definitely doesn't exist.
	err := Delete("zz", "zz9")
	if err != nil {
		t.Errorf("Delete(nonexistent) = %v, want nil", err)
	}
}

func TestAddCreatesTapLink(t *testing.T) {
	requireRoot(t)

	vpc, att := "at", "b1"
	addVRFStandIn(t, vpc)
	t.Cleanup(func() { _ = Delete(vpc, att) })

	err := Add(vpc, att, 1500)
	if err != nil {
		t.Fatalf("Add(%q, %q) = %v", vpc, att, err)
	}

	// Verify the link exists and is a tap.
	link, err := findLink(t, intf.GenerateInterfaceNameHost(vpc, att))
	if err != nil {
		t.Fatalf("link not found: %v", err)
	}
	if link.Type() != "tuntap" {
		t.Errorf("link type = %q, want %q", link.Type(), "tuntap")
	}
}

// testMTU differs from the kernel's 1500 default, so a tap that silently kept
// the default fails the assertion.
const testMTU = 1460

// addVRFStandIn creates the master device Add enslaves the tap to. A bridge
// stands in for the VRF because Add only needs a master-capable link under the
// VRF's name, and not every kernel that runs these tests ships the VRF module.
func addVRFStandIn(t *testing.T, vpc string) {
	t.Helper()
	name := intf.GenerateInterfaceNameVRF(vpc)
	if err := netlink.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		t.Fatalf("create VRF stand-in %q: %v", name, err)
	}
	t.Cleanup(func() {
		if link, err := netlink.LinkByName(name); err == nil {
			_ = netlink.LinkDel(link)
		}
	})
}

func TestAddAppliesConfiguredMTU(t *testing.T) {
	requireRoot(t)

	vpc, att := "mt", "a1"
	addVRFStandIn(t, vpc)
	t.Cleanup(func() { _ = Delete(vpc, att) })

	if err := Add(vpc, att, testMTU); err != nil {
		t.Fatalf("Add(%q, %q) = %v", vpc, att, err)
	}

	link, err := findLink(t, intf.GenerateInterfaceNameHost(vpc, att))
	if err != nil {
		t.Fatalf("link not found: %v", err)
	}
	if got := link.Attrs().MTU; got != testMTU {
		t.Errorf("tap MTU = %d, want %d", got, testMTU)
	}
}

func TestAddRepairRestoresConfiguredMTU(t *testing.T) {
	requireRoot(t)

	vpc, att := "mr", "b1"
	addVRFStandIn(t, vpc)
	t.Cleanup(func() { _ = Delete(vpc, att) })

	if err := Add(vpc, att, testMTU); err != nil {
		t.Fatalf("Add(%q, %q) = %v", vpc, att, err)
	}
	hostName := intf.GenerateInterfaceNameHost(vpc, att)
	link, err := findLink(t, hostName)
	if err != nil {
		t.Fatalf("link not found: %v", err)
	}
	// Model a tap an earlier ADD left at the kernel default.
	if err := netlink.LinkSetMTU(link, 1500); err != nil {
		t.Fatalf("LinkSetMTU: %v", err)
	}

	if err := Add(vpc, att, testMTU); err != nil {
		t.Fatalf("repeat Add(%q, %q) = %v", vpc, att, err)
	}
	link, err = findLink(t, hostName)
	if err != nil {
		t.Fatalf("link not found after repair: %v", err)
	}
	if got := link.Attrs().MTU; got != testMTU {
		t.Errorf("tap MTU after repair = %d, want %d", got, testMTU)
	}
}

func TestAddEnslavesToVRF(t *testing.T) {
	requireRoot(t)

	vpc, att := "ct", "d1"
	addVRFStandIn(t, vpc)
	t.Cleanup(func() { _ = Delete(vpc, att) })

	err := Add(vpc, att, 1500)
	if err != nil {
		t.Fatalf("Add(%q, %q) = %v", vpc, att, err)
	}

	hostName := intf.GenerateInterfaceNameHost(vpc, att)
	vrfName := intf.GenerateInterfaceNameVRF(vpc)

	link, err := findLink(t, hostName)
	if err != nil {
		t.Fatalf("link not found: %v", err)
	}

	master := link.Attrs().MasterIndex
	masterLink, err := findLink(t, vrfName)
	if err != nil {
		t.Fatalf("VRF link not found: %v", err)
	}
	if master != masterLink.Attrs().Index {
		t.Errorf("tap master index = %d, want %d (VRF)", master, masterLink.Attrs().Index)
	}
}

func TestAddBidirectionalRules(t *testing.T) {
	requireRoot(t)

	vpc, att := "et", "f1"
	addVRFStandIn(t, vpc)
	t.Cleanup(func() { _ = Delete(vpc, att) })

	err := Add(vpc, att, 1500)
	if err != nil {
		t.Fatalf("Add(%q, %q) = %v", vpc, att, err)
	}

	hostName := intf.GenerateInterfaceNameHost(vpc, att)

	// Check iptables rules exist for both -i and -o.
	for _, proto := range []int{iptablesProtocolIPv4, iptablesProtocolIPv6} {
		ipt, err := newIptables(proto)
		if err != nil {
			// iptables unavailable — skip.
			continue
		}
		rules, err := ipt.List("filter", "FORWARD")
		if err != nil {
			t.Fatalf("iptables list: %v", err)
		}
		foundIngress, foundEgress := false, false
		for _, rule := range rules {
			if rule == "-A FORWARD -i "+hostName+" -j ACCEPT" {
				foundIngress = true
			}
			if rule == "-A FORWARD -o "+hostName+" -j ACCEPT" {
				foundEgress = true
			}
		}
		if !foundIngress {
			t.Errorf("proto=%d: missing ingress (-i) rule for %s", proto, hostName)
		}
		if !foundEgress {
			t.Errorf("proto=%d: missing egress (-o) rule for %s", proto, hostName)
		}
	}
}

func TestDeleteRemovesLink(t *testing.T) {
	requireRoot(t)

	vpc, att := "gt", "h1"
	addVRFStandIn(t, vpc)

	err := Add(vpc, att, 1500)
	if err != nil {
		t.Fatalf("Add(%q, %q) = %v", vpc, att, err)
	}

	hostName := intf.GenerateInterfaceNameHost(vpc, att)
	if _, err := findLink(t, hostName); err != nil {
		t.Fatalf("link not found after Add: %v", err)
	}

	if err := Delete(vpc, att); err != nil {
		t.Fatalf("Delete(%q, %q) = %v", vpc, att, err)
	}

	_, err = findLink(t, hostName)
	if err == nil {
		t.Error("link still exists after Delete, want removed")
	}
}

// ---- helpers -------------------------------------------------------------

const (
	iptablesProtocolIPv4 = 0
	iptablesProtocolIPv6 = 1
)

func newIptables(proto int) (*iptables.IPTables, error) {
	return iptables.NewWithProtocol(iptables.Protocol(proto))
}

func findLink(t *testing.T, name string) (netlink.Link, error) {
	t.Helper()
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	return link, nil
}
