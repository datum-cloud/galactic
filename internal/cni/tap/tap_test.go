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

// requiresRoot skips the test when not running as root.
func requiresRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root")
	}
}

func TestDeleteNonExistent(t *testing.T) {
	requiresRoot(t)

	// Delete with a name that definitely doesn't exist.
	err := Delete("zzz_nonexistent_vpc", "zzz_nonexistent_att")
	if err != nil {
		t.Errorf("Delete(nonexistent) = %v, want nil", err)
	}
}

func TestAddCreatesTapLink(t *testing.T) {
	requiresRoot(t)

	vpc := "taptest_a"
	att := "taptest_b"
	t.Cleanup(func() { _ = Delete(vpc, att) })

	err := Add(vpc, att, 1500)
	if err != nil {
		t.Fatalf("Add(%q, %q) = %v", vpc, att, err)
	}

	// Verify the link exists and is a tap.
	link, err := findLink(t, generateInterfaceNameHost(vpc, att))
	if err != nil {
		t.Fatalf("link not found: %v", err)
	}
	if link.Type() != "tap" {
		t.Errorf("link type = %q, want %q", link.Type(), "tap")
	}
}

func TestAddEnslavesToVRF(t *testing.T) {
	requiresRoot(t)

	vpc := "taptest_c"
	att := "taptest_d"
	t.Cleanup(func() { _ = Delete(vpc, att) })

	err := Add(vpc, att, 1500)
	if err != nil {
		t.Fatalf("Add(%q, %q) = %v", vpc, att, err)
	}

	hostName := generateInterfaceNameHost(vpc, att)
	vrfName := generateInterfaceNameVRF(vpc, att)

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
	requiresRoot(t)

	vpc := "taptest_e"
	att := "taptest_f"
	t.Cleanup(func() { _ = Delete(vpc, att) })

	err := Add(vpc, att, 1500)
	if err != nil {
		t.Fatalf("Add(%q, %q) = %v", vpc, att, err)
	}

	hostName := generateInterfaceNameHost(vpc, att)

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
	requiresRoot(t)

	vpc := "taptest_g"
	att := "taptest_h"

	err := Add(vpc, att, 1500)
	if err != nil {
		t.Fatalf("Add(%q, %q) = %v", vpc, att, err)
	}

	hostName := generateInterfaceNameHost(vpc, att)
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

func generateInterfaceNameHost(vpc, att string) string {
	// Inline the intf name generation to avoid a test-time import cycle.
	// This mirrors intf.GenerateInterfaceNameHost.
	return "H" + vpc + att
}

func generateInterfaceNameVRF(vpc, att string) string {
	// Inline the intf name generation to avoid a test-time import cycle.
	// This mirrors intf.GenerateInterfaceNameVRF.
	return "V" + vpc + att
}

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
