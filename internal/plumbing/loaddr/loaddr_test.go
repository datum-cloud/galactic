// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package loaddr

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

const testGlobalAddr = "fc00:0:2::1"

func addr(t *testing.T, cidr string) netlink.Addr {
	t.Helper()
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse CIDR %q: %v", cidr, err)
	}
	ipnet.IP = ip
	return netlink.Addr{IPNet: ipnet}
}

func TestSelectGlobalUnicast(t *testing.T) {
	tests := []struct {
		name    string
		addrs   []netlink.Addr
		want    string
		wantErr bool
	}{
		{
			name:    "loopback only",
			addrs:   []netlink.Addr{addr(t, "::1/128")},
			wantErr: true,
		},
		{
			name:    "link-local only",
			addrs:   []netlink.Addr{addr(t, "fe80::1/64")},
			wantErr: true,
		},
		{
			name:  "loopback and link-local skipped, global picked",
			addrs: []netlink.Addr{addr(t, "::1/128"), addr(t, "fe80::1/64"), addr(t, testGlobalAddr+"/48")},
			want:  testGlobalAddr,
		},
		{
			name:  "first global wins when multiple present",
			addrs: []netlink.Addr{addr(t, testGlobalAddr+"/48"), addr(t, "fc00:0:2::2/48")},
			want:  testGlobalAddr,
		},
		{
			name:    "empty list",
			addrs:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectGlobalUnicast(tt.addrs)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("selectGlobalUnicast() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("selectGlobalUnicast() error = %v, want nil", err)
			}
			if got != tt.want {
				t.Errorf("selectGlobalUnicast() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectInConfiguredNamespace(t *testing.T) {
	requireRoot(t)

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer nsObj.Close() //nolint:errcheck // best-effort cleanup

	err = nsObj.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName("lo")
		if err != nil {
			return fmt.Errorf("find lo in test netns: %w", err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("set lo up: %w", err)
		}
		want, err := netlink.ParseAddr(testGlobalAddr + "/48")
		if err != nil {
			return fmt.Errorf("parse test address: %w", err)
		}
		return netlink.AddrAdd(link, want)
	})
	if err != nil {
		t.Fatalf("configure test netns lo: %v", err)
	}

	var got string
	err = nsObj.Do(func(_ ns.NetNS) error {
		var derr error
		got, derr = Detect()
		return derr
	})
	if err != nil {
		t.Fatalf("Detect() in configured netns: %v", err)
	}
	if got != testGlobalAddr {
		t.Errorf("Detect() = %q, want %q", got, testGlobalAddr)
	}
}

// requireRoot skips the test when not running as root. Network namespace
// operations (unshare, interface configuration) require CAP_SYS_ADMIN.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("skipping: requires root (CAP_SYS_ADMIN)")
	}
}
