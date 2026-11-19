// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/config"
)

// internalLinks are the links of an uplink discovery fixture: a Local
// pair's NAT end in the host's namespace, a link carrying only a Local alias,
// a CNI host link and VRF that are not enslaved, and the real uplink.
var internalLinks = map[int]netlink.Link{
	2: &fakeLink{attrs: netlink.LinkAttrs{Index: 2, Name: "G000000080Ob1N", Alias: InternalAliasPrefix + "0000080/n"},
		linkType: "veth"},
	3: &fakeLink{attrs: netlink.LinkAttrs{Index: 3, Name: "natpeer0", Alias: InternalAliasPrefix + "0000081/n"},
		linkType: "veth"},
	4: &fakeLink{attrs: netlink.LinkAttrs{Index: 4, Name: "G000000080001H"}, linkType: "tuntap"},
	5: &fakeLink{attrs: netlink.LinkAttrs{Index: 5, Name: "G000000080V"}, linkType: "vrf"},
	6: &fakeLink{attrs: netlink.LinkAttrs{Index: 6, Name: testIfaceEth0}},
}

func stubInternalLinks(t *testing.T) {
	t.Helper()
	origByIndex, origByName, origList, origRoutes := linkByIndexFn, linkByNameFn, linkListFn, routeListFn
	t.Cleanup(func() {
		linkByIndexFn, linkByNameFn, linkListFn, routeListFn = origByIndex, origByName, origList, origRoutes
	})
	linkByIndexFn = func(index int) (netlink.Link, error) {
		if l, ok := internalLinks[index]; ok {
			return l, nil
		}
		return nil, errFixtureNotFound
	}
	linkByNameFn = func(name string) (netlink.Link, error) {
		for _, l := range internalLinks {
			if l.Attrs().Name == name {
				return l, nil
			}
		}
		return &fakeLink{attrs: netlink.LinkAttrs{Name: name}}, nil
	}
	linkListFn = func() ([]netlink.Link, error) { return nil, nil }
	// Every internal link carries a default route and a BGP route, as one
	// can when FRR learns a route over it, and each is reported before
	// the uplink's.
	routeListFn = func() ([]netlink.Route, error) {
		var out []netlink.Route
		for _, idx := range []int{2, 3, 4, 5} {
			out = append(out, netlink.Route{LinkIndex: idx},
				netlink.Route{LinkIndex: idx, Protocol: unix.RTPROT_BGP, Dst: mustIPNet(t, "2001:db8:ff::/48")})
		}
		return append(out, netlink.Route{LinkIndex: 6}), nil
	}
}

// TestUplinkDiscoveryNeverReturnsInternalLinks covers every discovery path:
// DetectUplinks, which galactic-nat's ResolveUplinks uses, and
// ResolveInterfaces, which UplinkIndexes and srv6.ResolvePublicUplink use,
// with and without the operator's override.
func TestUplinkDiscoveryNeverReturnsInternalLinks(t *testing.T) {
	stubInternalLinks(t)
	t.Setenv(config.EnvCNIEBPFInterfaces, "")

	got, err := DetectUplinks()
	if err != nil || !equalStringSlices(got, []string{testIfaceEth0}) {
		t.Fatalf("DetectUplinks() = %v, %v; want [%s]", got, err, testIfaceEth0)
	}
	got, err = ResolveInterfaces()
	if err != nil || !equalStringSlices(got, []string{testIfaceEth0}) {
		t.Fatalf("ResolveInterfaces() = %v, %v; want [%s]", got, err, testIfaceEth0)
	}

	t.Run("override", func(t *testing.T) {
		t.Setenv(config.EnvCNIEBPFInterfaces, "G000000080Ob1N,natpeer0,G000000080001H,"+testIfaceEth0)
		got, err := ResolveInterfaces()
		if err != nil || !equalStringSlices(got, []string{testIfaceEth0}) {
			t.Fatalf("ResolveInterfaces() = %v, %v; want [%s]", got, err, testIfaceEth0)
		}
		t.Setenv(config.EnvCNIEBPFInterfaces, "G000000080Ob1N")
		if got, err := ResolveInterfaces(); err == nil {
			t.Fatalf("ResolveInterfaces() = %v with only an internal link named, want an error", got)
		}
	})
}

func TestIsInternalLink(t *testing.T) {
	for idx, want := range map[int]bool{2: true, 3: true, 4: true, 5: true, 6: false} {
		if got := IsInternalLink(internalLinks[idx]); got != want {
			t.Errorf("IsInternalLink(%s) = %t, want %t", internalLinks[idx].Attrs().Name, got, want)
		}
	}
}

func mustIPNet(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
