// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/config"
)

// testIfaceEth0 and testIfaceEth1 are shared interface-name fixtures used
// across this package's tests.
const (
	testIfaceEth0 = "eth0"
	testIfaceEth1 = "eth1"
)

// fakeLink is a minimal netlink.Link implementation for tests.
type fakeLink struct {
	attrs netlink.LinkAttrs
}

func (f *fakeLink) Attrs() *netlink.LinkAttrs { return &f.attrs }
func (f *fakeLink) Type() string              { return "fake" }

func TestResolveInterfaces_EnvOverride(t *testing.T) {
	tests := []struct {
		name      string
		envValue  string
		want      []string
		wantError bool
	}{
		{"SingleInterface", testIfaceEth0, []string{testIfaceEth0}, false},
		{
			"MultipleInterfaces",
			strings.Join([]string{testIfaceEth0, testIfaceEth1}, ","),
			[]string{testIfaceEth0, testIfaceEth1},
			false,
		},
		{
			"WhitespaceTrimmed",
			"  " + testIfaceEth0 + " , " + testIfaceEth1 + "  ",
			[]string{testIfaceEth0, testIfaceEth1},
			false,
		},
		{
			"DuplicatesRemoved",
			strings.Join([]string{testIfaceEth0, testIfaceEth1, testIfaceEth0}, ","),
			[]string{testIfaceEth0, testIfaceEth1},
			false,
		},
		{
			"EmptyEntriesSkipped",
			testIfaceEth0 + ",," + testIfaceEth1,
			[]string{testIfaceEth0, testIfaceEth1},
			false,
		},
		{"OnlyCommasIsError", ",,,", nil, true},
		{"OnlyWhitespaceIsError", "   ", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(config.EnvCNIEBPFInterfaces, tt.envValue)

			got, err := ResolveInterfaces()
			if (err != nil) != tt.wantError {
				t.Fatalf("ResolveInterfaces() error = %v, wantError = %v", err, tt.wantError)
			}
			if tt.wantError {
				return
			}
			if !equalStringSlices(got, tt.want) {
				t.Errorf("ResolveInterfaces() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveInterfaces_AutoDetect(t *testing.T) {
	t.Setenv(config.EnvCNIEBPFInterfaces, "")

	origRouteListFn, origLinkByIndexFn := routeListFn, linkByIndexFn
	t.Cleanup(func() {
		routeListFn, linkByIndexFn = origRouteListFn, origLinkByIndexFn
	})

	links := map[int]netlink.Link{
		2: &fakeLink{attrs: netlink.LinkAttrs{Index: 2, Name: testIfaceEth0}},
		3: &fakeLink{attrs: netlink.LinkAttrs{Index: 3, Name: testIfaceEth1}},
	}
	linkByIndexFn = func(index int) (netlink.Link, error) {
		if l, ok := links[index]; ok {
			return l, nil
		}
		return nil, errFixtureNotFound
	}

	t.Run("DefaultRouteFound", func(t *testing.T) {
		routeListFn = func() ([]netlink.Route, error) {
			return []netlink.Route{
				{LinkIndex: 2, Dst: nil}, // default route, Dst == nil
			}, nil
		}
		got, err := ResolveInterfaces()
		if err != nil {
			t.Fatalf("ResolveInterfaces() error = %v", err)
		}
		if !equalStringSlices(got, []string{testIfaceEth0}) {
			t.Errorf("ResolveInterfaces() = %v, want [%s]", got, testIfaceEth0)
		}
	})

	t.Run("MultipleDefaultRoutesDeduped", func(t *testing.T) {
		_, zeroNet, _ := net.ParseCIDR("::/0")
		routeListFn = func() ([]netlink.Route, error) {
			return []netlink.Route{
				{LinkIndex: 2, Dst: zeroNet},
				{LinkIndex: 3, Dst: zeroNet},
				{LinkIndex: 2, Dst: zeroNet}, // duplicate route to eth0
			}, nil
		}
		got, err := ResolveInterfaces()
		if err != nil {
			t.Fatalf("ResolveInterfaces() error = %v", err)
		}
		if !equalStringSlices(got, []string{testIfaceEth0, testIfaceEth1}) {
			t.Errorf("ResolveInterfaces() = %v, want [%s %s]", got, testIfaceEth0, testIfaceEth1)
		}
	})

	t.Run("NonDefaultRoutesIgnored", func(t *testing.T) {
		_, specific, _ := net.ParseCIDR("2001:db8::/32")
		routeListFn = func() ([]netlink.Route, error) {
			return []netlink.Route{
				{LinkIndex: 2, Dst: specific},
			}, nil
		}
		_, err := ResolveInterfaces()
		if err == nil {
			t.Fatal("ResolveInterfaces() error = nil, want an error (no default route present)")
		}
	})

	t.Run("UnresolvableLinkSkipped", func(t *testing.T) {
		routeListFn = func() ([]netlink.Route, error) {
			return []netlink.Route{
				{LinkIndex: 99, Dst: nil}, // unknown link index
				{LinkIndex: 2, Dst: nil},
			}, nil
		}
		got, err := ResolveInterfaces()
		if err != nil {
			t.Fatalf("ResolveInterfaces() error = %v", err)
		}
		if !equalStringSlices(got, []string{testIfaceEth0}) {
			t.Errorf("ResolveInterfaces() = %v, want [%s] (unresolvable route skipped)", got, testIfaceEth0)
		}
	})

	t.Run("NoDefaultRouteIsActionableError", func(t *testing.T) {
		routeListFn = func() ([]netlink.Route, error) {
			return nil, nil
		}
		_, err := ResolveInterfaces()
		if err == nil {
			t.Fatal("ResolveInterfaces() error = nil, want an error naming the override env var")
		}
	})

	t.Run("RouteListError", func(t *testing.T) {
		routeListFn = func() ([]netlink.Route, error) {
			return nil, errFixtureNotFound
		}
		_, err := ResolveInterfaces()
		if err == nil {
			t.Fatal("ResolveInterfaces() error = nil, want the underlying route-list error surfaced")
		}
	})
}

var errFixtureNotFound = fixtureError("not found")

// fixtureError is a trivial error implementation for test fixtures.
type fixtureError string

func (e fixtureError) Error() string { return string(e) }

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
