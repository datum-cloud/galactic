// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/config"
)

// testIfaceEth0 and testIfaceEth1 are shared interface-name fixtures used
// across this package's tests.
const (
	testIfaceEth0 = "eth0"
	testIfaceEth1 = "eth1"
)

// fakeLink is a minimal netlink.Link implementation for tests. linkType
// defaults to "fake" when unset, so existing fixtures that never set it
// don't need updating.
type fakeLink struct {
	attrs    netlink.LinkAttrs
	linkType string
}

func (f *fakeLink) Attrs() *netlink.LinkAttrs { return &f.attrs }
func (f *fakeLink) Type() string {
	if f.linkType == "" {
		return "fake"
	}
	return f.linkType
}

// stubNonBondLinks configures linkByNameFn/linkListFn so ResolveInterfaces'
// expandBondSlaves pass is a no-op: every name resolves to a non-bond
// fakeLink, and there are no other links on the host to enumerate as
// slaves. Tests that only care about override-parsing or auto-detection
// behavior (not bond expansion itself) use this so expandBondSlaves' own
// netlink lookups don't need per-test fixtures.
func stubNonBondLinks(t *testing.T) {
	t.Helper()
	origLinkByNameFn, origLinkListFn := linkByNameFn, linkListFn
	t.Cleanup(func() {
		linkByNameFn, linkListFn = origLinkByNameFn, origLinkListFn
	})
	linkByNameFn = func(name string) (netlink.Link, error) {
		return &fakeLink{attrs: netlink.LinkAttrs{Name: name}}, nil
	}
	linkListFn = func() ([]netlink.Link, error) { return nil, nil }
}

func TestResolveInterfaces_EnvOverride(t *testing.T) {
	stubNonBondLinks(t)

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
	stubNonBondLinks(t)

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

	t.Run("WireguardLinkExcluded", func(t *testing.T) {
		// A WireGuard mesh interface can install an IPv6 default-ish
		// route alongside the real fabric NIC's; ResolveInterfaces must
		// never return a wireguard-type link even when its default
		// route sorts ahead of a real NIC's.
		const wireguardIface = "wg-mesh0"
		wgLinks := map[int]netlink.Link{
			2: &fakeLink{attrs: netlink.LinkAttrs{Index: 2, Name: wireguardIface}, linkType: "wireguard"},
			3: &fakeLink{attrs: netlink.LinkAttrs{Index: 3, Name: testIfaceEth0}},
		}
		origLinkByIndexFn := linkByIndexFn
		linkByIndexFn = func(index int) (netlink.Link, error) {
			if l, ok := wgLinks[index]; ok {
				return l, nil
			}
			return nil, errFixtureNotFound
		}
		defer func() { linkByIndexFn = origLinkByIndexFn }()

		routeListFn = func() ([]netlink.Route, error) {
			return []netlink.Route{
				{LinkIndex: 2, Dst: nil}, // the mesh interface's default route, reported first
				{LinkIndex: 3, Dst: nil}, // the real fabric NIC's
			}, nil
		}
		got, err := ResolveInterfaces()
		if err != nil {
			t.Fatalf("ResolveInterfaces() error = %v", err)
		}
		if !equalStringSlices(got, []string{testIfaceEth0}) {
			t.Errorf("ResolveInterfaces() = %v, want [%s] (wireguard link excluded)", got, testIfaceEth0)
		}
	})

	t.Run("VRFSlaveExcluded", func(t *testing.T) {
		// Reproduces the live bug found in internal/ingresssidecar: a VRF
		// slave (its own per-VPC veth pair, ensureEgressDatapath's
		// ivpN/ivsN) picked up a spurious default route in its VRF's own
		// table, sorting ahead of the real fabric NIC's -- see
		// autoDetectInterfaces' own doc comment. isVRFSlave's fakeLink
		// still reports its real Type() ("fake" here, "veth" live) --
		// only its MasterIndex plus the separately-resolved master's own
		// Type() ("vrf") mark the enslavement, exactly as isVRFSlave
		// requires.
		const (
			vrfSlaveIface = "ivs1"
			vrfMasterIdx  = 99
		)
		vrfLinks := map[int]netlink.Link{
			2: &fakeLink{attrs: netlink.LinkAttrs{Index: 2, Name: vrfSlaveIface, MasterIndex: vrfMasterIdx}},
			3: &fakeLink{attrs: netlink.LinkAttrs{Index: 3, Name: testIfaceEth0}},
			vrfMasterIdx: &fakeLink{
				attrs: netlink.LinkAttrs{Index: vrfMasterIdx, Name: "G000000002V"}, linkType: excludedMasterType,
			},
		}
		origLinkByIndexFn := linkByIndexFn
		linkByIndexFn = func(index int) (netlink.Link, error) {
			if l, ok := vrfLinks[index]; ok {
				return l, nil
			}
			return nil, errFixtureNotFound
		}
		defer func() { linkByIndexFn = origLinkByIndexFn }()

		routeListFn = func() ([]netlink.Route, error) {
			return []netlink.Route{
				{LinkIndex: 2, Dst: nil}, // the VRF slave's spurious default route, reported first
				{LinkIndex: 3, Dst: nil}, // the real fabric NIC's
			}, nil
		}
		got, err := ResolveInterfaces()
		if err != nil {
			t.Fatalf("ResolveInterfaces() error = %v", err)
		}
		if !equalStringSlices(got, []string{testIfaceEth0}) {
			t.Errorf("ResolveInterfaces() = %v, want [%s] (VRF slave excluded)", got, testIfaceEth0)
		}
	})

	t.Run("OnlyWireguardLinkIsActionableError", func(t *testing.T) {
		const wireguardIface = "wg-mesh0"
		wgLinks := map[int]netlink.Link{
			2: &fakeLink{attrs: netlink.LinkAttrs{Index: 2, Name: wireguardIface}, linkType: "wireguard"},
		}
		origLinkByIndexFn := linkByIndexFn
		linkByIndexFn = func(index int) (netlink.Link, error) {
			if l, ok := wgLinks[index]; ok {
				return l, nil
			}
			return nil, errFixtureNotFound
		}
		defer func() { linkByIndexFn = origLinkByIndexFn }()

		routeListFn = func() ([]netlink.Route, error) {
			return []netlink.Route{
				{LinkIndex: 2, Dst: nil},
			}, nil
		}
		_, err := ResolveInterfaces()
		if err == nil {
			t.Fatal("ResolveInterfaces() error = nil, want an error (only candidate is a wireguard link)")
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

// TestExpandBondSlaves exercises expandBondSlaves directly against a faked
// netlink view (linkByNameFn/linkListFn), covering the live bug: on a Linux
// bonding master, RX ingress tc/eBPF classification happens on the slave
// devices, not the master -- see expandBondSlaves' own doc comment.
func TestExpandBondSlaves(t *testing.T) {
	origLinkByNameFn, origLinkListFn := linkByNameFn, linkListFn
	t.Cleanup(func() {
		linkByNameFn, linkListFn = origLinkByNameFn, origLinkListFn
	})

	const (
		bondName  = "bond0"
		bondIndex = 10
		slave1    = "ens1f1np1"
		slave2    = "ens2f1np1"
	)

	slave1Link := &fakeLink{attrs: netlink.LinkAttrs{Name: slave1, Index: 11, MasterIndex: bondIndex}}
	bondLinks := map[string]netlink.Link{
		testIfaceEth0: &fakeLink{attrs: netlink.LinkAttrs{Name: testIfaceEth0, Index: 2}},
		bondName:      &fakeLink{attrs: netlink.LinkAttrs{Name: bondName, Index: bondIndex}, linkType: bondLinkType},
		slave1:        slave1Link, // also named explicitly, in MixedBondAndNonBondDeduped below
	}
	allLinks := []netlink.Link{
		bondLinks[testIfaceEth0],
		bondLinks[bondName],
		slave1Link,
		&fakeLink{attrs: netlink.LinkAttrs{Name: slave2, Index: 12, MasterIndex: bondIndex}},
		// A link enslaved to some other, unrelated master must never leak in.
		&fakeLink{attrs: netlink.LinkAttrs{Name: "unrelated-slave", Index: 13, MasterIndex: 999}},
	}

	linkByNameFn = func(name string) (netlink.Link, error) {
		if l, ok := bondLinks[name]; ok {
			return l, nil
		}
		return nil, errFixtureNotFound
	}
	linkListFn = func() ([]netlink.Link, error) { return allLinks, nil }

	t.Run("NonBondUnchanged", func(t *testing.T) {
		got, err := expandBondSlaves([]string{testIfaceEth0})
		if err != nil {
			t.Fatalf("expandBondSlaves() error = %v", err)
		}
		if !equalStringSlices(got, []string{testIfaceEth0}) {
			t.Errorf("expandBondSlaves() = %v, want [%s] (non-bond interface unchanged)", got, testIfaceEth0)
		}
	})

	t.Run("BondExpandsToMasterAndSlaves", func(t *testing.T) {
		got, err := expandBondSlaves([]string{bondName})
		if err != nil {
			t.Fatalf("expandBondSlaves() error = %v", err)
		}
		want := []string{bondName, slave1, slave2}
		if !equalStringSlices(got, want) {
			t.Errorf("expandBondSlaves() = %v, want %v (master plus both real slaves, unrelated slave excluded)", got, want)
		}
	})

	t.Run("MixedBondAndNonBondDeduped", func(t *testing.T) {
		got, err := expandBondSlaves([]string{testIfaceEth0, bondName, slave1})
		if err != nil {
			t.Fatalf("expandBondSlaves() error = %v", err)
		}
		want := []string{testIfaceEth0, bondName, slave1, slave2}
		if !equalStringSlices(got, want) {
			t.Errorf("expandBondSlaves() = %v, want %v (slave1 named explicitly must not be duplicated)", got, want)
		}
	})

	t.Run("UnresolvableInterfacePassedThrough", func(t *testing.T) {
		// A name that can't be resolved at all (e.g. this init container's
		// netns can't yet see it) is passed through unchanged rather than
		// failing the whole call -- ResolveInterfaces' override path has
		// never required its named interfaces to actually exist on the
		// host at resolution time (installer_test.go's TestResolveEBPFInterfaces
		// asserts exactly this for the pre-bond-expansion behavior).
		const name = "does-not-exist"
		got, err := expandBondSlaves([]string{name})
		if err != nil {
			t.Fatalf("expandBondSlaves() error = %v, want no error (unresolvable name passed through)", err)
		}
		if !equalStringSlices(got, []string{name}) {
			t.Errorf("expandBondSlaves() = %v, want [%s] unchanged", got, name)
		}
	})

	t.Run("LinkListErrorPropagated", func(t *testing.T) {
		origLinkListFn := linkListFn
		linkListFn = func() ([]netlink.Link, error) { return nil, errFixtureNotFound }
		defer func() { linkListFn = origLinkListFn }()

		_, err := expandBondSlaves([]string{bondName})
		if err == nil {
			t.Fatal("expandBondSlaves() error = nil, want the underlying link-list error surfaced")
		}
	})
}

// TestResolveInterfaces_BondExpansion exercises bond expansion end-to-end
// through ResolveInterfaces itself, for both the env-override and
// auto-detect paths -- so an operator naming only a bond master (or a
// default route resolving to one) gets its slaves attached too, without
// needing to hand-list them.
func TestResolveInterfaces_BondExpansion(t *testing.T) {
	const (
		bondName  = "bond0"
		bondIndex = 5
		slave1    = "ens1f1np1"
		slave2    = "ens2f1np1"
	)

	bondLink := &fakeLink{attrs: netlink.LinkAttrs{Name: bondName, Index: bondIndex}, linkType: bondLinkType}
	slaveLinks := []netlink.Link{
		&fakeLink{attrs: netlink.LinkAttrs{Name: slave1, Index: 6, MasterIndex: bondIndex}},
		&fakeLink{attrs: netlink.LinkAttrs{Name: slave2, Index: 7, MasterIndex: bondIndex}},
	}
	want := []string{bondName, slave1, slave2}

	t.Run("EnvOverride", func(t *testing.T) {
		t.Setenv(config.EnvCNIEBPFInterfaces, bondName)

		origLinkByNameFn, origLinkListFn := linkByNameFn, linkListFn
		t.Cleanup(func() { linkByNameFn, linkListFn = origLinkByNameFn, origLinkListFn })
		linkByNameFn = func(name string) (netlink.Link, error) {
			if name == bondName {
				return bondLink, nil
			}
			return nil, errFixtureNotFound
		}
		linkListFn = func() ([]netlink.Link, error) { return slaveLinks, nil }

		got, err := ResolveInterfaces()
		if err != nil {
			t.Fatalf("ResolveInterfaces() error = %v", err)
		}
		if !equalStringSlices(got, want) {
			t.Errorf("ResolveInterfaces() = %v, want %v (override naming only the bond master expands to its slaves)", got, want)
		}
	})

	t.Run("AutoDetect", func(t *testing.T) {
		t.Setenv(config.EnvCNIEBPFInterfaces, "")

		origRouteListFn, origLinkByIndexFn := routeListFn, linkByIndexFn
		origLinkByNameFn, origLinkListFn := linkByNameFn, linkListFn
		t.Cleanup(func() {
			routeListFn, linkByIndexFn = origRouteListFn, origLinkByIndexFn
			linkByNameFn, linkListFn = origLinkByNameFn, origLinkListFn
		})

		routeListFn = func() ([]netlink.Route, error) {
			return []netlink.Route{{LinkIndex: bondIndex, Dst: nil}}, nil
		}
		linkByIndexFn = func(index int) (netlink.Link, error) {
			if index == bondIndex {
				return bondLink, nil
			}
			return nil, errFixtureNotFound
		}
		linkByNameFn = func(name string) (netlink.Link, error) {
			if name == bondName {
				return bondLink, nil
			}
			return nil, errFixtureNotFound
		}
		linkListFn = func() ([]netlink.Link, error) { return slaveLinks, nil }

		got, err := ResolveInterfaces()
		if err != nil {
			t.Fatalf("ResolveInterfaces() error = %v", err)
		}
		if !equalStringSlices(got, want) {
			t.Errorf("ResolveInterfaces() = %v, want %v (auto-detected bond master expands to its slaves)", got, want)
		}
	})
}

// TestAutoDetectInterfaces_FindsDefaultRouteInNonMainTable is a real,
// root-gated integration test (not routeListFn-faked, unlike
// TestResolveInterfaces_AutoDetect above) covering the gap ecv's review
// flagged: a default IPv6 route living in a table other than main (e.g. a
// VRF-scoped underlay) must still be found. It exercises the real
// routeListFn against an actual kernel routing table entry, proving
// RouteListFiltered's RT_FILTER_TABLE/RT_TABLE_UNSPEC combination in
// interfaces.go genuinely surfaces non-main-table routes, not just that a
// faked routeListFn can be made to return one.
func TestAutoDetectInterfaces_FindsDefaultRouteInNonMainTable(t *testing.T) {
	requireRoot(t)

	const ifaceName = "usidrt0"
	const nonMainTable = 100

	nsObj, err := ns.TempNetNS()
	if err != nil {
		t.Fatalf("create test netns: %v", err)
	}
	defer func() { _ = nsObj.Close() }()

	err = nsObj.Do(func(_ ns.NetNS) error {
		dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: ifaceName}}
		if err := netlink.LinkAdd(dummy); err != nil {
			return fmt.Errorf("add dummy link: %w", err)
		}
		if err := netlink.LinkSetUp(dummy); err != nil {
			return fmt.Errorf("set link up: %w", err)
		}

		link, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return fmt.Errorf("find link: %w", err)
		}

		// A default IPv6 route in a non-main table -- no actual VRF device
		// needs to bind to nonMainTable for RTM_GETROUTE's dump to report
		// it; auto-detection only needs to observe that the route exists.
		_, zeroNet, _ := net.ParseCIDR("::/0")
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       zeroNet,
			Table:     nonMainTable,
		}
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("add default route in table %d: %w", nonMainTable, err)
		}

		got, err := autoDetectInterfaces()
		if err != nil {
			return fmt.Errorf("autoDetectInterfaces: %w", err)
		}
		if !equalStringSlices(got, []string{ifaceName}) {
			return fmt.Errorf("autoDetectInterfaces() = %v, want [%s] (default route in table %d must still be found)",
				got, ifaceName, nonMainTable)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
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
