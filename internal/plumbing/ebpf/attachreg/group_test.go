// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachreg

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/srv6"
)

// testShardSID is a static shard list of one entry.
const testShardSID = "2001:db8:ff01:9:e001::"

// fakeGroups is a shardGroupReader over fixed group statuses. openCalls lists
// what successive AnyOpen calls answer; the last answer repeats.
type fakeGroups struct {
	groups    map[uint32]egressroutemap.GroupStatus
	openCalls []bool
	calls     int
}

func (f *fakeGroups) AnyOpen() (bool, error) {
	if len(f.openCalls) == 0 {
		for _, s := range f.groups {
			if s.Open() {
				return true, nil
			}
		}
		return false, nil
	}
	i := min(f.calls, len(f.openCalls)-1)
	f.calls++
	return f.openCalls[i], nil
}

func (f *fakeGroups) FindClass(
	class egressroutemap.TranslationClass,
) (uint32, egressroutemap.GroupStatus, bool, error) {
	for id, s := range f.groups {
		if s.Class == class {
			return id, s, true, nil
		}
	}
	return 0, egressroutemap.GroupStatus{}, false, nil
}

func openStatus(class egressroutemap.TranslationClass, candidates, active int) egressroutemap.GroupStatus {
	return egressroutemap.GroupStatus{
		Present: true, Enabled: true, Class: class, Candidates: candidates, Active: active,
	}
}

var testNAT64Class = egressroutemap.NAT64Class(netip.MustParsePrefix(testNAT64Prefix))

// groupCall is one egressGroupRouteAddFn invocation.
type groupCall struct {
	group    uint32
	argument uint16
}

// recordGroupAdds replaces egressGroupRouteAddFn with a recorder, keyed by
// prefix.
func recordGroupAdds(t *testing.T) *map[string]groupCall {
	t.Helper()
	original := egressGroupRouteAddFn
	t.Cleanup(func() { egressGroupRouteAddFn = original })
	calls := map[string]groupCall{}
	egressGroupRouteAddFn = func(
		_ *egressroutemap.EgressRouteTable, _ uint32, prefix *net.IPNet, group uint32, argument uint16,
	) error {
		calls[prefix.String()] = groupCall{group, argument}
		return nil
	}
	return &calls
}

func refuseOrderedRoutes(t *testing.T) {
	t.Helper()
	original := egressPrefixRouteAddFn
	t.Cleanup(func() { egressPrefixRouteAddFn = original })
	egressPrefixRouteAddFn = func(*egressroutemap.EgressRouteTable, uint32, *net.IPNet, []net.IP) error {
		t.Error("ordered shard route written in hashed mode")
		return nil
	}
}

// TestInstallVRFEgress_EachRouteGoesToItsClassGroup checks that ::/0 names the
// NAT66 group and the NAT64 prefix names its own group, each carrying the
// attachment's Argument, and that the static list is not read.
func TestInstallVRFEgress_EachRouteGoesToItsClassGroup(t *testing.T) {
	calls := recordGroupAdds(t)
	refuseOrderedRoutes(t)
	groups := &fakeGroups{groups: map[uint32]egressroutemap.GroupStatus{
		0: openStatus(egressroutemap.NAT66Class, 2, 2),
		1: openStatus(testNAT64Class, 1, 1),
	}}
	n, err := installVRFEgress(groups, nil, 7, 0x21,
		EgressConfig{ShardSIDs: testShardSID, NAT64Prefix: testNAT64Prefix}, nil)
	if err != nil || n != 2 {
		t.Fatalf("installVRFEgress = %d, %v, want 2 routes", n, err)
	}
	if c := (*calls)[defaultPrefix]; c != (groupCall{0, 0x21}) {
		t.Errorf("::/0 -> %+v, want group 0 argument 0x21", c)
	}
	if c := (*calls)[testNAT64Prefix]; c != (groupCall{1, 0x21}) {
		t.Errorf("%s -> %+v, want group 1 argument 0x21", testNAT64Prefix, c)
	}
}

// TestInstallVRFEgress_SingleFamilyDeployments checks a cluster whose shards
// serve one family only, and one whose shards translate a different NAT64
// prefix: a route goes only to a group that can translate it, and a route no
// group can serve is not installed rather than pointed at shards that would
// drop it.
func TestInstallVRFEgress_SingleFamilyDeployments(t *testing.T) {
	cfg := EgressConfig{NAT64Prefix: testNAT64Prefix}
	tests := []struct {
		name   string
		groups map[uint32]egressroutemap.GroupStatus
		want   []string
		absent []string
	}{
		{
			name: "NAT66Only",
			groups: map[uint32]egressroutemap.GroupStatus{
				0: openStatus(egressroutemap.NAT66Class, 2, 2),
				1: openStatus(testNAT64Class, 0, 0), // every shard ineligible
			},
			want: []string{defaultPrefix}, absent: []string{testNAT64Prefix},
		},
		{
			name: "NAT64Only",
			groups: map[uint32]egressroutemap.GroupStatus{
				0: openStatus(egressroutemap.NAT66Class, 0, 0),
				1: openStatus(testNAT64Class, 2, 2),
			},
			want: []string{testNAT64Prefix}, absent: []string{defaultPrefix},
		},
		{
			name: "DualCapable",
			groups: map[uint32]egressroutemap.GroupStatus{
				0: openStatus(egressroutemap.NAT66Class, 2, 2),
				1: openStatus(testNAT64Class, 2, 2),
			},
			want: []string{defaultPrefix, testNAT64Prefix},
		},
		{
			name: "MismatchedPrefix",
			groups: map[uint32]egressroutemap.GroupStatus{
				0: openStatus(egressroutemap.NAT66Class, 1, 1),
				1: openStatus(egressroutemap.NAT64Class(netip.MustParsePrefix("2001:db8:65::/96")), 1, 1),
			},
			want: []string{defaultPrefix}, absent: []string{testNAT64Prefix},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := recordGroupAdds(t)
			if _, err := installVRFEgress(&fakeGroups{groups: tt.groups}, nil, 7, 0x21, cfg, nil); err != nil {
				t.Fatal(err)
			}
			for _, p := range tt.want {
				if _, ok := (*calls)[p]; !ok {
					t.Errorf("no route installed for %s", p)
				}
			}
			for _, p := range tt.absent {
				if c, ok := (*calls)[p]; ok {
					t.Errorf("route for %s installed toward group %d, which cannot translate it", p, c.group)
				}
			}
		})
	}
}

// TestInstallVRFEgress_UnreachableClassFails checks a class with candidates but
// none reachable fails the ADD, as an ordered list with no resolvable shard
// does.
func TestInstallVRFEgress_UnreachableClassFails(t *testing.T) {
	recordGroupAdds(t)
	groups := &fakeGroups{groups: map[uint32]egressroutemap.GroupStatus{
		0: openStatus(egressroutemap.NAT66Class, 3, 0),
	}}
	_, err := installVRFEgress(groups, nil, 7, 0x21, EgressConfig{}, nil)
	if !errors.Is(err, srv6.ErrNoShardResolvable) {
		t.Errorf("installVRFEgress = %v, want ErrNoShardResolvable", err)
	}
}

// TestInstallVRFEgress_ClosedGroupsUseTheStaticList checks that closing groups
// send ADD down the ordered path.
func TestInstallVRFEgress_ClosedGroupsUseTheStaticList(t *testing.T) {
	ordered := recordRouteAdds(t, nil)
	group := recordGroupAdds(t)
	closing := openStatus(egressroutemap.NAT66Class, 1, 1)
	closing.Closing = true
	groups := &fakeGroups{groups: map[uint32]egressroutemap.GroupStatus{0: closing}}
	if _, err := installVRFEgress(groups, nil, 7, 0x21, EgressConfig{ShardSIDs: testShardSID}, nil); err != nil {
		t.Fatal(err)
	}
	if len(*ordered) != 1 || len(*group) != 0 {
		t.Errorf("ordered routes %d, group routes %d, want 1 and 0", len(*ordered), len(*group))
	}
}

// TestInstallVRFEgress_GroupsCloseDuringInstall covers the F01 race from the
// ADD side: an ADD that saw the groups open, but finds them closed once its
// routes are written, rewrites them in ordered mode, so no route naming a
// group outlives galactic-cni's last scan.
func TestInstallVRFEgress_GroupsCloseDuringInstall(t *testing.T) {
	ordered := recordRouteAdds(t, nil)
	recordGroupAdds(t)
	groups := &fakeGroups{
		groups:    map[uint32]egressroutemap.GroupStatus{0: openStatus(egressroutemap.NAT66Class, 1, 1)},
		openCalls: []bool{true, false},
	}
	if _, err := installVRFEgress(groups, nil, 7, 0x21, EgressConfig{ShardSIDs: testShardSID}, nil); err != nil {
		t.Fatal(err)
	}
	if len(*ordered) != 1 || (*ordered)[0].prefix != defaultPrefix {
		t.Errorf("ordered rewrite = %+v, want ::/0 rewritten toward the static shard", *ordered)
	}
}

// TestInstallVRFEgress_GroupsCloseAndOrderedFails checks the ADD reports a
// failed ordered rewrite instead of succeeding with a route on a closing group.
func TestInstallVRFEgress_GroupsCloseAndOrderedFails(t *testing.T) {
	recordRouteAdds(t, srv6.ErrNoShardResolvable)
	recordGroupAdds(t)
	groups := &fakeGroups{
		groups:    map[uint32]egressroutemap.GroupStatus{0: openStatus(egressroutemap.NAT66Class, 1, 1)},
		openCalls: []bool{true, false},
	}
	_, err := installVRFEgress(groups, nil, 7, 0x21, EgressConfig{ShardSIDs: testShardSID}, nil)
	if !errors.Is(err, srv6.ErrNoShardResolvable) {
		t.Errorf("installVRFEgress = %v, want the ordered failure reported", err)
	}
}

// valueStore is a GroupStore over fixed snapshots.
type valueStore map[uint32]prog.UsidEgressShardGroupValue

func (s valueStore) Load(id uint32) (prog.UsidEgressShardGroupValue, bool, error) {
	v, ok := s[id]
	return v, ok, nil
}

func (s valueStore) Publish(id uint32, v prog.UsidEgressShardGroupValue) error {
	s[id] = v
	return nil
}

// TestFillVRF_HashedModeUsesTheGroups checks the datapath repair path goes
// through the same installer, against a real ShardGroupTable.
func TestFillVRF_HashedModeUsesTheGroups(t *testing.T) {
	calls := recordGroupAdds(t)
	refuseOrderedRoutes(t)
	nat64 := prog.UsidEgressShardGroupValue{Flags: 1, Candidates: 1, Active: 1, ClassKind: 2,
		ClassPrefix: netip.MustParsePrefix(testNAT64Prefix).Addr().As16()}
	m := newMemMaps(true)
	m.ShardGroups = egressroutemap.NewShardGroupTable(valueStore{
		0: {Flags: 1, Candidates: 1, Active: 1, ClassKind: 1},
		1: nat64,
	})
	written, err := m.FillVRF(testAttachment(), EgressConfig{NAT64Prefix: testNAT64Prefix})
	if err != nil || written.ShardEgressRoutes != 2 || len(*calls) != 2 {
		t.Errorf("FillVRF = %+v, %v with %d group routes, want 2", written.Counts, err, len(*calls))
	}
}

// TestFillVRF_DisabledGroupUsesTheStaticList checks ordered mode is unchanged
// when the group map exists but no group is open.
func TestFillVRF_DisabledGroupUsesTheStaticList(t *testing.T) {
	calls := recordRouteAdds(t, nil)
	group := recordGroupAdds(t)
	m := newMemMaps(true)
	m.ShardGroups = egressroutemap.NewShardGroupTable(valueStore{0: {ClassKind: 1}})
	if _, err := m.FillVRF(testAttachment(), EgressConfig{ShardSIDs: testShardSID}); err != nil {
		t.Fatalf("FillVRF: %v", err)
	}
	if len(*calls) != 1 || len(*group) != 0 {
		t.Errorf("ordered routes %d, group routes %d, want 1 and 0", len(*calls), len(*group))
	}
}

// TestOpenShardGroups_MissingPinIsOrderedMode checks that a datapath without
// the shard group map reads as no groups.
func TestOpenShardGroups_MissingPinIsOrderedMode(t *testing.T) {
	groups, closer, err := openShardGroupsFn(t.TempDir())
	if err != nil || groups != nil {
		t.Errorf("openShardGroupsFn = %v, %v, want no groups and no error", groups, err)
	}
	if err := closer.Close(); err != nil {
		t.Error(err)
	}
}
