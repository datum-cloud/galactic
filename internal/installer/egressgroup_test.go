// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

var (
	testNSP     = netip.MustParsePrefix("2001:db8:64::/96")
	testNSPNet  = &net.IPNet{IP: net.IP(testNSP.Addr().AsSlice()), Mask: net.CIDRMask(96, 128)}
	nat64NSP    = egressroutemap.NAT64Class(testNSP)
	nat64WKP    = egressroutemap.NAT64Class(egressroutemap.WellKnownPrefix)
	testHashed  = config.EgressGroupConfig{Mode: config.EgressModeHashed, Hash: config.EgressHashSource}
	testOrdered = config.EgressGroupConfig{Mode: config.EgressModeOrdered, Hash: config.EgressHashSource}
)

// shardObject is an EgressShard whose status reports sid, the masquerade
// addresses v6 and v4 (either may be empty), a NAT64 prefix and the two
// conditions.
func shardObject(name, sid, v6, v4, nat64 string, programmed, ready bool) bgpv1alpha1.EgressShard {
	status := func(ok bool) metav1.ConditionStatus {
		if ok {
			return metav1.ConditionTrue
		}
		return metav1.ConditionFalse
	}
	return bgpv1alpha1.EgressShard{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "galactic-system"},
		Status: bgpv1alpha1.EgressShardStatus{
			ShardSID: sid, ShardAddressIPv6: v6, ShardAddressIPv4: v4, NAT64Prefix: nat64,
			Conditions: []metav1.Condition{
				{Type: bgpv1alpha1.ConditionTypeProgrammed, Status: status(programmed)},
				{Type: bgpv1alpha1.ConditionTypeReady, Status: status(ready)},
			},
		},
	}
}

func shardSIDFor(nodeID uint16) string {
	addr, _ := uformat.Encode(uformat.Fields{Block: 0x20010db8ff09, NodeID: nodeID, Function: uformat.FunctionEndDT46})
	return addr.String()
}

func dual(name string, nodeID uint16) bgpv1alpha1.EgressShard {
	return shardObject(name, shardSIDFor(nodeID), "2001:db8:9966::1", "192.0.2.1", testNSP.String(), true, true)
}

func candidateNames(t *testing.T, got []egressroutemap.ShardCandidate) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, c := range got {
		out[c.SID.String()] = c.Draining
	}
	return out
}

// TestEgressShardCandidates covers pool admission (F04): each class admits only
// shards that can translate it, readiness and SID are required, drain is
// reported, and a shard being deleted is no candidate at all (F03).
func TestEgressShardCandidates(t *testing.T) {
	nat66Only := shardObject("nat66-only", shardSIDFor(0x11), "2001:db8:9966::2", "", "", true, true)
	nat64Only := shardObject("nat64-only", shardSIDFor(0x12), "", "192.0.2.3", testNSP.String(), true, true)
	otherPrefix := shardObject("other-prefix", shardSIDFor(0x13), "2001:db8:9966::4", "192.0.2.4",
		"2001:db8:65::/96", true, true)
	wkp := shardObject("wkp", shardSIDFor(0x14), "", "192.0.2.5", testNSP.String(), true, true)
	wkp.Status.TranslatesWellKnownPrefix = true
	draining := dual("draining", 0x15)
	draining.Spec.Drain = true
	deleting := dual("deleting", 0x16)
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	shards := []bgpv1alpha1.EgressShard{
		dual("dual", 0x10), nat66Only, nat64Only, otherPrefix, wkp, draining, deleting,
		shardObject("not-programmed", shardSIDFor(0x20), "2001:db8:9966::9", "", "", false, true),
		shardObject("not-ready", shardSIDFor(0x21), "2001:db8:9966::9", "", "", true, false),
		shardObject("no-sid", "", "2001:db8:9966::9", "", "", true, true),
		shardObject("bad-sid", "not-an-address", "2001:db8:9966::9", "", "", true, true),
	}

	tests := []struct {
		class      egressroutemap.TranslationClass
		eligible   map[string]bool
		ineligible []string
	}{
		{
			class: egressroutemap.NAT66Class,
			eligible: map[string]bool{
				shardSIDFor(0x10): false, shardSIDFor(0x11): false, shardSIDFor(0x13): false, shardSIDFor(0x15): true,
			},
			ineligible: []string{"nat64-only", "wkp"},
		},
		{
			class: nat64NSP,
			eligible: map[string]bool{
				shardSIDFor(0x10): false, shardSIDFor(0x12): false, shardSIDFor(0x14): false, shardSIDFor(0x15): true,
			},
			ineligible: []string{"nat66-only", "other-prefix"},
		},
		{
			class:      nat64WKP,
			eligible:   map[string]bool{shardSIDFor(0x14): false},
			ineligible: []string{"dual", "nat66-only", "nat64-only", "other-prefix", "draining"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.class.String(), func(t *testing.T) {
			eligible, ineligible := egressShardCandidates(shards, tt.class)
			if got := candidateNames(t, eligible); !reflect.DeepEqual(got, tt.eligible) {
				t.Errorf("eligible = %v, want %v", got, tt.eligible)
			}
			if !reflect.DeepEqual(ineligible, tt.ineligible) {
				t.Errorf("ineligible = %v, want %v", ineligible, tt.ineligible)
			}
		})
	}
}

func TestCheckEgressClasses(t *testing.T) {
	four := []netip.Prefix{testNSP, egressroutemap.WellKnownPrefix,
		netip.MustParsePrefix("2001:db8:65::/96"), netip.MustParsePrefix("2001:db8:66::/96")}
	if err := checkEgressClasses(testHashed, four[:3]); err != nil {
		t.Errorf("three NAT64 prefixes in hashed mode: %v, want accepted", err)
	}
	if err := checkEgressClasses(testHashed, four); err == nil {
		t.Error("four NAT64 prefixes in hashed mode accepted, want an error")
	}
	if err := checkEgressClasses(testOrdered, four); err != nil {
		t.Errorf("four NAT64 prefixes in ordered mode: %v, want accepted", err)
	}
}

func TestRouteAffectsShards(t *testing.T) {
	g := newEgressGroup(config.EgressGroupConfig{}, nil, nil, "")
	locators := []netip.Prefix{netip.MustParsePrefix("2001:db8:ff09:10::/64")}
	g.locators.Store(&locators)

	cidr := func(s string) *net.IPNet {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	tests := []struct {
		dst  *net.IPNet
		want bool
	}{
		{nil, true},
		{cidr("::/0"), true},
		{cidr("2001:db8:ff09:10::/64"), true},
		{cidr("2001:db8:ff09::/48"), true},
		{cidr("2001:db8:ff09:10:e000::/128"), true},
		{cidr("2001:db8:ff09:11::/64"), false},
		{cidr("10.0.0.0/8"), false},
	}
	for _, tt := range tests {
		if got := g.routeAffectsShards(tt.dst); got != tt.want {
			t.Errorf("routeAffectsShards(%v) = %v, want %v", tt.dst, got, tt.want)
		}
	}
}

func TestEgressGroupKickCoalesces(t *testing.T) {
	g := newEgressGroup(config.EgressGroupConfig{}, nil, nil, "")
	for range 5 {
		g.kick()
	}
	if len(g.trigger) != 1 {
		t.Errorf("queued kicks = %d, want 1", len(g.trigger))
	}
}

// --- Sweep sequencing, against in-memory maps with injected faults ---------

// memStore is an in-memory GroupStore.
type memStore map[uint32]prog.UsidEgressShardGroupValue

func (s memStore) Load(id uint32) (prog.UsidEgressShardGroupValue, bool, error) {
	v, ok := s[id]
	return v, ok, nil
}

func (s memStore) Publish(id uint32, v prog.UsidEgressShardGroupValue) error {
	s[id] = v
	return nil
}

// routeTable is an in-memory egress_route_table with injected faults.
// iterErr fails the next iteration; putFailures fails that many Puts;
// afterScan runs once an iteration has read every entry, standing in for a
// concurrent writer.
type routeTable struct {
	keys        []prog.UsidEgressRouteKey
	values      map[prog.UsidEgressRouteKey]prog.UsidEgressRouteValue
	iterErr     error
	putFailures int
	afterScan   func()
}

func newRouteTable() *routeTable {
	return &routeTable{values: map[prog.UsidEgressRouteKey]prog.UsidEgressRouteValue{}}
}

var errInjected = errors.New("injected map failure")

func (r *routeTable) Put(key, value any) error {
	if r.putFailures > 0 {
		r.putFailures--
		return errInjected
	}
	k := key.(prog.UsidEgressRouteKey)
	if _, ok := r.values[k]; !ok {
		r.keys = append(r.keys, k)
	}
	r.values[k] = value.(prog.UsidEgressRouteValue)
	return nil
}

func (r *routeTable) Lookup(key, out any) error {
	v, ok := r.values[key.(prog.UsidEgressRouteKey)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	reflect.ValueOf(out).Elem().Set(reflect.ValueOf(v))
	return nil
}

func (r *routeTable) Delete(key any) error {
	delete(r.values, key.(prog.UsidEgressRouteKey))
	return nil
}

func (r *routeTable) Iterate() usidmap.Iterator {
	keys := append([]prog.UsidEgressRouteKey(nil), r.keys...)
	err := r.iterErr
	r.iterErr = nil
	return &routeIter{table: r, keys: keys, err: err}
}

type routeIter struct {
	table *routeTable
	keys  []prog.UsidEgressRouteKey
	i     int
	err   error
	done  bool
}

func (it *routeIter) Next(keyOut, valueOut any) bool {
	if it.i >= len(it.keys) {
		if !it.done && it.table.afterScan != nil {
			it.done = true
			hook := it.table.afterScan
			it.table.afterScan = nil
			hook()
		}
		return false
	}
	k := it.keys[it.i]
	it.i++
	reflect.ValueOf(keyOut).Elem().Set(reflect.ValueOf(k))
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(it.table.values[k]))
	return true
}

func (it *routeIter) Err() error { return it.err }

// fixture is one node: its egress_route_table, its shard groups and an
// egressGroup sweeping them.
type fixture struct {
	raw    *routeTable
	routes *egressroutemap.EgressRouteTable
	groups *egressroutemap.ShardGroupTable
	g      *egressGroup
}

func newFixture(t *testing.T, cfg config.EgressGroupConfig, static []string, nat64 []netip.Prefix) *fixture {
	t.Helper()
	restore := egressroutemap.OverrideResolverForTest(func(net.IP) (int, net.HardwareAddr, net.HardwareAddr, error) {
		return 7, net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.HardwareAddr{2, 0, 0, 0, 0, 2}, nil
	})
	t.Cleanup(restore)
	sids := make([]net.IP, 0, len(static))
	for _, s := range static {
		sids = append(sids, net.ParseIP(s))
	}
	raw := newRouteTable()
	return &fixture{
		raw:    raw,
		routes: egressroutemap.NewEgressRouteTable(raw),
		groups: egressroutemap.NewShardGroupTable(memStore{}),
		g:      newEgressGroup(cfg, sids, nat64, ""),
	}
}

func (f *fixture) sweep(t *testing.T) error {
	t.Helper()
	return f.g.sweepWith(context.Background(), f.routes, f.groups, nil)
}

// sentinels counts the routes naming any group.
func (f *fixture) sentinels() int {
	n := 0
	for _, v := range f.raw.values {
		if v.LinkIfindex == 0xFFFFFFFF {
			n++
		}
	}
	return n
}

// hashedNode leaves the fixture as hashed mode would: a NAT66 group with one
// shard, and VRFs 1-3 routed to it.
func (f *fixture) hashedNode(t *testing.T) {
	t.Helper()
	shard := net.ParseIP(shardSIDFor(0x10))
	candidates := []egressroutemap.ShardCandidate{{SID: shard}}
	if _, err := f.groups.Apply(0, egressroutemap.GroupPolicy{}, candidates); err != nil {
		t.Fatal(err)
	}
	for vrf := uint32(1); vrf <= 3; vrf++ {
		argument := uint16(0x10 + vrf) //nolint:gosec // test
		if err := f.routes.RegisterGroup(vrf, egressroutemap.DefaultPrefix, 0, argument); err != nil {
			t.Fatal(err)
		}
	}
}

func status(t *testing.T, groups *egressroutemap.ShardGroupTable, id uint32) egressroutemap.GroupStatus {
	t.Helper()
	s, err := groups.Status(id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSweepOrdered_RetiresGroupsOnlyAfterACompleteConversion covers F01: a
// switch to ordered mode marks the groups closing, and disables them only
// after a sweep that read every route and wrote every move. An iteration
// failure or a failed write leaves the groups forwarding; the next sweep
// finishes the job.
func TestSweepOrdered_RetiresGroupsOnlyAfterACompleteConversion(t *testing.T) {
	static := []string{shardSIDFor(0x10)}
	t.Run("IterationFailure", func(t *testing.T) {
		f := newFixture(t, testOrdered, static, nil)
		f.hashedNode(t)
		f.raw.iterErr = errInjected
		if err := f.sweep(t); !errors.Is(err, errInjected) {
			t.Fatalf("sweep = %v, want the iteration failure", err)
		}
		if s := status(t, f.groups, 0); !s.Enabled || !s.Closing || f.sentinels() != 3 {
			t.Errorf("after a failed scan: status %+v with %d sentinels, want closing, enabled, 3 sentinels",
				s, f.sentinels())
		}
	})
	t.Run("PartialWriteThenRetry", func(t *testing.T) {
		f := newFixture(t, testOrdered, static, nil)
		f.hashedNode(t)
		f.raw.putFailures = 1
		if err := f.sweep(t); !errors.Is(err, errInjected) {
			t.Fatalf("sweep = %v, want the write failure", err)
		}
		if s := status(t, f.groups, 0); !s.Enabled || f.sentinels() == 0 {
			t.Fatalf("after a failed write: status %+v with %d sentinels, want the group still enabled", s,
				f.sentinels())
		}
		if err := f.sweep(t); err != nil {
			t.Fatalf("retry = %v", err)
		}
		if s := status(t, f.groups, 0); s.Enabled || f.sentinels() != 0 {
			t.Errorf("after the retry: status %+v with %d sentinels, want disabled and none left", s, f.sentinels())
		}
	})
	t.Run("NoStaticShardKeepsTheGroup", func(t *testing.T) {
		f := newFixture(t, testOrdered, nil, nil)
		f.hashedNode(t)
		if err := f.sweep(t); err != nil {
			t.Fatal(err)
		}
		if s := status(t, f.groups, 0); !s.Enabled || f.sentinels() != 3 {
			t.Errorf("with nothing to move routes to: status %+v with %d sentinels, want the group kept", s,
				f.sentinels())
		}
	})
	t.Run("ConcurrentADDAfterTheScan", func(t *testing.T) {
		// An ADD that read the groups open, and writes its sentinel after the
		// sweep's iterator has passed. It must find the groups already
		// closing when it checks again, and so rewrite its route itself.
		f := newFixture(t, testOrdered, static, nil)
		f.hashedNode(t)
		f.raw.afterScan = func() {
			if err := f.routes.RegisterGroup(9, egressroutemap.DefaultPrefix, 0, 0x99); err != nil {
				t.Error(err)
			}
			if open, _ := f.groups.AnyOpen(); open {
				t.Error("the groups were still open when the sweep's scan finished; a late ADD would not rewrite")
				return
			}
			sid, _ := egressroutemap.BaseShardSID(net.ParseIP(static[0]))
			b := sid.As16()
			b[9] = 0x99
			if err := f.routes.Register(9, egressroutemap.DefaultPrefix, net.IP(b[:])); err != nil {
				t.Error(err)
			}
		}
		if err := f.sweep(t); err != nil {
			t.Fatal(err)
		}
		if f.sentinels() != 0 {
			t.Errorf("%d sentinels survive the sweep that disabled their group", f.sentinels())
		}
	})
	t.Run("Success", func(t *testing.T) {
		f := newFixture(t, testOrdered, static, nil)
		f.hashedNode(t)
		if err := f.sweep(t); err != nil {
			t.Fatal(err)
		}
		if s := status(t, f.groups, 0); s.Enabled || f.sentinels() != 0 {
			t.Errorf("status %+v with %d sentinels, want disabled and none left", s, f.sentinels())
		}
	})
}

// fakeLister is an egressShardLister over a fixed answer.
type fakeLister struct {
	shards []bgpv1alpha1.EgressShard
	synced bool
	err    error
}

func (l *fakeLister) ListEgressShards(context.Context) ([]bgpv1alpha1.EgressShard, bool, error) {
	return l.shards, l.synced, l.err
}

// TestSweepHashed_ClassGroups checks hashed mode end to end on the control
// side: each class's group holds only the shards that translate it, routes
// move onto their class's group, and a membership change removes a shard
// that is no longer eligible.
func TestSweepHashed_ClassGroups(t *testing.T) {
	f := newFixture(t, testHashed, nil, []netip.Prefix{testNSP})
	nat66Only := shardObject("nat66-only", shardSIDFor(0x11), "2001:db8:9966::2", "", "", true, true)
	lister := &fakeLister{shards: []bgpv1alpha1.EgressShard{dual("dual", 0x10), nat66Only}, synced: true}
	f.g.shards = lister

	staticSID, _ := egressroutemap.BaseShardSID(net.ParseIP(shardSIDFor(0x10)))
	withArg := staticSID.As16()
	withArg[9] = 0x21
	if err := f.routes.Register(1, egressroutemap.DefaultPrefix, net.IP(withArg[:])); err != nil {
		t.Fatal(err)
	}
	if err := f.routes.Register(1, testNSPNet, net.IP(withArg[:])); err != nil {
		t.Fatal(err)
	}

	if err := f.sweep(t); err != nil {
		t.Fatal(err)
	}
	nat66, nat64 := status(t, f.groups, 0), status(t, f.groups, 1)
	if nat66.Class != egressroutemap.NAT66Class || nat66.Candidates != 2 || nat66.Ineligible != 0 {
		t.Errorf("NAT66 group = %+v, want both shards", nat66)
	}
	if nat64.Class != nat64NSP || nat64.Candidates != 1 || nat64.Ineligible != 1 {
		t.Errorf("NAT64 group = %+v, want only the dual shard, one ineligible", nat64)
	}
	if f.sentinels() != 2 {
		t.Errorf("%d routes on groups, want both", f.sentinels())
	}

	// The dual shard stops being Programmed: it leaves both groups.
	lister.shards[0].Status.Conditions[0].Status = metav1.ConditionFalse
	if err := f.sweep(t); err != nil {
		t.Fatal(err)
	}
	if s := status(t, f.groups, 1); s.Candidates != 0 {
		t.Errorf("NAT64 group after its only shard left = %+v, want no candidate", s)
	}
	members, _ := f.groups.Members(0)
	if len(members) != 1 || members[0].SID.String() != staticSIDFor(0x11) {
		t.Errorf("NAT66 members = %+v, want only the NAT66-only shard", members)
	}
}

func staticSIDFor(nodeID uint16) string {
	sid, _ := egressroutemap.BaseShardSID(net.ParseIP(shardSIDFor(nodeID)))
	return sid.String()
}

// TestSweepHashed_UnsyncedOrFailingWatch checks that until the watch has listed
// the cluster, and while listing fails, no group is published or changed and
// no route moves: an unknown membership is not an empty one.
func TestSweepHashed_UnsyncedOrFailingWatch(t *testing.T) {
	f := newFixture(t, testHashed, []string{shardSIDFor(0x10)}, nil)
	f.g.shards = &fakeLister{synced: false}
	if err := f.routes.Register(1, egressroutemap.DefaultPrefix, net.ParseIP(shardSIDFor(0x10))); err != nil {
		t.Fatal(err)
	}
	if err := f.sweep(t); err != nil {
		t.Fatal(err)
	}
	if s := status(t, f.groups, 0); s.Present || f.sentinels() != 0 {
		t.Errorf("unsynced watch published %+v and moved %d routes, want nothing", s, f.sentinels())
	}

	f.g.shards = &fakeLister{shards: []bgpv1alpha1.EgressShard{dual("dual", 0x10)}, synced: true}
	if err := f.sweep(t); err != nil {
		t.Fatal(err)
	}
	before := status(t, f.groups, 0)
	f.g.shards = &fakeLister{synced: true, err: errInjected}
	if err := f.sweep(t); !errors.Is(err, errInjected) {
		t.Fatalf("sweep with a failing watch = %v, want the error", err)
	}
	if after := status(t, f.groups, 0); after != before {
		t.Errorf("a failing watch changed the group: %+v -> %+v", before, after)
	}
}
