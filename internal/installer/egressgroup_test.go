// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"encoding/binary"
	"errors"
	"maps"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/metrics"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
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
			eligible, ineligible := egressShardCandidates(shards, tt.class, "")
			if got := candidateNames(t, eligible); !reflect.DeepEqual(got, tt.eligible) {
				t.Errorf("eligible = %v, want %v", got, tt.eligible)
			}
			if !reflect.DeepEqual(ineligible, tt.ineligible) {
				t.Errorf("ineligible = %v, want %v", ineligible, tt.ineligible)
			}
		})
	}
}

const (
	// nodeKind is the TargetRef kind an EgressShard targets.
	nodeKind = "Node"
	// shardNode is the node the tests' own shard runs on.
	shardNode = "edge-a"
)

// TestEgressShardCandidates_Local checks that only the shard targeting this
// node is local, and that no node name marks none.
func TestEgressShardCandidates_Local(t *testing.T) {
	here, there := dual("here", 0x10), dual("there", 0x11)
	here.Spec.TargetRef = bgpv1alpha1.TargetRef{Kind: nodeKind, Name: shardNode}
	there.Spec.TargetRef = bgpv1alpha1.TargetRef{Kind: nodeKind, Name: "edge-b"}
	shards := []bgpv1alpha1.EgressShard{here, there}

	local := func(nodeName string) map[string]bool {
		eligible, _ := egressShardCandidates(shards, egressroutemap.NAT66Class, nodeName)
		out := map[string]bool{}
		for _, c := range eligible {
			out[c.SID.String()] = c.Local
		}
		return out
	}
	want := map[string]bool{shardSIDFor(0x10): true, shardSIDFor(0x11): false}
	if got := local(shardNode); !reflect.DeepEqual(got, want) {
		t.Errorf("on edge-a: local = %v, want %v", got, want)
	}
	none := map[string]bool{shardSIDFor(0x10): false, shardSIDFor(0x11): false}
	if got := local("compute-a"); !reflect.DeepEqual(got, none) {
		t.Errorf("on a node with no shard: local = %v, want %v", got, none)
	}
	if got := local(""); !reflect.DeepEqual(got, none) {
		t.Errorf("with no node name: local = %v, want %v", got, none)
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

// natLocatorSink records the shard SIDs each sweep hands traffic policy.
type natLocatorSink struct {
	calls int
	sids  map[string]bool
}

func (s *natLocatorSink) set(sids []net.IP) {
	s.calls++
	s.sids = map[string]bool{}
	for _, sid := range sids {
		s.sids[sid.String()] = true
	}
}

// TestSweepHashed_NATLocatorsWithoutWatch checks that traffic policy gets the
// shard SIDs this node can egress through on every sweep, whether or not the
// EgressShard watch has started or synced (#1084): the configured shards and
// every member of a published group, plus the watch's shards once synced.
// Without them every tenant packet on a path rule fails classification.
func TestSweepHashed_NATLocatorsWithoutWatch(t *testing.T) {
	configured := shardSIDFor(0x10)
	published := []string{staticSIDFor(0x20), staticSIDFor(0x21)}
	watched := shardSIDFor(0x30)
	cases := map[string]struct {
		lister egressShardLister
		want   []string
	}{
		"WatchNotStarted": {nil, append([]string{configured}, published...)},
		"WatchUnsynced":   {&fakeLister{synced: false}, append([]string{configured}, published...)},
		"WatchFailing": {
			&fakeLister{shards: []bgpv1alpha1.EgressShard{dual("watched", 0x30)}, synced: true, err: errInjected},
			append([]string{configured}, published...),
		},
		"WatchSynced": {
			&fakeLister{shards: []bgpv1alpha1.EgressShard{dual("watched", 0x30)}, synced: true},
			append([]string{configured, watched}, published...),
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, testHashed, []string{configured}, nil)
			candidates := []egressroutemap.ShardCandidate{
				{SID: net.ParseIP(shardSIDFor(0x20))}, {SID: net.ParseIP(shardSIDFor(0x21))},
			}
			if _, err := f.groups.Apply(0, egressroutemap.GroupPolicy{}, candidates); err != nil {
				t.Fatal(err)
			}
			if tc.lister != nil {
				f.g.shards = tc.lister
			}
			sink := &natLocatorSink{}
			f.g.natLocators = sink.set
			_ = f.sweep(t)
			if sink.calls != 1 {
				t.Fatalf("natLocators called %d times, want once", sink.calls)
			}
			for _, sid := range tc.want {
				if !sink.sids[sid] {
					t.Errorf("natLocators got %v, missing %s", sink.sids, sid)
				}
			}
			if len(sink.sids) != len(tc.want) {
				t.Errorf("natLocators got %d SIDs %v, want %v", len(sink.sids),
					sink.sids, tc.want)
			}
		})
	}
}

// TestSweep_NATLocatorsWithoutGroupMap checks that a datapath without the
// shard group map, which can only route to the configured shards, hands
// traffic policy those shards.
func TestSweep_NATLocatorsWithoutGroupMap(t *testing.T) {
	f := newFixture(t, testHashed, []string{shardSIDFor(0x10)}, nil)
	sink := &natLocatorSink{}
	f.g.natLocators = sink.set
	if err := f.g.sweepWith(context.Background(), f.routes, nil, nil); err != nil {
		t.Fatal(err)
	}
	if sink.calls != 1 || len(sink.sids) != 1 || !sink.sids[shardSIDFor(0x10)] {
		t.Errorf("natLocators got %d calls with %v, want the configured shard", sink.calls, sink.sids)
	}
}

// TestSweepHashed_ShardNode checks a node that runs an egress shard: its own
// shard is a local member, not an unreachable one, while a remote shard whose
// SID does not resolve is still unreachable. Neither is alive, so neither
// takes a tenant from this node.
func TestSweepHashed_ShardNode(t *testing.T) {
	f := newFixture(t, testHashed, nil, nil)
	f.g.nodeName = shardNode
	here, remote := dual("here", 0x10), dual("remote", 0x11)
	here.Spec.TargetRef = bgpv1alpha1.TargetRef{Kind: nodeKind, Name: shardNode}
	remote.Spec.TargetRef = bgpv1alpha1.TargetRef{Kind: nodeKind, Name: "edge-b"}
	f.g.shards = &fakeLister{shards: []bgpv1alpha1.EgressShard{here, remote}, synced: true}

	resolved := map[string]bool{}
	restore := egressroutemap.OverrideResolverForTest(func(sid net.IP) (int, net.HardwareAddr, net.HardwareAddr, error) {
		resolved[sid.String()] = true
		return 0, nil, nil, errInjected
	})
	t.Cleanup(restore)

	if err := f.sweep(t); err != nil {
		t.Fatal(err)
	}
	if resolved[staticSIDFor(0x10)] {
		t.Error("the local shard's SID was resolved; it has no route over an uplink to find")
	}
	members, err := f.groups.Members(0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]egressroutemap.ShardState{}
	for _, m := range members {
		got[m.SID.String()] = m
	}
	if m := got[staticSIDFor(0x10)]; !m.Local || m.Alive {
		t.Errorf("own shard = %+v, want local and not alive", m)
	}
	if m := got[staticSIDFor(0x11)]; m.Local || m.Alive {
		t.Errorf("unresolvable remote shard = %+v, want unreachable (neither local nor alive)", m)
	}
	if s := status(t, f.groups, 0); s.Candidates != 2 || s.Active != 0 {
		t.Errorf("group = %+v, want two candidates and none active", s)
	}
}

var (
	testP2 = netip.MustParsePrefix("2001:db8:65::/96")
	testP3 = netip.MustParsePrefix("2001:db8:66::/96")
	testP4 = netip.MustParsePrefix("2001:db8:67::/96")

	nat64P2 = egressroutemap.NAT64Class(testP2)
	nat64P3 = egressroutemap.NAT64Class(testP3)
	nat64P4 = egressroutemap.NAT64Class(testP4)
)

// classShards is one NAT66-only shard plus one NAT64-only shard per prefix in
// all, so every class has exactly its own member.
func classShards(all ...netip.Prefix) []bgpv1alpha1.EgressShard {
	shards := make([]bgpv1alpha1.EgressShard, 0, 1+len(all))
	shards = append(shards, shardObject("nat66", shardSIDFor(0x20), "2001:db8:9966::1", "", "", true, true))
	for i, p := range all {
		nodeID := uint16(0x30 + i) //nolint:gosec // test
		shards = append(shards, shardObject(p.String(), shardSIDFor(nodeID), "", "192.0.2.1", p.String(), true, true))
	}
	return shards
}

// restart replaces the fixture's sweep with a fresh process configured for
// nat64, over the same pinned maps.
func (f *fixture) restart(nat64 []netip.Prefix, shards []bgpv1alpha1.EgressShard) {
	f.g = newEgressGroup(testHashed, nil, nat64, "")
	f.g.shards = &fakeLister{shards: shards, synced: true}
}

// settle sweeps until a sweep queues no further one.
func (f *fixture) settle(t *testing.T) {
	t.Helper()
	for range 5 {
		if err := f.sweep(t); err != nil {
			t.Fatal(err)
		}
		if len(f.g.trigger) == 0 {
			return
		}
		<-f.g.trigger
	}
	t.Fatal("sweeps kept queueing more sweeps")
}

// attach writes vrf's routes as CNI ADD does: one sentinel per class, naming
// the group FindClass gives for it.
func (f *fixture) attach(t *testing.T, vrf uint32, nat64 []netip.Prefix) {
	t.Helper()
	prefixes := make([]*net.IPNet, 0, 1+len(nat64))
	prefixes = append(prefixes, egressroutemap.DefaultPrefix)
	for _, p := range nat64 {
		prefixes = append(prefixes, &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(96, 128)})
	}
	for _, prefix := range prefixes {
		class, _ := egressroutemap.ClassForRoute(prefix)
		id, s, found, err := f.groups.FindClass(class)
		if err != nil || !found || !s.Open() {
			t.Fatalf("FindClass(%s) = %d, %+v, %t, %v; want an open group", class, id, s, found, err)
		}
		if err := f.routes.RegisterGroup(vrf, prefix, id, uint16(0x100+vrf)); err != nil { //nolint:gosec // test
			t.Fatal(err)
		}
	}
}

// routeClasses maps every sentinel's own class to the class of the group it
// names, failing on any sentinel naming a group published for another class.
// The test prefixes differ in their address bits, so a key's address is
// enough to tell its class.
func (f *fixture) routeClasses(t *testing.T) map[egressroutemap.TranslationClass]int {
	t.Helper()
	got := map[egressroutemap.TranslationClass]int{}
	for key, value := range f.raw.values {
		if value.LinkIfindex != 0xFFFFFFFF {
			continue
		}
		class := egressroutemap.NAT66Class
		if key.Addr != [16]byte{} {
			class = egressroutemap.NAT64Class(netip.PrefixFrom(netip.AddrFrom16(key.Addr), 96))
		}
		id := binary.NativeEndian.Uint32(value.Sid[0:4])
		if s := status(t, f.groups, id); !s.Present || s.Class != class {
			t.Errorf("VRF %d's %s route names group %d, published for %s", key.TableId, class, id, s.Class)
		}
		got[class]++
	}
	return got
}

// enabledClasses maps each enabled group's class to its ID, failing on a class
// two enabled groups share.
func (f *fixture) enabledClasses(t *testing.T) map[egressroutemap.TranslationClass]uint32 {
	t.Helper()
	got := map[egressroutemap.TranslationClass]uint32{}
	for id := range uint32(egressroutemap.MaxShardGroups) {
		s := status(t, f.groups, id)
		if !s.Enabled {
			continue
		}
		if prev, dup := got[s.Class]; dup {
			t.Errorf("groups %d and %d both serve %s", prev, id, s.Class)
		}
		got[s.Class] = id
	}
	return got
}

// TestSweepHashed_ClassListChanges covers R05: editing the NAT64 prefix list
// never leaves a route on a group serving another class. A class keeps its
// group across removal, reorder and restart; a removed class's routes are
// deleted and its group retired; and a retired group's ID goes to a new class
// only once nothing names it.
func TestSweepHashed_ClassListChanges(t *testing.T) {
	all := classShards(testNSP, testP2, testP3, testP4)
	start := func(t *testing.T, nat64 []netip.Prefix) *fixture {
		t.Helper()
		f := newFixture(t, testHashed, nil, nat64)
		f.restart(nat64, all)
		f.settle(t)
		f.attach(t, 1, nat64)
		f.attach(t, 2, nat64)
		return f
	}

	t.Run("Removal", func(t *testing.T) {
		f := start(t, []netip.Prefix{testNSP, testP2})
		before := f.enabledClasses(t)
		f.restart([]netip.Prefix{testP2}, all)
		if err := f.sweep(t); err != nil {
			t.Fatal(err)
		}
		routes := f.routeClasses(t)
		if routes[nat64NSP] != 0 || routes[nat64P2] != 2 {
			t.Errorf("routes by class after removal = %v, want the NSP's gone and P2's kept", routes)
		}
		if s := status(t, f.groups, before[nat64NSP]); !s.Closing {
			t.Errorf("removed class's group = %+v, want it closing", s)
		}
		f.settle(t)
		after := f.enabledClasses(t)
		if _, ok := after[nat64NSP]; ok || after[nat64P2] != before[nat64P2] {
			t.Errorf("enabled groups = %v, want P2 on its old group %d and the NSP retired", after,
				before[nat64P2])
		}
	})

	t.Run("Reorder", func(t *testing.T) {
		f := start(t, []netip.Prefix{testNSP, testP2, testP3})
		before := f.enabledClasses(t)
		f.restart([]netip.Prefix{testP3, testNSP, testP2}, all)
		f.settle(t)
		if after := f.enabledClasses(t); !reflect.DeepEqual(after, before) {
			t.Errorf("groups after reorder = %v, want unchanged %v", after, before)
		}
		if routes := f.routeClasses(t); len(routes) != 4 {
			t.Errorf("routes by class = %v, want all four classes kept", routes)
		}
	})

	t.Run("ReplacementWithAFreeGroup", func(t *testing.T) {
		f := start(t, []netip.Prefix{testNSP, testP2})
		before := f.enabledClasses(t)
		f.restart([]netip.Prefix{testNSP, testP3}, all)
		f.settle(t)
		after := f.enabledClasses(t)
		p2, p3 := before[nat64P2], after[nat64P3]
		if p3 == p2 || after[nat64NSP] != before[nat64NSP] {
			t.Errorf("groups %v -> %v: P3 must not take P2's group while a free one exists", before, after)
		}
		if routes := f.routeClasses(t); routes[nat64P2] != 0 {
			t.Errorf("routes by class = %v, want P2's removed", routes)
		}
		f.attach(t, 3, []netip.Prefix{testNSP, testP3})
		f.routeClasses(t)
	})

	t.Run("ReplacementReusesARetiredGroup", func(t *testing.T) {
		full := []netip.Prefix{testNSP, testP2, testP3}
		f := start(t, full)
		before := f.enabledClasses(t)
		f.restart([]netip.Prefix{testNSP, testP2, testP4}, all)
		if err := f.sweep(t); err != nil {
			t.Fatal(err)
		}
		if s := status(t, f.groups, before[nat64P3]); s.Class != nat64P3 {
			t.Errorf("P3's group was handed on in the sweep that retired it: %+v", s)
		}
		f.routeClasses(t)
		f.settle(t)
		after := f.enabledClasses(t)
		if after[nat64P4] != before[nat64P3] {
			t.Errorf("groups %v -> %v: want P4 on P3's retired group once no route names it", before, after)
		}
		f.attach(t, 3, []netip.Prefix{testNSP, testP2, testP4})
		if routes := f.routeClasses(t); routes[nat64P3] != 0 ||
			routes[nat64P4] != 1 {
			t.Errorf("routes by class = %v, want no P3 route and VRF 3's P4 route", routes)
		}
	})

	t.Run("RetiredGroupHeldByAForeignRoute", func(t *testing.T) {
		f := start(t, []netip.Prefix{testNSP, testP2, testP3})
		before := f.enabledClasses(t)
		p3 := before[nat64P3]
		p3Net := &net.IPNet{IP: net.IP(testP3.Addr().AsSlice()), Mask: net.CIDRMask(96, 128)}
		if err := f.routes.RegisterGroup(9, p3Net, p3, 0x199); err != nil {
			t.Fatal(err)
		}
		f.restart([]netip.Prefix{testNSP, testP2, testP4}, all)
		for range 3 {
			if err := f.g.sweepWith(context.Background(), f.routes, f.groups, map[uint32]struct{}{9: {}}); err != nil {
				t.Fatal(err)
			}
		}
		if s := status(t, f.groups, p3); !s.Enabled || s.Class != nat64P3 {
			t.Errorf("P3's group = %+v, want it kept for P3 while a foreign route names it", s)
		}
		if _, ok := f.enabledClasses(t)[nat64P4]; ok {
			t.Error("P4 was given a group while every group is held")
		}
		f.routeClasses(t)
	})

	t.Run("UpgradeFromPositionalGroups", func(t *testing.T) {
		// What the positional layout left after the NSP was removed from
		// [NAT66, NSP, P2]: group 1 republished for P2 under the NSP's routes,
		// and group 2 a duplicate P2 group with P2's routes.
		f := start(t, []netip.Prefix{testNSP, testP2})
		eligible, _ := egressShardCandidates(all, nat64P2, "")
		if _, err := f.groups.Apply(1, f.g.policy(nat64P2, 0), eligible); err != nil {
			t.Fatal(err)
		}
		f.restart([]netip.Prefix{testP2}, all)
		f.settle(t)
		if routes := f.routeClasses(t); routes[nat64NSP] != 0 || routes[nat64P2] != 2 {
			t.Errorf("routes by class = %v, want the NSP's removed and P2's kept", routes)
		}
		if got := f.enabledClasses(t); got[nat64P2] != 1 || len(got) != 2 {
			t.Errorf("enabled groups = %v, want NAT66 and one P2 group, the lowest", got)
		}
	})
}

// TestSweepHashed_EmptyMembershipKeepsRoutesOnGroups checks that when no
// shard can serve any class, hashed mode keeps every route on its class's
// group, where the datapath drops it as group_empty, rather than falling
// back to the static shard list, which is not checked for readiness or
// translation. The routes stay counted against their groups.
func TestSweepHashed_EmptyMembershipKeepsRoutesOnGroups(t *testing.T) {
	cases := map[string]func(*fakeLister){
		"NoShards": func(l *fakeLister) { l.shards = nil },
		"NoneEligible": func(l *fakeLister) {
			l.shards[0].Status.Conditions[0].Status = metav1.ConditionFalse
		},
	}
	for name, empty := range cases {
		t.Run(name, func(t *testing.T) {
			static := shardSIDFor(0x10)
			f := newFixture(t, testHashed, []string{static}, []netip.Prefix{testNSP})
			reg := prometheus.NewRegistry()
			f.g.ctl = metrics.NewEgressControl(reg)
			lister := &fakeLister{shards: []bgpv1alpha1.EgressShard{dual("dual", 0x10)}, synced: true}
			f.g.shards = lister

			base, _ := egressroutemap.BaseShardSID(net.ParseIP(static))
			for vrf := uint32(1); vrf <= 3; vrf++ {
				sid := base.As16()
				sid[9] = byte(0x20 + vrf)
				if err := f.routes.Register(vrf, egressroutemap.DefaultPrefix, net.IP(sid[:])); err != nil {
					t.Fatal(err)
				}
				if vrf == 1 {
					if err := f.routes.Register(vrf, testNSPNet, net.IP(sid[:])); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := f.sweep(t); err != nil {
				t.Fatal(err)
			}
			if f.sentinels() != 4 {
				t.Fatalf("%d routes on groups after the first sweep, want 4", f.sentinels())
			}
			before := maps.Clone(f.raw.values)

			empty(lister)
			if err := f.sweep(t); err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(f.raw.values, before) {
				t.Errorf("routes changed with no shard to serve them; %d of 4 still on a group", f.sentinels())
			}
			for id := range uint32(2) {
				if s := status(t, f.groups, id); !s.Open() || s.Candidates != 0 {
					t.Errorf("group %d = %+v, want open with no candidate", id, s)
				}
			}
			want := map[string]float64{egressroutemap.NAT66Class.String(): 3, nat64NSP.String(): 1}
			if got := groupRoutes(t, reg); !maps.Equal(got, want) {
				t.Errorf("group_routes = %v, want %v", got, want)
			}
		})
	}
}

// groupRoutes reads galactic_cni_egress_group_routes from reg, by class.
func groupRoutes(t *testing.T, reg *prometheus.Registry) map[string]float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, mf := range families {
		if mf.GetName() != "galactic_cni_egress_group_routes" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "class" {
					got[l.GetValue()] = m.GetGauge().GetValue()
				}
			}
		}
	}
	return got
}
