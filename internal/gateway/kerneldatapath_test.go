// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// fakeVIPTable is an in-memory edgemap.Table, letting KernelDatapath's
// key-management logic (apply/prune/remove/reconcile) be exercised without
// a kernel or root privileges -- same pattern as edgemap's own tests.
//
// failOnNthPut, when non-zero, makes the failOnNthPut-th call to Put
// (1-indexed) fail instead of writing the entry, letting a test simulate
// ApplyRule failing partway through a multi-VIP rule's Register loop.
type fakeVIPTable struct {
	entries map[edgeprog.EdgedsrVipKey]edgeprog.EdgedsrVipValue

	failOnNthPut int
	putCount     int
}

func newFakeVIPTable() *fakeVIPTable {
	return &fakeVIPTable{entries: make(map[edgeprog.EdgedsrVipKey]edgeprog.EdgedsrVipValue)}
}

func (f *fakeVIPTable) Put(key, value any) error {
	f.putCount++
	if f.failOnNthPut != 0 && f.putCount == f.failOnNthPut {
		return fmt.Errorf("fakeVIPTable: injected failure on Put #%d", f.putCount)
	}
	f.entries[key.(edgeprog.EdgedsrVipKey)] = value.(edgeprog.EdgedsrVipValue)
	return nil
}

func (f *fakeVIPTable) Lookup(key, valueOut any) error {
	v, ok := f.entries[key.(edgeprog.EdgedsrVipKey)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*edgeprog.EdgedsrVipValue) = v
	return nil
}

func (f *fakeVIPTable) Delete(key any) error {
	k := key.(edgeprog.EdgedsrVipKey)
	if _, ok := f.entries[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f.entries, k)
	return nil
}

func (f *fakeVIPTable) Iterate() edgemap.Iterator {
	keys := make([]edgeprog.EdgedsrVipKey, 0, len(f.entries))
	for k := range f.entries {
		keys = append(keys, k)
	}
	return &fakeVIPIterator{table: f, keys: keys}
}

type fakeVIPIterator struct {
	table *fakeVIPTable
	keys  []edgeprog.EdgedsrVipKey
	i     int
}

func (it *fakeVIPIterator) Next(keyOut, valueOut any) bool {
	if it.i >= len(it.keys) {
		return false
	}
	k := it.keys[it.i]
	it.i++
	*keyOut.(*edgeprog.EdgedsrVipKey) = k
	*valueOut.(*edgeprog.EdgedsrVipValue) = it.table.entries[k]
	return true
}

func (it *fakeVIPIterator) Err() error { return nil }

var _ edgemap.Table = (*fakeVIPTable)(nil)

// fakeStatsTable is an in-memory edgemap.Table standing in for
// vip_stats_table -- KernelDatapath's own tests never assert on hit
// counters (that's edgemetrics/collector_test.go's job), so this needs no
// injected-failure knobs, just enough of edgemap.Table to satisfy
// NewVIPTable's second argument.
type fakeStatsTable struct {
	entries map[edgeprog.EdgedsrVipKey]edgeprog.EdgedsrVipStatsValue
}

func newFakeStatsTable() *fakeStatsTable {
	return &fakeStatsTable{entries: make(map[edgeprog.EdgedsrVipKey]edgeprog.EdgedsrVipStatsValue)}
}

func (f *fakeStatsTable) Put(key, value any) error {
	f.entries[key.(edgeprog.EdgedsrVipKey)] = value.(edgeprog.EdgedsrVipStatsValue)
	return nil
}

func (f *fakeStatsTable) Lookup(key, valueOut any) error {
	v, ok := f.entries[key.(edgeprog.EdgedsrVipKey)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*edgeprog.EdgedsrVipStatsValue) = v
	return nil
}

func (f *fakeStatsTable) Delete(key any) error {
	k := key.(edgeprog.EdgedsrVipKey)
	if _, ok := f.entries[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f.entries, k)
	return nil
}

func (f *fakeStatsTable) Iterate() edgemap.Iterator {
	return &fakeStatsIterator{}
}

// fakeStatsIterator always yields zero entries -- nothing in this
// package's tests lists vip_stats_table.
type fakeStatsIterator struct{}

func (it *fakeStatsIterator) Next(keyOut, valueOut any) bool { return false }
func (it *fakeStatsIterator) Err() error                     { return nil }

var _ edgemap.Table = (*fakeStatsTable)(nil)

// fakeReturnMap is an in-memory Table for the two return-path maps, which this
// package's tests need present but never assert against: the address set's own
// behaviour is edgemap's to test.
type fakeReturnMap[V any] struct {
	entries map[edgeprog.EdgedsrVipAddrKey]V
}

func newFakeReturnMap[V any]() *fakeReturnMap[V] {
	return &fakeReturnMap[V]{entries: make(map[edgeprog.EdgedsrVipAddrKey]V)}
}

func (f *fakeReturnMap[V]) Put(key, value any) error {
	f.entries[key.(edgeprog.EdgedsrVipAddrKey)] = value.(V)
	return nil
}

func (f *fakeReturnMap[V]) Lookup(key, valueOut any) error {
	v, ok := f.entries[key.(edgeprog.EdgedsrVipAddrKey)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*V) = v
	return nil
}

func (f *fakeReturnMap[V]) Delete(key any) error {
	k := key.(edgeprog.EdgedsrVipAddrKey)
	if _, ok := f.entries[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f.entries, k)
	return nil
}

func (f *fakeReturnMap[V]) Iterate() edgemap.Iterator {
	keys := make([]edgeprog.EdgedsrVipAddrKey, 0, len(f.entries))
	for k := range f.entries {
		keys = append(keys, k)
	}
	return &fakeReturnIterator[V]{table: f, keys: keys}
}

type fakeReturnIterator[V any] struct {
	table *fakeReturnMap[V]
	keys  []edgeprog.EdgedsrVipAddrKey
	i     int
}

func (it *fakeReturnIterator[V]) Next(keyOut, valueOut any) bool {
	if it.i >= len(it.keys) {
		return false
	}
	k := it.keys[it.i]
	it.i++
	*keyOut.(*edgeprog.EdgedsrVipAddrKey) = k
	*valueOut.(*V) = it.table.entries[k]
	return true
}

func (it *fakeReturnIterator[V]) Err() error { return nil }

func newFakeAddrTable() *fakeReturnMap[edgeprog.EdgedsrVipAddrValue] {
	return newFakeReturnMap[edgeprog.EdgedsrVipAddrValue]()
}

func newFakeReturnStatsTable() *fakeReturnMap[edgeprog.EdgedsrVipStatsValue] {
	return newFakeReturnMap[edgeprog.EdgedsrVipStatsValue]()
}

func newTestKernelDatapath() *KernelDatapath {
	return &KernelDatapath{
		vipTable: edgemap.NewVIPTable(
			newFakeVIPTable(), newFakeStatsTable(), newFakeAddrTable(), newFakeReturnStatsTable()),
		vipKeysByName: make(map[string][]edgemap.VIPKey),
	}
}

func testDesiredRule(t *testing.T, key string, vips ...string) DesiredRule {
	t.Helper()
	addrs := make([]netip.Addr, len(vips))
	for i, v := range vips {
		addrs[i] = netip.MustParseAddr(v)
	}
	return DesiredRule{
		Key:          key,
		Protocol:     "tcp",
		Port:         443,
		VIPAddresses: addrs,
		Backends: []DesiredBackend{
			{
				Address: netip.MustParseAddr("fd00:10:1::20"),
				Port:    8443,
				USID:    netip.MustParseAddr("2001:db8:2::1"),
			},
		},
	}
}

func TestKernelDatapath_ApplyRuleRegistersOneKeyPerVIP(t *testing.T) {
	d := newTestKernelDatapath()
	rule := testDesiredRule(t, testKeyA, "2001:db8:1::10", "2001:db8:1::11")

	if err := d.ApplyRule(context.Background(), rule); err != nil {
		t.Fatalf("ApplyRule: %v", err)
	}

	if len(d.vipKeysByName[testKeyA]) != 2 {
		t.Fatalf("vipKeysByName[%s] = %v, want 2 keys", testKeyA, d.vipKeysByName[testKeyA])
	}
	for _, key := range d.vipKeysByName[testKeyA] {
		entry, ok, err := d.vipTable.Get(key)
		if err != nil || !ok {
			t.Fatalf("Get(%+v): ok=%v err=%v", key, ok, err)
		}
		if len(entry.Backends) != 1 || entry.Backends[0].USID != rule.Backends[0].USID {
			t.Errorf("Get(%+v).Backends = %+v, want backend with USID %s", key, entry.Backends, rule.Backends[0].USID)
		}
		// A single-backend rule's Maglev table must point every slot at
		// the only backend, index 0.
		for slot, idx := range entry.MaglevTable {
			if idx != 0 {
				t.Fatalf("MaglevTable[%d] = %d, want 0 (single backend)", slot, idx)
			}
		}
	}
}

// TestKernelDatapath_ApplyRuleTracksKeysWrittenBeforeAPartialFailure covers
// issue #359 item 3: a multi-VIP rule's Register loop writes one vip_table
// entry per VIP, and a failure partway through must not leave the earlier
// entries untracked -- RemoveRule only knows what to unregister via
// vipKeysByName, so an untracked entry would be invisible to teardown and
// left for ReconcileOrphans to eventually sweep up instead.
func TestKernelDatapath_ApplyRuleTracksKeysWrittenBeforeAPartialFailure(t *testing.T) {
	table := newFakeVIPTable()
	table.failOnNthPut = 2 // fail registering the second of three VIPs
	d := &KernelDatapath{
		vipTable: edgemap.NewVIPTable(
			table, newFakeStatsTable(), newFakeAddrTable(), newFakeReturnStatsTable()),
		vipKeysByName: make(map[string][]edgemap.VIPKey),
	}
	ctx := context.Background()
	rule := testDesiredRule(t, testKeyA, "2001:db8:1::10", "2001:db8:1::11", "2001:db8:1::12")

	if err := d.ApplyRule(ctx, rule); err == nil {
		t.Fatal("ApplyRule: want an error from the injected Put failure, got nil")
	}

	writtenKey := edgemap.VIPKey{Proto: 6, VPort: 443, VIP: netip.MustParseAddr("2001:db8:1::10")}
	if got := d.vipKeysByName[testKeyA]; len(got) != 1 || got[0] != writtenKey {
		t.Fatalf("vipKeysByName[%s] = %v, want [%v] (only the key written before the failure)",
			testKeyA, got, writtenKey)
	}
	if _, ok, err := d.vipTable.Get(writtenKey); err != nil || !ok {
		t.Fatalf("Get(%+v): ok=%v err=%v, want the pre-failure entry still present", writtenKey, ok, err)
	}

	// RemoveRule must find and clean up the partial write via
	// vipKeysByName rather than relying on ReconcileOrphans.
	if err := d.RemoveRule(ctx, testKeyA); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	if _, ok, _ := d.vipTable.Get(writtenKey); ok {
		t.Error("RemoveRule left the partially-applied rule's entry in vip_table")
	}
	if len(d.vipKeysByName[testKeyA]) != 0 {
		t.Errorf("vipKeysByName[%s] = %v, want empty after RemoveRule", testKeyA, d.vipKeysByName[testKeyA])
	}
}

func TestKernelDatapath_ApplyRulePrunesDroppedVIP(t *testing.T) {
	d := newTestKernelDatapath()
	ctx := context.Background()

	first := testDesiredRule(t, testKeyA, "2001:db8:1::10", "2001:db8:1::11")
	if err := d.ApplyRule(ctx, first); err != nil {
		t.Fatalf("first ApplyRule: %v", err)
	}

	second := testDesiredRule(t, testKeyA, "2001:db8:1::10") // dropped ::11
	if err := d.ApplyRule(ctx, second); err != nil {
		t.Fatalf("second ApplyRule: %v", err)
	}

	if len(d.vipKeysByName[testKeyA]) != 1 {
		t.Fatalf("vipKeysByName[%s] = %v, want exactly 1 key after dropping a VIP", testKeyA, d.vipKeysByName[testKeyA])
	}

	droppedKey := edgemap.VIPKey{Proto: 6, VPort: 443, VIP: netip.MustParseAddr("2001:db8:1::11")}
	if _, ok, _ := d.vipTable.Get(droppedKey); ok {
		t.Error("dropped VIP's vip_table entry is still present")
	}
}

func TestKernelDatapath_RemoveRuleUnregistersAllOwnedKeys(t *testing.T) {
	d := newTestKernelDatapath()
	ctx := context.Background()
	rule := testDesiredRule(t, testKeyA, "2001:db8:1::10", "2001:db8:1::11")

	if err := d.ApplyRule(ctx, rule); err != nil {
		t.Fatalf("ApplyRule: %v", err)
	}
	if err := d.RemoveRule(ctx, testKeyA); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}

	if len(d.vipKeysByName[testKeyA]) != 0 {
		t.Errorf("vipKeysByName[%s] = %v, want empty after RemoveRule", testKeyA, d.vipKeysByName[testKeyA])
	}
	entries, err := d.vipTable.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("vip_table has %d entries after RemoveRule, want 0", len(entries))
	}
}

func TestKernelDatapath_ApplyRuleRejectsUnsupportedProtocol(t *testing.T) {
	d := newTestKernelDatapath()
	rule := testDesiredRule(t, testKeyA, "2001:db8:1::10")
	rule.Protocol = "sctp"

	if err := d.ApplyRule(context.Background(), rule); err == nil {
		t.Error("ApplyRule with an unsupported protocol: want an error, got nil")
	}
}

func TestKernelDatapath_ApplyRuleRejectsTooManyBackends(t *testing.T) {
	d := newTestKernelDatapath()
	rule := testDesiredRule(t, testKeyA, "2001:db8:1::10")
	rule.Backends = make([]DesiredBackend, edgemap.MaxBackends+1)
	for i := range rule.Backends {
		rule.Backends[i] = DesiredBackend{
			Address: netip.MustParseAddr(fmt.Sprintf("fd00:10:1::%x", i+1)),
			Port:    8443,
			USID:    netip.MustParseAddr("2001:db8:2::1"),
		}
	}

	if err := d.ApplyRule(context.Background(), rule); err == nil {
		t.Error("ApplyRule with more than MaxBackends backends: want an error, got nil")
	}
}

// TestKernelDatapath_ApplyRuleBuildsMaglevTableOverMultipleBackends covers
// the multi-backend case: every slot in the registered Maglev table must
// resolve to a valid backend index, and every backend must be reachable
// from at least one slot (with EDGE_MAGLEV_TABLE_SIZE=1021 and only two
// backends, both must get a meaningful share of the table).
func TestKernelDatapath_ApplyRuleBuildsMaglevTableOverMultipleBackends(t *testing.T) {
	d := newTestKernelDatapath()
	rule := testDesiredRule(t, testKeyA, "2001:db8:1::10")
	rule.Backends = []DesiredBackend{
		{Address: netip.MustParseAddr("fd00:10:1::20"), Port: 8443, USID: netip.MustParseAddr("2001:db8:2::1")},
		{Address: netip.MustParseAddr("fd00:10:1::21"), Port: 8443, USID: netip.MustParseAddr("2001:db8:2::2")},
	}

	if err := d.ApplyRule(context.Background(), rule); err != nil {
		t.Fatalf("ApplyRule: %v", err)
	}

	key := edgemap.VIPKey{Proto: 6, VPort: 443, VIP: netip.MustParseAddr("2001:db8:1::10")}
	entry, ok, err := d.vipTable.Get(key)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if len(entry.Backends) != 2 {
		t.Fatalf("Backends = %+v, want 2", entry.Backends)
	}

	seen := map[byte]int{}
	for _, idx := range entry.MaglevTable {
		if idx > 1 {
			t.Fatalf("MaglevTable contains index %d, want only 0 or 1 (2 backends)", idx)
		}
		seen[idx]++
	}
	if seen[0] == 0 || seen[1] == 0 {
		t.Errorf("MaglevTable slot distribution = %v, want both backend indices represented", seen)
	}
}

func TestKernelDatapath_ReconcileOrphansRemovesUnownedKeys(t *testing.T) {
	d := newTestKernelDatapath()
	ctx := context.Background()

	liveRule := testDesiredRule(t, testKeyA, "2001:db8:1::10")
	staleRule := testDesiredRule(t, testKeyB, "2001:db8:1::99")

	if err := d.ApplyRule(ctx, liveRule); err != nil {
		t.Fatalf("apply liveRule: %v", err)
	}
	if err := d.ApplyRule(ctx, staleRule); err != nil {
		t.Fatalf("apply staleRule: %v", err)
	}

	// cutoff greater than both entries' Generation (a fake clock defaulting
	// to monotonicNow would make this flaky across different real
	// timestamps — capture Generation() after both applies instead, then
	// bump it via a fresh table generation call is not available here, so
	// just use the datapath's own current Generation as a safe upper bound
	// for entries already written).
	cutoff := d.Generation() + 1

	if err := d.ReconcileOrphans(ctx, []DesiredRule{liveRule}, cutoff); err != nil {
		t.Fatalf("ReconcileOrphans: %v", err)
	}

	liveKey := edgemap.VIPKey{Proto: 6, VPort: 443, VIP: netip.MustParseAddr("2001:db8:1::10")}
	staleKey := edgemap.VIPKey{Proto: 6, VPort: 443, VIP: netip.MustParseAddr("2001:db8:1::99")}

	if _, ok, _ := d.vipTable.Get(liveKey); !ok {
		t.Error("ReconcileOrphans removed a live rule's entry")
	}
	if _, ok, _ := d.vipTable.Get(staleKey); ok {
		t.Error("ReconcileOrphans left a stale entry in place")
	}
}

func TestNewKernelDatapath_RejectsIPv4EncapSource(t *testing.T) {
	// NewKernelDatapath itself needs a real *edgeprog.EdgedsrObjects to
	// call Put against encap_config_table, which requires a loaded program
	// (root-gated, covered by edgeattach's own tests) -- this test only
	// exercises the address-family validation, which runs before that
	// call.
	_, err := NewKernelDatapath(&edgeprog.EdgedsrObjects{}, netip.MustParseAddr("192.0.2.1"))
	if err == nil {
		t.Error("NewKernelDatapath with an IPv4 encap source address: want an error, got nil")
	}
}

// testVPCA and testVPCB are the VPC identifiers the attribution tests assign.
const (
	testVPCA = "vpcA"
	testVPCB = "vpcB"
)

// TestKernelDatapath_VPCAttributionFollowsAppliedRules covers #709: the VPC a
// rule carries labels its vip_table keys from apply until the key is pruned or
// the rule removed.
func TestKernelDatapath_VPCAttributionFollowsAppliedRules(t *testing.T) {
	d := newTestKernelDatapath()
	ctx := context.Background()
	kept := edgemap.VIPKey{Proto: 6, VPort: 443, VIP: netip.MustParseAddr("2001:db8:1::10")}
	dropped := edgemap.VIPKey{Proto: 6, VPort: 443, VIP: netip.MustParseAddr("2001:db8:1::11")}

	rule := testDesiredRule(t, testKeyA, "2001:db8:1::10", "2001:db8:1::11")
	rule.VPCRef = testVPCA
	if err := d.ApplyRule(ctx, rule); err != nil {
		t.Fatalf("ApplyRule: %v", err)
	}
	rules, addrs := d.VPCAttribution()
	if rules[kept] != testVPCA || rules[dropped] != testVPCA {
		t.Fatalf("rules = %v, want both keys attributed to vpcA", rules)
	}
	if addrs[kept.VIP] != testVPCA || addrs[dropped.VIP] != testVPCA {
		t.Fatalf("addrs = %v, want both addresses attributed to vpcA", addrs)
	}

	rule.VIPAddresses = rule.VIPAddresses[:1]
	if err := d.ApplyRule(ctx, rule); err != nil {
		t.Fatalf("ApplyRule after dropping a VIP: %v", err)
	}
	rules, addrs = d.VPCAttribution()
	if _, ok := rules[dropped]; ok {
		t.Errorf("rules still attributes the pruned key %+v", dropped)
	}
	if _, ok := addrs[dropped.VIP]; ok {
		t.Errorf("addrs still attributes the pruned address %s", dropped.VIP)
	}

	if err := d.RemoveRule(ctx, testKeyA); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	if rules, addrs = d.VPCAttribution(); len(rules) != 0 || len(addrs) != 0 {
		t.Errorf("after RemoveRule: rules = %v, addrs = %v, want both empty", rules, addrs)
	}
}

// TestKernelDatapath_VPCAttributionOmitsSharedAddress covers an address two
// VPCs' rules both use on different ports: each rule key keeps its own VPC, but
// the per-address return counters cannot be split, so the address is left out.
func TestKernelDatapath_VPCAttributionOmitsSharedAddress(t *testing.T) {
	d := newTestKernelDatapath()
	ctx := context.Background()

	a := testDesiredRule(t, testKeyA, "2001:db8:1::10")
	a.VPCRef = testVPCA
	b := testDesiredRule(t, testKeyA+"-b", "2001:db8:1::10")
	b.VPCRef = testVPCB
	b.Port = 80
	for _, rule := range []DesiredRule{a, b} {
		if err := d.ApplyRule(ctx, rule); err != nil {
			t.Fatalf("ApplyRule(%s): %v", rule.Key, err)
		}
	}

	rules, addrs := d.VPCAttribution()
	vip := netip.MustParseAddr("2001:db8:1::10")
	if got := rules[edgemap.VIPKey{Proto: 6, VPort: 443, VIP: vip}]; got != testVPCA {
		t.Errorf("port 443 key VPC = %q, want vpcA", got)
	}
	if got := rules[edgemap.VIPKey{Proto: 6, VPort: 80, VIP: vip}]; got != testVPCB {
		t.Errorf("port 80 key VPC = %q, want vpcB", got)
	}
	if got, ok := addrs[vip]; ok {
		t.Errorf("addrs[%s] = %q, want absent for an address two VPCs share", vip, got)
	}
}

// TestKernelDatapath_VPCAttributionOnPartialApplyFailure covers a re-apply that
// moves a rule to another VPC and then fails partway: every key the rule still
// owns carries the new VPC, and a key that never landed is not attributed.
func TestKernelDatapath_VPCAttributionOnPartialApplyFailure(t *testing.T) {
	table := newFakeVIPTable()
	d := &KernelDatapath{
		vipTable: edgemap.NewVIPTable(
			table, newFakeStatsTable(), newFakeAddrTable(), newFakeReturnStatsTable()),
		vipKeysByName: make(map[string][]edgemap.VIPKey),
	}
	ctx := context.Background()
	owned := edgemap.VIPKey{Proto: 6, VPort: 443, VIP: netip.MustParseAddr("2001:db8:1::10")}
	unwritten := edgemap.VIPKey{Proto: 6, VPort: 443, VIP: netip.MustParseAddr("2001:db8:1::11")}

	rule := testDesiredRule(t, testKeyA, "2001:db8:1::10")
	rule.VPCRef = testVPCA
	if err := d.ApplyRule(ctx, rule); err != nil {
		t.Fatalf("ApplyRule: %v", err)
	}

	// Re-apply under testVPCB with a second VIP, failing the first write: the
	// already-owned key, which stays in vip_table under the rule.
	table.failOnNthPut = table.putCount + 1
	rule.VPCRef = testVPCB
	rule.VIPAddresses = append(rule.VIPAddresses, unwritten.VIP)
	if err := d.ApplyRule(ctx, rule); err == nil {
		t.Fatal("ApplyRule: want an error from the injected Put failure, got nil")
	}

	rules, _ := d.VPCAttribution()
	if got := rules[owned]; got != testVPCB {
		t.Errorf("owned key VPC = %q, want %q", got, testVPCB)
	}
	if got, ok := rules[unwritten]; ok {
		t.Errorf("unwritten key attributed to %q, want absent", got)
	}
}

// TestKernelDatapath_VPCAttributionConcurrentWithApply runs scrapes alongside
// applies and removals, for the race detector.
func TestKernelDatapath_VPCAttributionConcurrentWithApply(t *testing.T) {
	d := newTestKernelDatapath()
	ctx := context.Background()
	rule := testDesiredRule(t, testKeyA, "2001:db8:1::10", "2001:db8:1::11")
	rule.VPCRef = testVPCA

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			d.VPCAttribution()
		}
	}()
	for range 200 {
		if err := d.ApplyRule(ctx, rule); err != nil {
			t.Errorf("ApplyRule: %v", err)
		}
		if err := d.RemoveRule(ctx, testKeyA); err != nil {
			t.Errorf("RemoveRule: %v", err)
		}
	}
	<-done
}
