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

// fakeRuleTable is an in-memory edgemap.Table, letting KernelDatapath's
// key-management logic (apply/prune/remove/reconcile) be exercised without
// a kernel or root privileges -- same pattern as edgemap's own tests.
//
// failOnNthPut, when non-zero, makes the failOnNthPut-th call to Put
// (1-indexed) fail instead of writing the entry, letting a test simulate
// ApplyRule failing partway through a multi-VIP rule's Register loop.
type fakeRuleTable struct {
	entries map[edgeprog.EdgenatRuleKey]edgeprog.EdgenatRuleValue

	failOnNthPut int
	putCount     int
}

func newFakeRuleTable() *fakeRuleTable {
	return &fakeRuleTable{entries: make(map[edgeprog.EdgenatRuleKey]edgeprog.EdgenatRuleValue)}
}

func (f *fakeRuleTable) Put(key, value any) error {
	f.putCount++
	if f.failOnNthPut != 0 && f.putCount == f.failOnNthPut {
		return fmt.Errorf("fakeRuleTable: injected failure on Put #%d", f.putCount)
	}
	f.entries[key.(edgeprog.EdgenatRuleKey)] = value.(edgeprog.EdgenatRuleValue)
	return nil
}

func (f *fakeRuleTable) Lookup(key, valueOut any) error {
	v, ok := f.entries[key.(edgeprog.EdgenatRuleKey)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*edgeprog.EdgenatRuleValue) = v
	return nil
}

func (f *fakeRuleTable) Delete(key any) error {
	k := key.(edgeprog.EdgenatRuleKey)
	if _, ok := f.entries[k]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(f.entries, k)
	return nil
}

func (f *fakeRuleTable) Iterate() edgemap.Iterator {
	keys := make([]edgeprog.EdgenatRuleKey, 0, len(f.entries))
	for k := range f.entries {
		keys = append(keys, k)
	}
	return &fakeRuleIterator{table: f, keys: keys}
}

type fakeRuleIterator struct {
	table *fakeRuleTable
	keys  []edgeprog.EdgenatRuleKey
	i     int
}

func (it *fakeRuleIterator) Next(keyOut, valueOut any) bool {
	if it.i >= len(it.keys) {
		return false
	}
	k := it.keys[it.i]
	it.i++
	*keyOut.(*edgeprog.EdgenatRuleKey) = k
	*valueOut.(*edgeprog.EdgenatRuleValue) = it.table.entries[k]
	return true
}

func (it *fakeRuleIterator) Err() error { return nil }

var _ edgemap.Table = (*fakeRuleTable)(nil)

func newTestKernelDatapath() *KernelDatapath {
	return &KernelDatapath{
		ruleTable:      edgemap.NewRuleTable(newFakeRuleTable()),
		ruleKeysByName: make(map[string][]edgemap.RuleKey),
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

	if len(d.ruleKeysByName[testKeyA]) != 2 {
		t.Fatalf("ruleKeysByName[%s] = %v, want 2 keys", testKeyA, d.ruleKeysByName[testKeyA])
	}
	for _, key := range d.ruleKeysByName[testKeyA] {
		entry, ok, err := d.ruleTable.Get(key)
		if err != nil || !ok {
			t.Fatalf("Get(%+v): ok=%v err=%v", key, ok, err)
		}
		if len(entry.Backends) != 1 || entry.Backends[0].USID != rule.Backends[0].USID {
			t.Errorf("Get(%+v).Backends = %+v, want backend with USID %s", key, entry.Backends, rule.Backends[0].USID)
		}
	}
}

// TestKernelDatapath_ApplyRuleTracksKeysWrittenBeforeAPartialFailure covers
// issue #359 item 3: a multi-VIP rule's Register loop writes one rule_table
// entry per VIP, and a failure partway through must not leave the earlier
// entries untracked -- RemoveRule only knows what to unregister via
// ruleKeysByName, so an untracked entry would be invisible to teardown and
// left for ReconcileOrphans to eventually sweep up instead.
func TestKernelDatapath_ApplyRuleTracksKeysWrittenBeforeAPartialFailure(t *testing.T) {
	table := newFakeRuleTable()
	table.failOnNthPut = 2 // fail registering the second of three VIPs
	d := &KernelDatapath{
		ruleTable:      edgemap.NewRuleTable(table),
		ruleKeysByName: make(map[string][]edgemap.RuleKey),
	}
	ctx := context.Background()
	rule := testDesiredRule(t, testKeyA, "2001:db8:1::10", "2001:db8:1::11", "2001:db8:1::12")

	if err := d.ApplyRule(ctx, rule); err == nil {
		t.Fatal("ApplyRule: want an error from the injected Put failure, got nil")
	}

	writtenKey := edgemap.RuleKey{Proto: 6, VPort: 443, VIP: netip.MustParseAddr("2001:db8:1::10")}
	if got := d.ruleKeysByName[testKeyA]; len(got) != 1 || got[0] != writtenKey {
		t.Fatalf("ruleKeysByName[%s] = %v, want [%v] (only the key written before the failure)",
			testKeyA, got, writtenKey)
	}
	if _, ok, err := d.ruleTable.Get(writtenKey); err != nil || !ok {
		t.Fatalf("Get(%+v): ok=%v err=%v, want the pre-failure entry still present", writtenKey, ok, err)
	}

	// RemoveRule must find and clean up the partial write via
	// ruleKeysByName rather than relying on ReconcileOrphans.
	if err := d.RemoveRule(ctx, testKeyA); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	if _, ok, _ := d.ruleTable.Get(writtenKey); ok {
		t.Error("RemoveRule left the partially-applied rule's entry in rule_table")
	}
	if len(d.ruleKeysByName[testKeyA]) != 0 {
		t.Errorf("ruleKeysByName[%s] = %v, want empty after RemoveRule", testKeyA, d.ruleKeysByName[testKeyA])
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

	if len(d.ruleKeysByName[testKeyA]) != 1 {
		t.Fatalf("ruleKeysByName[%s] = %v, want exactly 1 key after dropping a VIP", testKeyA, d.ruleKeysByName[testKeyA])
	}

	droppedKey := edgemap.RuleKey{Proto: 6, VPort: 443, VIP: netip.MustParseAddr("2001:db8:1::11")}
	if _, ok, _ := d.ruleTable.Get(droppedKey); ok {
		t.Error("dropped VIP's rule_table entry is still present")
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

	if len(d.ruleKeysByName[testKeyA]) != 0 {
		t.Errorf("ruleKeysByName[%s] = %v, want empty after RemoveRule", testKeyA, d.ruleKeysByName[testKeyA])
	}
	entries, err := d.ruleTable.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("rule_table has %d entries after RemoveRule, want 0", len(entries))
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

	liveKey := edgemap.RuleKey{Proto: 6, VPort: 443, VIP: netip.MustParseAddr("2001:db8:1::10")}
	staleKey := edgemap.RuleKey{Proto: 6, VPort: 443, VIP: netip.MustParseAddr("2001:db8:1::99")}

	if _, ok, _ := d.ruleTable.Get(liveKey); !ok {
		t.Error("ReconcileOrphans removed a live rule's entry")
	}
	if _, ok, _ := d.ruleTable.Get(staleKey); ok {
		t.Error("ReconcileOrphans left a stale entry in place")
	}
}

func TestNewKernelDatapath_RejectsIPv4GatewayAddress(t *testing.T) {
	// NewKernelDatapath itself needs a real *edgeprog.EdgenatObjects to
	// call Put against gw_config_table, which requires a loaded program
	// (root-gated, covered by edgeattach's own tests) -- this test only
	// exercises the address-family validation, which runs before that
	// call.
	_, err := NewKernelDatapath(&edgeprog.EdgenatObjects{}, netip.MustParseAddr("192.0.2.1"))
	if err == nil {
		t.Error("NewKernelDatapath with an IPv4 gateway address: want an error, got nil")
	}
}
