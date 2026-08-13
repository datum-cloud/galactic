// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// fakeRuleTable is an in-memory edgemap.Table, letting KernelDatapath's
// key-management logic (apply/prune/remove/reconcile) be exercised without
// a kernel or root privileges -- same pattern as edgemap's own tests.
type fakeRuleTable struct {
	entries map[edgeprog.EdgenatRuleKey]edgeprog.EdgenatRuleValue
}

func newFakeRuleTable() *fakeRuleTable {
	return &fakeRuleTable{entries: make(map[edgeprog.EdgenatRuleKey]edgeprog.EdgenatRuleValue)}
}

func (f *fakeRuleTable) Put(key, value any) error {
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
	_, err := NewKernelDatapath(&edgeprog.EdgenatObjects{}, netip.MustParseAddr("192.0.2.1"), netip.Addr{}, netip.Addr{})
	if err == nil {
		t.Error("NewKernelDatapath with an IPv4 gateway address: want an error, got nil")
	}
}

// TestNewKernelDatapath_RejectsMismatchedEgressPair covers the defensive
// pairing check on egressSID/masqAddr (datum-cloud/enhancements#865) --
// config.GatewayConfig.Validate already enforces this pairing before this
// constructor is reached in production, but this constructor must not
// silently half-configure egress if that invariant is ever violated.
// Exercises only the validation, which runs before any real Put call --
// same reasoning as TestNewKernelDatapath_RejectsIPv4GatewayAddress above.
func TestNewKernelDatapath_RejectsMismatchedEgressPair(t *testing.T) {
	gwAddr := netip.MustParseAddr("2001:db8:3::1")
	egressSID := netip.MustParseAddr("2001:db8:8::1")

	_, err := NewKernelDatapath(&edgeprog.EdgenatObjects{}, gwAddr, egressSID, netip.Addr{})
	if err == nil {
		t.Error("NewKernelDatapath with egressSID set but masqAddr empty: want an error, got nil")
	}

	_, err = NewKernelDatapath(&edgeprog.EdgenatObjects{}, gwAddr, netip.Addr{}, egressSID)
	if err == nil {
		t.Error("NewKernelDatapath with masqAddr set but egressSID empty: want an error, got nil")
	}
}

// TestNewKernelDatapath_RejectsIPv4EgressSID covers the same address-family
// validation NewKernelDatapath applies to gwAddr, mirrored onto egressSID.
func TestNewKernelDatapath_RejectsIPv4EgressSID(t *testing.T) {
	gwAddr := netip.MustParseAddr("2001:db8:3::1")
	masqAddr := netip.MustParseAddr("2001:db8:8::1")

	_, err := NewKernelDatapath(&edgeprog.EdgenatObjects{}, gwAddr, netip.MustParseAddr("192.0.2.1"), masqAddr)
	if err == nil {
		t.Error("NewKernelDatapath with an IPv4 egress SID: want an error, got nil")
	}
}
