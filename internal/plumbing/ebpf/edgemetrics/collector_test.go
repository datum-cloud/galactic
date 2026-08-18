// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgemetrics

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

// fakeVIPTable is an in-memory edgemap.Table, the same technique
// internal/plumbing/ebpf/edgemap/viptable_test.go's identical fake uses
// (unexported there, so not reusable across package boundaries --
// reimplemented here rather than promoted, to keep that package's own test
// surface unchanged; same convention
// internal/plumbing/ebpf/metrics/faketable_test.go documents for its own
// duplicate).
type fakeVIPTable struct {
	entries map[edgeprog.EdgedsrVipKey]edgeprog.EdgedsrVipValue
}

func newFakeVIPTable() *fakeVIPTable {
	return &fakeVIPTable{entries: make(map[edgeprog.EdgedsrVipKey]edgeprog.EdgedsrVipValue)}
}

func (f *fakeVIPTable) Put(key, value any) error {
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
// vip_stats_table (issue #361's split-out counters map) -- same technique
// as fakeVIPTable, but keyed/valued for edgeprog.EdgedsrVipStatsValue.
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
	keys := make([]edgeprog.EdgedsrVipKey, 0, len(f.entries))
	for k := range f.entries {
		keys = append(keys, k)
	}
	return &fakeStatsIterator{table: f, keys: keys}
}

type fakeStatsIterator struct {
	table *fakeStatsTable
	keys  []edgeprog.EdgedsrVipKey
	i     int
}

func (it *fakeStatsIterator) Next(keyOut, valueOut any) bool {
	if it.i >= len(it.keys) {
		return false
	}
	k := it.keys[it.i]
	it.i++
	*keyOut.(*edgeprog.EdgedsrVipKey) = k
	*valueOut.(*edgeprog.EdgedsrVipStatsValue) = it.table.entries[k]
	return true
}

func (it *fakeStatsIterator) Err() error { return nil }

var _ edgemap.Table = (*fakeStatsTable)(nil)

// fakeDropReasons is an in-memory DropReasonsReader for tests -- same
// shape as internal/plumbing/ebpf/metrics's identical fake.
type fakeDropReasons map[uint32]uint64

func (f fakeDropReasons) Lookup(key, valueOut any) error {
	k := key.(uint32)
	out := valueOut.(*[]uint64)
	*out = []uint64{f[k]}
	return nil
}

var _ DropReasonsReader = fakeDropReasons{}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("netip.ParseAddr(%q): %v", s, err)
	}
	return a
}

// collectedMetric pairs a prometheus.Metric with its decoded protobuf
// form, so tests can filter by Desc() identity (distinguishing e.g.
// rulePacketsDesc from ruleBytesDesc even though both share the same
// label set) and then assert on the decoded value/labels.
type collectedMetric struct {
	desc *prometheus.Desc
	pb   *dto.Metric
}

// collect runs c's Collect method to completion and returns every emitted
// metric, decoded to its protobuf form alongside its Desc -- extends
// internal/plumbing/ebpf/metrics/collector_test.go's identical helper
// (which returns only the decoded form) with the Desc, since this
// package's per-rule metrics all share one label set (proto/port/vip)
// across five different Descs, unlike usid's Collector where every Desc
// carries visibly different values in these tests.
func collect(t *testing.T, c prometheus.Collector) []collectedMetric {
	t.Helper()
	ch := make(chan prometheus.Metric, 256)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	var out []collectedMetric
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		out = append(out, collectedMetric{desc: m.Desc(), pb: &pb})
	}
	return out
}

func labelValue(m *dto.Metric, name string) string {
	for _, lp := range m.GetLabel() {
		if lp.GetName() == name {
			return lp.GetValue()
		}
	}
	return ""
}

func metricValue(m *dto.Metric) float64 {
	switch {
	case m.Counter != nil:
		return m.Counter.GetValue()
	case m.Gauge != nil:
		return m.Gauge.GetValue()
	default:
		return 0
	}
}

// findMetric returns the single metric matching desc and, if labelName is
// non-empty, carrying labelVal for labelName. Fails the test if none or
// more than one match, so a broken disambiguation never silently passes.
func findMetric(
	t *testing.T, metrics []collectedMetric, desc *prometheus.Desc, labelName, labelVal string,
) *dto.Metric {
	t.Helper()
	var found *dto.Metric
	for _, m := range metrics {
		if m.desc != desc {
			continue
		}
		if labelName != "" && labelValue(m.pb, labelName) != labelVal {
			continue
		}
		if found != nil {
			t.Fatalf("multiple metrics matched desc %v with %s=%q", desc, labelName, labelVal)
		}
		found = m.pb
	}
	if found == nil {
		t.Fatalf("no metric found matching desc %v with %s=%q", desc, labelName, labelVal)
	}
	return found
}

func TestCollector_CollectsRuleCounters(t *testing.T) {
	table := newFakeVIPTable()
	statsTable := newFakeStatsTable()
	vt := edgemap.NewVIPTable(table, statsTable)
	key := edgemap.VIPKey{Proto: 6, VPort: 443, VIP: mustAddr(t, "2001:db8:1::10")}
	backend := edgemap.Backend{
		Addr: mustAddr(t, "fd00:10:1::20"),
		Port: 8443,
		USID: mustAddr(t, "2001:db8:2::1"),
	}
	if err := vt.Register(key, []edgemap.Backend{backend}, [edgemap.MaglevTableSize]byte{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Simulate datapath-accumulated counters directly on the fake stats
	// table's backing map, the way edgedsr.c's __sync_fetch_and_add calls
	// into vip_stats_table would in the real kernel map. LastSeenNs is
	// set behind "now" (the fake table's own clock, read via
	// vt.Generation() below) by exactly 5s.
	now := vt.Generation()
	for k := range table.entries {
		statsTable.entries[k] = edgeprog.EdgedsrVipStatsValue{
			Packets:        10,
			Bytes:          2000,
			DroppedPackets: 1,
			LastSeenNs:     now - 5_000_000_000,
		}
	}

	c := NewCollector(vt, fakeDropReasons{})
	metrics := collect(t, c)

	packets := findMetric(t, metrics, rulePacketsDesc, "vip", "2001:db8:1::10")
	if got := metricValue(packets); got != 10 {
		t.Errorf("rule_packets_total = %v, want 10", got)
	}
	if got := labelValue(packets, "proto"); got != "tcp" {
		t.Errorf("proto label = %q, want tcp", got)
	}
	if got := labelValue(packets, "port"); got != "443" {
		t.Errorf("port label = %q, want 443", got)
	}

	bytes := findMetric(t, metrics, ruleBytesDesc, "vip", "2001:db8:1::10")
	if got := metricValue(bytes); got != 2000 {
		t.Errorf("rule_bytes_total = %v, want 2000", got)
	}

	dropped := findMetric(t, metrics, ruleDroppedDesc, "vip", "2001:db8:1::10")
	if got := metricValue(dropped); got != 1 {
		t.Errorf("rule_dropped_packets_total = %v, want 1", got)
	}

	backends := findMetric(t, metrics, ruleBackendsDesc, "vip", "2001:db8:1::10")
	if got := metricValue(backends); got != 1 {
		t.Errorf("rule_backends = %v, want 1", got)
	}

	staleness := findMetric(t, metrics, ruleSecondsSinceLastPacketDesc, "vip", "2001:db8:1::10")
	if got := metricValue(staleness); got < 4.9 || got > 5.1 {
		t.Errorf("rule_seconds_since_last_packet = %v, want ~5", got)
	}
}

func TestCollector_OmitsSecondsSinceLastPacketWhenNeverSeen(t *testing.T) {
	table := newFakeVIPTable()
	vt := edgemap.NewVIPTable(table, newFakeStatsTable())
	key := edgemap.VIPKey{Proto: 6, VPort: 443, VIP: mustAddr(t, "2001:db8:1::10")}
	if err := vt.Register(key, []edgemap.Backend{{
		Addr: mustAddr(t, "fd00:10:1::20"), Port: 8443, USID: mustAddr(t, "2001:db8:2::1"),
	}}, [edgemap.MaglevTableSize]byte{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	c := NewCollector(vt, fakeDropReasons{})
	metrics := collect(t, c)

	// 4 metrics per rule (packets/bytes/dropped/backends) when
	// LastSeenNs == 0, not 5 -- the staleness gauge must be absent.
	count := 0
	for _, m := range metrics {
		if labelValue(m.pb, "vip") == "2001:db8:1::10" {
			count++
		}
	}
	if count != 4 {
		t.Errorf("metrics with vip label = %d, want 4 (staleness gauge must be omitted when never seen)", count)
	}
}

func TestCollector_CollectsDropsByReason(t *testing.T) {
	drops := fakeDropReasons{
		edgeprog.DropReasonEmptyBackendList: 3,
		edgeprog.DropReasonFibLookupFailed:  7,
	}
	c := NewCollector(edgemap.NewVIPTable(newFakeVIPTable(), newFakeStatsTable()), drops)
	metrics := collect(t, c)

	emptyBackends := findMetric(t, metrics, dropsDesc, "reason", "empty_backend_list")
	if got := metricValue(emptyBackends); got != 3 {
		t.Errorf("drops_total{reason=empty_backend_list} = %v, want 3", got)
	}
	fibFailed := findMetric(t, metrics, dropsDesc, "reason", "fib_lookup_failed")
	if got := metricValue(fibFailed); got != 7 {
		t.Errorf("drops_total{reason=fib_lookup_failed} = %v, want 7", got)
	}
}
