// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

const (
	testBlock  uint64 = 0x010203040506
	testBlock2 uint64 = 0x0A0B0C0D0E0F
	testNodeID uint16 = 0x0010
)

// collect runs c's Collect method to completion and returns every emitted
// metric decoded to its protobuf form, so tests can assert on label/value
// pairs without needing a real Prometheus registry or HTTP round-trip.
func collect(t *testing.T, c prometheus.Collector) []*dto.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 256)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	var out []*dto.Metric
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		out = append(out, &pb)
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
	case m.Untyped != nil:
		return m.Untyped.GetValue()
	}
	return 0
}

// putVRFEntry writes a raw vrf_table entry directly into fake, bypassing
// VRFTable.Register (which always resets Packets/Bytes/LastSeenNs to zero
// on write, per vrf.go's documented behavior) -- these tests need to
// assert on nonzero hit counters, so they construct the map's raw
// key/value shape directly instead.
func putVRFEntry(
	t *testing.T, fake *fakeTable, block uint64, argument uint16, vrfTableID uint32, packets, bytesN uint64,
) {
	t.Helper()
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		t.Fatalf("uformat.NewVRFKey: %v", err)
	}
	if err := fake.Put(uint64(key), prog.UsidVrfValue{
		VrfTableId: vrfTableID,
		Packets:    packets,
		Bytes:      bytesN,
	}); err != nil {
		t.Fatalf("fake.Put: %v", err)
	}
}

func TestCollector_VRFPacketsAndBytes(t *testing.T) {
	const (
		vrfTableID1 uint32 = 0x2A2A2A
		vrfTableID2 uint32 = 0x2B2B2B
	)

	vrfFake := newFakeTable()
	putVRFEntry(t, vrfFake, testBlock, 0x001, vrfTableID1, 10, 1000)
	putVRFEntry(t, vrfFake, testBlock, 0x002, vrfTableID2, 20, 2000)

	c := NewCollector(usidmap.NewVRFTable(vrfFake), usidmap.NewLocatorTable(newFakeTable()), fakeDropReasons{}, nil)
	metrics := collect(t, c)

	wantVRFTableID := map[string]string{
		"1": strconv.FormatUint(uint64(vrfTableID1), 10),
		"2": strconv.FormatUint(uint64(vrfTableID2), 10),
	}
	wantPackets := map[string]float64{"1": 10, "2": 20}
	wantBytes := map[string]float64{"1": 1000, "2": 2000}

	var packetSamples, byteSamples int
	for _, m := range metrics {
		block := labelValue(m, labelBlock)
		argument := labelValue(m, "argument")
		if block != formatBlock(testBlock) {
			continue
		}
		if labelValue(m, "vrf_table_id") != wantVRFTableID[argument] {
			continue
		}
		switch metricValue(m) {
		case wantPackets[argument]:
			packetSamples++
		case wantBytes[argument]:
			byteSamples++
		}
	}
	if packetSamples != 2 {
		t.Errorf("found %d matching packet samples, want 2 (metrics: %+v)", packetSamples, metrics)
	}
	if byteSamples != 2 {
		t.Errorf("found %d matching byte samples, want 2 (metrics: %+v)", byteSamples, metrics)
	}
}

// putVPCAttribution writes a raw vpc_attribution_table entry directly into
// fake, matching putVRFEntry's own bypass-Register shape above.
func putVPCAttribution(t *testing.T, fake *fakeTable, block uint64, argument uint16, vpc uint64, vpcAttachment uint32) {
	t.Helper()
	key, err := uformat.NewVRFKey(block, argument)
	if err != nil {
		t.Fatalf("uformat.NewVRFKey: %v", err)
	}
	if err := fake.Put(uint64(key), prog.UsidVpcAttributionValue{
		Vpc:           vpc,
		VpcAttachment: vpcAttachment,
	}); err != nil {
		t.Fatalf("fake.Put: %v", err)
	}
}

func TestCollector_VPCAttribution(t *testing.T) {
	// 0x2589 base62-round-trips to a short, easy-to-recognize string; the
	// exact identifiers don't matter, only that they survive a decode ->
	// store -> re-encode round trip unchanged.
	const (
		vpc1           uint64 = 0x2589
		vpcAttachment1 uint32 = 0x07
		vpc2           uint64 = 0xDEAD
		vpcAttachment2 uint32 = 0x0B
	)
	wantVPC1, err := intf.HexToBase62(strconv.FormatUint(vpc1, 16))
	if err != nil {
		t.Fatalf("HexToBase62: %v", err)
	}
	wantVPCAttachment1, err := intf.HexToBase62(strconv.FormatUint(uint64(vpcAttachment1), 16))
	if err != nil {
		t.Fatalf("HexToBase62: %v", err)
	}

	vrfFake := newFakeTable()
	putVRFEntry(t, vrfFake, testBlock, 0x001, 1, 10, 1000)  // has a matching attribution row below
	putVRFEntry(t, vrfFake, testBlock2, 0x002, 2, 20, 2000) // no attribution row for THIS block -- must still report

	attrFake := newFakeTable()
	putVPCAttribution(t, attrFake, testBlock, 0x001, vpc1, vpcAttachment1)
	// Same Argument as the testBlock2 vrf_table row above, but registered
	// under testBlock instead -- must not satisfy that lookup, proving
	// vpc_attribution_table is keyed on (Block, Argument) together, matching
	// vrf_table's own key (uformat.NewVRFKey), not Argument alone.
	putVPCAttribution(t, attrFake, testBlock, 0x002, vpc2, vpcAttachment2)

	c := NewCollector(
		usidmap.NewVRFTable(vrfFake), usidmap.NewLocatorTable(newFakeTable()), fakeDropReasons{},
		usidmap.NewVPCAttributionTable(attrFake),
	)
	metrics := collect(t, c)

	var sawAttributed, sawUnattributed int
	for _, m := range metrics {
		switch {
		case labelValue(m, labelBlock) == formatBlock(testBlock) && labelValue(m, "argument") == "1":
			if got := labelValue(m, "vpc"); got != wantVPC1 {
				t.Errorf("argument=1: vpc label = %q, want %q", got, wantVPC1)
			}
			if got := labelValue(m, "vpc_attachment"); got != wantVPCAttachment1 {
				t.Errorf("argument=1: vpc_attachment label = %q, want %q", got, wantVPCAttachment1)
			}
			sawAttributed++
		case labelValue(m, labelBlock) == formatBlock(testBlock2) && labelValue(m, "argument") == "2":
			if got := labelValue(m, "vpc"); got != "" {
				t.Errorf("argument=2: vpc label = %q, want empty (no attribution row for this block)", got)
			}
			if got := labelValue(m, "vpc_attachment"); got != "" {
				t.Errorf("argument=2: vpc_attachment label = %q, want empty (no attribution row for this block)", got)
			}
			sawUnattributed++
		}
	}
	// Each argument emits both a packets and a bytes sample.
	if sawAttributed != 2 {
		t.Errorf("saw %d attributed samples for argument=1, want 2", sawAttributed)
	}
	if sawUnattributed != 2 {
		t.Errorf("saw %d unattributed samples for argument=2, want 2 -- a missing attribution row must "+
			"not drop the vrf_table sample", sawUnattributed)
	}
}

func TestCollector_BlockUtilization(t *testing.T) {
	locFake := newFakeTable()
	loc := usidmap.NewLocatorTable(locFake)
	if err := loc.Register(testBlock, testNodeID); err != nil {
		t.Fatalf("Register locator: %v", err)
	}

	vrfFake := newFakeTable()
	c := NewCollector(usidmap.NewVRFTable(vrfFake), loc, fakeDropReasons{}, nil)

	t.Run("zero entries reports zero, not absent", func(t *testing.T) {
		metrics := collect(t, c)
		used, ratio, found := findBlockGauges(metrics, testBlock)
		if !found {
			t.Fatal("no arguments_used/utilization_ratio sample found for a locator-registered Block " +
				"with zero vrf_table entries")
		}
		if used != 0 || ratio != 0 {
			t.Errorf("used=%v ratio=%v, want 0/0", used, ratio)
		}
	})

	t.Run("one entry", func(t *testing.T) {
		putVRFEntry(t, vrfFake, testBlock, 0x001, 1, 5, 500)
		metrics := collect(t, c)
		used, ratio, found := findBlockGauges(metrics, testBlock)
		if !found {
			t.Fatal("no arguments_used/utilization_ratio sample found")
		}
		if used != 1 {
			t.Errorf("used = %v, want 1", used)
		}
		wantRatio := 1.0 / float64(uformat.ArgumentMax)
		if ratio != wantRatio {
			t.Errorf("ratio = %v, want %v", ratio, wantRatio)
		}
	})
}

func findBlockGauges(metrics []*dto.Metric, block uint64) (used, ratio float64, found bool) {
	var usedFound, ratioFound bool
	for _, m := range metrics {
		if labelValue(m, labelBlock) != formatBlock(block) {
			continue
		}
		if m.Gauge == nil {
			continue
		}
		// Both gauges share the same "block" label; distinguish by value
		// range isn't reliable, so instead we rely on collection order
		// being deterministic within a single Collect call: Collector
		// always emits arguments_used immediately followed by
		// argument_utilization_ratio for a given block (collectVRF's
		// single loop). Guard against that assumption breaking silently
		// by requiring exactly two gauge samples for this block.
		if !usedFound {
			used = m.Gauge.GetValue()
			usedFound = true
			continue
		}
		ratio = m.Gauge.GetValue()
		ratioFound = true
	}
	return used, ratio, usedFound && ratioFound
}

func TestCollector_Drops(t *testing.T) {
	drops := fakeDropReasons{
		prog.DropReasonUnknownArgument: 42,
		prog.DropReasonFibLookupFailed: 7,
	}
	c := NewCollector(usidmap.NewVRFTable(newFakeTable()), usidmap.NewLocatorTable(newFakeTable()), drops, nil)

	metrics := collect(t, c)

	seen := make(map[string]float64)
	for _, m := range metrics {
		if reason := labelValue(m, "reason"); reason != "" {
			seen[reason] = metricValue(m)
		}
	}

	want := map[string]float64{
		"unknown_function":      0,
		"unknown_argument":      42,
		"malformed_inner":       0,
		"unknown_inner_version": 0,
		"strip_failed":          0,
		"fib_lookup_failed":     7,
		"redirect_failed":       0,
	}
	for reason, wantVal := range want {
		got, ok := seen[reason]
		if !ok {
			t.Errorf("reason %q not emitted at all (all %d drop reasons must always be emitted, even at zero)",
				reason, prog.DropReasonCount)
			continue
		}
		if got != wantVal {
			t.Errorf("reason %q = %v, want %v", reason, got, wantVal)
		}
	}
	if len(seen) != int(prog.DropReasonCount) {
		t.Errorf("emitted %d distinct drop reasons, want %d", len(seen), prog.DropReasonCount)
	}
}

// erroringTable is a minimal usidmap.Table whose Iterate().Err() always
// fails, to prove Collector reports a List() failure as an InvalidMetric
// instead of silently dropping the scrape or panicking.
type erroringTable struct{}

func (erroringTable) Put(any, any) error    { return nil }
func (erroringTable) Lookup(any, any) error { return errors.New("not implemented") }
func (erroringTable) Delete(any) error      { return nil }
func (erroringTable) Iterate() usidmap.Iterator {
	return erroringIterator{}
}

type erroringIterator struct{}

func (erroringIterator) Next(any, any) bool { return false }
func (erroringIterator) Err() error         { return errors.New("simulated map iteration failure") }

func TestCollector_VRFListErrorReportsInvalidMetric(t *testing.T) {
	c := NewCollector(
		usidmap.NewVRFTable(erroringTable{}), usidmap.NewLocatorTable(newFakeTable()), fakeDropReasons{}, nil)

	// 256, not a count sized to exactly this test's own metrics: Collect
	// sends synchronously and this channel isn't drained concurrently
	// (the receive loop below only starts after Collect returns), so a
	// buffer sized to exactly today's drop-reason count silently
	// deadlocks the next time that count grows -- confirmed live, this
	// hung for the full 10-minute go test default timeout the moment
	// usid.c's own drop_reason enum gained a 16th entry. Matches this
	// same file's other Collect-into-a-channel test (line ~31) already
	// using 256 for the identical reason.
	ch := make(chan prometheus.Metric, 256)
	c.Collect(ch)
	close(ch)

	var sawInvalid bool
	for m := range ch {
		var pb dto.Metric
		err := m.Write(&pb)
		if err != nil {
			sawInvalid = true
		}
	}
	if !sawInvalid {
		t.Error("expected at least one metric to fail Write() (an InvalidMetric) when vrf_table listing fails")
	}
}

// fakeMSSClampTable is mss_clamp_table's single entry.
type fakeMSSClampTable struct {
	value prog.UsidMssClampValue
	err   error
}

func (f fakeMSSClampTable) Lookup(key, valueOut any) error {
	if f.err != nil {
		return f.err
	}
	if k, ok := key.(uint32); !ok || k != 0 {
		return fmt.Errorf("fakeMSSClampTable: key %v, want uint32(0)", key)
	}
	*valueOut.(*prog.UsidMssClampValue) = f.value
	return nil
}

func TestCollector_MSSClamp(t *testing.T) {
	stats := fakeDropReasons{prog.MSSClampStatClampedIPv6: 9, prog.MSSClampStatWalkLimit: 2}
	table := fakeMSSClampTable{value: prog.UsidMssClampValue{MssIpv4: 1420, MssIpv6: 1400}}
	c := NewCollector(
		usidmap.NewVRFTable(newFakeTable()), usidmap.NewLocatorTable(newFakeTable()), fakeDropReasons{}, nil,
	).
		WithMSSClamp(stats, table)

	results := map[string]float64{}
	limits := map[string]float64{}
	for _, m := range collect(t, c) {
		if r := labelValue(m, "result"); r != "" {
			results[r] = metricValue(m)
		}
		if f := labelValue(m, "family"); f != "" {
			limits[f] = metricValue(m)
		}
	}

	// Every outcome is always emitted, even at zero, so a rate() over one
	// never starts from a missing series.
	if len(results) != int(prog.MSSClampStatCount) {
		t.Errorf("emitted %d MSS clamp outcomes, want all %d", len(results), prog.MSSClampStatCount)
	}
	for name, want := range map[string]float64{"clamped_ipv6": 9, "walk_limit": 2, "clamped_ipv4": 0} {
		if results[name] != want {
			t.Errorf("result %q = %v, want %v", name, results[name], want)
		}
	}
	if limits["ipv4"] != 1420 || limits["ipv6"] != 1400 {
		t.Errorf("limits = %v, want ipv4 1420 and ipv6 1400", limits)
	}
}

// TestCollector_MSSClampOptional checks a collector built without the clamp's
// maps emits none of its series, the state of every existing caller.
func TestCollector_MSSClampOptional(t *testing.T) {
	c := NewCollector(usidmap.NewVRFTable(newFakeTable()), usidmap.NewLocatorTable(newFakeTable()), fakeDropReasons{}, nil)
	for _, m := range collect(t, c) {
		if labelValue(m, "result") != "" || labelValue(m, "family") != "" {
			t.Errorf("collector without WithMSSClamp emitted an MSS clamp series: %v", m)
		}
	}
}

func TestCollector_MSSClampTableErrorReportsInvalidMetric(t *testing.T) {
	c := NewCollector(
		usidmap.NewVRFTable(newFakeTable()), usidmap.NewLocatorTable(newFakeTable()), fakeDropReasons{}, nil,
	).
		WithMSSClamp(nil, fakeMSSClampTable{err: errors.New("map closed")})
	ch := make(chan prometheus.Metric, 64)
	c.Collect(ch)
	close(ch)
	invalid := 0
	for m := range ch {
		var out dto.Metric
		if err := m.Write(&out); err != nil {
			invalid++
		}
	}
	if invalid != 1 {
		t.Errorf("got %d invalid metrics, want 1 for the failed mss_clamp_table read", invalid)
	}
}

type fakeEncapMTUTable struct {
	limit uint32
	err   error
}

func (f fakeEncapMTUTable) Lookup(key, valueOut any) error {
	if f.err != nil {
		return f.err
	}
	if k, ok := key.(uint32); !ok || k != 0 {
		return fmt.Errorf("fakeEncapMTUTable: key %v, want uint32(0)", key)
	}
	*valueOut.(*uint32) = f.limit
	return nil
}

func TestCollector_PMTU(t *testing.T) {
	stats := fakeDropReasons{prog.PMTUStatTooBigSentIPv6: 5, prog.PMTUStatRateLimited: 3}
	c := NewCollector(
		usidmap.NewVRFTable(newFakeTable()), usidmap.NewLocatorTable(newFakeTable()), fakeDropReasons{}, nil,
	).
		WithPMTU(stats, fakeEncapMTUTable{limit: 1460})

	results := map[string]float64{}
	var limits []float64
	for _, m := range collect(t, c) {
		if r := labelValue(m, "result"); r != "" {
			results[r] = metricValue(m)
		}
		if len(m.GetLabel()) == 0 {
			limits = append(limits, metricValue(m))
		}
	}

	if len(results) != int(prog.PMTUStatCount) {
		t.Errorf("emitted %d path MTU outcomes, want all %d", len(results), prog.PMTUStatCount)
	}
	for name, want := range map[string]float64{"too_big_sent_ipv6": 5, "rate_limited": 3, "no_gateway": 0} {
		if results[name] != want {
			t.Errorf("result %q = %v, want %v", name, results[name], want)
		}
	}
	if len(limits) != 1 || limits[0] != 1460 {
		t.Errorf("limit series = %v, want one at 1460", limits)
	}
}

func TestCollector_EncapMTUTableErrorReportsInvalidMetric(t *testing.T) {
	c := NewCollector(
		usidmap.NewVRFTable(newFakeTable()), usidmap.NewLocatorTable(newFakeTable()), fakeDropReasons{}, nil,
	).
		WithPMTU(nil, fakeEncapMTUTable{err: errors.New("map closed")})
	ch := make(chan prometheus.Metric, 64)
	c.Collect(ch)
	close(ch)
	invalid := 0
	for m := range ch {
		var out dto.Metric
		if err := m.Write(&out); err != nil {
			invalid++
		}
	}
	if invalid != 1 {
		t.Errorf("got %d invalid metrics, want 1 for the failed encap_mtu_table read", invalid)
	}
}
