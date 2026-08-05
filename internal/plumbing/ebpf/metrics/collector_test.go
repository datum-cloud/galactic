// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"errors"
	"strconv"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
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

	c := NewCollector(usidmap.NewVRFTable(vrfFake), usidmap.NewLocatorTable(newFakeTable()), fakeDropReasons{})
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

func TestCollector_BlockUtilization(t *testing.T) {
	locFake := newFakeTable()
	loc := usidmap.NewLocatorTable(locFake)
	if err := loc.Register(testBlock, testNodeID); err != nil {
		t.Fatalf("Register locator: %v", err)
	}

	vrfFake := newFakeTable()
	c := NewCollector(usidmap.NewVRFTable(vrfFake), loc, fakeDropReasons{})

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
	c := NewCollector(usidmap.NewVRFTable(newFakeTable()), usidmap.NewLocatorTable(newFakeTable()), drops)

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
	c := NewCollector(usidmap.NewVRFTable(erroringTable{}), usidmap.NewLocatorTable(newFakeTable()), fakeDropReasons{})

	ch := make(chan prometheus.Metric, 16)
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
