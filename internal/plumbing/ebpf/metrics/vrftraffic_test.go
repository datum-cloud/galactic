// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"errors"
	"slices"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

const (
	forwardedPacketsName = "galactic_usid_vrf_forwarded_packets_total"
	forwardedBytesName   = "galactic_usid_vrf_forwarded_bytes_total"
	droppedPacketsName   = "galactic_usid_vrf_dropped_packets_total"
)

// fakeTrafficTable is an in-memory usidmap.CounterTable whose rows are
// per-CPU slices, the shape the kernel's per-CPU hash map hands back.
type fakeTrafficTable struct {
	keys    []uint64
	rows    map[uint64][]prog.UsidVrfTrafficValue
	iterErr error
}

func newFakeTrafficTable() *fakeTrafficTable {
	return &fakeTrafficTable{rows: make(map[uint64][]prog.UsidVrfTrafficValue)}
}

func (f *fakeTrafficTable) put(t *testing.T, argument uint16, perCPU ...prog.UsidVrfTrafficValue) {
	t.Helper()
	key, err := uformat.NewVRFKey(testBlock, argument)
	if err != nil {
		t.Fatalf("uformat.NewVRFKey: %v", err)
	}
	if _, ok := f.rows[uint64(key)]; !ok {
		f.keys = append(f.keys, uint64(key))
	}
	f.rows[uint64(key)] = perCPU
}

func (f *fakeTrafficTable) Create(any, any) error { return errors.New("not implemented") }
func (f *fakeTrafficTable) Delete(any) error      { return errors.New("not implemented") }

func (f *fakeTrafficTable) Iterate() usidmap.Iterator {
	return &fakeTrafficIterator{table: f}
}

type fakeTrafficIterator struct {
	table *fakeTrafficTable
	idx   int
}

func (it *fakeTrafficIterator) Next(keyOut, valueOut any) bool {
	if it.table.iterErr != nil || it.idx >= len(it.table.keys) {
		return false
	}
	k := it.table.keys[it.idx]
	it.idx++
	*keyOut.(*uint64) = k
	*valueOut.(*[]prog.UsidVrfTrafficValue) = slices.Clone(it.table.rows[k])
	return true
}

func (it *fakeTrafficIterator) Err() error { return it.table.iterErr }

func trafficValue(inPackets, inBytes, inDrops, outPackets, outBytes, outDrops uint64) prog.UsidVrfTrafficValue {
	return prog.UsidVrfTrafficValue{
		Ingress: prog.UsidVrfDirectionCounter{Packets: inPackets, Bytes: inBytes, DroppedPackets: inDrops},
		Egress:  prog.UsidVrfDirectionCounter{Packets: outPackets, Bytes: outBytes, DroppedPackets: outDrops},
	}
}

// sampleKey names one per-VRF, per-direction series.
type sampleKey struct {
	name, argument, direction string
}

// gatherTraffic collects c through a registry and returns the per-direction
// VRF samples by name, Argument and direction, with the vpc label of each.
func gatherTraffic(t *testing.T, c prometheus.Collector) (values map[sampleKey]float64, vpcs map[sampleKey]string) {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	values, vpcs = map[sampleKey]float64{}, map[sampleKey]string{}
	for _, f := range families {
		switch f.GetName() {
		case forwardedPacketsName, forwardedBytesName, droppedPacketsName:
		default:
			continue
		}
		for _, m := range f.GetMetric() {
			k := sampleKey{f.GetName(), labelValue(m, "argument"), labelValue(m, "direction")}
			values[k] = metricValue(m)
			vpcs[k] = labelValue(m, "vpc")
		}
	}
	return values, vpcs
}

func newTrafficCollector(vrf, attribution *fakeTable, traffic *fakeTrafficTable) *Collector {
	var attr *usidmap.VPCAttributionTable
	if attribution != nil {
		attr = usidmap.NewVPCAttributionTable(attribution)
	}
	return NewCollector(usidmap.NewVRFTable(vrf), usidmap.NewLocatorTable(newFakeTable()), fakeDropReasons{}, attr).
		WithVRFTraffic(usidmap.NewVRFTrafficTable(traffic))
}

func TestCollector_VRFTrafficSumsCPUsPerDirection(t *testing.T) {
	vrfFake := newFakeTable()
	putVRFEntry(t, vrfFake, testBlock, 0x001, 7, 0, 0)
	putVRFEntry(t, vrfFake, testBlock, 0x002, 8, 0, 0)

	traffic := newFakeTrafficTable()
	traffic.put(t, 0x001,
		trafficValue(1, 100, 0, 2, 200, 1),
		trafficValue(3, 300, 2, 4, 400, 0))
	traffic.put(t, 0x002, trafficValue(0, 0, 0, 5, 1500, 0))

	values, _ := gatherTraffic(t, newTrafficCollector(vrfFake, nil, traffic))

	want := map[sampleKey]float64{
		{forwardedPacketsName, "1", directionIngress}: 4,
		{forwardedBytesName, "1", directionIngress}:   400,
		{droppedPacketsName, "1", directionIngress}:   2,
		{forwardedPacketsName, "1", directionEgress}:  6,
		{forwardedBytesName, "1", directionEgress}:    600,
		{droppedPacketsName, "1", directionEgress}:    1,
		{forwardedPacketsName, "2", directionIngress}: 0,
		{forwardedBytesName, "2", directionIngress}:   0,
		{droppedPacketsName, "2", directionIngress}:   0,
		{forwardedPacketsName, "2", directionEgress}:  5,
		{forwardedBytesName, "2", directionEgress}:    1500,
		{droppedPacketsName, "2", directionEgress}:    0,
	}
	if len(values) != len(want) {
		t.Errorf("got %d per-direction samples, want %d: %v", len(values), len(want), values)
	}
	for k, w := range want {
		if got, ok := values[k]; !ok || got != w {
			t.Errorf("%v = %v (present %v), want %v", k, got, ok, w)
		}
	}
}

func TestCollector_VRFTrafficAttribution(t *testing.T) {
	vrfFake := newFakeTable()
	putVRFEntry(t, vrfFake, testBlock, 0x001, 7, 0, 0)
	putVRFEntry(t, vrfFake, testBlock, 0x002, 8, 0, 0)
	attrFake := newFakeTable()
	putVPCAttribution(t, attrFake, testBlock, 0x001, 0x2589, 0x07)

	traffic := newFakeTrafficTable()
	traffic.put(t, 0x001, trafficValue(1, 1, 0, 1, 1, 0))
	traffic.put(t, 0x002, trafficValue(1, 1, 0, 1, 1, 0))

	values, vpcs := gatherTraffic(t, newTrafficCollector(vrfFake, attrFake, traffic))

	attributed := sampleKey{forwardedPacketsName, "1", directionEgress}
	if vpcs[attributed] == "" {
		t.Errorf("argument=1 has an attribution row but its vpc label is empty")
	}
	missed := sampleKey{forwardedPacketsName, "2", directionEgress}
	if _, ok := values[missed]; !ok {
		t.Fatalf("argument=2 has no attribution row and was not reported; a miss must not drop the series")
	}
	if vpcs[missed] != "" {
		t.Errorf("argument=2 vpc label = %q, want empty for an attribution miss", vpcs[missed])
	}
}

func TestCollector_VRFTrafficEmptyMapReportsNoDirectionSeries(t *testing.T) {
	vrfFake := newFakeTable()
	putVRFEntry(t, vrfFake, testBlock, 0x001, 7, 10, 1000)

	c := newTrafficCollector(vrfFake, nil, newFakeTrafficTable())
	values, _ := gatherTraffic(t, c)
	if len(values) != 0 {
		t.Errorf("got per-direction samples %v from an empty vrf_traffic_counters, want none", values)
	}

	var sawPackets bool
	for _, m := range collect(t, c) {
		if labelValue(m, "argument") == "1" && labelValue(m, "direction") == "" && metricValue(m) == 10 {
			sawPackets = true
		}
	}
	if !sawPackets {
		t.Error("galactic_usid_vrf_packets_total missing: the existing series must not depend on vrf_traffic_counters")
	}
}

func TestCollector_VRFTrafficRowWithoutVRFIsNotReported(t *testing.T) {
	vrfFake := newFakeTable()
	putVRFEntry(t, vrfFake, testBlock, 0x001, 7, 0, 0)
	traffic := newFakeTrafficTable()
	traffic.put(t, 0x001, trafficValue(1, 1, 0, 1, 1, 0))
	traffic.put(t, 0x003, trafficValue(9, 9, 9, 9, 9, 9))

	values, _ := gatherTraffic(t, newTrafficCollector(vrfFake, nil, traffic))
	for k := range values {
		if k.argument == "3" {
			t.Errorf("reported %v for a counter row vrf_table no longer holds", k)
		}
	}
}

func TestCollector_VRFTrafficListErrorReportsInvalidMetric(t *testing.T) {
	vrfFake := newFakeTable()
	putVRFEntry(t, vrfFake, testBlock, 0x001, 7, 10, 1000)
	traffic := newFakeTrafficTable()
	traffic.iterErr = errors.New("simulated map iteration failure")

	c := newTrafficCollector(vrfFake, nil, traffic)
	ch := make(chan prometheus.Metric, 64)
	c.collectVRF(ch)
	close(ch)

	var invalid, vrfSamples int
	for m := range ch {
		if err := m.Write(new(dto.Metric)); err != nil {
			invalid++
			continue
		}
		vrfSamples++
	}
	if invalid != 1 {
		t.Errorf("got %d invalid metrics, want 1 for the failed vrf_traffic_counters read", invalid)
	}
	if vrfSamples == 0 {
		t.Error("a failed vrf_traffic_counters read suppressed every per-VRF sample")
	}
}
