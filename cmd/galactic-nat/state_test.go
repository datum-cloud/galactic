// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"go.datum.net/galactic/internal/controller"
	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

const (
	testUplink0 = "up0"
	testUplink1 = "up1"

	metricDatapathEnabled  = "galactic_nat_datapath_enabled"
	metricDatapathAttached = "galactic_nat_datapath_attached"
	metricProgrammed       = "galactic_nat_programmed"
	metricUplinkCovered    = "galactic_nat_uplink_covered"
	metricFamilyEnabled    = "galactic_nat_family_enabled"
	metricInfo             = "galactic_nat_info"
	metricPacketsTotal     = "galactic_nat_packets_total"
	metricBytesTotal       = "galactic_nat_bytes_total"
)

// gatherAll collects c through a registry and returns every series by metric
// name and its label values joined with "/", counters and gauges alike.
func gatherAll(t *testing.T, c prometheus.Collector) map[string]map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := map[string]map[string]float64{}
	for _, mf := range families {
		series := map[string]float64{}
		for _, m := range mf.GetMetric() {
			labels := make([]string, 0, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				labels = append(labels, lp.GetValue())
			}
			value := m.GetGauge().GetValue()
			if mf.GetType() == dto.MetricType_COUNTER {
				value = m.GetCounter().GetValue()
			}
			series[strings.Join(labels, "/")] = value
		}
		out[mf.GetName()] = series
	}
	return out
}

// fakeTraffic is a natmap.TrafficReader over fixed per-CPU slot values.
type fakeTraffic struct {
	perCPU map[uint32][]natprog.NatNatTrafficCounter
	err    error
}

func (f fakeTraffic) Lookup(key, valueOut any) error {
	if f.err != nil {
		return f.err
	}
	*valueOut.(*[]natprog.NatNatTrafficCounter) = f.perCPU[key.(uint32)]
	return nil
}

func TestNatCollectorReportsTranslatedTraffic(t *testing.T) {
	outboundRedirect := natprog.TrafficSlot(natprog.TrafficFamilyNAT66, natprog.TrafficDirectionOutbound,
		natprog.TrafficActionRedirect)
	returnTX := natprog.TrafficSlot(natprog.TrafficFamilyNAT64, natprog.TrafficDirectionReturn,
		natprog.TrafficActionTX)
	c := &natCollector{traffic: fakeTraffic{perCPU: map[uint32][]natprog.NatNatTrafficCounter{
		outboundRedirect: {{Packets: 2, Bytes: 200}, {Packets: 3, Bytes: 300}},
		returnTX:         {{Packets: 1, Bytes: 60}},
	}}}

	got := gatherAll(t, c)
	for _, name := range []string{metricPacketsTotal, metricBytesTotal} {
		if n := len(got[name]); n != 8 {
			t.Errorf("%s has %d series, want all 8 family/direction/action combinations: %v", name, n, got[name])
		}
	}
	checks := []struct {
		name, labels string
		want         float64
	}{
		{metricPacketsTotal, "redirect/outbound/nat66", 5},
		{metricBytesTotal, "redirect/outbound/nat66", 500},
		{metricPacketsTotal, "tx/return/nat64", 1},
		{metricBytesTotal, "tx/return/nat64", 60},
		{metricPacketsTotal, "tx/outbound/nat66", 0},
	}
	for _, c := range checks {
		if v, ok := got[c.name][c.labels]; !ok || v != c.want {
			t.Errorf("%s{%s} = %v (present %v), want %v", c.name, c.labels, v, ok, c.want)
		}
	}
}

func TestNatCollectorTrafficReadErrorKeepsOtherSeries(t *testing.T) {
	c := &natCollector{
		traffic:     fakeTraffic{err: errors.New("lookup failed")},
		dropReasons: fakeDropReasons{},
	}
	got := gatherAll(t, c)
	if _, ok := got[metricPacketsTotal]; ok {
		t.Errorf("reported %s after a failed nat_traffic read", metricPacketsTotal)
	}
	if len(got["galactic_nat_drops_total"]) == 0 {
		t.Error("a failed nat_traffic read suppressed the drop counters")
	}
}

// fakeDropReasons answers every drop_reasons lookup with one CPU's zero.
type fakeDropReasons struct{}

func (fakeDropReasons) Lookup(_, valueOut any) error {
	*valueOut.(*[]uint64) = []uint64{0}
	return nil
}

// fakeShard is a controller.EgressDatapath with a fixed state, and the uplinks
// and coverage a natDatapath reports.
type fakeShard struct {
	attached   bool
	uplinks    []string
	missing    []string
	identity   controller.EgressShardIdentity
	programmed bool
}

func (f fakeShard) Attached() bool                             { return f.attached }
func (f fakeShard) MissingUplinks() []string                   { return f.missing }
func (f fakeShard) Coverage() ([]string, []string)             { return f.uplinks, f.missing }
func (fakeShard) Program(controller.EgressShardIdentity) error { return nil }
func (fakeShard) Clear() error                                 { return nil }
func (f fakeShard) Programmed() (controller.EgressShardIdentity, bool) {
	return f.identity, f.programmed
}

func TestShardStateCollector(t *testing.T) {
	sid := netip.MustParseAddr("fc00:1:2::")
	tests := []struct {
		name     string
		datapath controller.EgressDatapath
		enabled  bool
		want     map[string]map[string]float64
	}{
		{
			name: "ProgrammedNAT66MissingOneUplink",
			datapath: fakeShard{
				attached: true, uplinks: []string{testUplink0, testUplink1}, missing: []string{testUplink1}, programmed: true,
				identity: controller.EgressShardIdentity{
					ShardSID: sid, ShardAddressIPv6: netip.MustParseAddr("2001:db8::1"),
				},
			},
			enabled: true,
			want: map[string]map[string]float64{
				metricDatapathEnabled:  {"": 1},
				metricDatapathAttached: {"": 1},
				metricProgrammed:       {"": 1},
				metricUplinkCovered:    {testUplink0: 1, testUplink1: 0},
				metricFamilyEnabled:    {familyNAT66: 1, familyNAT64: 0},
				metricInfo:             {"/fc00:1:2::/test/dispatch": 1},
			},
		},
		{
			name:     "AttachedUnprogrammed",
			datapath: fakeShard{attached: true, uplinks: []string{testUplink0}},
			enabled:  true,
			want: map[string]map[string]float64{
				metricDatapathEnabled:  {"": 1},
				metricDatapathAttached: {"": 1},
				metricProgrammed:       {"": 0},
				metricUplinkCovered:    {testUplink0: 1},
				metricFamilyEnabled:    {familyNAT66: 0, familyNAT64: 0},
				metricInfo:             {"//test/dispatch": 1},
			},
		},
		{
			name:     "TurnedOff",
			datapath: disabledDatapath{},
			enabled:  false,
			want: map[string]map[string]float64{
				metricDatapathEnabled:  {"": 0},
				metricDatapathAttached: {"": 0},
				metricProgrammed:       {"": 0},
				metricFamilyEnabled:    {familyNAT66: 0, familyNAT64: 0},
				metricInfo:             {"//test/off": 1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newShardStateCollector(tt.datapath, tt.enabled, "dispatch")
			c.version = "test"
			got := gatherAll(t, c)
			if len(got) != len(tt.want) {
				t.Errorf("got metrics %v, want exactly %v", keys(got), keys(tt.want))
			}
			for name, series := range tt.want {
				for labels, want := range series {
					if v, ok := got[name][labels]; !ok || v != want {
						t.Errorf("%s{%s} = %v (present %v), want %v; all: %v", name, labels, v, ok, want, got[name])
					}
				}
				if len(got[name]) != len(series) {
					t.Errorf("%s has series %v, want %v", name, got[name], series)
				}
			}
		})
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
