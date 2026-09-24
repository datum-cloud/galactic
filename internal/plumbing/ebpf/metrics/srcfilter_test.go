// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"maps"
	"net/netip"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/srcfiltermap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

func TestCollectorSourceFilter(t *testing.T) {
	filter, tables := srcfiltermap.NewFake()
	if err := filter.SetConfig(srcfiltermap.Config{Mode: srcfiltermap.ModeAudit, Populated: true}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"2001:db8:0:2::/64", "2001:db8:0:3::/64"} {
		if err := filter.PutAllow(srcfiltermap.Entry{Prefix: netip.MustParsePrefix(p), AnyIface: true}); err != nil {
			t.Fatal(err)
		}
	}
	stats := map[uint32][]uint64{
		prog.SrcFilterStatChecked:           {5, 5},
		prog.SrcFilterStatAllowed:           {4, 3},
		prog.SrcFilterStatDenyPrefix:        {1, 1},
		prog.SrcFilterStatDenyIface:         {0, 1},
		prog.SrcFilterStatBypassUnpopulated: {2, 0},
	}
	for slot, perCPU := range stats {
		if err := tables.Stats.Put(slot, perCPU); err != nil {
			t.Fatal(err)
		}
	}
	if err := tables.Denied.Put(prog.UsidSrcDeniedKey{Prefix: [8]uint8{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 9}},
		prog.UsidSrcDeniedValue{Count: 3, LastReason: prog.SrcFilterStatDenyPrefix}); err != nil {
		t.Fatal(err)
	}

	c := NewCollector(usidmap.NewVRFTable(newFakeTable()), nil, nil).WithSourceFilter(filter)
	got := gatherSrcFilter(t, c)
	want := map[string]float64{
		"galactic_usid_src_filter_packets_total/checked":            10,
		"galactic_usid_src_filter_packets_total/allowed":            7,
		"galactic_usid_src_filter_packets_total/deny_prefix":        2,
		"galactic_usid_src_filter_packets_total/deny_iface":         1,
		"galactic_usid_src_filter_packets_total/bypass_unpopulated": 2,
		"galactic_usid_src_filter_entries":                          2,
		"galactic_usid_src_filter_mode":                             1,
		"galactic_usid_src_filter_populated":                        1,
		"galactic_usid_src_filter_denied_sources":                   1,
	}
	if !maps.Equal(got, want) {
		t.Errorf("source filter series:\n got  %v\n want %v", got, want)
	}
}

// gatherSrcFilter registers c in a private registry and returns every
// galactic_usid_src_filter_* sample keyed by name, plus "/<result>" for the
// labeled counter.
func gatherSrcFilter(t *testing.T, c prometheus.Collector) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := make(map[string]float64)
	for _, mf := range families {
		if !strings.HasPrefix(mf.GetName(), "galactic_usid_src_filter_") {
			continue
		}
		for _, m := range mf.GetMetric() {
			key := mf.GetName()
			if r := labelValue(m, labelResult); r != "" {
				key += "/" + r
			}
			out[key] = metricValue(m)
		}
	}
	return out
}

func TestCollectorWithoutSourceFilterEmitsNone(t *testing.T) {
	c := NewCollector(usidmap.NewVRFTable(newFakeTable()), nil, nil)
	if got := gatherSrcFilter(t, c); len(got) != 0 {
		t.Errorf("src filter series emitted without a source filter: %v", got)
	}
}
