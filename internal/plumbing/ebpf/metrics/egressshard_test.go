// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// snapshotStore is a GroupStore over fixed snapshots.
type snapshotStore map[uint32]prog.UsidEgressShardGroupValue

func (s snapshotStore) Load(id uint32) (prog.UsidEgressShardGroupValue, bool, error) {
	v, ok := s[id]
	return v, ok, nil
}

func (s snapshotStore) Publish(id uint32, v prog.UsidEgressShardGroupValue) error {
	s[id] = v
	return nil
}

// perCPUTable answers a per-CPU lookup with a fixed slice per key.
type perCPUTable map[uint32]any

func (p perCPUTable) Lookup(key, out any) error {
	v, ok := p[key.(uint32)]
	if !ok {
		v = reflect.MakeSlice(reflect.TypeOf(out).Elem(), 2, 2).Interface()
	}
	reflect.ValueOf(out).Elem().Set(reflect.ValueOf(v))
	return nil
}

func sidBytes(s string) [16]byte { return netip.MustParseAddr(s).As16() }

func TestEgressShardCollector(t *testing.T) {
	nat66 := prog.UsidEgressShardGroupValue{Flags: 1, Candidates: 3, Active: 1, ClassKind: 1}
	nat66.Shards[0] = prog.UsidEgressShardMember{Sid: sidBytes("2001:db8:ff09:10:e000::"), Flags: 1, Generation: 1}
	nat66.Shards[1] = prog.UsidEgressShardMember{Sid: sidBytes("2001:db8:ff09:11:e000::"), Flags: 3, Generation: 2}
	nat66.Shards[4] = prog.UsidEgressShardMember{Sid: sidBytes("2001:db8:ff09:12:e000::"), Flags: 0, Generation: 3}
	// A NAT64 class no shard can serve, being retired: it forwards but is
	// not open.
	nat64 := prog.UsidEgressShardGroupValue{Flags: 1 | 4, Ineligible: 3, ClassKind: 2,
		ClassPrefix: sidBytes("2001:db8:64::")}
	store := snapshotStore{0: nat66, 1: nat64, 2: {ClassKind: 2}}
	counters := perCPUTable{
		uint32(0): []prog.UsidEgressShardCounter{{Packets: 3, Bytes: 300}, {Packets: 4, Bytes: 400}},
	}
	stats := perCPUTable{
		prog.EgressShardStatMaglev:     []uint64{5, 6},
		prog.EgressShardStatGroupEmpty: []uint64{1, 0},
	}
	c := NewEgressShardCollector(egressroutemap.NewShardGroupTable(store), counters, stats, 2)

	got := map[string]float64{}
	for _, m := range collectNamed(t, c) {
		got[m.name] = m.value
	}
	const nat64Class = `class="nat64:2001:db8:64::/96"`
	want := map[string]float64{
		`galactic_cni_egress_pool_min_active`:                                                        2,
		`galactic_cni_egress_pool_enabled{class="nat66"}`:                                            1,
		`galactic_cni_egress_pool_enabled{` + nat64Class + `}`:                                       0,
		`galactic_cni_egress_pool_members{class="nat66",state="active"}`:                             1,
		`galactic_cni_egress_pool_members{class="nat66",state="draining"}`:                           1,
		`galactic_cni_egress_pool_members{class="nat66",state="unreachable"}`:                        1,
		`galactic_cni_egress_pool_members{class="nat66",state="ineligible"}`:                         0,
		`galactic_cni_egress_pool_members{` + nat64Class + `,state="active"}`:                        0,
		`galactic_cni_egress_pool_members{` + nat64Class + `,state="ineligible"}`:                    3,
		`galactic_cni_egress_shard_packets_total{class="nat66",shard_sid="2001:db8:ff09:10:e000::"}`: 7,
		`galactic_cni_egress_shard_bytes_total{class="nat66",shard_sid="2001:db8:ff09:10:e000::"}`:   700,
		`galactic_cni_egress_shard_packets_total{class="nat66",shard_sid="2001:db8:ff09:12:e000::"}`: 0,
		`galactic_cni_egress_shard_selections_total{result="maglev"}`:                                11,
		`galactic_cni_egress_shard_selections_total{result="group_empty"}`:                           1,
		`galactic_cni_egress_shard_selections_total{result="pin_hit"}`:                               0,
	}
	for name, value := range want {
		if v, ok := got[name]; !ok || v != value {
			t.Errorf("%s = %v (present %v), want %v", name, v, ok, value)
		}
	}
	for name := range got {
		if strings.Contains(name, `class="nat64:::/96"`) {
			t.Errorf("an empty, disabled group was reported: %s", name)
		}
	}
}

// TestEgressShardCollectorReportsNothingUnpublished checks that a node with no
// published group reports no pool series at all, rather than zeros that read
// as an empty but healthy pool.
func TestEgressShardCollectorReportsNothingUnpublished(t *testing.T) {
	c := NewEgressShardCollector(egressroutemap.NewShardGroupTable(snapshotStore{}), perCPUTable{}, perCPUTable{}, 1)
	for _, m := range collectNamed(t, c) {
		if strings.HasPrefix(m.name, "galactic_cni_egress_pool_members") ||
			strings.HasPrefix(m.name, "galactic_cni_egress_pool_enabled") {
			t.Errorf("unpublished node reported %s", m.name)
		}
	}
}

func TestEgressControlSeries(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewEgressControl(reg)
	c.SetMode("hashed", "ordered", "hashed")
	c.SetWatchSynced(false)
	c.SetGroupRoutes(map[string]int{"nat66": 4})
	c.SweepError("refresh")
	got := map[string]float64{}
	for _, m := range collectNamed(t, registryCollector{reg}) {
		got[m.name] = m.value
	}
	for name, value := range map[string]float64{
		`galactic_cni_egress_mode{mode="hashed"}`:                 1,
		`galactic_cni_egress_mode{mode="ordered"}`:                0,
		`galactic_cni_egress_shard_watch_synced`:                  0,
		`galactic_cni_egress_group_routes{class="nat66"}`:         4,
		`galactic_cni_egress_sweep_errors_total{stage="refresh"}`: 1,
		`galactic_cni_egress_sweep_errors_total{stage="apply"}`:   0,
	} {
		if v, ok := got[name]; !ok || v != value {
			t.Errorf("%s = %v (present %v), want %v", name, v, ok, value)
		}
	}
	var nilControl *EgressControl
	nilControl.SweepError("apply") // must not panic
}

// registryCollector adapts a registry to prometheus.Collector for collectNamed.
type registryCollector struct{ reg *prometheus.Registry }

func (r registryCollector) Describe(chan<- *prometheus.Desc) {}

func (r registryCollector) Collect(ch chan<- prometheus.Metric) {
	families, _ := r.reg.Gather()
	for _, f := range families {
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			names := make([]string, 0, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
				names = append(names, lp.GetName())
			}
			desc := prometheus.NewDesc(f.GetName(), f.GetHelp(), names, nil)
			values := make([]string, 0, len(names))
			for _, n := range names {
				values = append(values, labels[n])
			}
			v := m.GetGauge().GetValue()
			if m.GetCounter() != nil {
				v = m.GetCounter().GetValue()
			}
			ch <- prometheus.MustNewConstMetric(desc, prometheus.UntypedValue, v, values...)
		}
	}
}

type namedMetric struct {
	name  string
	value float64
}

// collectNamed collects c and names each metric as name{label="value",...}.
func collectNamed(t *testing.T, c prometheus.Collector) []namedMetric {
	t.Helper()
	ch := make(chan prometheus.Metric, 256)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	var out []namedMetric
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		desc := m.Desc().String()
		start := strings.Index(desc, `fqName: "`) + len(`fqName: "`)
		name := desc[start : start+strings.Index(desc[start:], `"`)]
		labels := make([]string, 0, len(pb.GetLabel()))
		for _, lp := range pb.GetLabel() {
			labels = append(labels, lp.GetName()+`="`+lp.GetValue()+`"`)
		}
		if len(labels) > 0 {
			name += "{" + strings.Join(labels, ",") + "}"
		}
		out = append(out, namedMetric{name: name, value: metricValue(&pb)})
	}
	return out
}
