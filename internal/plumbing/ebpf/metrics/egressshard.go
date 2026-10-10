// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// egressNamespace prefixes the hashed egress series. They describe the
// galactic-cni installer's view of the cluster's egress shard pool, which is
// what the pool alert reads.
const egressNamespace = "galactic_cni"

// labelClass is the Prometheus label name for an egress translation class.
const labelClass = "class"

// The pool member states galactic_cni_egress_pool_members reports.
const (
	poolStateActive      = "active"
	poolStateDraining    = "draining"
	poolStateUnreachable = "unreachable"
	poolStateIneligible  = "ineligible"
)

var (
	egressShardPacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(egressNamespace, "egress_shard", "packets_total"),
		"Tenant packets this node encapsulated toward each egress shard, by the translation class whose group "+
			"placed them, counted since the shard took its slot.",
		[]string{"shard_sid", labelClass}, nil,
	)
	egressShardBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(egressNamespace, "egress_shard", "bytes_total"),
		"Tenant bytes this node encapsulated toward each egress shard, by the translation class whose group "+
			"placed them, counted since the shard took its slot.",
		[]string{"shard_sid", labelClass}, nil,
	)
	egressShardSelectionsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(egressNamespace, "egress_shard", "selections_total"),
		"How usid_egress placed each packet whose route names a shard group (egress_shard_stats map). "+
			"pin_hit and maglev forwarded it; pin_stale re-placed it; group_empty, shard_dead and "+
			"parse_failed dropped it.",
		[]string{labelResult}, nil,
	)
	egressPoolMembersDesc = prometheus.NewDesc(
		prometheus.BuildFQName(egressNamespace, "egress_pool", "members"),
		"The cluster's egress shards as this node's group for each translation class sees them: active shards "+
			"take new tenant addresses, draining ones serve only the tenants pinned to them, unreachable ones "+
			"have no route from this node, and ineligible ones cannot translate the class (no address in its "+
			"family, or another NAT64 prefix).",
		[]string{labelClass, "state"}, nil,
	)
	egressPoolMinActiveDesc = prometheus.NewDesc(
		prometheus.BuildFQName(egressNamespace, "egress_pool", "min_active"),
		"The fewest active egress shards each class is expected to have (GALACTIC_CNI_EGRESS_POOL_MIN_ACTIVE). "+
			"The pool alert compares galactic_cni_egress_pool_members{state=\"active\"} against it.",
		nil, nil,
	)
	egressPoolEnabledDesc = prometheus.NewDesc(
		prometheus.BuildFQName(egressNamespace, "egress_pool", "enabled"),
		"1 while the class's shard group takes new routes (hashed mode), else 0. A group being retired for the "+
			"move back to ordered mode still forwards but reads 0.",
		[]string{labelClass}, nil,
	)
)

// EgressShardCollector reads the hashed egress maps at every scrape: each
// class's shard group, each shard slot's packet and byte counters, and how
// usid_egress placed packets.
type EgressShardCollector struct {
	groups    *egressroutemap.ShardGroupTable
	counters  DropReasonsReader
	stats     DropReasonsReader
	minActive int
}

// NewEgressShardCollector builds a collector from already-constructed readers,
// so tests can pass fakes.
func NewEgressShardCollector(
	groups *egressroutemap.ShardGroupTable, counters, stats DropReasonsReader, minActive int,
) *EgressShardCollector {
	return &EgressShardCollector{groups: groups, counters: counters, stats: stats, minActive: minActive}
}

// RegisterEgressShardCollector registers an EgressShardCollector reading objs'
// maps, with minActive as the pool's expected floor.
func (m *Metrics) RegisterEgressShardCollector(objs *prog.UsidObjects, minActive int) error {
	groups := egressroutemap.NewShardGroupTable(egressroutemap.NewKernelGroupStore(objs.EgressShardGroups))
	return m.Registry.Register(
		NewEgressShardCollector(groups, objs.EgressShardCounters, objs.EgressShardStats, minActive))
}

// Describe implements prometheus.Collector.
func (c *EgressShardCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- egressShardPacketsDesc
	ch <- egressShardBytesDesc
	ch <- egressShardSelectionsDesc
	ch <- egressPoolMembersDesc
	ch <- egressPoolMinActiveDesc
	ch <- egressPoolEnabledDesc
}

// Collect implements prometheus.Collector. A group that has never been
// published reports nothing; galactic_cni_egress_mode says whether one was
// expected.
func (c *EgressShardCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(egressPoolMinActiveDesc, prometheus.GaugeValue, float64(c.minActive))
	c.collectSelections(ch)

	for group := range uint32(egressroutemap.MaxShardGroups) {
		status, err := c.groups.Status(group)
		if err != nil {
			ch <- prometheus.NewInvalidMetric(egressPoolEnabledDesc, err)
			continue
		}
		if !status.Present || (!status.Enabled && status.Candidates == 0 && status.Ineligible == 0) {
			continue
		}
		class := status.Class.String()
		enabled := 0.0
		if status.Open() {
			enabled = 1
		}
		ch <- prometheus.MustNewConstMetric(egressPoolEnabledDesc, prometheus.GaugeValue, enabled, class)

		members, err := c.groups.Members(group)
		if err != nil {
			ch <- prometheus.NewInvalidMetric(egressPoolMembersDesc, err)
			continue
		}
		states := map[string]int{
			poolStateActive: 0, poolStateDraining: 0, poolStateUnreachable: 0,
			poolStateIneligible: status.Ineligible,
		}
		for _, member := range members {
			switch {
			case !member.Alive:
				states[poolStateUnreachable]++
			case member.Draining:
				states[poolStateDraining]++
			default:
				states[poolStateActive]++
			}
			c.collectShardCounters(ch, group, class, member)
		}
		for state, n := range states {
			ch <- prometheus.MustNewConstMetric(egressPoolMembersDesc, prometheus.GaugeValue, float64(n), class, state)
		}
	}
}

func (c *EgressShardCollector) collectShardCounters(
	ch chan<- prometheus.Metric, group uint32, class string, member egressroutemap.ShardState,
) {
	key := group*egressroutemap.MaxShardsPerGroup + uint32(member.Slot) //nolint:gosec // slot < 32
	var perCPU []prog.UsidEgressShardCounter
	if err := c.counters.Lookup(key, &perCPU); err != nil {
		ch <- prometheus.NewInvalidMetric(egressShardPacketsDesc,
			fmt.Errorf("lookup egress_shard_counters[%d]: %w", key, err))
		return
	}
	var packets, bytes uint64
	for _, v := range perCPU {
		packets += v.Packets
		bytes += v.Bytes
	}
	sid := member.SID.String()
	ch <- prometheus.MustNewConstMetric(egressShardPacketsDesc, prometheus.CounterValue, float64(packets), sid, class)
	ch <- prometheus.MustNewConstMetric(egressShardBytesDesc, prometheus.CounterValue, float64(bytes), sid, class)
}

func (c *EgressShardCollector) collectSelections(ch chan<- prometheus.Metric) {
	for i := range prog.EgressShardStatCount {
		var perCPU []uint64
		if err := c.stats.Lookup(i, &perCPU); err != nil {
			ch <- prometheus.NewInvalidMetric(egressShardSelectionsDesc,
				fmt.Errorf("lookup egress_shard_stats[%d]: %w", i, err))
			continue
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		name := prog.EgressShardStatNames[i]
		if name == "" {
			name = fmt.Sprintf("unknown_%d", i)
		}
		ch <- prometheus.MustNewConstMetric(egressShardSelectionsDesc, prometheus.CounterValue, float64(total), name)
	}
}
