// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgemetrics

import (
	"fmt"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

const namespace = "galactic_edgenat"

// DropReasonsReader abstracts drop_reasons's per-CPU lookup (a
// BPF_MAP_TYPE_PERCPU_ARRAY keyed by drop reason index) down to the one
// operation Collector needs, so tests can substitute an in-memory fake
// instead of a real, kernel-loaded map -- same interface shape as
// internal/plumbing/ebpf/metrics's identical type. *ebpf.Map already
// satisfies this interface structurally.
type DropReasonsReader interface {
	Lookup(key, valueOut any) error
}

// ConnCounter abstracts conn_table down to the one operation Collector
// needs: counting live entries. Deliberately not edgemap.Table's full
// interface -- Collector never needs Put/Lookup/Delete on conn_table,
// only a live count for utilization reporting (per-flow labels would be
// an unbounded-cardinality Prometheus anti-pattern; see collectConn's doc
// comment).
type ConnCounter interface {
	Iterate() edgemap.Iterator
}

// Collector is a prometheus.Collector reading the edge gateway's live eBPF
// map state at every scrape: per-rule hit counters from rule_table,
// conn_table utilization, and drops by reason (package doc comment).
type Collector struct {
	ruleTable   *edgemap.RuleTable
	connTable   ConnCounter
	connMax     uint32
	dropReasons DropReasonsReader
}

// NewCollector builds a Collector from already-constructed values, so
// tests can pass fakes (a fake edgemap.Table wrapped in
// edgemap.NewRuleTable, and any ConnCounter/DropReasonsReader) without a
// kernel. Production callers normally use NewCollectorFromObjects.
func NewCollector(
	ruleTable *edgemap.RuleTable, connTable ConnCounter, connMax uint32, dropReasons DropReasonsReader,
) *Collector {
	return &Collector{ruleTable: ruleTable, connTable: connTable, connMax: connMax, dropReasons: dropReasons}
}

// NewCollectorFromObjects builds a Collector reading directly from a
// loaded *edgeprog.EdgenatObjects's rule_table/conn_table/drop_reasons
// maps -- e.g. the object internal/plumbing/ebpf/edgeattach.Load returns.
func NewCollectorFromObjects(objs *edgeprog.EdgenatObjects) *Collector {
	return NewCollector(
		edgemap.NewRuleTable(edgemap.KernelTable{Map: objs.RuleTable}, edgemap.KernelTable{Map: objs.RuleStatsTable}),
		edgemap.KernelTable{Map: objs.ConnTable},
		objs.ConnTable.MaxEntries(),
		objs.DropReasons,
	)
}

const (
	labelProto = "proto"
	labelPort  = "port"
	labelVIP   = "vip"
)

var (
	rulePacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "rule", "packets_total"),
		"Packets that matched this rule's VIP+port+protocol, regardless of outcome, since the rule "+
			"was first registered. Not reset by re-registration (e.g. a controller reconcile pass "+
			"that only changes the backend list) -- rule_table and this counter's backing map "+
			"(rule_stats_table) are separate, so registering a rule never touches it.",
		[]string{labelProto, labelPort, labelVIP}, nil,
	)
	ruleBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "rule", "bytes_total"),
		"Bytes that matched this rule's VIP+port+protocol, regardless of outcome, since the rule "+
			"was first registered. Not reset by re-registration -- see rule_packets_total's help text.",
		[]string{labelProto, labelPort, labelVIP}, nil,
	)
	ruleDroppedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "rule", "dropped_packets_total"),
		"Packets that matched this rule but were then dropped by the datapath (e.g. no backends, "+
			"PAT-port exhaustion) -- a subset of rule_packets_total, not an additional count. Not "+
			"reset by re-registration -- see rule_packets_total's help text.",
		[]string{labelProto, labelPort, labelVIP}, nil,
	)
	ruleBackendsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "rule", "backends"),
		"Current number of load-balancing backends registered for this rule.",
		[]string{labelProto, labelPort, labelVIP}, nil,
	)
	ruleSecondsSinceLastPacketDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "rule", "seconds_since_last_packet"),
		"Seconds since the most recent packet matched this rule, per rule_stats_table's LastSeenNs "+
			"(CLOCK_MONOTONIC). Absent for a rule that has never seen a matching packet.",
		[]string{labelProto, labelPort, labelVIP}, nil,
	)
	dropsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "drops_total"),
		"Packets dropped by the edge_nat program, by reason (drop_reasons map).",
		[]string{"reason"}, nil,
	)
	connTableEntriesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "conn_table", "entries"),
		"Current number of live conn_table entries (both forward and reverse rows).",
		nil, nil,
	)
	connTableUtilizationDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "conn_table", "utilization_ratio"),
		"galactic_edgenat_conn_table_entries divided by conn_table's configured capacity -- "+
			"an exhaustion-alerting input; conn_table is BPF_MAP_TYPE_LRU_HASH, so exhaustion causes "+
			"self-eviction of the least-recently-used flow rather than a hard failure, but sustained "+
			"high utilization still means shorter flow lifetimes than intended.",
		nil, nil,
	)
)

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- rulePacketsDesc
	ch <- ruleBytesDesc
	ch <- ruleDroppedDesc
	ch <- ruleBackendsDesc
	ch <- ruleSecondsSinceLastPacketDesc
	ch <- dropsDesc
	ch <- connTableEntriesDesc
	ch <- connTableUtilizationDesc
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.collectRules(ch)
	c.collectDrops(ch)
	c.collectConn(ch)
}

// protoLabel renders a rule_key.proto value as a metric label -- the
// IANA-numeric value's name where this package knows it (tcp/udp, the
// only two protocols NetworkRuleSpec.Protocol accepts), the raw number
// otherwise, so an unrecognized value is still visible rather than
// silently dropped.
func protoLabel(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return strconv.Itoa(int(proto))
	}
}

func (c *Collector) collectRules(ch chan<- prometheus.Metric) {
	entries, err := c.ruleTable.List()
	if err != nil {
		ch <- prometheus.NewInvalidMetric(rulePacketsDesc, fmt.Errorf("list rule_table: %w", err))
		return
	}

	now := c.ruleTable.Generation() // same CLOCK_MONOTONIC domain as LastSeenNs
	for _, e := range entries {
		proto := protoLabel(e.Proto)
		port := strconv.Itoa(int(e.VPort))
		vip := e.VIP.String()

		ch <- prometheus.MustNewConstMetric(rulePacketsDesc, prometheus.CounterValue, float64(e.Packets), proto, port, vip)
		ch <- prometheus.MustNewConstMetric(ruleBytesDesc, prometheus.CounterValue, float64(e.Bytes), proto, port, vip)
		ch <- prometheus.MustNewConstMetric(
			ruleDroppedDesc, prometheus.CounterValue, float64(e.DroppedPackets), proto, port, vip)
		ch <- prometheus.MustNewConstMetric(
			ruleBackendsDesc, prometheus.GaugeValue, float64(len(e.Backends)), proto, port, vip)
		if e.LastSeenNs != 0 && now >= e.LastSeenNs {
			secondsSince := float64(now-e.LastSeenNs) / 1e9
			ch <- prometheus.MustNewConstMetric(
				ruleSecondsSinceLastPacketDesc, prometheus.GaugeValue, secondsSince, proto, port, vip)
		}
	}
}

func (c *Collector) collectDrops(ch chan<- prometheus.Metric) {
	if c.dropReasons == nil {
		return
	}
	for i := range edgeprog.DropReasonCount {
		var perCPU []uint64
		if err := c.dropReasons.Lookup(i, &perCPU); err != nil {
			ch <- prometheus.NewInvalidMetric(dropsDesc, fmt.Errorf("lookup drop_reasons[%d]: %w", i, err))
			continue
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		name := edgeprog.DropReasonNames[i]
		if name == "" {
			name = fmt.Sprintf("unknown_%d", i)
		}
		ch <- prometheus.MustNewConstMetric(dropsDesc, prometheus.CounterValue, float64(total), name)
	}
}

// collectConn reports only an aggregate live entry count and utilization
// ratio, never a per-entry metric: conn_table's key is a client-facing
// 5-tuple, so a per-entry label set would mean one Prometheus series per
// active connection -- unbounded cardinality driven directly by end-user
// traffic, exactly the anti-pattern Prometheus's own labeling best
// practices warn against. The aggregate count is still directly useful
// for exhaustion alerting (connTableUtilizationDesc's doc comment).
func (c *Collector) collectConn(ch chan<- prometheus.Metric) {
	if c.connTable == nil {
		return
	}
	var (
		count  uint64
		rawKey edgeprog.EdgenatConnKey
		value  edgeprog.EdgenatConnValue
	)
	it := c.connTable.Iterate()
	for it.Next(&rawKey, &value) {
		count++
	}
	if err := it.Err(); err != nil {
		ch <- prometheus.NewInvalidMetric(connTableEntriesDesc, fmt.Errorf("iterate conn_table: %w", err))
		return
	}

	ch <- prometheus.MustNewConstMetric(connTableEntriesDesc, prometheus.GaugeValue, float64(count))
	if c.connMax > 0 {
		ch <- prometheus.MustNewConstMetric(
			connTableUtilizationDesc, prometheus.GaugeValue, float64(count)/float64(c.connMax))
	}
}
