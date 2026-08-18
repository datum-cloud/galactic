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

const namespace = "galactic_edge"

// DropReasonsReader abstracts drop_reasons's per-CPU lookup (a
// BPF_MAP_TYPE_PERCPU_ARRAY keyed by drop reason index) down to the one
// operation Collector needs, so tests can substitute an in-memory fake
// instead of a real, kernel-loaded map -- same interface shape as
// internal/plumbing/ebpf/metrics's identical type. *ebpf.Map already
// satisfies this interface structurally.
type DropReasonsReader interface {
	Lookup(key, valueOut any) error
}

// Collector is a prometheus.Collector reading the edge gateway's live eBPF
// map state at every scrape: per-VIP hit counters from vip_table/
// vip_stats_table, and drops by reason (package doc comment). Unlike this
// package's Full-NAT predecessor, there is no conn_table here at all --
// DSR keeps no per-flow state to report on (see edgedsr.c's own header
// comment).
type Collector struct {
	vipTable    *edgemap.VIPTable
	dropReasons DropReasonsReader
}

// NewCollector builds a Collector from already-constructed values, so tests
// can pass fakes (a fake edgemap.Table wrapped in edgemap.NewVIPTable, and
// any DropReasonsReader) without a kernel. Production callers normally use
// NewCollectorFromObjects.
func NewCollector(vipTable *edgemap.VIPTable, dropReasons DropReasonsReader) *Collector {
	return &Collector{vipTable: vipTable, dropReasons: dropReasons}
}

// NewCollectorFromObjects builds a Collector reading directly from a loaded
// *edgeprog.EdgedsrObjects's vip_table/vip_stats_table/drop_reasons maps --
// e.g. the object internal/plumbing/ebpf/edgeattach.Load returns.
func NewCollectorFromObjects(objs *edgeprog.EdgedsrObjects) *Collector {
	return NewCollector(
		edgemap.NewVIPTable(edgemap.KernelTable{Map: objs.VipTable}, edgemap.KernelTable{Map: objs.VipStatsTable}),
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
		"Packets that matched this VIP+port+protocol, regardless of outcome, since it was first "+
			"registered. Not reset by re-registration (e.g. a controller reconcile pass that only "+
			"changes the backend list) -- vip_table and this counter's backing map (vip_stats_table) "+
			"are separate, so registering a VIP never touches it.",
		[]string{labelProto, labelPort, labelVIP}, nil,
	)
	ruleBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "rule", "bytes_total"),
		"Bytes that matched this VIP+port+protocol, regardless of outcome, since it was first "+
			"registered. Not reset by re-registration -- see rule_packets_total's help text.",
		[]string{labelProto, labelPort, labelVIP}, nil,
	)
	ruleDroppedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "rule", "dropped_packets_total"),
		"Packets that matched this VIP but were then dropped by the datapath (e.g. no backends) -- "+
			"a subset of rule_packets_total, not an additional count. Not reset by re-registration -- "+
			"see rule_packets_total's help text.",
		[]string{labelProto, labelPort, labelVIP}, nil,
	)
	ruleBackendsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "rule", "backends"),
		"Current number of load-balancing backends registered for this VIP.",
		[]string{labelProto, labelPort, labelVIP}, nil,
	)
	ruleSecondsSinceLastPacketDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "rule", "seconds_since_last_packet"),
		"Seconds since the most recent packet matched this VIP, per vip_stats_table's LastSeenNs "+
			"(CLOCK_MONOTONIC). Absent for a VIP that has never seen a matching packet.",
		[]string{labelProto, labelPort, labelVIP}, nil,
	)
	dropsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "drops_total"),
		"Packets dropped by the edge_lb program, by reason (drop_reasons map).",
		[]string{"reason"}, nil,
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
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.collectRules(ch)
	c.collectDrops(ch)
}

// protoLabel renders a vip_key.proto value as a metric label -- the
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
	entries, err := c.vipTable.List()
	if err != nil {
		ch <- prometheus.NewInvalidMetric(rulePacketsDesc, fmt.Errorf("list vip_table: %w", err))
		return
	}

	now := c.vipTable.Generation() // same CLOCK_MONOTONIC domain as LastSeenNs
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
