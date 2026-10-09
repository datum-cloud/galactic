// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgemetrics

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/plumbing/ebpf/edgemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/edgeprog"
)

const namespace = "galactic_edge"

// DropReasonsReader narrows the drop-reason map, a per-CPU array keyed by
// reason index, to the one operation Collector needs, so tests can substitute an
// in-memory fake. A real loaded map already satisfies it structurally.
type DropReasonsReader interface {
	Lookup(key, valueOut any) error
}

// VPCAttribution names the VPC that owns each registered VIP, the label the
// per-VIP series carry. The maps hold no tenant identity, so it comes from
// whatever wrote them: the gateway's kernel datapath, which receives each rule's
// VPC when it applies the rule.
type VPCAttribution interface {
	// VPCAttribution returns a snapshot of the VPC owning each vip_table key,
	// and of the VPC owning each VIP address. An address used by rules of more
	// than one VPC is absent from addrs: its return counters cannot be split
	// between them.
	VPCAttribution() (rules map[edgemap.VIPKey]string, addrs map[netip.Addr]string)
}

// Collector reads the edge gateway's live map state at every scrape: per-VIP
// counters and drops by reason. There is no connection table here at all, direct
// server return keeping no per-flow state to report.
type Collector struct {
	vipTable    *edgemap.VIPTable
	dropReasons DropReasonsReader
	attribution VPCAttribution
}

// NewCollector builds a Collector from already-constructed values, so tests can
// pass fakes without a kernel. Production callers normally use
// NewCollectorFromObjects. attribution may be nil, in which case every per-VIP
// series carries an empty vpc label.
func NewCollector(vipTable *edgemap.VIPTable, dropReasons DropReasonsReader, attribution VPCAttribution) *Collector {
	return &Collector{vipTable: vipTable, dropReasons: dropReasons, attribution: attribution}
}

// NewCollectorFromObjects builds a Collector reading directly from a loaded
// object set's maps.
func NewCollectorFromObjects(objs *edgeprog.EdgedsrObjects, attribution VPCAttribution) *Collector {
	return NewCollector(
		edgemap.NewVIPTable(
			edgemap.KernelTable{Map: objs.VipTable}, edgemap.KernelTable{Map: objs.VipStatsTable},
			edgemap.KernelTable{Map: objs.VipAddrTable}, edgemap.KernelTable{Map: objs.VipReturnStatsTable}),
		objs.DropReasons,
		attribution,
	)
}

const (
	labelProto = "proto"
	labelPort  = "port"
	labelVIP   = "vip"

	// labelVPC carries the owning VPC's opaque identifier, the same string the
	// usid collector's vpc label carries for vrf_table counters. Empty when no
	// rule this process applied owns the entry yet, as after a restart before
	// the first reconcile.
	labelVPC = "vpc"
)

var (
	rulePacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "rule", "packets_total"),
		"Packets that matched this VIP+port+protocol, regardless of outcome, since it was first "+
			"registered. Not reset by re-registration (e.g. a controller reconcile pass that only "+
			"changes the backend list) -- vip_table and this counter's backing map (vip_stats_table) "+
			"are separate, so registering a VIP never touches it.",
		[]string{labelProto, labelPort, labelVIP, labelVPC}, nil,
	)
	ruleBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "rule", "bytes_total"),
		"Bytes that matched this VIP+port+protocol, regardless of outcome, since it was first "+
			"registered. Not reset by re-registration -- see rule_packets_total's help text.",
		[]string{labelProto, labelPort, labelVIP, labelVPC}, nil,
	)
	ruleDroppedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "rule", "dropped_packets_total"),
		"Packets that matched this VIP but were then dropped by the datapath (e.g. no backends) -- "+
			"a subset of rule_packets_total, not an additional count. Not reset by re-registration -- "+
			"see rule_packets_total's help text.",
		[]string{labelProto, labelPort, labelVIP, labelVPC}, nil,
	)
	ruleBackendsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "rule", "backends"),
		"Current number of load-balancing backends registered for this VIP.",
		[]string{labelProto, labelPort, labelVIP, labelVPC}, nil,
	)
	ruleSecondsSinceLastPacketDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "rule", "seconds_since_last_packet"),
		"Seconds since the most recent packet matched this VIP, per vip_stats_table's LastSeenNs "+
			"(CLOCK_MONOTONIC). Absent for a VIP that has never seen a matching packet.",
		[]string{labelProto, labelPort, labelVIP, labelVPC}, nil,
	)
	dropsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "drops_total"),
		"Packets dropped by the edge_lb and edge_return programs, by reason (drop_reasons map). "+
			"The two share these buckets: a FIB or redirect failure means the same thing in either "+
			"direction.",
		[]string{"reason"}, nil,
	)
	returnPacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "return", "packets_total"),
		"Reply packets this node forwarded for traffic sourced from this VIP, bypassing the kernel "+
			"forwarding path (edge_return). Counted per VIP address, with no port or protocol "+
			"dimension, since the return program matches on the source address alone.",
		[]string{labelVIP, labelVPC}, nil,
	)
	returnBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "return", "bytes_total"),
		"Reply bytes this node forwarded for traffic sourced from this VIP -- see "+
			"return_packets_total's help text.",
		[]string{labelVIP, labelVPC}, nil,
	)
	returnDroppedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "return", "dropped_packets_total"),
		"Reply packets sourced from this VIP that the datapath then dropped (e.g. an expired hop "+
			"limit, or no route) -- a subset of return_packets_total, not an additional count.",
		[]string{labelVIP, labelVPC}, nil,
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
	ch <- returnPacketsDesc
	ch <- returnBytesDesc
	ch <- returnDroppedDesc
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.collectRules(ch)
	c.collectReturn(ch)
	c.collectDrops(ch)
}

// vpcs snapshots the attribution. Callers take it after listing a map: the
// datapath attributes a key before writing it, so every listed key is then
// already in the snapshot.
func (c *Collector) vpcs() (map[edgemap.VIPKey]string, map[netip.Addr]string) {
	if c.attribution == nil {
		return nil, nil
	}
	return c.attribution.VPCAttribution()
}

// protoLabel renders a protocol number as a metric label: its name where this
// package knows it, and the raw number otherwise, so an unrecognized value is
// still visible rather than silently dropped.
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
	vpcs, _ := c.vpcs()

	now := c.vipTable.Generation() // same CLOCK_MONOTONIC domain as LastSeenNs
	for _, e := range entries {
		proto := protoLabel(e.Proto)
		port := strconv.Itoa(int(e.VPort))
		vip := e.VIP.String()
		vpc := vpcs[e.VIPKey]

		ch <- prometheus.MustNewConstMetric(
			rulePacketsDesc, prometheus.CounterValue, float64(e.Packets), proto, port, vip, vpc)
		ch <- prometheus.MustNewConstMetric(
			ruleBytesDesc, prometheus.CounterValue, float64(e.Bytes), proto, port, vip, vpc)
		ch <- prometheus.MustNewConstMetric(
			ruleDroppedDesc, prometheus.CounterValue, float64(e.DroppedPackets), proto, port, vip, vpc)
		ch <- prometheus.MustNewConstMetric(
			ruleBackendsDesc, prometheus.GaugeValue, float64(len(e.Backends)), proto, port, vip, vpc)
		if e.LastSeenNs != 0 && now >= e.LastSeenNs {
			secondsSince := float64(now-e.LastSeenNs) / 1e9
			ch <- prometheus.MustNewConstMetric(
				ruleSecondsSinceLastPacketDesc, prometheus.GaugeValue, secondsSince, proto, port, vip, vpc)
		}
	}
}

// collectReturn reports the return path's per-VIP counters. A node with no
// compute tier behind it never attaches edge_return, and vip_addr_table's rows
// then simply never gain counters, so these read zero rather than going absent.
func (c *Collector) collectReturn(ch chan<- prometheus.Metric) {
	entries, err := c.vipTable.ListReturn()
	if err != nil {
		ch <- prometheus.NewInvalidMetric(returnPacketsDesc, fmt.Errorf("list vip_addr_table: %w", err))
		return
	}
	_, vpcs := c.vpcs()
	for _, e := range entries {
		vip := e.VIP.String()
		vpc := vpcs[e.VIP]
		ch <- prometheus.MustNewConstMetric(returnPacketsDesc, prometheus.CounterValue, float64(e.Packets), vip, vpc)
		ch <- prometheus.MustNewConstMetric(returnBytesDesc, prometheus.CounterValue, float64(e.Bytes), vip, vpc)
		ch <- prometheus.MustNewConstMetric(
			returnDroppedDesc, prometheus.CounterValue, float64(e.DroppedPackets), vip, vpc)
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
