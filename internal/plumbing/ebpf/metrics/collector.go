// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
)

const namespace = "galactic_usid"

// DropReasonsReader narrows the drop-reason map, a per-CPU array keyed by
// reason index, to the one operation Collector needs, so tests can substitute an
// in-memory fake. A real loaded map already satisfies it structurally.
type DropReasonsReader interface {
	Lookup(key, valueOut any) error
}

// Collector reads the uSID datapath's live map state at every scrape:
// per-Argument packet and byte counters, drops by reason, and Argument-space
// utilization per Block.
type Collector struct {
	vrf            *usidmap.VRFTable
	locator        *usidmap.LocatorTable
	dropReasons    DropReasonsReader
	vpcAttribution *usidmap.VPCAttributionTable

	// vrfTraffic is nil unless set by WithVRFTraffic, in which case each VRF's
	// per-direction forwarded and dropped counters are collected too.
	vrfTraffic *usidmap.VRFTrafficTable

	// mssClampStats and mssClampTable are nil unless set by WithMSSClamp, in
	// which case the TCP MSS clamp's outcomes and limits are collected too.
	mssClampStats DropReasonsReader
	mssClampTable DropReasonsReader

	// pmtuStats and encapMTUTable are nil unless set by WithPMTU, in which
	// case what usid_egress did with packets too big for the fabric, and the
	// limit it checks, are collected too.
	pmtuStats     DropReasonsReader
	encapMTUTable DropReasonsReader

	// hostOnlyPortDrops is nil unless set by WithHostOnlyPorts, in which case
	// the packets tp_deliver refused for a host-only port are collected too.
	hostOnlyPortDrops DropReasonsReader
}

// NewCollector builds a Collector from already-constructed tables and reader.
// Production callers normally use NewCollectorFromObjects; this exists so tests
// can pass fakes without a kernel. vpcAttribution may be nil, in which case
// vrf/bytes metrics carry no vpc/vpc_attachment labels.
func NewCollector(
	vrf *usidmap.VRFTable, locator *usidmap.LocatorTable, dropReasons DropReasonsReader,
	vpcAttribution *usidmap.VPCAttributionTable,
) *Collector {
	return &Collector{vrf: vrf, locator: locator, dropReasons: dropReasons, vpcAttribution: vpcAttribution}
}

// NewCollectorFromObjects builds a Collector reading directly from a loaded
// object set's maps.
func NewCollectorFromObjects(objs *prog.UsidObjects) *Collector {
	return NewCollector(
		usidmap.NewVRFTable(usidmap.KernelTable{Map: objs.VrfTable}),
		usidmap.NewLocatorTable(usidmap.KernelTable{Map: objs.LocatorTable}),
		objs.DropReasons,
		usidmap.NewVPCAttributionTable(usidmap.KernelTable{Map: objs.VpcAttributionTable}),
	).WithMSSClamp(objs.MssClampStats, objs.MssClampTable).
		WithPMTU(objs.PmtuStats, objs.EncapMtuTable).
		WithVRFTraffic(usidmap.NewVRFTrafficTable(usidmap.KernelCounterTable{Map: objs.VrfTrafficCounters})).
		WithHostOnlyPorts(objs.HostOnlyPortDrops)
}

// WithVRFTraffic adds vrf_traffic_counters to c, so each VRF's per-direction
// forwarded and dropped counters are collected. It returns c.
func (c *Collector) WithVRFTraffic(traffic *usidmap.VRFTrafficTable) *Collector {
	c.vrfTraffic = traffic
	return c
}

// WithMSSClamp adds the TCP MSS clamp's maps to c: stats, the per-CPU
// mss_clamp_stats counters, and table, the single-entry mss_clamp_table. It
// returns c.
func (c *Collector) WithMSSClamp(stats, table DropReasonsReader) *Collector {
	c.mssClampStats, c.mssClampTable = stats, table
	return c
}

// WithPMTU adds the path MTU check's maps to c: stats, the per-CPU pmtu_stats
// counters, and table, the single-entry encap_mtu_table. It returns c.
func (c *Collector) WithPMTU(stats, table DropReasonsReader) *Collector {
	c.pmtuStats, c.encapMTUTable = stats, table
	return c
}

// WithHostOnlyPorts adds host_only_port_drops, the per-CPU count of packets
// tp_deliver refused for a host-only port, to c. It returns c.
func (c *Collector) WithHostOnlyPorts(drops DropReasonsReader) *Collector {
	c.hostOnlyPortDrops = drops
	return c
}

// labelBlock is the Prometheus label name for a uSID Block, shared by every
// metric below that carries one. labelVPC and labelVPCAttachment name the
// attachment a series belongs to, shared with the attachment series in
// attachment.go.
const (
	labelBlock         = "block"
	labelVPC           = "vpc"
	labelVPCAttachment = "vpc_attachment"
)

// vrfLabels are the identity labels of every per-VRF series, and
// vrfDirectionLabels adds the direction of travel.
var (
	vrfLabels          = []string{labelBlock, "argument", "vrf_table_id", labelVPC, labelVPCAttachment, "vrf_interface"}
	vrfDirectionLabels = append(append([]string(nil), vrfLabels...), "direction")
)

// labelResult is the Prometheus label name for an outcome, shared by the MSS
// clamp series here and the datapath event counters in events.go.
const labelResult = "result"

var (
	vrfPacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "vrf", "packets_total"),
		"Packets forwarded through vrf_table for this (uSID Block, Argument) entry since it was last (re-)registered.",
		vrfLabels, nil,
	)
	vrfBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "vrf", "bytes_total"),
		"Bytes forwarded through vrf_table for this (uSID Block, Argument) entry since it was last (re-)registered.",
		vrfLabels, nil,
	)
	vrfForwardedPacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "vrf", "forwarded_packets_total"),
		"Packets forwarded into (direction=ingress) or out of (direction=egress) this VRF: decapsulated and "+
			"delivered to an attachment, or encapsulated, sent out the public uplink, or delivered to another "+
			"attachment on this node. Counted once the datapath has committed to forwarding the packet. A GSO or "+
			"GRO super-packet counts once.",
		vrfDirectionLabels, nil,
	)
	vrfForwardedBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "vrf", "forwarded_bytes_total"),
		"Bytes of the packets in galactic_usid_vrf_forwarded_packets_total, measured as the tenant packet "+
			"alone: its IP header and payload, without the Ethernet header or any SRv6 outer header, in both "+
			"directions.",
		vrfDirectionLabels, nil,
	)
	vrfDroppedPacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "vrf", "dropped_packets_total"),
		"Packets usid_ingress or usid_egress dropped after resolving them to this VRF, by the direction they "+
			"were travelling. Outbound private service route drops and failed public-uplink redirects are "+
			"counted only in galactic_usid_drops_total, which has the reasons, without the VRF.",
		vrfDirectionLabels, nil,
	)
	dropsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "drops_total"),
		"Packets dropped by the usid_ingress program, by reason (drop_reasons map, design plan §4.4).",
		[]string{"reason"}, nil,
	)
	blockArgumentsUsedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "block", "arguments_used"),
		"Number of vrf_table entries (registered Arguments) currently active for this uSID Block.",
		[]string{labelBlock}, nil,
	)
	mssClampDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "tcp_mss_clamp", "syns_total"),
		"TCP SYNs the MSS clamp examined, by outcome (mss_clamp_stats map). Anything but clamped_* or "+
			"within_limit is a SYN that crossed the fabric unclamped.",
		[]string{labelResult}, nil,
	)
	mssClampLimitDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "tcp_mss_clamp", "limit_bytes"),
		"The MSS the clamp lowers SYNs to, per tenant address family. Zero means clamping is off for that family.",
		[]string{"family"}, nil,
	)
	pmtuDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "pmtu", "packets_total"),
		"Tenant packets too big to cross the fabric once encapsulated, by what usid_egress did with them "+
			"(pmtu_stats map). too_big_sent_ipv6 and frag_needed_sent_ipv4 sent the tenant an ICMP error; "+
			"every other result dropped the packet without one.",
		[]string{labelResult}, nil,
	)
	encapMTUDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "pmtu", "limit_bytes"),
		"The largest tenant packet usid_egress encapsulates, the fabric MTU less the outer header. "+
			"Zero means the check is off.",
		nil, nil,
	)
	hostOnlyPortDropsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "host_only_port", "drops_total"),
		"TCP packets to a tap's host-only port that tp_deliver dropped because they were not addressed to the "+
			"guest's link-local address (host_only_port_drops map).",
		nil, nil,
	)
	blockArgumentUtilizationDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "block", "argument_utilization_ratio"),
		"galactic_usid_block_arguments_used divided by 4095, the per-Block usable Argument capacity under "+
			"design plan §2's Option 2 -- an exhaustion-alerting input.",
		[]string{labelBlock}, nil,
	)
)

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- vrfPacketsDesc
	ch <- vrfBytesDesc
	ch <- vrfForwardedPacketsDesc
	ch <- vrfForwardedBytesDesc
	ch <- vrfDroppedPacketsDesc
	ch <- dropsDesc
	ch <- blockArgumentsUsedDesc
	ch <- blockArgumentUtilizationDesc
	ch <- mssClampDesc
	ch <- mssClampLimitDesc
	ch <- pmtuDesc
	ch <- encapMTUDesc
	ch <- hostOnlyPortDropsDesc
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.collectVRF(ch)
	c.collectDrops(ch)
	c.collectMSSClamp(ch)
	c.collectPMTU(ch)
	c.collectHostOnlyPorts(ch)
}

func (c *Collector) collectHostOnlyPorts(ch chan<- prometheus.Metric) {
	if c.hostOnlyPortDrops == nil {
		return
	}
	var perCPU []uint64
	if err := c.hostOnlyPortDrops.Lookup(uint32(0), &perCPU); err != nil {
		ch <- prometheus.NewInvalidMetric(hostOnlyPortDropsDesc, fmt.Errorf("lookup host_only_port_drops: %w", err))
		return
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	ch <- prometheus.MustNewConstMetric(hostOnlyPortDropsDesc, prometheus.CounterValue, float64(total))
}

func (c *Collector) collectMSSClamp(ch chan<- prometheus.Metric) {
	if c.mssClampStats != nil {
		for i := range prog.MSSClampStatCount {
			var perCPU []uint64
			if err := c.mssClampStats.Lookup(i, &perCPU); err != nil {
				ch <- prometheus.NewInvalidMetric(mssClampDesc, fmt.Errorf("lookup mss_clamp_stats[%d]: %w", i, err))
				continue
			}
			var total uint64
			for _, v := range perCPU {
				total += v
			}
			name := prog.MSSClampStatNames[i]
			if name == "" {
				name = fmt.Sprintf("unknown_%d", i)
			}
			ch <- prometheus.MustNewConstMetric(mssClampDesc, prometheus.CounterValue, float64(total), name)
		}
	}
	if c.mssClampTable != nil {
		var v prog.UsidMssClampValue
		if err := c.mssClampTable.Lookup(uint32(0), &v); err != nil {
			ch <- prometheus.NewInvalidMetric(mssClampLimitDesc, fmt.Errorf("lookup mss_clamp_table: %w", err))
			return
		}
		ch <- prometheus.MustNewConstMetric(mssClampLimitDesc, prometheus.GaugeValue, float64(v.MssIpv4), "ipv4")
		ch <- prometheus.MustNewConstMetric(mssClampLimitDesc, prometheus.GaugeValue, float64(v.MssIpv6), "ipv6")
	}
}

func (c *Collector) collectPMTU(ch chan<- prometheus.Metric) {
	if c.pmtuStats != nil {
		for i := range prog.PMTUStatCount {
			var perCPU []uint64
			if err := c.pmtuStats.Lookup(i, &perCPU); err != nil {
				ch <- prometheus.NewInvalidMetric(pmtuDesc, fmt.Errorf("lookup pmtu_stats[%d]: %w", i, err))
				continue
			}
			var total uint64
			for _, v := range perCPU {
				total += v
			}
			name := prog.PMTUStatNames[i]
			if name == "" {
				name = fmt.Sprintf("unknown_%d", i)
			}
			ch <- prometheus.MustNewConstMetric(pmtuDesc, prometheus.CounterValue, float64(total), name)
		}
	}
	if c.encapMTUTable != nil {
		var limit uint32
		if err := c.encapMTUTable.Lookup(uint32(0), &limit); err != nil {
			ch <- prometheus.NewInvalidMetric(encapMTUDesc, fmt.Errorf("lookup encap_mtu_table: %w", err))
			return
		}
		ch <- prometheus.MustNewConstMetric(encapMTUDesc, prometheus.GaugeValue, float64(limit))
	}
}

// formatBlock renders a Block as a metric label, in hex, matching how Block
// values are formatted in error messages elsewhere.
func formatBlock(block uint64) string {
	return fmt.Sprintf("%#x", block)
}

func (c *Collector) collectVRF(ch chan<- prometheus.Metric) {
	// Seed every currently active Block with a zero count, so one with no
	// entries yet still reports zero rather than being absent. An alert on high
	// utilization needs the series to exist at zero to compare against, not
	// spring into existence once traffic starts.
	perBlockUsed := make(map[uint64]int)
	if c.locator != nil {
		locatorEntries, err := c.locator.List()
		if err != nil {
			ch <- prometheus.NewInvalidMetric(blockArgumentsUsedDesc, fmt.Errorf("list locator_table: %w", err))
		} else {
			for _, e := range locatorEntries {
				if _, ok := perBlockUsed[e.Block]; !ok {
					perBlockUsed[e.Block] = 0
				}
			}
		}
	}

	// Keyed the same as vrf_table, so each entry below looks its own
	// attribution up by VRFKey. A lookup miss (a registration race, or an
	// entry predating this feature) must not drop the sample -- see
	// vpcLabels's own doc comment.
	attribution := make(map[usidmap.VRFKey]usidmap.VPCAttributionEntry)
	if c.vpcAttribution != nil {
		attributionEntries, err := c.vpcAttribution.List()
		if err != nil {
			ch <- prometheus.NewInvalidMetric(vrfPacketsDesc, fmt.Errorf("list vpc_attribution_table: %w", err))
		} else {
			for _, e := range attributionEntries {
				attribution[e.VRFKey] = e
			}
		}
	}

	traffic := c.listVRFTraffic(ch)

	entries, err := c.vrf.List()
	if err != nil {
		ch <- prometheus.NewInvalidMetric(vrfPacketsDesc, fmt.Errorf("list vrf_table: %w", err))
		return
	}
	for _, e := range entries {
		block := formatBlock(e.Block)
		argument := strconv.Itoa(int(e.Argument))
		vrfTableID := strconv.FormatUint(uint64(e.VRFTableID), 10)
		attributionEntry, found := attribution[e.VRFKey]
		vpc, vpcAttachment := vpcLabels(attributionEntry, found, e.VRFKey)
		labels := []string{block, argument, vrfTableID, vpc, vpcAttachment, attributionEntry.VRFInterface}
		ch <- prometheus.MustNewConstMetric(
			vrfPacketsDesc, prometheus.CounterValue, float64(e.Packets), labels...)
		ch <- prometheus.MustNewConstMetric(
			vrfBytesDesc, prometheus.CounterValue, float64(e.Bytes), labels...)
		if t, ok := traffic[e.VRFKey]; ok {
			emitVRFDirection(ch, t.Ingress, append(labels, directionIngress))
			emitVRFDirection(ch, t.Egress, append(labels, directionEgress))
		}
		perBlockUsed[e.Block]++
	}

	for block, used := range perBlockUsed {
		label := formatBlock(block)
		ch <- prometheus.MustNewConstMetric(blockArgumentsUsedDesc, prometheus.GaugeValue, float64(used), label)
		ch <- prometheus.MustNewConstMetric(blockArgumentUtilizationDesc, prometheus.GaugeValue,
			float64(used)/float64(uformat.ArgumentMax), label)
	}
}

// direction label values for the per-direction VRF series.
const (
	directionIngress = "ingress"
	directionEgress  = "egress"
)

// listVRFTraffic reads vrf_traffic_counters keyed by VRF, or returns nil when
// the collector has none. A read failure is reported on ch and also returns
// nil, so the per-VRF series that do not depend on it are still collected.
func (c *Collector) listVRFTraffic(ch chan<- prometheus.Metric) map[usidmap.VRFKey]usidmap.VRFTrafficEntry {
	if c.vrfTraffic == nil {
		return nil
	}
	entries, err := c.vrfTraffic.List()
	if err != nil {
		ch <- prometheus.NewInvalidMetric(vrfForwardedPacketsDesc, fmt.Errorf("list vrf_traffic_counters: %w", err))
		return nil
	}
	traffic := make(map[usidmap.VRFKey]usidmap.VRFTrafficEntry, len(entries))
	for _, e := range entries {
		traffic[e.VRFKey] = e
	}
	return traffic
}

// emitVRFDirection sends one direction's three per-VRF counters, labelled
// with labels, the VRF's identity labels followed by the direction.
func emitVRFDirection(ch chan<- prometheus.Metric, counters usidmap.VRFTrafficCounters, labels []string) {
	ch <- prometheus.MustNewConstMetric(
		vrfForwardedPacketsDesc, prometheus.CounterValue, float64(counters.Packets), labels...)
	ch <- prometheus.MustNewConstMetric(
		vrfForwardedBytesDesc, prometheus.CounterValue, float64(counters.Bytes), labels...)
	ch <- prometheus.MustNewConstMetric(
		vrfDroppedPacketsDesc, prometheus.CounterValue, float64(counters.DroppedPackets), labels...)
}

// vpcLabels re-encodes entry's VPC/VPCAttachment identifiers back to the
// base62 form used everywhere else in this codebase (CNI conflist,
// interface names). found is false when this key had no vpc_attribution_table
// row -- not an error, since vrf_table's own counters must never go
// unreported for want of an attribution row (a registration race, or an
// entry that predates this feature) -- and both labels come back empty in
// that case.
func vpcLabels(entry usidmap.VPCAttributionEntry, found bool, key usidmap.VRFKey) (vpc, vpcAttachment string) {
	if !found {
		return "", ""
	}

	vpc, err := intf.HexToBase62(strconv.FormatUint(entry.VPC, 16))
	if err != nil {
		slog.Warn("metrics: could not re-encode vpc_attribution_table VPC identifier as base62",
			"block", key.Block, "argument", key.Argument, "vpc", entry.VPC, "err", err)
		vpc = ""
	}
	vpcAttachment, err = intf.HexToBase62(strconv.FormatUint(uint64(entry.VPCAttachment), 16))
	if err != nil {
		slog.Warn("metrics: could not re-encode vpc_attribution_table VPCAttachment identifier as base62",
			"block", key.Block, "argument", key.Argument, "vpcAttachment", entry.VPCAttachment, "err", err)
		vpcAttachment = ""
	}
	return vpc, vpcAttachment
}

func (c *Collector) collectDrops(ch chan<- prometheus.Metric) {
	if c.dropReasons == nil {
		return
	}
	for _, i := range prog.DropReasonMetricIndices {
		var perCPU []uint64
		if err := c.dropReasons.Lookup(i, &perCPU); err != nil {
			ch <- prometheus.NewInvalidMetric(dropsDesc, fmt.Errorf("lookup drop_reasons[%d]: %w", i, err))
			continue
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		name := prog.DropReasonNames[i]
		if name == "" {
			name = fmt.Sprintf("unknown_%d", i)
		}
		ch <- prometheus.MustNewConstMetric(dropsDesc, prometheus.CounterValue, float64(total), name)
	}
}
