// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"fmt"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
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
	vrf         *usidmap.VRFTable
	locator     *usidmap.LocatorTable
	dropReasons DropReasonsReader
}

// NewCollector builds a Collector from already-constructed tables and reader.
// Production callers normally use NewCollectorFromObjects; this exists so tests
// can pass fakes without a kernel.
func NewCollector(vrf *usidmap.VRFTable, locator *usidmap.LocatorTable, dropReasons DropReasonsReader) *Collector {
	return &Collector{vrf: vrf, locator: locator, dropReasons: dropReasons}
}

// NewCollectorFromObjects builds a Collector reading directly from a loaded
// object set's maps.
func NewCollectorFromObjects(objs *prog.UsidObjects) *Collector {
	return NewCollector(
		usidmap.NewVRFTable(usidmap.KernelTable{Map: objs.VrfTable}),
		usidmap.NewLocatorTable(usidmap.KernelTable{Map: objs.LocatorTable}),
		objs.DropReasons,
	)
}

// labelBlock is the Prometheus label name for a uSID Block, shared by every
// metric below that carries one.
const labelBlock = "block"

var (
	vrfPacketsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "vrf", "packets_total"),
		"Packets forwarded through vrf_table for this (uSID Block, Argument) entry since it was last (re-)registered.",
		[]string{labelBlock, "argument", "vrf_table_id"}, nil,
	)
	vrfBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "vrf", "bytes_total"),
		"Bytes forwarded through vrf_table for this (uSID Block, Argument) entry since it was last (re-)registered.",
		[]string{labelBlock, "argument", "vrf_table_id"}, nil,
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
	ch <- dropsDesc
	ch <- blockArgumentsUsedDesc
	ch <- blockArgumentUtilizationDesc
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.collectVRF(ch)
	c.collectDrops(ch)
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

	entries, err := c.vrf.List()
	if err != nil {
		ch <- prometheus.NewInvalidMetric(vrfPacketsDesc, fmt.Errorf("list vrf_table: %w", err))
		return
	}
	for _, e := range entries {
		block := formatBlock(e.Block)
		argument := strconv.Itoa(int(e.Argument))
		vrfTableID := strconv.FormatUint(uint64(e.VRFTableID), 10)
		ch <- prometheus.MustNewConstMetric(
			vrfPacketsDesc, prometheus.CounterValue, float64(e.Packets), block, argument, vrfTableID)
		ch <- prometheus.MustNewConstMetric(
			vrfBytesDesc, prometheus.CounterValue, float64(e.Bytes), block, argument, vrfTableID)
		perBlockUsed[e.Block]++
	}

	for block, used := range perBlockUsed {
		label := formatBlock(block)
		ch <- prometheus.MustNewConstMetric(blockArgumentsUsedDesc, prometheus.GaugeValue, float64(used), label)
		ch <- prometheus.MustNewConstMetric(blockArgumentUtilizationDesc, prometheus.GaugeValue,
			float64(used)/float64(uformat.ArgumentMax), label)
	}
}

func (c *Collector) collectDrops(ch chan<- prometheus.Metric) {
	if c.dropReasons == nil {
		return
	}
	for i := range prog.DropReasonCount {
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
