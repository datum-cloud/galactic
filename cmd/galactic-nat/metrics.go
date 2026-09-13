// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/plumbing/ebpf/natmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

const metricsNamespace = "galactic_nat"

// natCollector reads this shard's live map state at every scrape: drops by
// reason and connection-table occupancy by address family. It is a pull-based collector like the other datapaths',
// scoped to what the map layer exposes read access to, the connection table
// being entirely datapath-owned and so observability-only.
type natCollector struct {
	connTable   *natmap.ConnTable
	dropReasons natmap.DropReasonsReader
}

// newNatCollector builds a collector reading directly from a loaded object
// set's maps.
func newNatCollector(objs *natprog.NatObjects) *natCollector {
	return &natCollector{
		connTable:   natmap.NewConnTable(natmap.KernelTable{Map: objs.NatConnTable}),
		dropReasons: objs.DropReasons,
	}
}

var (
	connsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "conns"),
		"Current number of flows in this shard's nat_conn_table, by address family -- a point-in-time "+
			"snapshot; the table is a self-evicting LRU, so this can fluctuate independently of actual "+
			"live traffic under memory pressure.",
		[]string{"family"}, nil,
	)
	dropsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "drops_total"),
		"Packets dropped by this shard's datapath, by reason (drop_reasons map).",
		[]string{"reason"}, nil,
	)
)

// Describe implements prometheus.Collector.
func (c *natCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- connsDesc
	ch <- dropsDesc
}

// Collect implements prometheus.Collector.
func (c *natCollector) Collect(ch chan<- prometheus.Metric) {
	c.collectConns(ch)
	c.collectDrops(ch)
}

func familyLabel(family uint8) string {
	switch family {
	case natprog.FamilyIPv4:
		return "nat64"
	case natprog.FamilyIPv6:
		return "nat66"
	default:
		return "unknown"
	}
}

func (c *natCollector) collectConns(ch chan<- prometheus.Metric) {
	entries, err := c.connTable.List()
	if err != nil {
		ch <- prometheus.NewInvalidMetric(connsDesc, fmt.Errorf("list nat_conn_table: %w", err))
		return
	}
	// Both families are always reported, zero included: a family that
	// disappears from the output entirely reads as "not scraped" rather than
	// "no flows", which is the difference that matters at 3am.
	byFamily := map[string]int{"nat66": 0, "nat64": 0}
	for _, entry := range entries {
		byFamily[familyLabel(entry.Family)]++
	}
	for family, count := range byFamily {
		ch <- prometheus.MustNewConstMetric(connsDesc, prometheus.GaugeValue, float64(count), family)
	}
}

func (c *natCollector) collectDrops(ch chan<- prometheus.Metric) {
	if c.dropReasons == nil {
		return
	}
	totals, err := natmap.DropReasonTotals(c.dropReasons)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(dropsDesc, fmt.Errorf("read drop_reasons: %w", err))
		return
	}
	for i, total := range totals {
		name := natprog.DropReasonNames[i]
		if name == "" {
			name = fmt.Sprintf("unknown_%d", i)
		}
		ch <- prometheus.MustNewConstMetric(dropsDesc, prometheus.CounterValue, float64(total), name)
	}
}
