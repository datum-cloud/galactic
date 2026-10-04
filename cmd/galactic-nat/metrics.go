// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
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
	connTable      *natmap.ConnTable
	connMaxEntries uint32
	dropReasons    natmap.DropReasonsReader
}

// newNatCollector builds a collector reading directly from a loaded object
// set's maps.
func newNatCollector(objs *natprog.NatObjects) *natCollector {
	return &natCollector{
		connTable:      natmap.NewConnTable(natmap.KernelTable{Map: objs.NatConnTable}),
		connMaxEntries: mapMaxEntries(objs.NatConnTable),
		dropReasons:    objs.DropReasons,
	}
}

func mapMaxEntries(m *ebpf.Map) uint32 {
	info, err := m.Info()
	if err != nil {
		return m.MaxEntries()
	}
	return info.MaxEntries
}

var (
	connsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "conns"),
		"Current number of flows in this shard's nat_conn_table, by address family -- a point-in-time "+
			"snapshot; the table is a self-evicting LRU, so this can fluctuate independently of actual "+
			"live traffic under memory pressure.",
		[]string{"family"}, nil,
	)
	connTableMaxEntriesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "conn_table_max_entries"),
		"Capacity of nat_conn_table in rows.",
		nil, nil,
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
	ch <- connTableMaxEntriesDesc
	ch <- dropsDesc
}

// Collect implements prometheus.Collector.
func (c *natCollector) Collect(ch chan<- prometheus.Metric) {
	c.collectConns(ch)
	c.collectConnTableMaxEntries(ch)
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
	// A walk the datapath's own inserts and evictions disturbed still reports
	// what it counted: an error metric here fails the whole scrape, drops
	// included.
	counts, err := c.connTable.CountByFamily()
	if err != nil {
		slog.Debug("nat_conn_table walk incomplete; reporting an approximate count", "err", err)
	}
	// Both families are always reported, zero included: a family that
	// disappears from the output entirely reads as "not scraped" rather than
	// "no flows", which is the difference that matters at 3am.
	byFamily := map[string]int{"nat66": 0, "nat64": 0}
	for family, count := range counts {
		byFamily[familyLabel(family)] += count
	}
	for family, count := range byFamily {
		ch <- prometheus.MustNewConstMetric(connsDesc, prometheus.GaugeValue, float64(count), family)
	}
}

func (c *natCollector) collectConnTableMaxEntries(ch chan<- prometheus.Metric) {
	if c.connMaxEntries == 0 {
		return
	}
	ch <- prometheus.MustNewConstMetric(connTableMaxEntriesDesc, prometheus.GaugeValue, float64(c.connMaxEntries))
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
