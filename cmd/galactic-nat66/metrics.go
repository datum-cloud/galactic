// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/plumbing/ebpf/nat66map"
	"go.datum.net/galactic/internal/plumbing/ebpf/nat66prog"
)

const metricsNamespace = "galactic_nat66"

// nat66Collector is a prometheus.Collector reading this shard's live eBPF
// map state at every scrape: drops by reason (drop_reasons) and the
// current nat66_conn_table occupancy -- mirroring
// internal/plumbing/ebpf/edgemetrics.Collector's pull-based-collector
// shape (reading live at scrape time rather than incrementally-updated
// Gauges), scoped down to what nat66map actually exposes read access to
// (see that package's doc comment for why nat66_conn_table is
// observability-only: it is entirely datapath-owned).
type nat66Collector struct {
	connTable   *nat66map.ConnTable
	dropReasons nat66map.DropReasonsReader
}

// newNat66Collector builds a nat66Collector reading directly from a
// loaded *nat66prog.Nat66Objects's Nat66ConnTable/DropReasons maps -- the
// object internal/plumbing/ebpf/nat66attach.Load returns.
func newNat66Collector(objs *nat66prog.Nat66Objects) *nat66Collector {
	return &nat66Collector{
		connTable:   nat66map.NewConnTable(nat66map.KernelTable{Map: objs.Nat66ConnTable}),
		dropReasons: objs.DropReasons,
	}
}

var (
	connsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "conns"),
		"Current number of flows in this shard's nat66_conn_table -- a point-in-time snapshot; the table "+
			"is a self-evicting LRU, so this can fluctuate independently of actual live traffic under memory pressure.",
		nil, nil,
	)
	dropsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "drops_total"),
		"Packets dropped by the nat66_ingress program, by reason (drop_reasons map).",
		[]string{"reason"}, nil,
	)
)

// Describe implements prometheus.Collector.
func (c *nat66Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- connsDesc
	ch <- dropsDesc
}

// Collect implements prometheus.Collector.
func (c *nat66Collector) Collect(ch chan<- prometheus.Metric) {
	c.collectConns(ch)
	c.collectDrops(ch)
}

func (c *nat66Collector) collectConns(ch chan<- prometheus.Metric) {
	entries, err := c.connTable.List()
	if err != nil {
		ch <- prometheus.NewInvalidMetric(connsDesc, fmt.Errorf("list nat66_conn_table: %w", err))
		return
	}
	ch <- prometheus.MustNewConstMetric(connsDesc, prometheus.GaugeValue, float64(len(entries)))
}

func (c *nat66Collector) collectDrops(ch chan<- prometheus.Metric) {
	if c.dropReasons == nil {
		return
	}
	totals, err := nat66map.DropReasonTotals(c.dropReasons)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(dropsDesc, fmt.Errorf("read drop_reasons: %w", err))
		return
	}
	for i, total := range totals {
		name := nat66prog.DropReasonNames[i]
		if name == "" {
			name = fmt.Sprintf("unknown_%d", i)
		}
		ch <- prometheus.MustNewConstMetric(dropsDesc, prometheus.CounterValue, float64(total), name)
	}
}
