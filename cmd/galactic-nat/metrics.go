// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/natmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

const metricsNamespace = "galactic_nat"

// natCollector reads this shard's live map state at every scrape: drops by
// reason, connection-table rows by address family, and live sessions by family
// and protocol. It is a pull-based collector like the other datapaths',
// scoped to what the map layer exposes read access to, the connection table
// being entirely datapath-owned and so observability-only.
type natCollector struct {
	connTable      *natmap.ConnTable
	connMaxEntries uint32
	dropReasons    natmap.DropReasonsReader

	// now reads the clock the datapath stamps last_seen with. Nil means
	// datapathNow.
	now func() uint32
}

// datapathNow reads the datapath's session clock: bpf_ktime_get_ns is
// CLOCK_MONOTONIC, which the datapath keeps in whole seconds truncated to 32
// bits (now_sec in nat.c).
func datapathNow() uint32 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint32(ts.Sec)
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
		"Rows in this shard's nat_conn_table, by address family, expired sessions included: "+
			"a session holds two rows, and an expired one keeps them until the LRU evicts them or a "+
			"new claim reuses its port. See galactic_nat_sessions for live sessions.",
		[]string{"family"}, nil,
	)
	sessionsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "sessions"),
		"Live sessions in this shard's nat_conn_table, by address family and protocol: sessions "+
			"within their idle timeout, one per session. Expired sessions are not counted.",
		[]string{"family", "proto"}, nil,
	)
	oldestRowAgeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "conn_table_oldest_row_age_seconds"),
		"Seconds since the least recently seen session in nat_conn_table last translated a packet, "+
			"expired sessions included. On a full table this approximates how long an idle session "+
			"survives before the LRU evicts it; below the longest session timeout, idle live sessions "+
			"are being evicted.",
		nil, nil,
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
	ch <- sessionsDesc
	ch <- oldestRowAgeDesc
	ch <- connTableMaxEntriesDesc
	ch <- dropsDesc
}

// Collect implements prometheus.Collector.
func (c *natCollector) Collect(ch chan<- prometheus.Metric) {
	c.collectConns(ch)
	c.collectConnTableMaxEntries(ch)
	c.collectDrops(ch)
}

// Family label values, one per address family a shard translates.
const (
	familyNAT66 = "nat66"
	familyNAT64 = "nat64"
)

func familyLabel(family uint8) string {
	switch family {
	case natprog.FamilyIPv4:
		return familyNAT64
	case natprog.FamilyIPv6:
		return familyNAT66
	default:
		return "unknown"
	}
}

func (c *natCollector) collectConns(ch chan<- prometheus.Metric) {
	if c.connTable == nil {
		return
	}
	now := c.now
	if now == nil {
		now = datapathNow
	}
	// A walk the datapath's own inserts and evictions disturbed still reports
	// what it counted: an error metric here fails the whole scrape, drops
	// included.
	counts, err := c.connTable.CountSessions(now())
	if err != nil {
		slog.Debug("nat_conn_table walk incomplete; reporting an approximate count", "err", err)
	}
	// Every family and protocol is always reported, zero included: a series
	// that disappears from the output entirely reads as "not scraped" rather
	// than "no flows", which is the difference that matters at 3am.
	rows := map[string]int{familyNAT66: 0, familyNAT64: 0}
	for family, count := range counts.Rows {
		rows[familyLabel(family)] += count
	}
	for family, count := range rows {
		ch <- prometheus.MustNewConstMetric(connsDesc, prometheus.GaugeValue, float64(count), family)
	}

	live := map[[2]string]int{}
	for _, family := range []string{familyNAT66, familyNAT64} {
		for _, proto := range []string{natmap.SessionProtoTCP, natmap.SessionProtoUDP, natmap.SessionProtoICMP} {
			live[[2]string{family, proto}] = 0
		}
	}
	for key, count := range counts.Live {
		live[[2]string{familyLabel(key.Family), key.Proto}] += count
	}
	for key, count := range live {
		ch <- prometheus.MustNewConstMetric(sessionsDesc, prometheus.GaugeValue, float64(count), key[0], key[1])
	}

	if counts.HasReverse {
		ch <- prometheus.MustNewConstMetric(oldestRowAgeDesc, prometheus.GaugeValue, float64(counts.OldestAge))
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
