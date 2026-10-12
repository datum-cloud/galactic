// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/natmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/natprog"
)

const metricsNamespace = "galactic_nat"

// labelFamily is the label carrying an address family, familyNAT66 or
// familyNAT64, and labelProto the one carrying a session protocol.
const (
	labelFamily = "family"
	labelProto  = "proto"
)

// masqueradeLabels label the masquerade port series.
var masqueradeLabels = []string{labelFamily, "address", labelProto}

// trafficLabels label the translated-traffic series.
var trafficLabels = []string{labelFamily, "direction", "action"}

// natCollector reads this shard's live map state at every scrape: drops by
// reason, connection-table rows by address family, and live sessions by family
// and protocol. It is a pull-based collector like the other datapaths',
// scoped to what the map layer exposes read access to, the connection table
// being entirely datapath-owned and so observability-only.
type natCollector struct {
	connTable      *natmap.ConnTable
	connMaxEntries uint32
	dropReasons    natmap.DropReasonsReader
	traffic        natmap.TrafficReader
	claims         natmap.CounterReader

	// shardConfig names the masquerade addresses whose port usage is always
	// reported, zero included. Nil reports only the addresses rows hold.
	shardConfig *natmap.ShardConfigTable

	// now reads the clock the datapath stamps last_seen with. Nil means
	// datapathNow.
	now func() (uint32, error)
}

// datapathNow reads the datapath's session clock: bpf_ktime_get_ns is
// CLOCK_MONOTONIC, which the datapath keeps in whole seconds truncated to 32
// bits (now_sec in nat.c).
func datapathNow() (uint32, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("read CLOCK_MONOTONIC: %w", err)
	}
	return uint32(ts.Sec), nil //nolint:gosec // truncated to 32 bits, as the datapath's now_sec does
}

// newNatCollector builds a collector reading directly from a loaded object
// set's maps.
func newNatCollector(objs *natprog.NatObjects) *natCollector {
	return &natCollector{
		connTable:      natmap.NewConnTable(natmap.KernelTable{Map: objs.NatConnTable}),
		connMaxEntries: mapMaxEntries(objs.NatConnTable),
		dropReasons:    objs.DropReasons,
		traffic:        objs.NatTraffic,
		claims:         objs.NatClaims,
		shardConfig:    natmap.NewShardConfigTable(natmap.KernelTable{Map: objs.ShardConfigTable}),
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
		[]string{labelFamily}, nil,
	)
	sessionsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "sessions"),
		"Live sessions in this shard's nat_conn_table, by address family and protocol: sessions "+
			"within their idle timeout, one per session. Expired sessions are not counted.",
		[]string{labelFamily, labelProto}, nil,
	)
	oldestRowAgeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "conn_table_oldest_row_age_seconds"),
		"Seconds since the least recently seen session in nat_conn_table last translated a packet, "+
			"expired sessions included. Meaningful only while the table is near full: then it "+
			"approximates how long an idle session survives before the LRU evicts it, and a value "+
			"below the longest session timeout means idle live sessions are being evicted. On a "+
			"table with room it only grows.",
		nil, nil,
	)
	connTableMaxEntriesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "conn_table_max_entries"),
		"Capacity of nat_conn_table in rows.",
		nil, nil,
	)
	packetsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "packets_total"),
		"Packets this shard translated and queued for transmit, by address family, direction (outbound: tenant "+
			"to internet, return: internet to tenant) and action (redirect: out another interface, tx: out the "+
			"interface it arrived on). Packets the shard generates itself, such as Packet Too Big, and packets it "+
			"passes on unclaimed are not counted.",
		trafficLabels, nil,
	)
	bytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "bytes_total"),
		"Bytes of the packets in galactic_nat_packets_total: the translated packet's IP header and payload, "+
			"without the Ethernet header or the SRv6 outer header a return packet carries.",
		trafficLabels, nil,
	)
	portsInUseDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "masquerade", "ports_in_use"),
		"Distinct masquerade ports live sessions hold on this masquerade address and protocol, toward any "+
			"destination. A port is claimed per destination address and port, so this can sit near "+
			"galactic_nat_masquerade_port_range on a healthy shard; see "+
			"galactic_nat_masquerade_destination_ports_max for exhaustion.",
		masqueradeLabels, nil,
	)
	destinationPortsMaxDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "masquerade", "destination_ports_max"),
		"The most masquerade ports live sessions hold toward any single destination address and port, on this "+
			"masquerade address and protocol. New flows to that destination start failing as it approaches "+
			"galactic_nat_masquerade_port_range.",
		masqueradeLabels, nil,
	)
	portRangeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "masquerade", "port_range"),
		"Masquerade ports (or ICMP Echo Identifiers) available toward each destination address and port.",
		nil, nil,
	)
	sessionCreatesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "session_creates_total"),
		"New sessions this shard opened, each one a masquerade port (or ICMP Echo Identifier) it claimed, by "+
			"address family and protocol. A claim that found no free port is a *_pat_exhausted drop instead.",
		[]string{labelFamily, labelProto}, nil,
	)
	claimProbesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "masquerade", "claim_probes_total"),
		"New sessions' masquerade port claims by how many probes each took, 1 to 8. With a share u of a "+
			"destination's ports held, a claim needs more than k probes with probability of roughly u^k, so the share of "+
			"claims needing more than one probe estimates how full the busiest destinations are.",
		[]string{labelFamily, labelProto, "probes"}, nil,
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
	ch <- packetsDesc
	ch <- bytesDesc
	ch <- portsInUseDesc
	ch <- destinationPortsMaxDesc
	ch <- portRangeDesc
	ch <- sessionCreatesDesc
	ch <- claimProbesDesc
}

// Collect implements prometheus.Collector.
func (c *natCollector) Collect(ch chan<- prometheus.Metric) {
	c.collectConns(ch)
	c.collectConnTableMaxEntries(ch)
	c.collectDrops(ch)
	c.collectTraffic(ch)
	c.collectClaims(ch)
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

// collectConns reports the session table's rows, live sessions and oldest row.
// A collector with no table, like one with no capacity, reports none of them;
// newNatCollector always sets one, so that happens only in tests.
func (c *natCollector) collectConns(ch chan<- prometheus.Metric) {
	if c.connTable == nil {
		return
	}
	clock := c.now
	if clock == nil {
		clock = datapathNow
	}
	// Without the datapath's clock every row's age is meaningless, so the
	// scrape skips these series rather than report wrong ones; the drop
	// counters are still reported.
	now, err := clock()
	if err != nil {
		slog.Warn("cannot read the session clock; skipping session table metrics", "err", err)
		ch <- prometheus.MustNewConstMetric(portRangeDesc, prometheus.GaugeValue, float64(natprog.PATPortRange))
		return
	}
	// A walk the datapath's own inserts and evictions disturbed still reports
	// what it counted: an error metric here fails the whole scrape, drops
	// included.
	counts, err := c.connTable.CountSessions(now)
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

	c.collectPorts(ch, counts.Ports)
}

// collectPorts reports port usage for every masquerade address and protocol
// the programmed identity serves, zero included, and for any other address
// live rows still hold, such as one a re-programmed identity replaced.
func (c *natCollector) collectPorts(ch chan<- prometheus.Metric, usage map[natmap.MasqueradeKey]natmap.PortUsage) {
	ch <- prometheus.MustNewConstMetric(portRangeDesc, prometheus.GaugeValue, float64(natprog.PATPortRange))

	all := map[natmap.MasqueradeKey]natmap.PortUsage{}
	if c.shardConfig != nil {
		if cfg, ok, err := c.shardConfig.Get(); err != nil {
			slog.Debug("cannot read shard_config_table; reporting port usage only for held addresses", "err", err)
		} else if ok {
			for _, served := range []struct {
				family uint8
				addr   netip.Addr
			}{{natprog.FamilyIPv6, cfg.ShardPubAddr6}, {natprog.FamilyIPv4, cfg.ShardPubAddr4}} {
				if !served.addr.IsValid() {
					continue
				}
				for _, proto := range []string{natmap.SessionProtoTCP, natmap.SessionProtoUDP, natmap.SessionProtoICMP} {
					all[natmap.MasqueradeKey{Family: served.family, Address: served.addr, Proto: proto}] = natmap.PortUsage{}
				}
			}
		}
	}
	maps.Copy(all, usage)
	for key, u := range all {
		labels := []string{familyLabel(key.Family), key.Address.String(), key.Proto}
		ch <- prometheus.MustNewConstMetric(portsInUseDesc, prometheus.GaugeValue, float64(u.InUse), labels...)
		ch <- prometheus.MustNewConstMetric(destinationPortsMaxDesc, prometheus.GaugeValue,
			float64(u.MaxPerDestination), labels...)
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
		slog.Warn("cannot read drop_reasons; skipping drop metrics", "err", err)
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

// collectTraffic reports every family, direction and action, zero included.
func (c *natCollector) collectTraffic(ch chan<- prometheus.Metric) {
	if c.traffic == nil {
		return
	}
	// Skipped rather than reported as an invalid metric, which the metrics
	// server turns into a failed scrape of every other series.
	totals, err := natmap.TrafficTotals(c.traffic)
	if err != nil {
		slog.Warn("cannot read nat_traffic; skipping translated traffic metrics", "err", err)
		return
	}
	families := []struct {
		id    uint32
		label string
	}{{natprog.TrafficFamilyNAT66, familyNAT66}, {natprog.TrafficFamilyNAT64, familyNAT64}}
	directions := []struct {
		id    uint32
		label string
	}{{natprog.TrafficDirectionOutbound, "outbound"}, {natprog.TrafficDirectionReturn, "return"}}
	actions := []struct {
		id    uint32
		label string
	}{{natprog.TrafficActionRedirect, "redirect"}, {natprog.TrafficActionTX, "tx"}}
	for _, f := range families {
		for _, d := range directions {
			for _, a := range actions {
				t := totals[natprog.TrafficSlot(f.id, d.id, a.id)]
				ch <- prometheus.MustNewConstMetric(packetsDesc, prometheus.CounterValue, float64(t.Packets),
					f.label, d.label, a.label)
				ch <- prometheus.MustNewConstMetric(bytesDesc, prometheus.CounterValue, float64(t.Bytes),
					f.label, d.label, a.label)
			}
		}
	}
}

// collectClaims reports new sessions by family and protocol, and their claims
// by probe count, every combination zero included.
func (c *natCollector) collectClaims(ch chan<- prometheus.Metric) {
	if c.claims == nil {
		return
	}
	totals, err := natmap.ClaimTotals(c.claims)
	if err != nil {
		slog.Warn("cannot read nat_claims; skipping session creation metrics", "err", err)
		return
	}
	families := []struct {
		id    uint32
		label string
	}{{natprog.TrafficFamilyNAT66, familyNAT66}, {natprog.TrafficFamilyNAT64, familyNAT64}}
	protos := []struct {
		id    uint32
		label string
	}{
		{natprog.ClaimProtoTCP, natmap.SessionProtoTCP},
		{natprog.ClaimProtoUDP, natmap.SessionProtoUDP},
		{natprog.ClaimProtoICMP, natmap.SessionProtoICMP},
	}
	for _, f := range families {
		for _, p := range protos {
			var creates uint64
			for probes := 1; probes <= natprog.PATProbeLimit; probes++ {
				n := totals[natprog.ClaimSlot(f.id, p.id, probes)]
				creates += n
				ch <- prometheus.MustNewConstMetric(claimProbesDesc, prometheus.CounterValue, float64(n),
					f.label, p.label, strconv.Itoa(probes))
			}
			ch <- prometheus.MustNewConstMetric(sessionCreatesDesc, prometheus.CounterValue, float64(creates),
				f.label, p.label)
		}
	}
}
