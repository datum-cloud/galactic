// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nicstats reads a NIC's per-receive-queue counters from its ethtool
// statistics and exports them to Prometheus.
//
// The NIC drops packets before any XDP program sees them, so a datapath's own
// drop counters stay flat while one receive queue stalls (#673). The
// interface-wide counters do not help either: a queue dropping a large share of
// its traffic is a small share of the whole. Only the per-queue counters tell a
// stalled queue apart from an ordinary burst.
//
// ethtool statistic names are driver-specific, so each supported driver has
// its own parser. A driver with no parser exports nothing, rather than a guess
// at which of its counters mean what.
//
// For bnxt_en, the driver the stall has been seen on, a queue's other ring
// counters are exported too, along with every uplink's driver, firmware and
// kernel versions, as the data needed to find the stall's cause.
package nicstats

import (
	"regexp"
	"sort"
	"strconv"
)

// QueueStats is one receive queue's counters. HasDiscards is false for a
// driver that does not report receive discards per queue.
type QueueStats struct {
	Queue       int
	Packets     uint64
	Discards    uint64
	HasDiscards bool
}

// parser turns one driver's ethtool statistics into per-queue counters.
type parser func(stats map[string]uint64) map[int]*QueueStats

// Driver names, as ethtool's driver info reports them.
const (
	DriverBnxt  = "bnxt_en"
	DriverIxgbe = "ixgbe"
	DriverIce   = "ice"
	DriverI40e  = "i40e"
	DriverMlx5  = "mlx5_core"
)

// parsers maps a driver name to its parser.
var parsers = map[string]parser{
	DriverBnxt:  parseBnxt,
	DriverIxgbe: parsePackets(regexp.MustCompile(`^rx_queue_(\d+)_packets$`)),
	DriverIce:   parsePackets(regexp.MustCompile(`^rx_queue_(\d+)_packets$`)),
	DriverI40e:  parsePackets(regexp.MustCompile(`^rx-(\d+)\.packets$`)),
	DriverMlx5:  parsePackets(regexp.MustCompile(`^rx(\d+)_packets$`)),
}

// Supported reports whether driver has a parser.
func Supported(driver string) bool {
	_, ok := parsers[driver]
	return ok
}

// ParseQueueStats returns stats' per-queue receive counters for driver, keyed
// by queue. It returns nil for a driver with no parser.
func ParseQueueStats(driver string, stats map[string]uint64) map[int]*QueueStats {
	p, ok := parsers[driver]
	if !ok {
		return nil
	}
	return p(stats)
}

// bnxtRing matches bnxt_en's per-ring counters, "[2]: rx_discards". A ring's
// packets are its unicast, multicast and broadcast counts together.
var bnxtRing = regexp.MustCompile(`^\[(\d+)\]: (rx_ucast_packets|rx_mcast_packets|rx_bcast_packets|rx_discards)$`)

func parseBnxt(stats map[string]uint64) map[int]*QueueStats {
	queues := map[int]*QueueStats{}
	for name, value := range stats {
		m := bnxtRing.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		q := queue(queues, m[1])
		if m[2] == "rx_discards" {
			q.Discards = value
			q.HasDiscards = true
		} else {
			q.Packets += value
		}
	}
	return queues
}

// parsePackets builds a parser for a driver that counts packets per receive
// queue but not discards, the queue being pattern's first submatch.
func parsePackets(pattern *regexp.Regexp) parser {
	return func(stats map[string]uint64) map[int]*QueueStats {
		queues := map[int]*QueueStats{}
		for name, value := range stats {
			if m := pattern.FindStringSubmatch(name); m != nil {
				queue(queues, m[1]).Packets = value
			}
		}
		return queues
	}
}

// queue returns queues' entry for the decimal index, creating it if absent.
// The patterns only match digits, so the conversion cannot fail short of an
// index too large for an int, which no NIC has.
func queue(queues map[int]*QueueStats, index string) *QueueStats {
	n, _ := strconv.Atoi(index)
	q, ok := queues[n]
	if !ok {
		q = &QueueStats{Queue: n}
		queues[n] = q
	}
	return q
}

// RingStat is one of a queue's other driver counters, exported under its
// ethtool name so a stalled queue can be compared with its siblings counter by
// counter.
type RingStat struct {
	Queue int
	Stat  string
	Value uint64
}

// ringStatParsers maps a driver name to the parser for its other per-queue
// counters. Only bnxt_en has one: it is the driver the stall has been seen on
// (#673), and its rings carry the counters that tell its causes apart.
var ringStatParsers = map[string]*regexp.Regexp{
	// A bnxt_en ring's receive and transmit share one completion ring, so a
	// transmit side that stops completing shows here next to its receive
	// queue's discards. rx_resets, rx_buf_errors and missed_irqs are the
	// driver's own recovery and interrupt counters.
	DriverBnxt: regexp.MustCompile(`^\[(\d+)\]: (tx_ucast_packets|tx_mcast_packets|tx_bcast_packets|tx_discards|` +
		`tx_errors|rx_errors|rx_buf_errors|rx_resets|missed_irqs)$`),
}

// ParseRingStats returns stats' other per-queue counters for driver, sorted by
// queue and then name. It returns nil for a driver with no such parser.
func ParseRingStats(driver string, stats map[string]uint64) []RingStat {
	pattern, ok := ringStatParsers[driver]
	if !ok {
		return nil
	}
	var out []RingStat
	for name, value := range stats {
		m := pattern.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		out = append(out, RingStat{Queue: n, Stat: m[2], Value: value})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Queue != out[j].Queue {
			return out[i].Queue < out[j].Queue
		}
		return out[i].Stat < out[j].Stat
	})
	return out
}
