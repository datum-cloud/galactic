// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nicstats

import (
	"log/slog"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// Reader is the part of ethtool the collector uses, so tests can substitute a
// fake. *ethtool.Ethtool satisfies it.
type Reader interface {
	DriverName(intf string) (string, error)
	Stats(intf string) (map[string]uint64, error)
}

const (
	packetsHelp  = "Packets received on one NIC receive queue of an uplink, from the driver's ethtool statistics."
	discardsHelp = "Packets one NIC receive queue of an uplink discarded before any XDP program saw them, from the " +
		"driver's ethtool statistics. Only drivers that count discards per queue report it."
)

// Collector exports the per-queue receive counters of a changing set of
// interfaces, read from ethtool at every scrape.
type Collector struct {
	reader     Reader
	interfaces func() []string

	packetsDesc  *prometheus.Desc
	discardsDesc *prometheus.Desc
}

// NewCollector builds a Collector whose metrics are named under namespace.
// interfaces is called at every scrape, so the exported set follows
// interfaces that come and go.
func NewCollector(namespace string, reader Reader, interfaces func() []string) *Collector {
	labels := []string{"interface", "driver", "queue"}
	return &Collector{
		reader:     reader,
		interfaces: interfaces,
		packetsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "uplink", "rx_queue_packets_total"),
			packetsHelp,
			labels, nil,
		),
		discardsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "uplink", "rx_queue_discards_total"),
			discardsHelp,
			labels, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packetsDesc
	ch <- c.discardsDesc
}

// Collect implements prometheus.Collector. An interface whose driver or
// statistics cannot be read is left out of this scrape rather than failing it,
// since that would also hide every other metric on the endpoint. An uplink
// that has just disappeared is the usual cause.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	for _, iface := range c.interfaces() {
		driver, err := c.reader.DriverName(iface)
		if err != nil {
			slog.Debug("Cannot read uplink driver name", "interface", iface, "error", err)
			continue
		}
		if !Supported(driver) {
			continue
		}
		stats, err := c.reader.Stats(iface)
		if err != nil {
			slog.Debug("Cannot read uplink ethtool statistics", "interface", iface, "error", err)
			continue
		}
		for _, q := range ParseQueueStats(driver, stats) {
			queue := strconv.Itoa(q.Queue)
			ch <- prometheus.MustNewConstMetric(c.packetsDesc, prometheus.CounterValue,
				float64(q.Packets), iface, driver, queue)
			if q.HasDiscards {
				ch <- prometheus.MustNewConstMetric(c.discardsDesc, prometheus.CounterValue,
					float64(q.Discards), iface, driver, queue)
			}
		}
	}
}
