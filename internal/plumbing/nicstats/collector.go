// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nicstats

import (
	"log/slog"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/safchain/ethtool"
	"golang.org/x/sys/unix"
)

// Reader is the part of ethtool the collector uses, so tests can substitute a
// fake. *ethtool.Ethtool satisfies it.
type Reader interface {
	DriverInfo(intf string) (ethtool.DrvInfo, error)
	Stats(intf string) (map[string]uint64, error)
}

const (
	packetsHelp  = "Packets received on one NIC receive queue of an uplink, from the driver's ethtool statistics."
	discardsHelp = "Packets one NIC receive queue of an uplink discarded before any XDP program saw them, from the " +
		"driver's ethtool statistics. Only drivers that count discards per queue report it."
	ringStatHelp = "One of a NIC queue's other driver counters on an uplink, under its ethtool name in stat. " +
		"Reported for bnxt_en only."
	infoHelp = "Always 1. Names an uplink's driver, driver version, NIC firmware version and the node's kernel release."
)

// kernelRelease returns the running kernel's release, as uname -r prints it.
// It is a variable so tests can pin it.
var kernelRelease = func() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return unix.ByteSliceToString(u.Release[:])
}

// Collector exports the per-queue receive counters of a changing set of
// interfaces, read from ethtool at every scrape.
type Collector struct {
	reader     Reader
	interfaces func() []string

	kernel string

	packetsDesc  *prometheus.Desc
	discardsDesc *prometheus.Desc
	ringStatDesc *prometheus.Desc
	infoDesc     *prometheus.Desc
}

// NewCollector builds a Collector whose metrics are named under namespace.
// interfaces is called at every scrape, so the exported set follows
// interfaces that come and go.
func NewCollector(namespace string, reader Reader, interfaces func() []string) *Collector {
	const iface, driver, queue = "interface", "driver", "queue"
	labels := []string{iface, driver, queue}
	return &Collector{
		reader:     reader,
		interfaces: interfaces,
		kernel:     kernelRelease(),
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
		ringStatDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "uplink", "queue_driver_stat_total"),
			ringStatHelp,
			[]string{iface, driver, queue, "stat"}, nil,
		),
		infoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "uplink", "info"),
			infoHelp,
			[]string{iface, driver, "driver_version", "firmware_version", "kernel"}, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packetsDesc
	ch <- c.discardsDesc
	ch <- c.ringStatDesc
	ch <- c.infoDesc
}

// Collect implements prometheus.Collector. An interface whose driver
// information cannot be read is left out of this scrape rather than failing it,
// since that would also hide every other metric on the endpoint. An uplink
// that has just disappeared is the usual cause. If statistics cannot be read,
// galactic_nat_uplink_info is still exported; an unsupported driver skips the
// queue counters but exports the info metric.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	for _, iface := range c.interfaces() {
		info, err := c.reader.DriverInfo(iface)
		if err != nil {
			slog.Debug("Cannot read uplink driver info", "interface", iface, "error", err)
			continue
		}
		driver := info.Driver
		ch <- prometheus.MustNewConstMetric(c.infoDesc, prometheus.GaugeValue, 1,
			iface, driver, info.Version, info.FwVersion, c.kernel)
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
		for _, r := range ParseRingStats(driver, stats) {
			ch <- prometheus.MustNewConstMetric(c.ringStatDesc, prometheus.CounterValue,
				float64(r.Value), iface, driver, strconv.Itoa(r.Queue), r.Stat)
		}
	}
}
