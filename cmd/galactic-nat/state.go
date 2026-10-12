// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"github.com/prometheus/client_golang/prometheus"

	"go.datum.net/galactic/internal/controller"
	"go.datum.net/galactic/internal/metadata"
)

// coverageReporter is the part of a datapath that knows which uplinks it
// checked and which of them it misses, read together. A datapath without it,
// like a turned-off one, has no uplinks to report.
type coverageReporter interface {
	Coverage() (uplinks, missing []string)
}

// shardStateCollector reports, at every scrape, whether this shard is turned
// on, attached and programmed, which uplinks it covers, which families it
// serves, and an info series naming its identity and build. A shard that is
// attached but unprogrammed, or misses an uplink, passes traffic through
// untranslated, and these series are how that shows outside the logs.
type shardStateCollector struct {
	datapath  controller.EgressDatapath
	enabled   bool
	xdpAttach string
	version   string
}

// newShardStateCollector builds a collector over datapath. enabled is whether
// the datapath is turned on by configuration, and xdpAttach the attach mode
// it was configured with.
func newShardStateCollector(datapath controller.EgressDatapath, enabled bool, xdpAttach string) *shardStateCollector {
	return &shardStateCollector{datapath: datapath, enabled: enabled, xdpAttach: xdpAttach, version: metadata.Version}
}

var (
	datapathEnabledDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "datapath_enabled"),
		"1 when this shard's datapath is turned on by configuration, 0 when it is turned off and translates "+
			"nothing by design.",
		nil, nil,
	)
	datapathAttachedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "datapath_attached"),
		"1 once this shard's datapath has loaded and attached to its uplinks or the XDP dispatcher, 0 before "+
			"that or when the datapath is turned off.",
		nil, nil,
	)
	programmedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "programmed"),
		"1 when the datapath holds an EgressShard identity to translate with, 0 when it claims no packet.",
		nil, nil,
	)
	uplinkCoveredDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "uplink_covered"),
		"1 for each resolved uplink the datapath translates on, 0 for one it misses, whose traffic leaves "+
			"untranslated. Absent while the datapath is turned off.",
		[]string{"interface"}, nil,
	)
	familyEnabledDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "family_enabled"),
		"1 when the programmed identity has a masquerade address for this family, so the shard translates it.",
		[]string{labelFamily}, nil,
	)
	shardInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metricsNamespace, "", "info"),
		"Always 1. Labels carry the programmed shard SID and NAT64 prefix, empty while unprogrammed, the XDP "+
			"attach mode (off when the datapath is turned off) and the build version.",
		[]string{"shard_sid", "nat64_prefix", "xdp_attach", "version"}, nil,
	)
)

// Describe implements prometheus.Collector.
func (c *shardStateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- datapathEnabledDesc
	ch <- datapathAttachedDesc
	ch <- programmedDesc
	ch <- uplinkCoveredDesc
	ch <- familyEnabledDesc
	ch <- shardInfoDesc
}

// Collect implements prometheus.Collector.
func (c *shardStateCollector) Collect(ch chan<- prometheus.Metric) {
	identity, programmed := c.datapath.Programmed()

	ch <- prometheus.MustNewConstMetric(datapathEnabledDesc, prometheus.GaugeValue, boolValue(c.enabled))
	ch <- prometheus.MustNewConstMetric(datapathAttachedDesc, prometheus.GaugeValue, boolValue(c.datapath.Attached()))
	ch <- prometheus.MustNewConstMetric(programmedDesc, prometheus.GaugeValue, boolValue(programmed))

	if reporter, ok := c.datapath.(coverageReporter); ok {
		uplinks, missingList := reporter.Coverage()
		missing := map[string]bool{}
		for _, iface := range missingList {
			missing[iface] = true
		}
		for _, iface := range uplinks {
			ch <- prometheus.MustNewConstMetric(uplinkCoveredDesc, prometheus.GaugeValue, boolValue(!missing[iface]), iface)
		}
	}

	ch <- prometheus.MustNewConstMetric(familyEnabledDesc, prometheus.GaugeValue,
		boolValue(programmed && identity.ShardAddressIPv6.IsValid()), familyNAT66)
	ch <- prometheus.MustNewConstMetric(familyEnabledDesc, prometheus.GaugeValue,
		boolValue(programmed && identity.ShardAddressIPv4.IsValid()), familyNAT64)

	var shardSID, nat64Prefix string
	if programmed {
		if identity.ShardSID.IsValid() {
			shardSID = identity.ShardSID.String()
		}
		if identity.NAT64Prefix.IsValid() {
			nat64Prefix = identity.NAT64Prefix.String()
		}
	}
	xdpAttach := c.xdpAttach
	if !c.enabled {
		xdpAttach = "off"
	}
	ch <- prometheus.MustNewConstMetric(shardInfoDesc, prometheus.GaugeValue, 1,
		shardSID, nat64Prefix, xdpAttach, c.version)
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
