// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/intf"
)

const attachmentNamespace = "galactic_vpc_attachment"

var attachmentLabels = []string{labelVPC, labelVPCAttachment, "host_interface"}

var (
	attachmentReceiveBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(attachmentNamespace, "", "receive_bytes_total"),
		"Bytes delivered to the instance through this VPC attachment, read from the host-side link's "+
			"transmit counter. Counts link-layer frames.",
		attachmentLabels, nil)
	attachmentTransmitBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(attachmentNamespace, "", "transmit_bytes_total"),
		"Bytes sent by the instance through this VPC attachment, read from the host-side link's "+
			"receive counter. Counts link-layer frames.",
		attachmentLabels, nil)
)

// LinkLister lists every link in the host network namespace.
type LinkLister func() ([]netlink.Link, error)

// AttachmentCollector exports kernel byte counters for each VPC attachment's
// host-side link, read at scrape time.
type AttachmentCollector struct{ listLinks LinkLister }

// NewAttachmentCollector builds an AttachmentCollector that reads links from
// listLinks at every scrape.
func NewAttachmentCollector(listLinks LinkLister) *AttachmentCollector {
	return &AttachmentCollector{listLinks: listLinks}
}

// Describe implements prometheus.Collector.
func (c *AttachmentCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- attachmentReceiveBytesDesc
	ch <- attachmentTransmitBytesDesc
}

// Collect implements prometheus.Collector. The host-side link faces the
// instance, so its transmit counter is what the instance received and its
// receive counter is what the instance sent.
func (c *AttachmentCollector) Collect(ch chan<- prometheus.Metric) {
	links, err := c.listLinks()
	if err != nil {
		err = fmt.Errorf("list links: %w", err)
		ch <- prometheus.NewInvalidMetric(attachmentReceiveBytesDesc, err)
		ch <- prometheus.NewInvalidMetric(attachmentTransmitBytesDesc, err)
		return
	}
	for _, link := range links {
		attrs := link.Attrs()
		vpc, att, ok := intf.ParseInterfaceNameHost(attrs.Name)
		if !ok || attrs.Statistics == nil {
			continue
		}
		stats := attrs.Statistics
		ch <- prometheus.MustNewConstMetric(attachmentReceiveBytesDesc, prometheus.CounterValue,
			float64(stats.TxBytes), vpc, att, attrs.Name)
		ch <- prometheus.MustNewConstMetric(attachmentTransmitBytesDesc, prometheus.CounterValue,
			float64(stats.RxBytes), vpc, att, attrs.Name)
	}
}
